package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// chainName is the chain knock owns. Everything this tool does lives inside it,
// so INPUT/OUTPUT/FORWARD and their policies belong to whoever else runs on the
// box and are never flushed or rewritten.
const chainName = "KNOCK"

// buildChainRules returns the contents of the KNOCK chain in order, as argument
// lists ready to append with `iptables -A KNOCK`. v6 selects the ip6tables
// variant. Kept free of side effects so the rules can be asserted in tests.
func buildChainRules(config *Config, v6 bool) [][]string {
	var rules [][]string

	rules = append(rules, []string{"-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"})
	rules = append(rules, []string{"-i", "lo", "-j", "ACCEPT"})

	// On IPv6 this is not cosmetic: neighbour discovery and path MTU discovery
	// ride on ICMPv6, so dropping it breaks the stack rather than hardening it.
	if v6 {
		rules = append(rules, []string{"-p", "ipv6-icmp", "-j", "ACCEPT"})
	} else {
		rules = append(rules, []string{"-p", "icmp", "-j", "ACCEPT"})
	}

	for _, publicPort := range config.PublicPorts {
		dport := strconv.Itoa(publicPort)
		rules = append(rules, []string{"-p", "tcp", "--dport", dport, "-j", "ACCEPT"})
	}

	// The knock port is the way back in, so it stays reachable from anywhere.
	// Rate limit new connections per source: each one costs a key exchange, and
	// nothing else on this port is throttled.
	// On IPv6 a source is a /64: one host is routinely handed a whole one, and
	// counting each /128 apart would hand it endless fresh quotas.
	knockPort := strconv.Itoa(port)
	limit := []string{
		"-p", "tcp", "--dport", knockPort,
		"-m", "conntrack", "--ctstate", "NEW",
		"-m", "hashlimit",
		"--hashlimit-name", "knock",
		"--hashlimit-mode", "srcip",
		"--hashlimit-above", "10/minute",
		"--hashlimit-burst", "10",
	}
	if v6 {
		limit = append(limit, "--hashlimit-srcmask", "64")
	}
	rules = append(rules, append(limit, "-j", "DROP"))
	rules = append(rules, []string{"-p", "tcp", "--dport", knockPort, "-j", "ACCEPT"})

	// Protected ports: only from whitelisted IPs of the matching family.
	// iptables rejects a v6 source in the v4 table and vice versa.
	for _, ip := range config.AllowedIPs {
		if isIPv6(ip) != v6 {
			continue
		}
		for _, protectedPort := range config.ProtectedPorts {
			dport := strconv.Itoa(protectedPort)
			rules = append(rules, []string{"-s", ip, "-p", "tcp", "--dport", dport, "-j", "ACCEPT"})
		}
	}

	// The chain denies by default on its own — the INPUT policy is not ours.
	rules = append(rules, []string{"-j", "DROP"})

	return rules
}

// applyIPTablesRules rebuilds the KNOCK chain and makes sure INPUT jumps to it.
//
// The whole chain goes in as one iptables-restore transaction. Flushing it and
// appending rule by rule would leave it empty or without its final DROP for a
// moment — and for good if a rule failed halfway — and an unterminated chain
// returns to INPUT, which usually accepts: the box would fail open.
func applyIPTablesRules(config *Config) error {
	for _, iptables := range []string{"iptables", "ip6tables"} {
		v6 := iptables == "ip6tables"
		input := buildRestoreInput(buildChainRules(config, v6), !jumpInstalled(iptables))

		// --noflush leaves every other chain alone. Declaring KNOCK still
		// creates or flushes it, inside the same commit.
		cmd := exec.Command(iptables+"-restore", "--noflush")
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s-restore: %v: %s", iptables, err, strings.TrimSpace(string(output)))
		}
	}

	return nil
}

// buildRestoreInput renders the chain as iptables-restore input for the filter
// table. addJump hooks INPUT up to the chain in the same commit.
func buildRestoreInput(rules [][]string, addJump bool) string {
	var b strings.Builder
	b.WriteString("*filter\n")
	b.WriteString(":" + chainName + " - [0:0]\n")
	for _, rule := range rules {
		b.WriteString("-A " + chainName + " " + strings.Join(rule, " ") + "\n")
	}
	if addJump {
		b.WriteString("-I INPUT 1 -j " + chainName + "\n")
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// removeIPTablesRules wipes the firewall completely: every chain flushed, every
// policy back to ACCEPT, the KNOCK chain gone.
//
// This is deliberately destructive, unlike applyIPTablesRules, which only ever
// touches its own chain. `knock open` is the escape hatch you reach for when
// you are locked out or debugging, so it has to leave nothing behind — half
// opening the firewall would be worse than either state.
func removeIPTablesRules() error {
	for _, iptables := range []string{"iptables", "ip6tables"} {
		for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			if err := runIPTables(iptables, "-P", chain, "ACCEPT"); err != nil {
				return err
			}
			if err := runIPTables(iptables, "-F", chain); err != nil {
				return err
			}
		}

		if chainExists(iptables) {
			if err := runIPTables(iptables, "-F", chainName); err != nil {
				return err
			}
			if err := runIPTables(iptables, "-X", chainName); err != nil {
				return err
			}
		}
	}

	return nil
}

func runIPTables(iptables string, args ...string) error {
	cmd := exec.Command(iptables, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s", iptables, strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	return nil
}

func chainExists(iptables string) bool {
	cmd := exec.Command(iptables, "-S", chainName)
	return cmd.Run() == nil
}

func jumpInstalled(iptables string) bool {
	cmd := exec.Command(iptables, "-C", "INPUT", "-j", chainName)
	return cmd.Run() == nil
}
