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
	knockPort := strconv.Itoa(port)
	rules = append(rules, []string{
		"-p", "tcp", "--dport", knockPort,
		"-m", "conntrack", "--ctstate", "NEW",
		"-m", "hashlimit",
		"--hashlimit-name", "knock",
		"--hashlimit-mode", "srcip",
		"--hashlimit-above", "10/minute",
		"--hashlimit-burst", "10",
		"-j", "DROP",
	})
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
// The chain ends in DROP, so during the rebuild the box fails closed instead of
// briefly accepting everything the way a policy flip would.
func applyIPTablesRules(config *Config) error {
	for _, iptables := range []string{"iptables", "ip6tables"} {
		v6 := iptables == "ip6tables"

		if !chainExists(iptables) {
			if err := runIPTables(iptables, "-N", chainName); err != nil {
				return err
			}
		}

		if err := runIPTables(iptables, "-F", chainName); err != nil {
			return err
		}

		rules := buildChainRules(config, v6)
		for _, rule := range rules {
			args := append([]string{"-A", chainName}, rule...)
			if err := runIPTables(iptables, args...); err != nil {
				return err
			}
		}

		if !jumpInstalled(iptables) {
			if err := runIPTables(iptables, "-I", "INPUT", "1", "-j", chainName); err != nil {
				return err
			}
		}
	}

	return nil
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
