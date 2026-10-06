package main

import (
	"strconv"
	"strings"
	"testing"
)

func flatten(rules [][]string) []string {
	joined := make([]string, 0, len(rules))
	for _, rule := range rules {
		joined = append(joined, strings.Join(rule, " "))
	}
	return joined
}

func testConfig() *Config {
	return &Config{
		AllowedIPs:     []string{"1.2.3.4", "2001:db8::1"},
		Enabled:        true,
		PublicPorts:    []int{80, 443, 9443},
		ProtectedPorts: []int{22, 2222},
	}
}

// A protected port must never be reachable without a source restriction — that
// is the whole point of the tool. Derived from the config rather than hardcoded
// so it keeps holding whatever ports get protected later.
func TestProtectedPortsAreNeverOpenToEveryone(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		config := testConfig()
		rules := buildChainRules(config, v6)
		for _, rule := range flatten(rules) {
			if !strings.Contains(rule, "-j ACCEPT") {
				continue
			}
			for _, protectedPort := range config.ProtectedPorts {
				dport := strconv.Itoa(protectedPort)
				if strings.Contains(rule, "--dport "+dport) && !strings.Contains(rule, "-s ") {
					t.Errorf("v6=%v: protected port %s accepted without source restriction: %q", v6, dport, rule)
				}
			}
		}
	}
}

// A port must not end up in both lists: whitelisting it would be pointless
// because the public ACCEPT comes first and already let everyone through.
func TestPublicAndProtectedPortsDoNotOverlap(t *testing.T) {
	config := defaultConfig()
	for _, publicPort := range config.PublicPorts {
		for _, protectedPort := range config.ProtectedPorts {
			if publicPort == protectedPort {
				t.Errorf("port %d is both public and protected", publicPort)
			}
		}
	}
}

// Whitelisted IPs must land only in the matching address family, otherwise
// iptables rejects the rule and the whole apply fails.
func TestWhitelistIsSplitByAddressFamily(t *testing.T) {
	v4 := strings.Join(flatten(buildChainRules(testConfig(), false)), "\n")
	v6 := strings.Join(flatten(buildChainRules(testConfig(), true)), "\n")

	if !strings.Contains(v4, "-s 1.2.3.4") {
		t.Error("IPv4 ruleset is missing the IPv4 whitelist entry")
	}
	if strings.Contains(v4, "2001:db8::1") {
		t.Error("IPv4 ruleset contains an IPv6 whitelist entry")
	}
	if !strings.Contains(v6, "-s 2001:db8::1") {
		t.Error("IPv6 ruleset is missing the IPv6 whitelist entry")
	}
	if strings.Contains(v6, "-s 1.2.3.4") {
		t.Error("IPv6 ruleset contains an IPv4 whitelist entry")
	}
}

// The chain is the only thing enforcing the policy — INPUT is left alone — so
// it has to deny by default on its own.
func TestChainEndsInDrop(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		rules := buildChainRules(testConfig(), v6)
		last := strings.Join(rules[len(rules)-1], " ")
		if last != "-j DROP" {
			t.Errorf("v6=%v: chain must end in an unconditional DROP, got %q", v6, last)
		}
	}
}

// ICMPv6 carries neighbour discovery and path MTU discovery. Dropping it does
// not harden the box, it breaks IPv6 on it.
func TestICMPv6IsAllowed(t *testing.T) {
	v6 := strings.Join(flatten(buildChainRules(testConfig(), true)), "\n")
	if !strings.Contains(v6, "-p ipv6-icmp -j ACCEPT") {
		t.Error("IPv6 ruleset must accept ICMPv6")
	}
}

// Removing every IP must not silently turn the protected ports back on.
func TestEmptyWhitelistLeavesProtectedPortsClosed(t *testing.T) {
	config := testConfig()
	config.AllowedIPs = nil
	rules := flatten(buildChainRules(config, false))

	for _, rule := range rules {
		if strings.Contains(rule, "--dport 22") && strings.Contains(rule, "-j ACCEPT") {
			t.Errorf("port 22 accepted with an empty whitelist: %q", rule)
		}
	}
}

// The knock port has to stay reachable from anywhere — it is the way back in —
// but new connections must be rate limited per source.
func TestKnockPortIsPublicButRateLimited(t *testing.T) {
	rules := flatten(buildChainRules(testConfig(), false))
	joined := strings.Join(rules, "\n")

	if !strings.Contains(joined, "--dport 722 -j ACCEPT") {
		t.Error("knock port must be accepted from anywhere")
	}
	if !strings.Contains(joined, "hashlimit") || !strings.Contains(joined, "--hashlimit-mode srcip") {
		t.Error("knock port must be rate limited per source IP")
	}

	limitIndex, acceptIndex := -1, -1
	for i, rule := range rules {
		if strings.Contains(rule, "hashlimit") {
			limitIndex = i
		}
		if rule == "-p tcp --dport 722 -j ACCEPT" {
			acceptIndex = i
		}
	}
	if limitIndex == -1 || acceptIndex == -1 || limitIndex > acceptIndex {
		t.Errorf("rate limit must come before the accept (limit=%d accept=%d)", limitIndex, acceptIndex)
	}
}

func TestIsIPv6(t *testing.T) {
	if isIPv6("1.2.3.4") {
		t.Error("IPv4 address classified as IPv6")
	}
	if !isIPv6("2001:db8::1") {
		t.Error("IPv6 address not classified as IPv6")
	}
	if isIPv6("not-an-ip") {
		t.Error("garbage classified as IPv6")
	}
}

// The chain goes in as one transaction: declared, filled and committed
// together, with its DROP inside the commit, so it is never seen half built.
func TestRestoreInputIsOneTransactionEndingInDrop(t *testing.T) {
	input := buildRestoreInput(buildChainRules(testConfig(), false), true)
	lines := strings.Split(strings.TrimSpace(input), "\n")

	if lines[0] != "*filter" || lines[1] != ":KNOCK - [0:0]" {
		t.Fatalf("restore input must open the filter table and declare the chain, got %q", lines[:2])
	}
	if lines[len(lines)-1] != "COMMIT" {
		t.Fatalf("restore input must end in COMMIT, got %q", lines[len(lines)-1])
	}
	if lines[len(lines)-2] != "-I INPUT 1 -j KNOCK" || lines[len(lines)-3] != "-A KNOCK -j DROP" {
		t.Errorf("the DROP and the jump must be inside the commit, got %q", lines[len(lines)-3:])
	}

	without := buildRestoreInput(buildChainRules(testConfig(), false), false)
	if strings.Contains(without, "INPUT") {
		t.Error("an installed jump must not be added twice")
	}
}

func TestKnockRateLimitCountsIPv6ByPrefix(t *testing.T) {
	v4 := strings.Join(flatten(buildChainRules(testConfig(), false)), "\n")
	v6 := strings.Join(flatten(buildChainRules(testConfig(), true)), "\n")

	if !strings.Contains(v6, "--hashlimit-srcmask 64") {
		t.Error("IPv6 rate limit must count a /64 as one source")
	}
	if strings.Contains(v4, "--hashlimit-srcmask") {
		t.Error("IPv4 rate limit must count each address")
	}
}
