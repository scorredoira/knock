package main

import (
	"strings"
	"testing"
	"time"
)

var noon = time.Date(2026, 7, 20, 12, 0, 0, 0, time.Local)

// A key restricted to one source must not be able to knock from another. This
// is the reason knock can read root's authorized_keys directly instead of
// keeping a copy: the restriction still means something.
func TestFromOptionIsEnforced(t *testing.T) {
	key := authorizedKey{options: []string{`from="10.0.0.5"`}}

	if err := keyAllows(key, "10.0.0.5", noon); err != nil {
		t.Errorf("allowed source rejected: %v", err)
	}
	if err := keyAllows(key, "10.0.0.6", noon); err == nil {
		t.Error("key restricted to 10.0.0.5 was accepted from 10.0.0.6")
	}
}

func TestFromOptionPatterns(t *testing.T) {
	cases := []struct {
		patterns string
		clientIP string
		allowed  bool
	}{
		{"192.168.1.0/24", "192.168.1.77", true},
		{"192.168.1.0/24", "192.168.2.77", false},
		{"192.168.*", "192.168.9.9", true},
		{"192.168.*", "10.0.0.1", false},
		{"10.0.0.1,10.0.0.2", "10.0.0.2", true},
		{"10.0.0.1,10.0.0.2", "10.0.0.3", false},
		// A negated pattern rejects even when a positive one matches.
		{"192.168.0.0/16,!192.168.5.5", "192.168.5.5", false},
		{"192.168.0.0/16,!192.168.5.5", "192.168.5.6", true},
		// Only negations: anything that does not match them is allowed.
		{"!10.0.0.1", "10.0.0.2", true},
		{"!10.0.0.1", "10.0.0.1", false},
		// knock never resolves names, so a hostname pattern cannot match.
		{"myhost.example.com", "10.0.0.1", false},
		{"2001:db8::/32", "2001:db8::1", true},
		{"2001:db8::/32", "2001:dead::1", false},
	}

	for _, c := range cases {
		got := matchFromPattern(c.patterns, c.clientIP)
		if got != c.allowed {
			t.Errorf("from=%q against %s: got %v, want %v", c.patterns, c.clientIP, got, c.allowed)
		}
	}
}

func TestExpiredKeyIsRejected(t *testing.T) {
	key := authorizedKey{options: []string{`expiry-time="20260101"`}}

	if err := keyAllows(key, "10.0.0.1", noon); err == nil {
		t.Error("key that expired in January was accepted in July")
	}

	future := authorizedKey{options: []string{`expiry-time="20270101"`}}
	if err := keyAllows(future, "10.0.0.1", noon); err != nil {
		t.Errorf("unexpired key rejected: %v", err)
	}
}

// An option knock cannot make sense of must not silently pass as valid.
func TestUnparseableExpiryIsRejected(t *testing.T) {
	key := authorizedKey{options: []string{`expiry-time="tomorrow"`}}

	if err := keyAllows(key, "10.0.0.1", noon); err == nil {
		t.Error("key with an unparseable expiry-time was accepted")
	}
}

// Session-scoped options constrain what a shell may do. knock opens no shell,
// so it must not invent a meaning for them and lock the key out.
func TestSessionOptionsDoNotBlockKnocking(t *testing.T) {
	key := authorizedKey{options: []string{"no-pty", "no-port-forwarding", "restrict", `command="/usr/bin/rrsync /backup"`}}

	if err := keyAllows(key, "10.0.0.1", noon); err != nil {
		t.Errorf("session-scoped options blocked a knock: %v", err)
	}
}

func TestKeyWithoutOptionsIsAllowed(t *testing.T) {
	if err := keyAllows(authorizedKey{}, "10.0.0.1", noon); err != nil {
		t.Errorf("unrestricted key rejected: %v", err)
	}
}

func TestSplitOption(t *testing.T) {
	name, value := splitOption(`from="1.2.3.4,5.6.7.8"`)
	if name != "from" || value != "1.2.3.4,5.6.7.8" {
		t.Errorf("got name=%q value=%q", name, value)
	}

	name, value = splitOption("no-pty")
	if name != "no-pty" || value != "" {
		t.Errorf("valueless option got name=%q value=%q", name, value)
	}
}

// The error has to name the source, otherwise a from= lockout is undebuggable
// from the daemon log.
func TestFromRejectionNamesTheClientIP(t *testing.T) {
	key := authorizedKey{options: []string{`from="10.0.0.5"`}}

	err := keyAllows(key, "10.0.0.6", noon)
	if err == nil || !strings.Contains(err.Error(), "10.0.0.6") {
		t.Errorf("rejection should name the client IP, got %v", err)
	}
}
