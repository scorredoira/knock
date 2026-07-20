package main

import (
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// authorizedKey is one entry of root's authorized_keys, with the options that
// came with it.
type authorizedKey struct {
	options []string
}

// loadAuthorizedKeys reads root's real authorized_keys. Deliberately the same
// file sshd uses: whoever can SSH into the box can knock, with nothing to keep
// in sync.
//
// The options that ride along are not ignored — see keyAllows.
func loadAuthorizedKeys() (map[string]authorizedKey, error) {
	data, err := os.ReadFile(authorizedKeys)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]authorizedKey)
	for len(data) > 0 {
		pubKey, _, options, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			data = rest
			continue
		}
		keys[string(pubKey.Marshal())] = authorizedKey{options: options}
		data = rest
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys found in %s", authorizedKeys)
	}

	return keys, nil
}

// keyAllows decides whether a key may knock from clientIP.
//
// Honoured: from= and expiry-time=, which say where and until when a key is
// valid — that means exactly the same thing here as it does to sshd.
//
// Ignored: command=, restrict, no-pty, no-port-forwarding and friends. Those
// constrain what a shell session may do, and knock opens no session: it checks
// a signature and writes a firewall rule. Treating them as "may not knock"
// would be inventing a meaning OpenSSH does not give them.
func keyAllows(key authorizedKey, clientIP string, now time.Time) error {
	for _, option := range key.options {
		name, value := splitOption(option)

		switch strings.ToLower(name) {
		case "from":
			if !matchFromPattern(value, clientIP) {
				return fmt.Errorf("key is restricted to from=%q, which does not match %s", value, clientIP)
			}
		case "expiry-time":
			expiry, err := parseExpiryTime(value)
			if err != nil {
				return fmt.Errorf("key has an unparseable expiry-time=%q: %w", value, err)
			}
			if now.After(expiry) {
				return fmt.Errorf("key expired at %s", expiry.Format(time.RFC3339))
			}
		}
	}

	return nil
}

// splitOption splits `from="1.2.3.4"` into its name and unquoted value. Options
// without a value (restrict, no-pty) come back with an empty value.
func splitOption(option string) (string, string) {
	name, value, found := strings.Cut(option, "=")
	if !found {
		return name, ""
	}
	return name, strings.Trim(value, `"`)
}

// matchFromPattern applies OpenSSH pattern-list rules: a matching negated
// pattern rejects outright, otherwise at least one positive pattern must match.
// A list of only negations that miss is a match.
//
// knock only ever sees an IP — it does not resolve names — so hostname patterns
// in a from= list will not match.
func matchFromPattern(patterns string, clientIP string) bool {
	hasPositive := false
	matchedPositive := false

	for _, pattern := range strings.Split(patterns, ",") {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		negated := strings.HasPrefix(pattern, "!")
		if negated {
			pattern = pattern[1:]
		} else {
			hasPositive = true
		}

		if !matchHostPattern(pattern, clientIP) {
			continue
		}
		if negated {
			return false
		}
		matchedPositive = true
	}

	if hasPositive {
		return matchedPositive
	}
	return true
}

func matchHostPattern(pattern string, clientIP string) bool {
	if strings.Contains(pattern, "/") {
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		address := net.ParseIP(clientIP)
		return address != nil && network.Contains(address)
	}

	// path.Match gives us OpenSSH's * and ? against an IP literal, which
	// contains no separator for it to trip over.
	matched, err := path.Match(pattern, clientIP)
	return err == nil && matched
}

// parseExpiryTime accepts the formats OpenSSH documents for expiry-time:
// YYYYMMDD and YYYYMMDDHHMM[SS], interpreted in local time.
func parseExpiryTime(value string) (time.Time, error) {
	layouts := []string{"20060102", "200601021504", "20060102150405"}
	for _, layout := range layouts {
		if len(value) != len(layout) {
			continue
		}
		expiry, err := time.ParseInLocation(layout, value, time.Local)
		if err == nil {
			return expiry, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised format")
}
