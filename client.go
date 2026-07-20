package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func knock(host string) {
	signers := loadClientKeys()
	if len(signers) == 0 {
		fmt.Fprintf(os.Stderr, "No SSH keys found in ~/.ssh/\n")
		os.Exit(1)
	}

	// Resolve host alias from ~/.ssh/config
	resolvedHost := resolveSSHHost(host)

	config := &ssh.ClientConfig{
		User: "knock",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signers...),
		},
		HostKeyCallback: verifyHostKey(host),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", resolvedHost, port)
	fmt.Printf("Knocking %s...\n", addr)

	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Wait for server response
	select {
	case ch := <-conn.HandleChannelOpen("ok"):
		ch.Accept()
		fmt.Println("OK - IP whitelisted")
	case ch := <-conn.HandleChannelOpen("error"):
		ch.Accept()
		fmt.Fprintf(os.Stderr, "Failed: server error\n")
		os.Exit(1)
	case <-time.After(5 * time.Second):
		fmt.Fprintf(os.Stderr, "Failed: timeout waiting for server\n")
		os.Exit(1)
	}
}

func knownHostsPath() string {
	return filepath.Join(os.Getenv("HOME"), ".knock", "known_hosts.json")
}

// verifyHostKey pins the server key on first use and refuses to knock at a
// server whose key changed. Without this, anything on the path can answer on
// port 722 and watch which of your keys authenticates.
func verifyHostKey(host string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)

		known, err := loadKnownHosts()
		if err != nil {
			return err
		}

		if stored, ok := known[host]; ok {
			if stored != fingerprint {
				return fmt.Errorf("host key changed for %s\n  expected %s\n  got      %s\nIf you rebuilt the server, delete the entry from %s", host, stored, fingerprint, knownHostsPath())
			}
			return nil
		}

		fmt.Printf("Unknown server %s, pinning key %s\n", host, fingerprint)
		known[host] = fingerprint
		return saveKnownHosts(known)
	}
}

func loadKnownHosts() (map[string]string, error) {
	data, err := os.ReadFile(knownHostsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}

	var known map[string]string
	if err := json.Unmarshal(data, &known); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", knownHostsPath(), err)
	}

	return known, nil
}

func saveKnownHosts(known map[string]string) error {
	path := knownHostsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(known, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func loadClientKeys() []ssh.Signer {
	home := os.Getenv("HOME")
	candidates := []string{
		home + "/.ssh/id_ed25519",
		home + "/.ssh/id_ecdsa",
		home + "/.ssh/id_rsa",
	}

	var signers []ssh.Signer
	for _, keyPath := range candidates {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			continue
		}
		signers = append(signers, signer)
	}
	return signers
}

func resolveSSHHost(alias string) string {
	home := os.Getenv("HOME")
	data, err := os.ReadFile(home + "/.ssh/config")
	if err != nil {
		return alias
	}

	lines := strings.Split(string(data), "\n")
	inMatchingHost := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "host ") {
			fields := strings.Fields(line)
			inMatchingHost = false
			for _, h := range fields[1:] {
				if h == alias {
					inMatchingHost = true
					break
				}
			}
		} else if inMatchingHost && strings.HasPrefix(lower, "hostname ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}

	return alias
}
