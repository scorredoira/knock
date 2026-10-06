package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// dial opens the knock port. user is what tells the server whether this
// connection is a knock or a command session.
func dial(host string, user string) (*ssh.Client, error) {
	signers := loadClientKeys()
	if len(signers) == 0 {
		return nil, fmt.Errorf("no SSH keys found in ~/.ssh/")
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signers...),
		},
		HostKeyCallback: verifyHostKey(host),
		Timeout:         10 * time.Second,
	}

	// Resolve host alias from ~/.ssh/config
	return ssh.Dial("tcp", serverAddress(host), config)
}

func serverAddress(host string) string {
	return fmt.Sprintf("%s:%d", resolveSSHHost(host), port)
}

func knock(host string) {
	fmt.Printf("Knocking %s...\n", serverAddress(host))

	conn, err := dial(host, knockUser)
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

// remoteCommand runs a command on the server over the knock port, which is the
// only one guaranteed to be reachable: port 22 is exactly what may be closed to
// you. The server decides which commands it will take from the network.
func remoteCommand(host string, args []string) {
	conn, err := dial(host, commandUser)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	channel, requests, err := conn.OpenChannel(commandChannel, ssh.Marshal(commandRequest{Command: strings.Join(args, " ")}))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "If that server runs an older knock, update it with: knock deploy <user@host>\n")
		os.Exit(1)
	}
	defer channel.Close()

	status := make(chan uint32, 1)
	go func() {
		defer close(status)
		for request := range requests {
			var payload exitStatus
			if request.Type == "exit-status" && ssh.Unmarshal(request.Payload, &payload) == nil {
				status <- payload.Status
			}
			if request.WantReply {
				request.Reply(false, nil)
			}
		}
	}()

	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		io.Copy(os.Stderr, channel.Stderr())
	}()

	io.Copy(os.Stdout, channel)
	<-stderrDone

	code, ok := <-status
	if !ok {
		fmt.Fprintf(os.Stderr, "Server closed the connection without reporting a status\n")
		os.Exit(1)
	}

	os.Exit(int(code))
}

// homeDir is the user's home on every OS: $HOME is not set on Windows.
func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func knownHostsPath() string {
	return filepath.Join(homeDir(), ".knock", "known_hosts.json")
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
	sshDir := filepath.Join(homeDir(), ".ssh")
	candidates := []string{
		filepath.Join(sshDir, "id_ed25519"),
		filepath.Join(sshDir, "id_ecdsa"),
		filepath.Join(sshDir, "id_rsa"),
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
	data, err := os.ReadFile(filepath.Join(homeDir(), ".ssh", "config"))
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
