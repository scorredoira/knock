package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// maxConcurrentKnocks bounds the handshakes in flight. Each connection holds a
// goroutine and a key exchange for up to the deadline below, and the port is
// open to the internet, so the count has to be capped somewhere.
const maxConcurrentKnocks = 32

const knockTimeout = 30 * time.Second

func serve() {
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Restore firewall rules on startup.
	if config.Enabled {
		if err := applyIPTablesRules(config); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to restore firewall rules: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Firewall restored - %d IPs whitelisted\n", len(config.AllowedIPs))
	}

	// Validate authorized_keys at startup so we fail loud on a missing/empty
	// file. The callback re-reads the file on every attempt (see below), so
	// keys added or revoked while the daemon runs take effect immediately.
	keys, err := loadAuthorizedKeys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load %s: %v\n", authorizedKeys, err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d authorized keys from %s\n", len(keys), authorizedKeys)

	hostKey, err := loadHostKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load host key: %v\n", err)
		os.Exit(1)
	}

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Re-read authorized_keys on every attempt (like sshd) so the
			// daemon never needs a restart to pick up added/revoked keys.
			// On a read error, deny — never fall through to accept.
			authorized, err := loadAuthorizedKeys()
			if err != nil {
				return nil, fmt.Errorf("could not load authorized_keys: %w", err)
			}

			authorizedKey, found := authorized[string(key.Marshal())]
			if !found {
				return nil, fmt.Errorf("unknown public key for %q", conn.User())
			}

			clientIP := extractIP(conn.RemoteAddr().String())
			if err := keyAllows(authorizedKey, clientIP, time.Now()); err != nil {
				return nil, err
			}

			return &ssh.Permissions{}, nil
		},
	}
	sshConfig.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on port %d: %v\n", port, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("knock listening on port %d\n", port)

	inFlight := make(chan struct{}, maxConcurrentKnocks)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to accept connection: %v\n", err)
			continue
		}

		select {
		case inFlight <- struct{}{}:
			go func() {
				defer func() { <-inFlight }()
				handleConnection(conn, sshConfig)
			}()
		default:
			fmt.Fprintf(os.Stderr, "Too many connections in flight, dropping %s\n", conn.RemoteAddr())
			conn.Close()
		}
	}
}

func handleConnection(conn net.Conn, sshConfig *ssh.ServerConfig) {
	defer conn.Close()

	clientIP := extractIP(conn.RemoteAddr().String())
	if clientIP == "" {
		fmt.Fprintf(os.Stderr, "Could not extract client IP\n")
		return
	}

	if err := conn.SetDeadline(time.Now().Add(knockTimeout)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set deadline for %s: %v\n", clientIP, err)
		return
	}

	sshConn, _, _, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		fmt.Printf("Auth failed from %s: %v\n", clientIP, err)
		return
	}
	defer sshConn.Close()

	fmt.Printf("Auth OK from %s, adding to whitelist\n", clientIP)

	if err := addIPToFirewall(clientIP); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add IP %s: %v\n", clientIP, err)
		sshConn.OpenChannel("error", []byte(err.Error()))
		time.Sleep(100 * time.Millisecond)
		return
	}

	fmt.Printf("IP %s whitelisted\n", clientIP)
	sshConn.OpenChannel("ok", nil)
	time.Sleep(100 * time.Millisecond)
}

func loadHostKey() (ssh.Signer, error) {
	data, err := os.ReadFile(hostKeyPath)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

func addIPToFirewall(ip string) error {
	if !isValidIP(ip) {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	return withConfigLock(func() error {
		config, err := loadConfig()
		if err != nil {
			return err
		}

		for _, existing := range config.AllowedIPs {
			if existing == ip {
				return nil
			}
		}

		config.AllowedIPs = append(config.AllowedIPs, ip)
		if err := saveConfig(config); err != nil {
			return err
		}

		if config.Enabled {
			return applyIPTablesRules(config)
		}

		return nil
	})
}
