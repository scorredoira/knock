package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	port           = 722
	authorizedKeys = "/root/.ssh/authorized_keys"
	configPath     = "/etc/knock/config.json"
)

// Config stores the firewall configuration
type Config struct {
	AllowedIPs []string `json:"allowedIPs"`
	Enabled    bool     `json:"enabled"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		serve()
	case "close":
		closeFirewall()
	case "open":
		openFirewall()
	case "status":
		status()
	case "list":
		listIPs()
	case "add":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: knock add <ip>\n")
			os.Exit(1)
		}
		addIP(os.Args[2])
	case "remove":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: knock remove <ip>\n")
			os.Exit(1)
		}
		removeIP(os.Args[2])
	case "clear":
		clearIPs()
	case "deploy":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: knock deploy <user@host>\n")
			os.Exit(1)
		}
		deploy(os.Args[2])
	default:
		knock(os.Args[1])
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  knock serve            Start daemon (port 722)")
	fmt.Println("  knock <host>           Knock to whitelist your IP")
	fmt.Println("  knock deploy <host>    Deploy to server")
	fmt.Println("")
	fmt.Println("Firewall commands (server):")
	fmt.Println("  knock close            Block all SSH except whitelisted IPs")
	fmt.Println("  knock open             Allow all SSH (disable firewall)")
	fmt.Println("  knock status           Show firewall status")
	fmt.Println("  knock list             List whitelisted IPs")
	fmt.Println("  knock add <ip>         Add IP to whitelist")
	fmt.Println("  knock remove <ip>      Remove IP from whitelist")
	fmt.Println("  knock clear            Remove all IPs from whitelist")
}

// Server mode
func serve() {
	// Restore firewall rules on startup
	fwConfig, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	if fwConfig.Enabled {
		if err := applyIPTablesRules(fwConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to restore firewall rules: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Firewall restored - %d IPs whitelisted\n", len(fwConfig.AllowedIPs))
	}

	authorizedKeysMap, err := loadAuthorizedKeys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load authorized_keys: %v\n", err)
		os.Exit(1)
	}

	hostKey, err := loadHostKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load host key: %v\n", err)
		os.Exit(1)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(key.Marshal())] {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", conn.User())
		},
	}
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on port %d: %v\n", port, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("knock listening on port %d\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to accept connection: %v\n", err)
			continue
		}
		go handleConnection(conn, config)
	}
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	clientIP := extractIP(conn.RemoteAddr().String())
	if clientIP == "" {
		fmt.Fprintf(os.Stderr, "Could not extract client IP\n")
		return
	}

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set deadline for %s: %v\n", clientIP, err)
		return
	}

	sshConn, _, _, err := ssh.NewServerConn(conn, config)
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

func loadAuthorizedKeys() (map[string]bool, error) {
	data, err := os.ReadFile(authorizedKeys)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]bool)
	for len(data) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			data = rest
			continue
		}
		keys[string(pubKey.Marshal())] = true
		data = rest
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys found in %s", authorizedKeys)
	}

	fmt.Printf("Loaded %d authorized keys\n", len(keys))
	return keys, nil
}

func loadHostKey() (ssh.Signer, error) {
	data, err := os.ReadFile("/etc/knock/host_key")
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

	config, err := loadConfig()
	if err != nil {
		return err
	}

	// Check if IP already exists
	for _, existing := range config.AllowedIPs {
		if existing == ip {
			return nil // Already exists
		}
	}

	// Add to config
	config.AllowedIPs = append(config.AllowedIPs, ip)

	if err := saveConfig(config); err != nil {
		return err
	}

	// Apply rules if firewall is enabled
	if config.Enabled {
		return applyIPTablesRules(config)
	}

	return nil
}

// Config management
func loadConfig() (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			config := &Config{
				AllowedIPs: []string{},
				Enabled:    false,
			}
			if err := saveConfig(config); err != nil {
				return nil, err
			}
			return config, nil
		}
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func saveConfig(config *Config) error {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0600)
}

var ipRegex = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

func isValidIP(ip string) bool {
	if !ipRegex.MatchString(ip) {
		return false
	}
	parts := strings.Split(ip, ".")
	for _, part := range parts {
		var num int
		if _, err := fmt.Sscanf(part, "%d", &num); err != nil {
			return false
		}
		if num < 0 || num > 255 {
			return false
		}
	}
	return true
}

// Firewall commands
func closeFirewall() {
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	config.Enabled = true
	if err := saveConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
		os.Exit(1)
	}

	if err := applyIPTablesRules(config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to apply iptables rules: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Firewall ENABLED - SSH restricted to %d whitelisted IPs\n", len(config.AllowedIPs))
}

func openFirewall() {
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	config.Enabled = false
	if err := saveConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
		os.Exit(1)
	}

	// Flush all chains and set ACCEPT policy
	commands := [][]string{
		{"iptables", "-F", "INPUT"},
		{"iptables", "-F", "OUTPUT"},
		{"iptables", "-F", "FORWARD"},
		{"iptables", "-P", "INPUT", "ACCEPT"},
		{"iptables", "-P", "OUTPUT", "ACCEPT"},
		{"iptables", "-P", "FORWARD", "ACCEPT"},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to run %v: %s\n", args, output)
			os.Exit(1)
		}
	}

	fmt.Println("Firewall DISABLED - SSH open to all")
}

func status() {
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if config.Enabled {
		fmt.Printf("Firewall: ENABLED (SSH restricted to %d whitelisted IPs)\n", len(config.AllowedIPs))
	} else {
		fmt.Printf("Firewall: DISABLED (SSH open to all)\n")
	}
}

func listIPs() {
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if len(config.AllowedIPs) == 0 {
		fmt.Println("No whitelisted IPs")
		return
	}

	fmt.Println("Whitelisted IPs:")
	for _, ip := range config.AllowedIPs {
		fmt.Printf("  %s\n", ip)
	}
}

func addIP(ip string) {
	if !isValidIP(ip) {
		fmt.Fprintf(os.Stderr, "Invalid IP address: %s\n", ip)
		os.Exit(1)
	}

	if err := addIPToFirewall(ip); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add IP: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("IP %s added to whitelist\n", ip)
}

func removeIP(ip string) {
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	found := false
	newIPs := make([]string, 0, len(config.AllowedIPs))
	for _, existing := range config.AllowedIPs {
		if existing != ip {
			newIPs = append(newIPs, existing)
		} else {
			found = true
		}
	}

	if !found {
		fmt.Printf("IP %s not in whitelist\n", ip)
		return
	}

	config.AllowedIPs = newIPs
	if err := saveConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
		os.Exit(1)
	}

	if config.Enabled {
		if err := applyIPTablesRules(config); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to apply iptables rules: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("IP %s removed from whitelist\n", ip)
}

func clearIPs() {
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	count := len(config.AllowedIPs)
	config.AllowedIPs = []string{}

	if err := saveConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
		os.Exit(1)
	}

	if config.Enabled {
		if err := applyIPTablesRules(config); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to apply iptables rules: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Cleared %d IPs from whitelist\n", count)
}

func applyIPTablesRules(config *Config) error {
	// Set ACCEPT first to avoid lockout during rule changes
	cmd := exec.Command("iptables", "-P", "INPUT", "ACCEPT")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set INPUT policy to ACCEPT: %s", output)
	}

	// Flush INPUT chain
	cmd = exec.Command("iptables", "-F", "INPUT")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to flush INPUT chain: %s", output)
	}

	// Allow established connections
	cmd = exec.Command("iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to allow established connections: %s", output)
	}

	// Allow loopback
	cmd = exec.Command("iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to allow loopback: %s", output)
	}

	// Allow HTTP/HTTPS
	cmd = exec.Command("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to allow HTTP: %s", output)
	}

	cmd = exec.Command("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to allow HTTPS: %s", output)
	}

	// Allow knock port (722) from anywhere - needed for knocking
	cmd = exec.Command("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "722", "-j", "ACCEPT")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to allow knock port: %s", output)
	}

	if !config.Enabled {
		return nil
	}

	// Allow SSH from whitelisted IPs
	for _, ip := range config.AllowedIPs {
		cmd = exec.Command("iptables", "-A", "INPUT", "-p", "tcp", "-s", ip, "--dport", "22", "-j", "ACCEPT")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add rule for IP %s: %s", ip, output)
		}
	}

	// Set default policy to DROP (block everything not explicitly allowed)
	cmd = exec.Command("iptables", "-P", "INPUT", "DROP")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set INPUT policy to DROP: %s", output)
	}

	return nil
}

// Client mode
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

// Deploy mode
func deploy(sshHost string) {
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get executable path: %v\n", err)
		os.Exit(1)
	}

	sourceDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get working directory: %v\n", err)
		os.Exit(1)
	}

	servicePath := filepath.Join(sourceDir, "knock.service")
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		sourceDir = filepath.Dir(execPath)
		servicePath = filepath.Join(sourceDir, "knock.service")
	}

	// 1. Detect remote architecture
	fmt.Print("Detecting remote architecture... ")
	archCmd := exec.Command("ssh", sshHost, "uname -m")
	archOutput, err := archCmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed to detect architecture: %v\n", err)
		os.Exit(1)
	}

	goarch := "amd64"
	switch strings.TrimSpace(string(archOutput)) {
	case "x86_64":
		goarch = "amd64"
	case "aarch64", "arm64":
		goarch = "arm64"
	case "armv7l", "armv6l":
		goarch = "arm"
	}
	fmt.Printf("%s (GOARCH=%s)\n", strings.TrimSpace(string(archOutput)), goarch)

	// 2. Build binary
	fmt.Printf("Building knock for linux/%s...\n", goarch)
	tmpBinary := "/tmp/knock-deploy"

	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", tmpBinary, ".")
	cmd.Dir = sourceDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Build failed: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmpBinary)

	// 3. Upload binary
	fmt.Println("Uploading binary...")
	scpArgs := []string{tmpBinary, sshHost + ":/tmp/knock"}
	if runtime.GOOS == "darwin" {
		scpArgs = append([]string{"-O"}, scpArgs...)
	}
	cmd = exec.Command("scp", scpArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Upload failed: %v\n", err)
		os.Exit(1)
	}

	// 4. Upload service file
	fmt.Println("Uploading service file...")
	scpArgs = []string{servicePath, sshHost + ":/tmp/knock.service"}
	if runtime.GOOS == "darwin" {
		scpArgs = append([]string{"-O"}, scpArgs...)
	}
	cmd = exec.Command("scp", scpArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Upload service file failed: %v\n", err)
		os.Exit(1)
	}

	// 5. Install on server
	fmt.Println("Installing...")
	installCmds := []string{
		"systemctl stop knock 2>/dev/null || true",
		"cp /tmp/knock /usr/local/bin/knock",
		"chmod 755 /usr/local/bin/knock",
		"cp /tmp/knock.service /etc/systemd/system/",
		"mkdir -p /etc/knock",
		"test -f /etc/knock/host_key || ssh-keygen -q -t ed25519 -f /etc/knock/host_key -N ''",
		"systemctl daemon-reload",
		"systemctl enable knock",
		"systemctl restart knock",
		"rm -f /tmp/knock /tmp/knock.service",
	}
	for _, c := range installCmds {
		cmd = exec.Command("ssh", sshHost, c)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Installation failed at '%s': %v\n", c, err)
			os.Exit(1)
		}
	}

	// 6. Reset and close firewall
	fmt.Println("Configuring firewall...")
	cmd = exec.Command("ssh", sshHost, "knock open && knock close")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to close firewall: %v\n", err)
		os.Exit(1)
	}

	// 7. Knock to whitelist our IP
	host := sshHost
	if idx := strings.Index(sshHost, "@"); idx != -1 {
		host = sshHost[idx+1:]
	}
	fmt.Printf("Knocking to whitelist our IP...\n")
	knock(host)

	fmt.Println("Done - firewall active, your IP whitelisted")
}
