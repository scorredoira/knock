package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	port           = 722
	authorizedKeys = "/root/.ssh/authorized_keys"
	configPath     = "/etc/knock/config.json"
	hostKeyPath    = "/etc/knock/host_key"
)

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
	fmt.Println("  knock close            Enable the firewall")
	fmt.Println("  knock open             Disable the firewall (escape hatch)")
	fmt.Println("  knock status           Show firewall status")
	fmt.Println("  knock list             List whitelisted IPs")
	fmt.Println("  knock add <ip>         Add IP to whitelist")
	fmt.Println("  knock remove <ip>      Remove IP from whitelist")
	fmt.Println("  knock clear            Remove all IPs from whitelist")
}

func closeFirewall() {
	err := withConfigLock(func() error {
		config, err := loadConfig()
		if err != nil {
			return err
		}

		if len(config.AllowedIPs) == 0 {
			return fmt.Errorf("cannot close firewall with 0 whitelisted IPs - you would be locked out\nFirst add an IP with: knock add <ip>")
		}

		config.Enabled = true
		if err := saveConfig(config); err != nil {
			return err
		}

		if err := applyIPTablesRules(config); err != nil {
			return err
		}

		fmt.Printf("Firewall ENABLED - %d IPs whitelisted, protected ports %v\n", len(config.AllowedIPs), config.ProtectedPorts)
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func openFirewall() {
	err := withConfigLock(func() error {
		config, err := loadConfig()
		if err != nil {
			return err
		}

		config.Enabled = false
		if err := saveConfig(config); err != nil {
			return err
		}

		return removeIPTablesRules()
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open firewall: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Firewall DISABLED - knock rules removed, all ports open")
}

func status() {
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if config.Enabled {
		fmt.Printf("Firewall: ENABLED\n")
	} else {
		fmt.Printf("Firewall: DISABLED (all ports open)\n")
	}
	fmt.Printf("Public ports:    %v\n", config.PublicPorts)
	fmt.Printf("Protected ports: %v (%d IPs whitelisted)\n", config.ProtectedPorts, len(config.AllowedIPs))
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
	err := withConfigLock(func() error {
		config, err := loadConfig()
		if err != nil {
			return err
		}

		found := false
		remaining := make([]string, 0, len(config.AllowedIPs))
		for _, existing := range config.AllowedIPs {
			if existing != ip {
				remaining = append(remaining, existing)
			} else {
				found = true
			}
		}

		if !found {
			fmt.Printf("IP %s not in whitelist\n", ip)
			return nil
		}

		if config.Enabled && len(remaining) == 0 {
			return fmt.Errorf("cannot remove last IP while firewall is enabled - you would be locked out\nFirst disable firewall with: knock open")
		}

		config.AllowedIPs = remaining
		if err := saveConfig(config); err != nil {
			return err
		}

		if config.Enabled {
			if err := applyIPTablesRules(config); err != nil {
				return err
			}
		}

		fmt.Printf("IP %s removed from whitelist\n", ip)
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func clearIPs() {
	err := withConfigLock(func() error {
		config, err := loadConfig()
		if err != nil {
			return err
		}

		if config.Enabled {
			return fmt.Errorf("cannot clear IPs while firewall is enabled - you would be locked out\nFirst disable firewall with: knock open")
		}

		count := len(config.AllowedIPs)
		config.AllowedIPs = []string{}

		if err := saveConfig(config); err != nil {
			return err
		}

		fmt.Printf("Cleared %d IPs from whitelist\n", count)
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
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

	// 6. Detect deployer's IP and whitelist it
	fmt.Print("Detecting your IP... ")
	ipCmd := exec.Command("ssh", sshHost, "echo $SSH_CLIENT | awk '{print $1}'")
	ipOutput, err := ipCmd.Output()
	deployerIP := strings.TrimSpace(string(ipOutput))
	if err != nil || deployerIP == "" {
		// Fallback: use 'who am i' or 'ss' to find the connecting IP
		ipCmd = exec.Command("ssh", sshHost, "ss -tnp | grep 'sshd' | head -1 | awk '{print $5}' | rev | cut -d: -f2- | rev")
		ipOutput, err = ipCmd.Output()
		deployerIP = strings.TrimSpace(string(ipOutput))
	}
	if deployerIP == "" || !isValidIP(deployerIP) {
		fmt.Fprintf(os.Stderr, "\nCould not detect your IP automatically.\n")
		fmt.Fprintf(os.Stderr, "Add it manually with: ssh %s knock add <your-ip> && ssh %s knock close\n", sshHost, sshHost)
		os.Exit(1)
	}
	fmt.Println(deployerIP)

	// 7. Whitelist and close firewall
	fmt.Println("Configuring firewall...")
	cmd = exec.Command("ssh", sshHost, fmt.Sprintf("knock add %s && knock close", deployerIP))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to configure firewall: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Done - firewall active, your IP whitelisted")
}
