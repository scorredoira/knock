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
	// Only the flags, never a bare `help`: that is a perfectly good host name,
	// and a host name is what this argument usually is.
	case "-h", "--help":
		printUsage()
		return
	case "serve":
		serve()
		return
	case "deploy":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: knock deploy <user@host>\n")
			os.Exit(1)
		}
		deploy(os.Args[2])
		return
	}

	// A known verb runs here, on this machine. Anything else is a host: bare
	// it is a knock, followed by a verb it is that verb run on that server.
	if cmd := findCommand(os.Args[1]); cmd != nil {
		runLocal(cmd, os.Args[2:])
		return
	}

	host := os.Args[1]
	if len(os.Args) == 2 {
		knock(host)
		return
	}
	remoteCommand(host, os.Args[2:])
}

func printUsage() {
	fmt.Println("knock - port knocking firewall")
	fmt.Println("")
	fmt.Println("From your machine:")
	fmt.Println("  knock <host>                 Knock: whitelist your IP")
	fmt.Println("  knock <host> out             Remove your IP - the opposite of a knock")
	fmt.Println("  knock deploy <user@host>     Build, upload and install knock")
	fmt.Println("")
	fmt.Println("On the server:")
	fmt.Println("  knock serve                  Run the daemon (port 722)")
	for _, cmd := range commands {
		if cmd.remote {
			continue
		}
		fmt.Printf("  knock %-22s %s\n", strings.TrimSpace(cmd.name+" "+cmd.params), cmd.help)
	}
	fmt.Println("")
	fmt.Println("The knock port is open to the whole internet, so it does one thing: it")
	fmt.Println("opens you and it closes you. Everything else administers the box and is")
	fmt.Println("run on the box.")
}

func runLocal(cmd *command, args []string) {
	if cmd.remote {
		fmt.Fprintf(os.Stderr, "%s only works against a remote server: knock <host> %s\n", cmd.name, cmd.name)
		os.Exit(1)
	}

	if len(args) != cmd.argCount() {
		fmt.Fprintf(os.Stderr, "Usage: knock %s %s\n", cmd.name, cmd.params)
		os.Exit(1)
	}

	output, err := cmd.run(invocation{args: args})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Println(output)
}

// Deploy mode
func deploy(sshHost string) {
	// Checked before anything touches the server: a release binary has no
	// source to build, and a half-run deploy is worse than none.
	sourceDir, err := findSourceDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		fmt.Fprintf(os.Stderr, "knock deploy builds knock from source: run it from a clone of https://github.com/scorredoira/knock, with Go installed.\n")
		os.Exit(1)
	}
	if _, err := exec.LookPath("go"); err != nil {
		fmt.Fprintf(os.Stderr, "Go is not installed: knock deploy needs it to build knock for the server.\n")
		os.Exit(1)
	}
	servicePath := filepath.Join(sourceDir, "knock.service")

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
	tmpDir, err := os.MkdirTemp("", "knock-deploy")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)
	tmpBinary := filepath.Join(tmpDir, "knock")

	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", tmpBinary, ".")
	cmd.Dir = sourceDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Build failed: %v\n", err)
		os.Exit(1)
	}

	// Staged in the remote user's home, not /tmp: in a world-writable dir
	// another user could swap the file between the upload and the copy that
	// installs it as root.
	const remoteBinary = ".knock-deploy"
	const remoteService = ".knock-deploy.service"

	// 3. Upload binary
	fmt.Println("Uploading binary...")
	scpArgs := []string{tmpBinary, sshHost + ":" + remoteBinary}
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
	scpArgs = []string{servicePath, sshHost + ":" + remoteService}
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
		"cp " + remoteBinary + " /usr/local/bin/knock",
		"chmod 755 /usr/local/bin/knock",
		"cp " + remoteService + " /etc/systemd/system/knock.service",
		"mkdir -p /etc/knock",
		"test -f /etc/knock/host_key || ssh-keygen -q -t ed25519 -f /etc/knock/host_key -N ''",
		"systemctl daemon-reload",
		"systemctl enable knock",
		"systemctl restart knock",
		"rm -f " + remoteBinary + " " + remoteService,
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

// findSourceDir returns the knock source tree deploy builds from: the working
// directory, or else the one the binary sits in, when it was built in place.
func findSourceDir() (string, error) {
	var candidates []string
	if dir, err := os.Getwd(); err == nil {
		candidates = append(candidates, dir)
	}
	if execPath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(execPath))
	}

	for _, dir := range candidates {
		if isSourceDir(dir) {
			return dir, nil
		}
	}
	return "", fmt.Errorf("knock source not found in the current directory")
}

func isSourceDir(dir string) bool {
	goMod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil || modfileModule(goMod) != "knock" {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, "knock.service"))
	return err == nil
}

func modfileModule(goMod []byte) string {
	for _, line := range strings.Split(string(goMod), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1]
		}
	}
	return ""
}
