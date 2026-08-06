package main

import (
	"fmt"
	"strings"
)

// invocation is what a command needs to run. clientIP is set only when the
// command arrived over the network, and is the address the connection came
// from — the one `out` removes.
type invocation struct {
	args     []string
	clientIP string
}

// command is one verb of the CLI. remote marks the ones that travel over the
// knock port instead of running on the box, and the two sets are disjoint.
type command struct {
	name   string
	params string
	help   string
	remote bool
	run    func(invocation) (string, error)
}

// Port 722 is open to the whole internet, so what it will do is kept to the
// smallest thing that is useful: it opens you and it closes you. `out` is the
// entire remote surface, and it takes no argument, so neither half can reach
// past the address it is called from.
//
// Everything else administers the box and belongs on the box. That is not a
// restriction to work around — it is the reason none of this needs reasoning
// about which commands are safe to expose.
var commands = []command{
	{
		name: "status",
		help: "Show firewall status",
		run:  statusCommand,
	},
	{
		name: "list",
		help: "List whitelisted IPs",
		run:  listCommand,
	},
	{
		name:   "add",
		params: "<ip>",
		help:   "Add an IP to the whitelist",
		run:    addCommand,
	},
	{
		name:   "remove",
		params: "<ip>",
		help:   "Remove an IP from the whitelist",
		run:    removeCommand,
	},
	{
		name: "close",
		help: "Enable the firewall",
		run:  closeCommand,
	},
	{
		name: "open",
		help: "Disable the firewall entirely (escape hatch)",
		run:  openCommand,
	},
	{
		name: "clear",
		help: "Remove all IPs from the whitelist",
		run:  clearCommand,
	},
	{
		name:   "out",
		help:   "Remove your IP - the opposite of a knock",
		remote: true,
		run:    outCommand,
	},
}

func findCommand(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

func (c *command) argCount() int {
	return len(strings.Fields(c.params))
}

func statusCommand(invocation) (string, error) {
	config, err := loadConfig()
	if err != nil {
		return "", err
	}

	state := "DISABLED (all ports open)"
	if config.Enabled {
		state = "ENABLED"
	}

	return fmt.Sprintf("Firewall: %s\nPublic ports:    %v\nProtected ports: %v (%d IPs whitelisted)",
		state, config.PublicPorts, config.ProtectedPorts, len(config.AllowedIPs)), nil
}

func listCommand(invocation) (string, error) {
	config, err := loadConfig()
	if err != nil {
		return "", err
	}

	if len(config.AllowedIPs) == 0 {
		return "No whitelisted IPs", nil
	}

	lines := []string{"Whitelisted IPs:"}
	for _, ip := range config.AllowedIPs {
		lines = append(lines, "  "+ip)
	}
	return strings.Join(lines, "\n"), nil
}

func addCommand(inv invocation) (string, error) {
	ip := inv.args[0]
	if !isValidIP(ip) {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	if err := addIPToFirewall(ip); err != nil {
		return "", err
	}

	return fmt.Sprintf("IP %s added to whitelist", ip), nil
}

func removeCommand(inv invocation) (string, error) {
	ip := inv.args[0]
	if !isValidIP(ip) {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}
	return removeIPFromWhitelist(ip, false)
}

// outCommand is the inverse of a knock: it removes the address the request came
// from and nothing else. There is no argument to give, so it cannot touch
// anybody else's access — which is why it is safe to expose over port 722.
func outCommand(inv invocation) (string, error) {
	if inv.clientIP == "" {
		return "", fmt.Errorf("out only works against a remote server: knock <host> out")
	}
	return removeIPFromWhitelist(inv.clientIP, true)
}

func removeIPFromWhitelist(ip string, self bool) (string, error) {
	var output string

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
			output = fmt.Sprintf("IP %s not in whitelist", ip)
			return nil
		}

		// Emptying the whitelist is refused for somebody else's address: they
		// lose access without asking for it. `out` is the opposite — you are
		// removing yourself, knowingly, and port 722 is still there to knock
		// your way back in.
		if !self && config.Enabled && len(remaining) == 0 {
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

		if self {
			output = fmt.Sprintf("IP %s removed - protected ports are closed to you again", ip)
		} else {
			output = fmt.Sprintf("IP %s removed from whitelist", ip)
		}
		return nil
	})

	return output, err
}

func closeCommand(invocation) (string, error) {
	var output string

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

		output = fmt.Sprintf("Firewall ENABLED - %d IPs whitelisted, protected ports %v", len(config.AllowedIPs), config.ProtectedPorts)
		return nil
	})

	return output, err
}

func openCommand(invocation) (string, error) {
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
		return "", fmt.Errorf("failed to open firewall: %w", err)
	}

	return "Firewall DISABLED - knock rules removed, all ports open", nil
}

func clearCommand(invocation) (string, error) {
	var output string

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

		output = fmt.Sprintf("Cleared %d IPs from whitelist", count)
		return nil
	})

	return output, err
}
