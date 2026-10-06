package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
)

// Config stores the firewall configuration.
//
// PublicPorts are reachable from anywhere. ProtectedPorts are reachable only
// from AllowedIPs — that is the list a knock adds to. Both are nil-checked on
// load rather than defaulted on empty, so an explicit empty list stays empty.
type Config struct {
	AllowedIPs     []string `json:"allowedIPs"`
	Enabled        bool     `json:"enabled"`
	PublicPorts    []int    `json:"publicPorts"`
	ProtectedPorts []int    `json:"protectedPorts"`
}

func defaultConfig() *Config {
	return &Config{
		AllowedIPs:     []string{},
		Enabled:        false,
		PublicPorts:    []int{80, 443},
		ProtectedPorts: []int{22},
	}
}

func loadConfig() (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			config := defaultConfig()
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

	// Configs written before ports were configurable have neither list. Fill
	// them in and write them back, so the file always states what it opens.
	if config.PublicPorts == nil || config.ProtectedPorts == nil {
		defaults := defaultConfig()
		if config.PublicPorts == nil {
			config.PublicPorts = defaults.PublicPorts
		}
		if config.ProtectedPorts == nil {
			config.ProtectedPorts = defaults.ProtectedPorts
		}
		if err := saveConfig(&config); err != nil {
			return nil, err
		}
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

	// Write and rename so a crash mid-write cannot leave a truncated config
	// that would fail to parse and take the daemon down on the next start.
	tmpPath := configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, configPath)
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}
