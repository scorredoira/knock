package main

import "fmt"

// The server side drives iptables and only runs on Linux. On Windows knock is
// a client: knocking and `out` never touch the config.
func withConfigLock(fn func() error) error {
	return fmt.Errorf("this command runs on the server, not on Windows")
}
