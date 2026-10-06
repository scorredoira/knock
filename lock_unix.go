//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// withConfigLock runs fn while holding an exclusive lock on the config, so the
// daemon and a CLI invocation cannot interleave a read-modify-write and lose an
// IP that was just added.
func withConfigLock(fn func() error) error {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	lock, err := os.OpenFile(configPath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()

	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to lock %s: %w", configPath, err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	return fn()
}
