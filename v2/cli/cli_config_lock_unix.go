//go:build unix

/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The lock `tdns-ncli config add` holds while it edits a CLI config file.
 */
package cli

import (
	"fmt"
	"os"
	"syscall"
)

// lockCliConfig takes the exclusive lock every `config add` takes before it
// reads the file it is about to edit, and returns the function that releases
// it. The lock is held through the read, the write, the reload and any undo:
// two adds that both read the old list and then both wrote would otherwise
// each report success while the second one's file drops the first one's
// entry. The lock is an flock(2) on cliConfigLockPath(path).
func lockCliConfig(path string) (func(), error) {
	lp := cliConfigLockPath(path)
	f, err := os.OpenFile(lp, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
