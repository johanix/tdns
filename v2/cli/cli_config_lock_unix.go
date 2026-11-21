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
	"path/filepath"
	"syscall"
)

// lockCliConfig takes the exclusive lock every `config add` takes before it
// reads the file it is about to edit, and returns the function that releases
// it. The lock is held through the read, the write, the reload and any undo:
// two adds that both read the old list and then both wrote would otherwise
// each report success while the second one's file drops the first one's
// entry.
//
// The lock is on a file of its own beside the edited one (".<name>.lock"),
// not on the edited file: an edit renames a new file over the old one, so a
// lock on the old one would be on a file the next writer no longer opens. The
// lock file is left in place afterwards. Removing it would let a waiting
// writer lock a file that no longer has a name while a third one creates a
// new lock file and locks that.
func lockCliConfig(path string) (func(), error) {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real // one lock for the file, however it is named
	}
	lp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock")
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
