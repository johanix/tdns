//go:build unix

/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The lock `tdns-ncli config add` holds while it edits a CLI config file.
 */
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// lockCliConfig takes the exclusive lock every `config add` takes before it
// reads the file it is about to edit, and returns the function that releases
// it. The lock is held through the read, the write, the reload and any undo:
// two adds that both read the old list and then both wrote would otherwise
// each report success while the second one's file drops the first one's
// entry. The lock is an flock(2) on cliConfigLockPath(path).
//
// The wait for another add's lock ends when ctx does: a blocking flock would
// not see Ctrl-C (the binaries turn SIGINT into a cancelled context), and the
// command would sit there until the other add let go, then go on to edit the
// file anyway. So the lock is tried without blocking, and tried again until it
// is free or ctx is done.
func lockCliConfig(ctx context.Context, path string) (func(), error) {
	lp := cliConfigLockPath(path)
	f, err := os.OpenFile(lp, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, fmt.Errorf("locking %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("waiting for the lock on %s: %w", path, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
