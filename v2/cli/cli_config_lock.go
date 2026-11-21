/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The locks `tdns-ncli config add` holds while it edits a CLI config.
 */
package cli

import (
	"path/filepath"
	"sort"
)

// cliConfigLockPath is the lock file for the CLI config file path: a file of
// its own beside it, ".<name>.lock", named after the file the path resolves
// to, so one file has one lock however it is reached.
//
// Not the edited file itself: an edit renames a new file over the old one, so
// a lock on the old one would be on a file the next writer no longer opens.
// The lock file is left in place afterwards. Removing it would let a waiting
// writer lock a file that no longer has a name while a third one creates a
// new lock file and locks that.
func cliConfigLockPath(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock")
}

// lockCliConfigs takes the lock of each of paths (lockCliConfig), each lock
// once and all in one order, so two adds that need the same two locks cannot
// each hold one and wait for the other. It returns the function that releases
// them all.
func lockCliConfigs(paths ...string) (func(), error) {
	byLock := map[string]string{}
	for _, p := range paths {
		byLock[cliConfigLockPath(p)] = p
	}
	order := make([]string, 0, len(byLock))
	for lp := range byLock {
		order = append(order, lp)
	}
	sort.Strings(order)

	var unlocks []func()
	release := func() {
		for i := len(unlocks) - 1; i >= 0; i-- {
			unlocks[i]()
		}
	}
	for _, lp := range order {
		u, err := lockCliConfig(byLock[lp])
		if err != nil {
			release()
			return nil, err
		}
		unlocks = append(unlocks, u)
	}
	return release, nil
}
