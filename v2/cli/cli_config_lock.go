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
	path = resolvedPath(path)
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock")
}

// resolvedPath is the absolute path p names with every symlink resolved:
// the one name of a file, whatever alias reaches it. A file that does not
// exist yet (config add is about to create it) has its directory resolved
// instead, so two aliases of a symlinked directory still give one name.
//
// It is the path a rename onto p would replace, not the file's identity: two
// hard links are two names, and a rename onto one leaves the other reading
// the old file.
func resolvedPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		return filepath.Join(dir, filepath.Base(p))
	}
	return filepath.Clean(p)
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
