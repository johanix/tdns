/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import "os"

// countOpenFDs counts the entries of /dev/fd, which on macOS reflects the
// calling process's open descriptors (unlike NetBSD, where /dev/fd holds
// static device nodes and counting them would lie). Readdirnames, not
// os.ReadDir: ReadDir fstatat()s every entry and fails with EBADF on
// kqueue descriptors — which every Go process with network activity has.
// The directory handle itself is one of the entries, so it is subtracted.
func countOpenFDs() (int, string) {
	f, err := os.Open("/dev/fd")
	if err != nil {
		return -1, "unavailable"
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil && len(names) == 0 {
		return -1, "unavailable"
	}
	return len(names) - 1, "devfd"
}
