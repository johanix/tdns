/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import "os"

// countOpenFDs counts the entries of /proc/self/fd. Readdirnames rather
// than os.ReadDir: names are all we need, and per-entry stats can fail on
// exotic descriptors (the macOS counter hit exactly that with kqueues).
// The directory handle itself is one of the entries, so it is subtracted.
func countOpenFDs() (int, string) {
	f, err := os.Open("/proc/self/fd")
	if err != nil {
		return -1, "unavailable"
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil && len(names) == 0 {
		return -1, "unavailable"
	}
	return len(names) - 1, "procfs"
}
