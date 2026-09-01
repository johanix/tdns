/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import "syscall"

// countOpenFDs returns the HIGHEST open descriptor via fcntl(F_MAXFD), a
// NetBSD extension. Not a count — /dev/fd is static device nodes here and
// /proc is not reliably mounted — but a leak drives the watermark toward
// RLIMIT_NOFILE just the same, which is what the status report exists to
// show.
func countOpenFDs() (int, string) {
	maxfd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 0, syscall.F_MAXFD, 0)
	if errno != 0 {
		return -1, "unavailable"
	}
	return int(maxfd), "maxfd"
}
