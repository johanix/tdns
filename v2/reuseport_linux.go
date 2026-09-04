//go:build linux

/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

// On Linux plain SO_REUSEPORT *is* the load-balancing option: the kernel picks
// the receiving socket by hashing the packet's 4-tuple. Go's stdlib syscall
// package deliberately omits the constant on Linux (the expectation is
// golang.org/x/sys/unix), so it is spelled out here rather than growing a
// dependency for one integer. Value from <asm-generic/socket.h>.
const (
	soReusePortLB = 0xf
	lbSupported   = true
	lbOptName     = "SO_REUSEPORT"
)
