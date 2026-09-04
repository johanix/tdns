//go:build freebsd

/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

// FreeBSD's SO_REUSEPORT_LB, where the option originates and is part of the
// base system. The out-of-tree NetBSD patch reuses this numbering, which is
// why reuseport_netbsd.go carries the same value.
const (
	soReusePortLB = 0x00010000
	lbSupported   = true
	lbOptName     = "SO_REUSEPORT_LB"
)
