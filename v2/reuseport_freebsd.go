//go:build freebsd

/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

// FreeBSD's SO_REUSEPORT_LB, which NetBSD's implementation is numerically
// compatible with.
const (
	soReusePortLB = 0x00010000
	lbSupported   = true
	lbOptName     = "SO_REUSEPORT_LB"
)
