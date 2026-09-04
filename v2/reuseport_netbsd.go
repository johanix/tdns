//go:build netbsd

/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

// NetBSD keeps the two options separate: plain SO_REUSEPORT retains its old
// semantics (all unicast traffic goes to one socket of the group), and
// SO_REUSEPORT_LB is the load-balancing variant, numerically compatible with
// FreeBSD's. It is UDP-only, so TCP listeners stay single-socket.
//
// The option is new enough that golang.org/x/sys/unix does not define it for
// netbsd yet. On a kernel without it, setsockopt fails with ENOPROTOOPT and
// listenUDPSockets falls back to a single plain socket.
const (
	soReusePortLB = 0x00010000
	lbSupported   = true
	lbOptName     = "SO_REUSEPORT_LB"
)
