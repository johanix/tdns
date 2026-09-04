//go:build netbsd

/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

// NetBSD does NOT ship SO_REUSEPORT_LB. Stock kernels define only plain
// SO_REUSEPORT, which keeps its old semantics -- every unicast datagram goes
// to one socket of the group, measured on NetBSD 10.1 -- so it distributes
// nothing and is useless for this.
//
// The constant is kept, and lbSupported stays true, because the option DOES
// exist on a kernel carrying the out-of-tree patch that adds it, using
// FreeBSD's numbering. Detection is therefore at RUN time, not build time: the
// setsockopt is attempted, and on a kernel without the patch it fails with
// ENOPROTOOPT, listenUDPSockets falls back to one plain socket, and the
// Degraded reason says so. That costs one socket and one failed setsockopt per
// listen address at startup.
//
// Building this as a nolb platform instead would be wrong in the direction
// that matters: it would refuse to use the option on the kernels that have it,
// which is the only reason it is here. On stock NetBSD, prefer several listen
// addresses over udp-sockets -- that gives one socket each, with no reliance
// on the kernel distributing.
const (
	soReusePortLB = 0x00010000
	lbSupported   = true
	lbOptName     = "SO_REUSEPORT_LB"
)
