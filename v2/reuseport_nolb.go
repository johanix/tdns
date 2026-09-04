//go:build !linux && !netbsd && !freebsd

/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

// Platforms with no load-balancing reuseport option. macOS and OpenBSD do
// define SO_REUSEPORT, but it does not distribute inbound UDP -- one socket
// receives everything (measured on macOS 26.3 and NetBSD 10.1) -- so opening
// several sockets there buys nothing and only obscures where traffic went.
// These platforms serve from a single socket regardless of udp-sockets.
const (
	soReusePortLB = 0
	lbSupported   = false
	lbOptName     = ""
)
