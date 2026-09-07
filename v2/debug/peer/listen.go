/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"net"
	"strings"
)

// bindPair binds one address on both TCP and UDP.
//
// A peer must answer on both — SOA probes and NOTIFY arrive over UDP,
// transfers over TCP — and it must advertise ONE address, so the two halves
// have to share a port. With an explicit port that is trivial. With ":0" it is
// not: the kernel picks the TCP port from the ephemeral range without regard
// for what is bound on UDP, so the second bind can lose a race it had no way
// to see coming. Retrying with a fresh TCP port is the fix; an explicit port
// that is taken will not free up by retrying, so that case fails at once.
func bindPair(listen string) (net.Listener, net.PacketConn, error) {
	const attempts = 20
	ephemeral := strings.HasSuffix(listen, ":0")
	var lastErr error
	for i := 0; i < attempts; i++ {
		l, err := net.Listen("tcp", listen)
		if err != nil {
			return nil, nil, err
		}
		pc, err := net.ListenPacket("udp", l.Addr().String())
		if err == nil {
			return l, pc, nil
		}
		l.Close()
		lastErr = err
		if !ephemeral {
			break
		}
	}
	return nil, nil, lastErr
}
