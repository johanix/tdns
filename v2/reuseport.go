/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// udpListeners is the outcome of opening the UDP sockets for one listen
// address. Conns is what the caller serves from; a returned error means
// nothing could be bound at all. Degraded is not an error the caller should
// fail on -- it says the sockets are serving, but fewer of them than asked
// for, and why.
type udpListeners struct {
	Conns    []net.PacketConn
	Balanced bool  // the kernel is distributing across Conns
	Degraded error // non-nil: got fewer sockets than requested, with the reason
}

// listenUDPSockets opens up to n UDP sockets on addr. When n > 1 and the
// platform has a load-balancing reuseport option, they are opened as one
// kernel load-balance group: the kernel then hands each arriving datagram to
// one member by hashing the sender, so every reader gets a private socket,
// receive buffer and wakeup instead of all readers contending on one queue.
//
// A single socket is not a failure -- it is the correct answer on a platform
// or kernel without the option, and the caller serves from it normally.
//
// The option must be set before bind(2), which is why this goes through
// ListenConfig.Control: that callback runs after socket(2) and before bind(2),
// exactly the window required. Setting it afterwards is accepted but does
// nothing.
func listenUDPSockets(addr string, n int) (udpListeners, error) {
	if n < 1 {
		n = 1
	}
	if n == 1 || !lbSupported {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return udpListeners{}, err
		}
		res := udpListeners{Conns: []net.PacketConn{pc}}
		if n > 1 {
			res.Degraded = fmt.Errorf("no load-balancing reuseport option on this platform")
		}
		return res, nil
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var oerr error
			cerr := c.Control(func(fd uintptr) {
				oerr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePortLB, 1)
			})
			if cerr != nil {
				return cerr
			}
			return oerr
		},
	}

	var conns []net.PacketConn
	var firstErr error
	for i := 0; i < n; i++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			firstErr = err
			break
		}
		conns = append(conns, pc)
	}

	// A group of one is not a group. That is what a kernel without the option
	// looks like (setsockopt gives ENOPROTOOPT on the very first socket), and
	// -- per the conflict rules -- what an endpoint already held by a non-LB
	// socket looks like (EADDRINUSE on the second bind). Either way, drop back
	// to one plain socket so the zone is still served.
	if len(conns) < 2 {
		for _, pc := range conns {
			pc.Close()
		}
		pc, perr := net.ListenPacket("udp", addr)
		if perr != nil {
			if firstErr != nil {
				return udpListeners{}, fmt.Errorf("%s unavailable (%v), and plain bind also failed: %w",
					lbOptName, firstErr, perr)
			}
			return udpListeners{}, perr
		}
		return udpListeners{
			Conns:    []net.PacketConn{pc},
			Degraded: reuseportUnavailable(firstErr),
		}, nil
	}

	res := udpListeners{Conns: conns, Balanced: true}
	if len(conns) < n {
		res.Degraded = fmt.Errorf("only %d of %d sockets could be opened: %v", len(conns), n, firstErr)
	}
	return res, nil
}

// reuseportUnavailable explains why a load-balance group could not be formed,
// in terms worth putting in a log line.
func reuseportUnavailable(err error) error {
	switch {
	case err == nil:
		return fmt.Errorf("%s group could not be formed", lbOptName)
	case errors.Is(err, syscall.ENOPROTOOPT):
		return fmt.Errorf("%s not supported by this kernel", lbOptName)
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Errorf("%s group could not be formed (address already held by a non-LB socket)", lbOptName)
	default:
		return err
	}
}
