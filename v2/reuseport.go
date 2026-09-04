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
// ctx is the engine's: every bind here goes through it, so a daemon cancelled
// mid-startup stops opening sockets instead of finishing the group and handing
// back listeners nobody will serve from.
func listenUDPSockets(ctx context.Context, addr string, n int) (udpListeners, error) {
	// Checked explicitly, not just handed to ListenPacket. ListenConfig uses
	// the context for name resolution and dial deadlines; binding a literal
	// address never consults it, so passing ctx alone would look like
	// cancellation support without being any. The bind calls below still take
	// ctx -- an address that needs resolving does honour it -- but this is what
	// makes a cancelled startup stop.
	if err := ctx.Err(); err != nil {
		return udpListeners{}, err
	}
	if n < 1 {
		n = 1
	}
	if n == 1 || !lbSupported {
		var plain net.ListenConfig
		pc, err := plain.ListenPacket(ctx, "udp", addr)
		if err != nil {
			return udpListeners{}, err
		}
		if cerr := closeIfCancelled(ctx, []net.PacketConn{pc}); cerr != nil {
			return udpListeners{}, cerr
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
		// Cancellation is not a degraded group -- it is "stop". Close what has
		// been opened and say so, rather than falling through to the
		// single-socket recovery below and serving from a daemon on its way out.
		if err := ctx.Err(); err != nil {
			for _, pc := range conns {
				pc.Close()
			}
			return udpListeners{}, err
		}
		pc, err := lc.ListenPacket(ctx, "udp", addr)
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
		if cerr := ctx.Err(); cerr != nil {
			return udpListeners{}, cerr
		}
		var plain net.ListenConfig
		pc, perr := plain.ListenPacket(ctx, "udp", addr)
		if perr == nil {
			if cerr := closeIfCancelled(ctx, []net.PacketConn{pc}); cerr != nil {
				return udpListeners{}, cerr
			}
		}
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

	if cerr := closeIfCancelled(ctx, conns); cerr != nil {
		return udpListeners{}, cerr
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

// closeIfCancelled reports cancellation that happened while sockets were being
// opened, closing them on the way out.
//
// The check has to come AFTER a successful bind as well as before one: a bind
// takes a moment, and a context cancelled during it still returns a usable
// socket. Handing that back means serving from a daemon that has been told to
// stop, and leaking the socket for as long as the process lingers. Returns nil
// and keeps the sockets when the context is still live.
func closeIfCancelled(ctx context.Context, conns []net.PacketConn) error {
	err := ctx.Err()
	if err == nil {
		return nil
	}
	for _, pc := range conns {
		pc.Close()
	}
	return err
}
