/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"net"
	"testing"
)

// A cancelled engine context must stop socket creation rather than finish the
// group and hand back listeners nobody will serve from. Checked on both shapes,
// because they take different paths through listenUDPSockets: n==1 goes
// straight to the plain bind, n>1 goes through the load-balance group (or its
// fallback, on a platform without the option -- which is the path most
// developer machines run).
func TestListenUDPSocketsHonoursCancellation(t *testing.T) {
	for _, n := range []int{1, 4} {
		t.Run(map[bool]string{true: "single", false: "group"}[n == 1], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			lst, err := listenUDPSockets(ctx, "127.0.0.1:0", n)
			if err == nil {
				for _, pc := range lst.Conns {
					pc.Close()
				}
				t.Fatalf("n=%d: sockets were opened under a cancelled context", n)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("n=%d: want context.Canceled, got %v", n, err)
			}
			if len(lst.Conns) != 0 {
				for _, pc := range lst.Conns {
					pc.Close()
				}
				t.Errorf("n=%d: %d socket(s) returned alongside the error", n, len(lst.Conns))
			}
		})
	}
}

// The ordinary path still works: a live context opens sockets, and asking for
// more than the platform will give back is degraded rather than fatal.
func TestListenUDPSocketsServesUnderLiveContext(t *testing.T) {
	lst, err := listenUDPSockets(context.Background(), "127.0.0.1:0", 1)
	if err != nil {
		t.Fatalf("single socket: %v", err)
	}
	defer func() {
		for _, pc := range lst.Conns {
			pc.Close()
		}
	}()
	if len(lst.Conns) != 1 {
		t.Fatalf("want 1 socket, got %d", len(lst.Conns))
	}
	if lst.Degraded != nil {
		t.Errorf("a single socket is the correct answer, not a degradation: %v", lst.Degraded)
	}
}

// closeIfCancelled is the post-bind half of cancellation handling, and it is
// the half a race test cannot reach deterministically: the window it covers is
// between ListenPacket returning and us returning its socket. Testing the
// helper directly is what makes that window's behaviour an asserted contract
// rather than an argument -- the call sites are then inspection.
func TestCloseIfCancelled(t *testing.T) {
	t.Run("live context keeps the sockets", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer pc.Close()

		if err := closeIfCancelled(context.Background(), []net.PacketConn{pc}); err != nil {
			t.Fatalf("a live context must keep the sockets: %v", err)
		}
		// Still usable: closing an already-closed PacketConn errors, so a
		// successful write proves it was left alone.
		if _, err := pc.WriteTo([]byte("x"), pc.LocalAddr()); err != nil {
			t.Errorf("socket was closed under a live context: %v", err)
		}
	})

	t.Run("cancelled context closes them and reports", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		cerr := closeIfCancelled(ctx, []net.PacketConn{pc})
		if !errors.Is(cerr, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", cerr)
		}
		// A closed socket refuses further use; that is the observable.
		if _, err := pc.WriteTo([]byte("x"), pc.LocalAddr()); err == nil {
			t.Error("socket was returned open under a cancelled context")
		}
	})
}

// The path every developer machine and every stock NetBSD kernel actually
// runs: more than one socket asked for, no load-balancing option available.
// It must serve -- one socket, not an error -- and say why it could not give
// what was asked for, because that log line is the only signal an operator
// gets that udp-sockets did nothing.
//
// Skipped where the platform DOES load-balance, since there the same call
// legitimately returns a group.
func TestListenUDPSocketsDegradesWithoutKernelSupport(t *testing.T) {
	if lbSupported {
		t.Skipf("platform has %s; the degraded path is not reachable here", lbOptName)
	}

	lst, err := listenUDPSockets(context.Background(), "127.0.0.1:0", 4)
	if err != nil {
		t.Fatalf("asking for more sockets than the kernel can distribute must not fail: %v", err)
	}
	defer func() {
		for _, pc := range lst.Conns {
			pc.Close()
		}
	}()

	if len(lst.Conns) != 1 {
		t.Errorf("want exactly 1 socket without kernel support, got %d", len(lst.Conns))
	}
	if lst.Balanced {
		t.Error("Balanced must be false: nothing is distributing across these sockets")
	}
	if lst.Degraded == nil {
		t.Fatal("Degraded must carry the reason; without it udp-sockets silently does nothing")
	}
}
