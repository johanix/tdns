/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The dangerous value is also the most likely one: ":6060" is the canonical
// pprof example and listens on every interface, on a process whose memory holds
// private keys and TSIG secrets. The rule used to live in a comment; this is
// what makes it a rule.
func TestValidatePprofAddress(t *testing.T) {
	for _, tc := range []struct {
		addr string
		ok   bool
		why  string
	}{
		{"127.0.0.1:6060", true, "the documented form"},
		{"[::1]:6060", true, "IPv6 loopback"},
		{"127.0.0.2:6060", true, "all of 127/8 is loopback"},
		{"localhost:6060", true, "accepted as the name of loopback"},
		{":6060", false, "every interface -- the tutorial value"},
		{"0.0.0.0:6060", false, "every interface, spelled out"},
		{"[::]:6060", false, "every interface, v6"},
		{"192.0.2.1:6060", false, "a public address"},
		{"example.com:6060", false, "a hostname that is not localhost"},
		{"127.0.0.1", false, "no port"},
		{"", false, "empty is handled by the caller, not here"},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			err := validatePprofAddress(tc.addr)
			if tc.ok && err != nil {
				t.Fatalf("%s: rejected %q: %v", tc.why, tc.addr, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("%s: accepted %q", tc.why, tc.addr)
			}
			// A refusal has to tell the operator what to do instead.
			if err != nil && !strings.Contains(err.Error(), "pprof-address") {
				t.Errorf("error does not name the setting: %v", err)
			}
		})
	}
}

// An unset address starts nothing and is not an error: that is the default.
func TestStartPprofUnsetIsNoop(t *testing.T) {
	conf := &Config{}
	if err := conf.startPprof(context.Background()); err != nil {
		t.Fatalf("unset pprof-address must be a no-op, got %v", err)
	}
}

// The finding this replaces: ListenAndServe ran inside a goroutine, so a bind
// failure was logged AFTER startup had reported success and the operator was
// left with no profiler and no error. Binding synchronously is what makes the
// failure reachable, so hold the port and check the error comes back.
func TestStartPprofReportsBindFailure(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not take a port to hold: %v", err)
	}
	defer held.Close()

	conf := &Config{}
	conf.Service.PprofAddress = held.Addr().String()

	err = conf.startPprof(context.Background())
	if err == nil {
		t.Fatal("a bind failure must be returned, not logged from a goroutine")
	}
	if !strings.Contains(err.Error(), "pprof") {
		t.Errorf("error should name the subsystem: %v", err)
	}
}

// A non-loopback address is refused before anything is bound, so a misconfigured
// daemon fails to start rather than serving profiles to the internet.
func TestStartPprofRefusesNonLoopback(t *testing.T) {
	conf := &Config{}
	conf.Service.PprofAddress = ":0"
	if err := conf.startPprof(context.Background()); err == nil {
		t.Fatal("a wildcard bind must be refused")
	}
}

// Cancelling the context takes the listener down, so the port does not outlive
// the daemon.
func TestStartPprofShutsDownWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conf := &Config{}
	conf.Service.PprofAddress = "127.0.0.1:0"

	// Port 0 means the kernel picks one, so read it back off a probe listener
	// instead: take a port, release it, and reuse the number.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()
	conf.Service.PprofAddress = addr

	if err := conf.startPprof(ctx); err != nil {
		t.Fatalf("startPprof: %v", err)
	}
	cancel()

	// The listener closes asynchronously; the port becoming bindable again is
	// the observable that matters.
	deadline := 0
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return
		}
		deadline++
		if deadline > 200 {
			t.Fatalf("port %s still held 2s after cancellation: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The regression the review asked for: /debug/pprof/profile is a 30s long poll,
// and http.Server.Shutdown never interrupts an active connection.
//
// The observable is the CLIENT's request returning, not the port becoming
// bindable. Shutdown closes listeners first and only then waits for
// connections to drain, so the port frees immediately whatever happens to the
// in-flight profile -- a port-based assertion passes even with both fixes
// removed, which is exactly the trap this test fell into first time round.
//
// Two mechanisms can deliver the outcome: BaseContext cancels the handler, and
// srv.Close() severs the connection once the grace period expires. This
// asserts the OUTCOME, so removing either alone still passes and removing both
// fails. That is the honest shape of it rather than a claim to isolate one.
func TestStartPprofClosesThroughALongRunningProfile(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	conf := &Config{}
	conf.Service.PprofAddress = addr
	if err := conf.startPprof(ctx); err != nil {
		t.Fatalf("startPprof: %v", err)
	}

	// A profile far longer than the grace period. done carries how long the
	// client was actually held.
	done := make(chan time.Duration, 1)
	go func() {
		began := time.Now()
		resp, err := http.Get("http://" + addr + "/debug/pprof/profile?seconds=30")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		done <- time.Since(began)
	}()

	// Let the request reach the handler and start profiling before shutting
	// down; otherwise this proves nothing about active connections.
	time.Sleep(300 * time.Millisecond)
	cancel()

	// Comfortably inside the profile's own 30s, and outside the grace period
	// plus scheduling slack.
	limit := pprofShutdownTimeout + 5*time.Second
	select {
	case held := <-done:
		if held > limit {
			t.Fatalf("the profile request was held %s; shutdown did not interrupt it", held)
		}
	case <-time.After(limit):
		t.Fatalf("the profile request outlived shutdown by more than %s; "+
			"a client holding a profile keeps the daemon's profiler alive", limit)
	}
}
