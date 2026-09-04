/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// pprofShutdownTimeout bounds how long the profiler is given to finish in-flight
// requests once the daemon is going down. A profile fetch is a long poll (30s is
// the usual), so this deliberately does not wait for one to finish.
const pprofShutdownTimeout = 5 * time.Second

// startPprof exposes the Go runtime profiler when service.pprof-address is set
// in the config. Unset (the default) means the profiler is never started and
// no port is opened.
//
// Loopback only, and enforced rather than merely advised: the pprof endpoints
// expose goroutine stacks, heap contents and the command line, and can be made
// to burn CPU on demand, with no authentication of any kind in front of them.
// See validatePprofAddress.
//
// Binding happens HERE, synchronously, so a failure to bind is returned to the
// caller instead of being logged from a goroutine after startup has already
// reported success. That distinction matters: the failure mode it replaces is
// an operator who configured the profiler, saw no error, and has no profiler.
//
// Usage once running:
//
//	go tool pprof -seconds 30 http://127.0.0.1:6060/debug/pprof/profile
func (conf *Config) startPprof(ctx context.Context) error {
	addr := conf.Service.PprofAddress
	if addr == "" {
		return nil
	}
	if err := validatePprofAddress(addr); err != nil {
		return err
	}

	// A dedicated mux: the pprof handlers install themselves on
	// http.DefaultServeMux, and the API server shares that process.
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// Hand the daemon's context to every request. /debug/pprof/profile is
		// a long poll -- 30 seconds by default -- and it honours the request
		// context, so without this a shutdown would sit behind whatever
		// profile happened to be running.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("pprof: cannot listen on %s: %w", addr, err)
	}

	lgConfig.Info("pprof: profiler listening", "addr", ln.Addr().String())
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			lgConfig.Error("pprof: profiler stopped", "addr", addr, "err", err)
		}
	}()

	// Close the listener when the daemon goes down. Without this the port
	// stays open for as long as the process does -- which is usually until
	// exit, but "usually" is not a lifecycle.
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), pprofShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			// Shutdown waits for active connections and never interrupts them,
			// so a client that keeps one open outlives the grace period. Close
			// is what actually takes the listener and the connections down;
			// without it the port stays held by a profiler the daemon has
			// already stopped waiting for.
			lgConfig.Warn("pprof: profiler did not shut down within the grace period; closing it", "addr", addr, "err", err)
			if cerr := srv.Close(); cerr != nil {
				lgConfig.Warn("pprof: closing the profiler failed", "addr", addr, "err", cerr)
			}
		}
	}()

	return nil
}

// validatePprofAddress refuses anything that is not a loopback address.
//
// pprof is unauthenticated and dumps process internals, so on a nameserver --
// whose memory holds private keys and TSIG secrets -- a wildcard bind is a
// credential disclosure waiting for someone to notice the port. The canonical
// pprof example in every tutorial is ":6060", which listens on EVERY interface,
// so the dangerous value is also the one most likely to be pasted in. Refusing
// it is worth more than documenting against it, which is what this code did
// before: the rule was in a comment and nothing enforced it.
//
// An operator who genuinely wants remote profiling forwards a port over ssh,
// which is what the loopback restriction is asking for anyway.
func validatePprofAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("service.pprof-address %q is not a host:port address: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("service.pprof-address %q has no port", addr)
	}
	// An empty host is the ":6060" form: every interface, including public ones.
	if host == "" {
		return fmt.Errorf("service.pprof-address %q listens on every interface; "+
			"pprof is unauthenticated and exposes heap and goroutine dumps, so it must bind to "+
			"loopback (use 127.0.0.1:%s or [::1]:%s, and forward a port over ssh for remote access)",
			addr, port, port)
	}
	// "localhost" is accepted as the name of loopback; anything else has to be
	// a loopback IP literal. A hostname that merely happens to resolve to
	// loopback today is not a guarantee worth taking.
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("service.pprof-address %q: host %q is neither \"localhost\" nor an IP address; "+
			"pprof must bind to loopback (127.0.0.1 or ::1)", addr, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("service.pprof-address %q binds the non-loopback address %s; "+
			"pprof is unauthenticated and exposes heap and goroutine dumps, so it must bind to "+
			"loopback (use 127.0.0.1:%s or [::1]:%s, and forward a port over ssh for remote access)",
			addr, host, port, port)
	}
	return nil
}
