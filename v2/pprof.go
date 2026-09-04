/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"net/http"
	"net/http/pprof"
	"time"
)

// startPprof exposes the Go runtime profiler when service.pprof-address is set
// in the config. Unset (the default) means the profiler is never started and
// no port is opened.
//
// Bind it to loopback. The pprof endpoints expose goroutine stacks, heap
// contents and command line, and can be made to burn CPU on demand, so this is
// not something to have listening on a public interface.
//
// Usage once running:
//
//	go tool pprof -seconds 30 http://127.0.0.1:6060/debug/pprof/profile
func (conf *Config) startPprof() {
	addr := conf.Service.PprofAddress
	if addr == "" {
		return
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
	}

	lgConfig.Info("pprof: profiler listening", "addr", addr)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lgConfig.Error("pprof: profiler failed to start", "addr", addr, "err", err)
		}
	}()
}
