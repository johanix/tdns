/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/johanix/dnssec-algorithms/mldsa44"
	"github.com/johanix/dnssec-algorithms/slhdsa128s"

	tdns "github.com/johanix/tdns/v2"
	algs "github.com/johanix/tdns/v2/algorithms"
)

// Pure-Go PQ algorithms (CIRCL-backed) — always registered. The
// liboqs-backed ones (falcon512, mayo1, snova24_5_4) are registered
// from pq_algorithms_liboqs.go (build tag liboqs) or have their
// metadata declared from pq_algorithms_noliboqs.go.
func init() {
	algs.Register(199, mldsa44.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(200, slhdsa128s.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}

func main() {
	tdns.Globals.App.Type = tdns.AppTypeImr
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate

	// Create root context with signal handling
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ExecuteContext(ctx)
}
