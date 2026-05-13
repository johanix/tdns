/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	// Side-effect imports: register out-of-tree DNSSEC algorithms.
	// Per-binary choice — tdns/v2 itself stays free of third-party
	// crypto deps; each application opts in here.
	_ "github.com/johanix/dnssec-algorithms/mldsa44"
	_ "github.com/johanix/dnssec-algorithms/slhdsa128s"

	tdns "github.com/johanix/tdns/v2"
)

func main() {
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate

	// Create root context with signal handling
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ExecuteContext(ctx)
}
