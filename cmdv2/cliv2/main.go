/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	tdns "github.com/johanix/tdns/v2"
	_ "github.com/johanix/tdns/v2/core" // Import for RR type registration
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
