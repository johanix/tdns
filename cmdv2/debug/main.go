/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	tdns "github.com/johanix/tdns/v2"
	_ "github.com/johanix/tdns/v2/core" // RR type registration
)

// tdns-debug is the tdns project's live test/debug instrument (see
// docs/2026-07-13-tdns-debug-test-tool.md). It is a pure client — no
// algorithm implementations are selected (no algs.list): SIG(0) signing
// uses the standard algorithms miekg/dns provides natively.

func main() {
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ExecuteContext(ctx)
}
