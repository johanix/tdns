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
	algs "github.com/johanix/tdns/v2/algorithms"
	_ "github.com/johanix/tdns/v2/core" // Import for RR type registration
)

// Register the PQ algorithm names as metadata only. tdns-cli doesn't
// sign or verify; it just builds API requests against tdns server
// binaries and needs to recognize the algorithm names + codepoints
// so CLI argument validation works. The actual crypto stays out of
// this binary — no CIRCL, no liboqs.
//
// Keep these codepoints in sync with what the server binaries
// register in their own init() functions.
func init() {
	algs.RegisterMetadata(199, "MLDSA44", algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.RegisterMetadata(200, "SLHDSA128S", algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.RegisterMetadata(201, "FALCON512", algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.RegisterMetadata(202, "MAYO1", algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.RegisterMetadata(203, "SNOVA24_5_4", algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}

func main() {
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate

	// Create root context with signal handling
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ExecuteContext(ctx)
}
