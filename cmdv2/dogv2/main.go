/*
 * Copyright (c) Johan Stenstam, johani@johani.org
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

// dogv2 builds with CGO_ENABLED=0 (statically-linked dig
// replacement). The liboqs-backed algorithms (falcon512, mayo1,
// snova24_5_4) require CGO and are deliberately omitted here.
// Their codepoints are still registered as metadata so dogv2's
// validation accepts the names — actual signing/verifying with
// them is not possible from this binary.
func init() {
	algs.Register(199, mldsa44.New(),    algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(200, slhdsa128s.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.RegisterMetadata(201, "FALCON512",   algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.RegisterMetadata(202, "MAYO1",       algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
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
