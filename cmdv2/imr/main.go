/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/johanix/dnssec-algorithms/falcon512"
	"github.com/johanix/dnssec-algorithms/mayo1"
	"github.com/johanix/dnssec-algorithms/mldsa44"
	"github.com/johanix/dnssec-algorithms/slhdsa128s"
	"github.com/johanix/dnssec-algorithms/snova24_5_4"

	tdns "github.com/johanix/tdns/v2"
	algs "github.com/johanix/tdns/v2/algorithms"
)

func init() {
	algs.Register(199, mldsa44.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(200, slhdsa128s.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(201, falcon512.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(202, mayo1.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(203, snova24_5_4.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
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
