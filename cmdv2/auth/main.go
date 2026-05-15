/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/mattn/go-sqlite3"

	"github.com/johanix/dnssec-algorithms/falcon512"
	"github.com/johanix/dnssec-algorithms/mayo1"
	"github.com/johanix/dnssec-algorithms/mldsa44"
	"github.com/johanix/dnssec-algorithms/slhdsa128s"
	"github.com/johanix/dnssec-algorithms/snova24_5_4"

	tdns "github.com/johanix/tdns/v2"
	algs "github.com/johanix/tdns/v2/algorithms"
)

func init() {
	algs.Register(199, mldsa44.New(),     algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(200, slhdsa128s.New(),  algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(201, falcon512.New(),   algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(202, mayo1.New(),       algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(203, snova24_5_4.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}

func main() {
	tdns.Globals.App.Type = tdns.AppTypeAuth
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conf := &tdns.Conf
	err := conf.MainInit(ctx, "") // Empty string means derive from Globals.App.Name
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	// Write the rollover-daemon sentinel so CLI --offline writers
	// can detect we're alive and refuse to race the rollover tick.
	// Best-effort cleanup on graceful shutdown via defer; SIGKILL or
	// crash leaves the row stale, which the CLI's kill -0 check
	// handles correctly.
	if conf.Internal.KeyDB != nil {
		// Sentinel write must succeed: it's the gate that lets CLI
		// --offline writers detect a live daemon and refuse to race
		// the rollover tick. Failing to write it means that gate is
		// silently disabled, so we treat it as a startup error.
		if err := tdns.WriteRolloverDaemonSentinel(conf.Internal.KeyDB); err != nil {
			tdns.Shutdowner(conf, fmt.Sprintf("error writing rollover daemon sentinel: %v", err))
		}
		defer tdns.ClearRolloverDaemonSentinel(conf.Internal.KeyDB)
	}

	apirouter, err := conf.SetupAPIRouter(ctx)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error setting up API router: %v", err))
	}

	// Start application threads
	// SIGHUP reload watcher
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if _, err := conf.ReloadZoneConfig(ctx); err != nil {
					log.Printf("SIGHUP reload failed: %v", err)
				}
			}
		}
	}()

	err = conf.StartAuth(ctx, apirouter)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error starting TDNS threads: %v", err))
	}

	// Enter main loop
	conf.MainLoop(ctx, stop)
}
