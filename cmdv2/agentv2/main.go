/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
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

// Register out-of-tree DNSSEC algorithms. Per-binary choice — tdns/v2
// itself stays free of third-party crypto deps; each application
// decides what to import and at which codepoints to register them.
func init() {
	algs.Register(199, mldsa44.New(),     algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(200, slhdsa128s.New(),  algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(201, falcon512.New(),   algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(202, mayo1.New(),       algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
	algs.Register(203, snova24_5_4.New(), algs.Capabilities{ForSIG0: true, ForDNSSEC: true})
}

func main() {
	tdns.Globals.App.Type = tdns.AppTypeAgent
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

	apirouter, err := conf.SetupAPIRouter(ctx)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error setting up API router: %v", err))
	}

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

	err = conf.StartAgent(ctx, apirouter)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error starting TDNS threads: %v", err))
	}

	conf.MainLoop(ctx, stop)
}
