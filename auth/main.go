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

	"github.com/johanix/tdns/tdns"
)

func main() {
	tdns.Globals.App.Type = tdns.AppTypeAuth
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conf := &tdns.Conf
	err := conf.MainInit(ctx, tdns.DefaultAuthCfgFile)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error initializing TDNS: %v", err))
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
				if _, err := conf.ParseZones(ctx, true); err != nil {
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
