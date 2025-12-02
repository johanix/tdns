/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/johanix/tdns/tdns"
)

func main() {
	var tconf tdns.Config

	tdns.Globals.App.Type = tdns.AppTypeScanner
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := tconf.MainInit(ctx, tdns.DefaultScannerCfgFile)
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	apirouter, err := tdns.SetupAPIRouter(&tconf) // sidecar mgmt API is a combo of TDNS and MUSIC
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error setting up API router: %v", err))
	}
	err = tdns.StartScanner(ctx, &tconf, apirouter)
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error starting TDNS threads: %v", err))
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
				continue
			}
		}
	}()

	tdns.MainLoop(ctx, stop, &tconf)
}
