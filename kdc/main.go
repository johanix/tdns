/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * tdns-kdc - Key Distribution Center daemon
 */

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/johanix/tdns/v0.x/tdns"
)

func main() {
	tdns.Globals.App.Type = tdns.AppTypeKdc
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conf := &tdns.Conf
	err := conf.MainInit(ctx, tdns.DefaultKdcCfgFile)
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
				log.Printf("SIGHUP received - reload not yet implemented for KDC")
			}
		}
	}()

	err = conf.StartKdc(ctx, apirouter)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error starting TDNS KDC threads: %v", err))
	}

	// Enter main loop
	conf.MainLoop(ctx, stop)
}

