/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/spf13/viper"
)

func main() {
	var conf tdns.Config

	tdns.Globals.App.Type = tdns.AppTypeReporter
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	if err := conf.MainInit(context.Background(), tdns.DefaultReporterCfgFile); err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("init: %v", err))
	}

	router, err := tdns.SetupReporterAPIRouter(&conf)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("router: %v", err))
	}

	// Start API HTTP server
	apiAddr := viper.GetString("reporter.api.listen")
	if apiAddr == "" {
		apiAddr = ":8080"
	}
	apiSrv := &http.Server{Addr: apiAddr, Handler: router}
	go func() {
		if err := apiSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			tdns.Shutdowner(&conf, fmt.Sprintf("api server error: %v", err))
		}
	}()

	numtsigs, tsigSecrets := tdns.ParseTsigKeys(&conf.Keys)
	if tdns.Globals.Debug {
		fmt.Printf("Parsed %d TSIG keys\n", numtsigs)
	}
	if numtsigs == 0 {
		fmt.Printf("No TSIG keys found in config. As TSIG is required for reporting, exiting.\n")
		tdns.Shutdowner(&conf, "No TSIG keys found in config. As TSIG is required for reporting, exiting.")
	}

	// Determine which servers to start based on config
	// Default to ["notify"] if not specified
	activeServers := viper.GetStringSlice("reporters.active")
	if len(activeServers) == 0 {
		activeServers = []string{"notify"} // Default to notify-only
	}

	var stopDNS func(context.Context) error
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Check if we should start notify server
	startNotify := false
	startErrorChannel := false
	for _, srv := range activeServers {
		if srv == "notify" {
			startNotify = true
		}
		if srv == "errorchannel" {
			startErrorChannel = true
		}
	}

	// Start notify-only DNS server if configured
	if startNotify {
		notifyAddr := viper.GetString("reporters.notify.listen")
		if notifyAddr == "" {
			notifyAddr = ":53"
		}
		var err error
		stopDNS, err = tdns.NotifyReporter(&conf, tsigSecrets, notifyAddr)
		if err != nil {
			tdns.Shutdowner(&conf, fmt.Sprintf("notify server: %v", err))
		}
		fmt.Printf("Started notify-only DNS server on %s\n", notifyAddr)
	}

	// Start full DNS engine if configured (for RFC9567 error channel reporting)
	if startErrorChannel {
		errorChannelAddr := viper.GetString("reporters.errorchannel.listen")
		if errorChannelAddr == "" {
			errorChannelAddr = ":53"
		}
		// Set the address for DnsEngine
		conf.DnsEngine.Addresses = []string{errorChannelAddr}
		if len(conf.DnsEngine.Transports) == 0 {
			conf.DnsEngine.Transports = []string{"do53"} // Default to Do53
		}

		// Start DnsEngine in a goroutine (it handles shutdown via context cancellation)
		go func() {
			if err := tdns.DnsEngine(ctx, &conf); err != nil {
				tdns.Shutdowner(&conf, fmt.Sprintf("error channel server: %v", err))
			}
			fmt.Printf("Started DNS engine for error channel reporting (RFC9567) on %s\n", errorChannelAddr)
		}()
	}

	// Simple signal loop for graceful shutdown
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
	<-sigch

	// Cancel context to signal DnsEngine to shutdown
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = apiSrv.Shutdown(shutdownCtx)
	if stopDNS != nil {
		_ = stopDNS(shutdownCtx)
	}
}
