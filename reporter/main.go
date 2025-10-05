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

	if err := conf.MainInit(tdns.DefaultReporterCfgFile); err != nil {
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

	// Start notify-only DNS server
	stopDNS, err := tdns.CreateNotifyOnlyDNSServer(&conf)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("dns: %v", err))
	}

	// Simple signal loop for graceful shutdown
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
	<-sigch

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = apiSrv.Shutdown(ctx)
	_ = stopDNS(ctx)
}