/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	// "flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	_ "github.com/mattn/go-sqlite3"

	"github.com/johanix/tdns/tdns"
	// "github.com/orcaman/concurrent-map/v2"
)

// var appVersion string
// var appMode string

func mainloop(conf *tdns.Config) {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

	var err error
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		for {
			// log.Println("mainloop: signal dispatcher")
			select {
			case <-exit:
				log.Println("mainloop: Exit signal received. Cleaning up.")
				// do whatever we need to do to wrap up nicely
				wg.Done()
			case <-hupper:
				log.Println("mainloop: SIGHUP received. Forcing refresh of all configured zones.")
				// err = ParseZones(conf.Zones, conf.Internal.RefreshZoneCh)
				_, err = tdns.ParseZones(conf, conf.Internal.RefreshZoneCh, true) // XXX: true = reload
				if err != nil {
					log.Fatalf("Error parsing zones: %v", err)
				}

			case <-conf.Internal.APIStopCh:
				log.Println("mainloop: Stop command received. Cleaning up.")
				wg.Done()
			}
		}
	}()
	wg.Wait()

	fmt.Println("mainloop: leaving signal dispatcher")
}

// const DefaultCfgFile = "/etc/axfr.net/tdnsd.yaml"

func main() {
	var conf tdns.Config

	conf.App.Mode = "server"
	conf.App.Version = appVersion
	conf.App.Name = appName
	conf.App.Date = appDate

	// These are the defaults, but they are defined here to make it possible for eg. MUSIC to use a different defaul
	conf.Internal.ZonesCfgFile = tdns.ZonesCfgFile
	conf.Internal.CfgFile = tdns.DefaultCfgFile

	err := tdns.MainInit(&conf)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	_, err = tdns.ParseZones(&conf, conf.Internal.RefreshZoneCh, false) // false: not reload, initial parsing
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error parsing zones: %v", err))
	}

	apirouter, err := tdns.SetupAPIRouter(&conf)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error setting up API router: %v", err))
	}
	err = tdns.MainStartThreads(&conf, apirouter)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error starting TDNS threads: %v", err))
	}

	tdns.MainLoop(&conf)
}
