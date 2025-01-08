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

func mainloop(conf *tdns.Config) {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

	var err error
	var all_zones []string
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
				all_zones, err = tdns.ParseZones(conf, conf.Internal.RefreshZoneCh, true) // true = reload
				if err != nil {
					log.Fatalf("Error parsing zones: %v", err)
				} else {
					log.Printf("mainloop: SIGHUP received. Forcing refresh of %d configured zones.", len(all_zones))
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

func main() {
	var conf tdns.Config

	conf.App.Mode = "agent"
	conf.App.Version = appVersion
	conf.App.Name = appName
	conf.App.Date = appDate

	// These are the defaults, but they are defined here to make it possible for eg. MUSIC to use a different defaul
	conf.Internal.ZonesCfgFile = tdns.ZonesCfgFile
	conf.Internal.CfgFile = tdns.DefaultCfgFile

	err := tdns.MainInit(&conf)
	if err != nil {
		log.Fatalf("Error initializing TDNS: %v", err)
	}

	_, err = tdns.ParseZones(&conf, conf.Internal.RefreshZoneCh, false) // false = !reload, initial config
	if err != nil {
		log.Fatalf("Error parsing zones: %v", err)
	}

	apirouter, err := tdns.SetupAPIRouter(&conf)
	if err != nil {
		log.Fatalf("Error setting up API router: %v", err)
	}
	err = tdns.MainStartThreads(&conf, apirouter)
	if err != nil {
		log.Fatalf("Error starting TDNS threads: %v", err)
	}

	tdns.MainLoop(&conf)
}
