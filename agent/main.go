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
	"time"

	_ "github.com/mattn/go-sqlite3"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/johanix/tdns/tdns"
	// "github.com/orcaman/concurrent-map/v2"
)

// var appVersion string
var appMode string

func mainloop(conf *tdns.Config, appMode string) {
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
				err = tdns.ParseZones(conf, conf.Internal.RefreshZoneCh, appMode)
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

	conf.ServerBootTime = time.Now()

	// The agent is not a mode of operation, an agent should not be able to run as a server by just starting it with the wrong arguments.
	// flag.StringVar(&appMode, "mode", "agent", "Mode of operation: server | agent | scanner")
	appMode = "agent"

	flag.BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "Debug mode")
	flag.BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "Verbose mode")
	flag.Parse()

	switch appMode {
	case "server", "agent", "scanner":
		fmt.Printf("*** TDNSD mode of operation: %s (verbose: %t, debug: %t)\n", appMode, tdns.Globals.Verbose, tdns.Globals.Debug)
	default:
		log.Fatalf("*** TDNSD: Error: unknown mode of operation: %s", appMode)
	}

	err := tdns.ParseConfig(&conf, appMode)
	if err != nil {
		log.Fatalf("Error parsing config: %v", err)
	}
	kdb := conf.Internal.KeyDB

	logfile := viper.GetString("log.file")
	tdns.SetupLogging(logfile)
	fmt.Printf("Logging to file: %s\n", logfile)

	fmt.Printf("TDNSD Agent version %s starting.\n", appVersion)

	var stopch = make(chan struct{}, 10)

	conf.Internal.RefreshZoneCh = make(chan tdns.ZoneRefresher, 10)
	conf.Internal.BumpZoneCh = make(chan tdns.BumperData, 10)
	conf.Internal.DelegationSyncQ = make(chan tdns.DelegationSyncRequest, 10)
	go tdns.RefreshEngine(&conf, stopch, appMode)

	//	conf.Internal.ValidatorCh = make(chan tdns.ValidatorRequest, 10)
	// 	go ValidatorEngine(&conf, stopch)

	conf.Internal.NotifyQ = make(chan tdns.NotifyRequest, 10)
	go tdns.Notifier(conf.Internal.NotifyQ)

	// err = ParseZones(conf.Zones, conf.Internal.RefreshZoneCh)
	err = tdns.ParseZones(&conf, conf.Internal.RefreshZoneCh, appMode)
	if err != nil {
		log.Fatalf("Error parsing zones: %v", err)
	}

	apistopper := make(chan struct{}) //
	conf.Internal.APIStopCh = apistopper
	go APIdispatcher(&conf, apistopper)

	conf.Internal.ScannerQ = make(chan tdns.ScanRequest, 5)
	conf.Internal.UpdateQ = kdb.UpdateQ
	conf.Internal.DnsUpdateQ = make(chan tdns.DnsUpdateRequest, 100)
	conf.Internal.DnsNotifyQ = make(chan tdns.DnsNotifyRequest, 100)
	conf.Internal.AuthQueryQ = make(chan tdns.AuthQueryRequest, 100)

	go tdns.AuthQueryEngine(conf.Internal.AuthQueryQ)
	go tdns.ScannerEngine(conf.Internal.ScannerQ, conf.Internal.AuthQueryQ)
	go kdb.UpdaterEngine(stopch)
	go UpdateHandler(&conf)
	go NotifyHandler(&conf)
	go DnsEngine(&conf)
	go kdb.DelegationSyncher(conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ)
	// go tdns.ResignerEngine(conf.Internal.ResignQ, make(chan struct{}))

	mainloop(&conf, appMode)
}