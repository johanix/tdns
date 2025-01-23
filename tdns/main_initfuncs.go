/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	// "flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	// "github.com/johanix/tdns/tdns"
	// "github.com/orcaman/concurrent-map/v2"
)

func MainLoop(conf *Config) {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

	defer signal.Stop(exit)
	defer signal.Stop(hupper)

	var err error
	var all_zones []string
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for {
			// log.Println("mainloop: signal dispatcher")
			select {
			case <-exit:
				log.Println("mainloop: Exit signal received. Cleaning up.")
				// do whatever we need to do to wrap up nicely
				return
			case <-hupper:
				log.Println("mainloop: SIGHUP received. Forcing refresh of all configured zones.")
				// err = ParseZones(conf.Zones, conf.Internal.RefreshZoneCh)
				all_zones, err = ParseZones(conf, conf.Internal.RefreshZoneCh, true) // true = reload
				if err != nil {
					log.Printf("Error parsing zones: %v", err)
					return // terminate MainLoop --> shutdown
				} else {
					log.Printf("mainloop: SIGHUP received. Forcing refresh of %d configured zones.", len(all_zones))
				}

			case <-conf.Internal.APIStopCh:
				log.Println("mainloop: Stop command received. Cleaning up.")
				return
			}
		}
	}()
	wg.Wait()

	fmt.Println("mainloop: leaving signal dispatcher")
}

// const DefaultCfgFile = "/etc/axfr.net/tdnsd.yaml"

func MainInit(conf *Config) error {
	conf.App.ServerBootTime = time.Now()
	conf.App.ServerConfigTime = time.Now()

	flag.BoolVarP(&Globals.Debug, "debug", "d", false, "Debug mode")
	flag.BoolVarP(&Globals.Verbose, "verbose", "v", false, "Verbose mode")
	flag.Parse()

	flag.Usage = func() {
		flag.PrintDefaults()
	}

	switch conf.App.Mode {
	case "server", "agent", "sidecar", "scanner":
		fmt.Printf("*** TDNS %s mode of operation: %s (verbose: %t, debug: %t)\n", conf.App.Name, conf.App.Mode, Globals.Verbose, Globals.Debug)
	default:
		return fmt.Errorf("*** TDNS %s: Error: unknown mode of operation: %s", conf.App.Name, conf.App.Mode)
	}

	err := ParseConfig(conf, false) // false = !reload, initial config
	if err != nil {
		return fmt.Errorf("Error parsing config \"%s\": %v", conf.Internal.CfgFile, err)
	}
	kdb := conf.Internal.KeyDB
	kdb.UpdateQ = make(chan UpdateRequest, 10)
	kdb.DeferredUpdateQ = make(chan DeferredUpdate, 10)
	conf.Internal.UpdateQ = kdb.UpdateQ
	conf.Internal.DeferredUpdateQ = kdb.DeferredUpdateQ

	conf.Internal.KeyDB = kdb

	logfile := viper.GetString("log.file")
	err = SetupLogging(logfile)
	if err != nil {
		return fmt.Errorf("Error setting up logging: %v", err)
	}
	fmt.Printf("Logging to file: %s\n", logfile)

	err = Globals.Validate()
	if err != nil {
		return fmt.Errorf("Error validating TDNS globals: %v", err)
	}

	fmt.Printf("TDNS %s version %s starting.\n", conf.App.Name, conf.App.Version)

	conf.Internal.StopCh = make(chan struct{}, 10)

	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	conf.Internal.BumpZoneCh = make(chan BumperData, 10)
	conf.Internal.DelegationSyncQ = make(chan DelegationSyncRequest, 10)
	conf.Internal.MusicSyncQ = make(chan MusicSyncRequest, 10) // Only used by sidecar.
	go RefreshEngine(conf, conf.Internal.StopCh)

	conf.Internal.ValidatorCh = make(chan ValidatorRequest, 10)
	go ValidatorEngine(conf, conf.Internal.StopCh)

	conf.Internal.NotifyQ = make(chan NotifyRequest, 10)
	go Notifier(conf.Internal.NotifyQ)

	return nil
}

func MainStartThreads(conf *Config, apirouter *mux.Router) error {
	kdb := conf.Internal.KeyDB
	stopch := conf.Internal.StopCh

	// if conf.App.Mode != "sidecar" {
	// The music sidecar has its own API, so we must not start the TDNS API here.
	conf.Internal.APIStopCh = make(chan struct{})
	// router := TdnsSetupRouter(conf)
	err := APIdispatcher(conf, apirouter, conf.Internal.APIStopCh)
	if err != nil {
		return fmt.Errorf("Error starting API dispatcher: %v", err)
	}
	// }

	conf.Internal.ScannerQ = make(chan ScanRequest, 5)
	conf.Internal.DnsUpdateQ = make(chan DnsUpdateRequest, 100)
	conf.Internal.DnsNotifyQ = make(chan DnsNotifyRequest, 100)
	conf.Internal.AuthQueryQ = make(chan AuthQueryRequest, 100)

	go AuthQueryEngine(conf.Internal.AuthQueryQ)
	go ScannerEngine(conf.Internal.ScannerQ, conf.Internal.AuthQueryQ)

	go kdb.ZoneUpdaterEngine(stopch)
	go kdb.DeferredUpdaterEngine(stopch)

	go UpdateHandler(conf)
	go NotifyHandler(conf)
	go DnsEngine(conf)
	go kdb.DelegationSyncher(conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ)

	switch conf.App.Mode {
	case "sidecar", "server":
		conf.Internal.ResignQ = make(chan *ZoneData, 10)
		go ResignerEngine(conf.Internal.ResignQ, stopch)
	default:
		// agent does not resign zones
		log.Printf("TDNS %s (%s): not starting resigner engine", conf.App.Name, conf.App.Mode)
	}

	return nil
}

func Shutdowner(conf *Config, msg string) {
	log.Printf("%s: shutting down: %s", conf.App.Name, msg)
	conf.Internal.StopCh <- struct{}{}
	time.Sleep(2 * time.Second)
	os.Exit(0)
}
