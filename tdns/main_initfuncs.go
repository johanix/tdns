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
	"github.com/spf13/pflag"
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
				all_zones, err = conf.ParseZones(true) // true = reload
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

func (conf *Config) MainInit(defaultcfg string) error {
	Globals.App.ServerBootTime = time.Now()
	Globals.App.ServerConfigTime = time.Now()

	pflag.StringVar(&conf.Internal.CfgFile, "config", defaultcfg, "config file path")
	pflag.BoolVarP(&Globals.Debug, "debug", "", false, "run in debug mode (may activate dangerous tests)")
	pflag.BoolVarP(&Globals.Verbose, "verbose", "v", false, "Verbose mode")
	pflag.Parse()

	flag.Usage = func() {
		flag.PrintDefaults()
	}

	if Globals.Debug {
		log.Printf("*** MainInit: 1 ***")
	}

	switch Globals.App.Type {
	case AppTypeServer, AppTypeAgent, AppTypeMSA, AppTypeCombiner:
		fmt.Printf("*** TDNS %s mode of operation: %q (verbose: %t, debug: %t)\n",
			Globals.App.Name, AppTypeToString[Globals.App.Type], Globals.Verbose, Globals.Debug)
	default:
		return fmt.Errorf("*** TDNS %s: Error: unknown mode of operation: %q",
			Globals.App.Name, Globals.App.Type)
	}

	err := conf.ParseConfig(false) // false = !reload, initial config
	if err != nil {
		return fmt.Errorf("Error parsing config %q: %v", conf.Internal.CfgFile, err)
	}

	if Globals.Debug {
		log.Printf("*** MainInit: 2 ***")
	}

	// Initialize channels and start engines
	kdb := conf.Internal.KeyDB
	kdb.UpdateQ = make(chan UpdateRequest, 10)
	kdb.DeferredUpdateQ = make(chan DeferredUpdate, 10)
	conf.Internal.UpdateQ = kdb.UpdateQ
	conf.Internal.DeferredUpdateQ = kdb.DeferredUpdateQ

	conf.Internal.KeyDB = kdb

	if Globals.Debug {
		log.Printf("*** MainInit: 3 ***")
	}

	logfile := viper.GetString("log.file")
	err = SetupLogging(logfile)
	if err != nil {
		return fmt.Errorf("Error setting up logging: %v", err)
	}
	fmt.Printf("Logging to file: %s\n", logfile)

	if Globals.Debug {
		log.Printf("*** MainInit: 4 ***")
	}

	err = Globals.Validate()
	if err != nil {
		return fmt.Errorf("Error validating TDNS globals: %v", err)
	}

	fmt.Printf("TDNS %s version %s starting.\n", Globals.App.Name, Globals.App.Version)

	conf.Internal.StopCh = make(chan struct{}, 10)

	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	conf.Internal.BumpZoneCh = make(chan BumperData, 10)
	conf.Internal.DelegationSyncQ = make(chan DelegationSyncRequest, 10)
	conf.Internal.SyncQ = make(chan SyncRequest, 10)           // Only used by agent
	conf.Internal.MusicSyncQ = make(chan MusicSyncRequest, 10) // Only used by sidecar.
	go RefreshEngine(conf, conf.Internal.StopCh)

	switch Globals.App.Type {
	case AppTypeCombiner, AppTypeAgent:
		// don't start validator engine for combiner or agent
	default:
		conf.Internal.ValidatorCh = make(chan ValidatorRequest, 10)
		go ValidatorEngine(conf, conf.Internal.StopCh)
	}

	conf.Internal.NotifyQ = make(chan NotifyRequest, 10)
	go Notifier(conf.Internal.NotifyQ)

	if Globals.Debug {
		log.Printf("*** MainInit: 5 ***")
	}

	// Parse all configured zones
	all_zones, err := conf.ParseZones(false) // false = initial load, not reload
	if err != nil {
		return fmt.Errorf("Error parsing zones: %v", err)
	}

	switch Globals.App.Type {
	case AppTypeAgent:
		// Setup agent identity and publish records
		err = conf.SetupAgent(all_zones)
		if err != nil {
			return fmt.Errorf("Error setting up agent: %v", err)
		}
		// Initialize AgentRegistry for agent mode only
		conf.Internal.Registry = conf.NewAgentRegistry()
	case AppTypeServer, AppTypeMSA, AppTypeCombiner:
		// ... existing server/MSA/combiner setup ...
	default:
		// ... existing server/MSA/combiner setup ...
	}

	if Globals.Debug {
		log.Printf("*** MainInit: DONE ***")
	}

	return nil
}

func MainStartThreads(conf *Config, apirouter *mux.Router) error {
	kdb := conf.Internal.KeyDB
	stopch := conf.Internal.StopCh

	// if Globals.App.Type != AppTypeMSA {
	// The music sidecar has its own apihandler, so we must not start the TDNS apihandler here.
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
	conf.Internal.AgentQs = AgentQs{
		Hello:          make(chan AgentMsgReport, 100),
		Beat:           make(chan AgentMsgReport, 100),
		Msg:            make(chan AgentMsgReport, 100),
		Command:        make(chan AgentMsgPost, 100),
		CombinerUpdate: make(chan *CombUpdate, 100),
	}

	if Globals.App.Type == AppTypeAgent {
		// we pass the HelloQ and HeartbeatQ channels to the HsyncEngine to ensure they are created before
		// the HsyncEngine starts listening for incoming connections
		go HsyncEngine(conf, conf.Internal.AgentQs, conf.Internal.StopCh) // Only used by agent
		go conf.CombinerUpdater(conf.Internal.AgentQs.CombinerUpdate, conf.Internal.StopCh)
		syncrtr, err := SetupAgentSyncRouter(conf)
		if err != nil {
			return fmt.Errorf("Error setting up agent-to-agent sync router: %v", err)
		}
		log.Printf("TDNS %s (%s): starting agent-to-agent sync engine", Globals.App.Name, AppTypeToString[Globals.App.Type])
		go APIdispatcherNG(conf, syncrtr, conf.Agent.Api.Addresses.Listen, conf.Agent.Api.CertFile, conf.Agent.Api.KeyFile, conf.Internal.APIStopCh)
	}

	switch Globals.App.Type {
	case AppTypeCombiner:
		log.Printf("TDNS %s (%s): not starting: authquery, scanner, zoneupdater, deferredupdater, updatehandler, delegation syncher", Globals.App.Name, AppTypeToString[Globals.App.Type])
	default:
		go AuthQueryEngine(conf.Internal.AuthQueryQ)
		go ScannerEngine(conf.Internal.ScannerQ, conf.Internal.AuthQueryQ)

		go kdb.ZoneUpdaterEngine(stopch)
		go kdb.DeferredUpdaterEngine(stopch)

		go UpdateHandler(conf)
		go kdb.DelegationSyncher(conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ)
	}
	go NotifyHandler(conf)
	go DnsEngine(conf)

	switch Globals.App.Type {
	case AppTypeMSA, AppTypeServer:
		conf.Internal.ResignQ = make(chan *ZoneData, 10)
		go ResignerEngine(conf.Internal.ResignQ, stopch)
	default:
		// agent does not resign zones
		log.Printf("TDNS %s (%s): not starting resigner engine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	return nil
}

func Shutdowner(conf *Config, msg string) {
	log.Printf("%s: shutting down: %s", Globals.App.Name, msg)
	conf.Internal.StopCh <- struct{}{}
	time.Sleep(2 * time.Second)
	os.Exit(0)
}
