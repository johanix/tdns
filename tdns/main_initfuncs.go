/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	// "flag"

	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
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

func MainLoop(ctx context.Context, cancel context.CancelFunc, conf *Config) {
	if Globals.Debug {
		debug.SetTraceback("all")
	}
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
			case <-ctx.Done():
				log.Println("mainloop: context cancelled. Cleaning up.")
				return
			case <-exit:
				log.Println("mainloop: Exit signal received. Cleaning up.")
				cancel()
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
				cancel()
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

	switch Globals.App.Type {
	case AppTypeServer, AppTypeAgent, AppTypeCombiner, AppTypeReporter:
		pflag.StringVar(&conf.Internal.CfgFile, "config", defaultcfg, "config file path")
		pflag.BoolVarP(&Globals.Debug, "debug", "", false, "run in debug mode (may activate dangerous tests)")
		pflag.BoolVarP(&Globals.Verbose, "verbose", "v", false, "Verbose mode")
		pflag.Parse()

		flag.Usage = func() {
			flag.PrintDefaults()
		}

	case AppTypeImr:
		conf.Internal.CfgFile = defaultcfg
	}

	if Globals.Debug {
		log.Printf("*** MainInit: 1. defaultcfg: %q conf.Internal.CfgFile: %q ***", defaultcfg, conf.Internal.CfgFile)
	}

	switch Globals.App.Type {
	case AppTypeServer, AppTypeAgent, AppTypeCombiner, AppTypeImr, AppTypeReporter, AppTypeCli:
		fmt.Printf("*** TDNS %s mode of operation: %q (verbose: %t, debug: %t)\n",
			Globals.App.Name, AppTypeToString[Globals.App.Type], Globals.Verbose, Globals.Debug)
	default:
		return fmt.Errorf("*** TDNS %s: Error: unknown mode of operation: %q",
			Globals.App.Name, Globals.App.Type)
	}

	err := conf.ParseConfig(false) // false = initial config, not reload
	if err != nil {
		return fmt.Errorf("Error parsing config %q: %v", conf.Internal.CfgFile, err)
	}

	logfile := viper.GetString("log.file")
	err = SetupLogging(logfile)
	if err != nil {
		return fmt.Errorf("Error setting up logging: %v", err)
	}
	fmt.Printf("Logging to file: %s\n", logfile)

	switch Globals.App.Type {
	case AppTypeServer, AppTypeAgent, AppTypeCombiner:
		// Note that AppTypeServer and AppTypeAgent feel though into here as well.
		kdb := conf.Internal.KeyDB
		if kdb == nil {
			err = conf.InitializeKeyDB()
			if err != nil {
				return fmt.Errorf("Error initializing KeyDB: %v", err)
			}
			/*
				// dbFile := viper.GetString("db.file")
				dbFile := conf.Db.File
				// Ensure the database file path is within allowed boundaries
				dbFile = filepath.Clean(dbFile)
				if strings.Contains(dbFile, "..") {
					return errors.New("invalid database file path: must not contain directory traversal")
				}
				if dbFile == "" {
					return fmt.Errorf("invalid database file: '%s'", dbFile)
				}
				switch Globals.App.Type {
				case AppTypeServer, AppTypeAgent, AppTypeCombiner:

					// Verify that we have a MUSIC DB file.
					fmt.Printf("Verifying existence of TDNS DB file: %s\n", dbFile)
					if _, err := os.Stat(dbFile); os.IsNotExist(err) {
						log.Printf("ParseConfig: TDNS DB file '%s' does not exist.", dbFile)
						log.Printf("Please initialize TDNS DB using 'tdns-cli|sidecar-cli db init -f %s'.", dbFile)
						return errors.New("ParseConfig: TDNS DB file does not exist")
					}
					kdb, err := NewKeyDB(dbFile, false)
					if err != nil {
						log.Fatalf("Error from NewKeyDB: %v", err)
					}
					conf.Internal.KeyDB = kdb

				default:
					// do nothing for tdns-imr, tdns-cli
				}
			*/
		}

	default:
		log.Printf("TDNS %s (%s): not initializing KeyDB", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	// if Globals.Debug {
	//	log.Printf("*** MainInit: 2 ***")
	// }

	// if Globals.Debug {
	//	log.Printf("*** MainInit: 4 ***")
	// }

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

	if Globals.App.Type == AppTypeAgent {
		conf.Internal.AgentQs = &AgentQs{
			Hello:             make(chan *AgentMsgReport, 100),
			Beat:              make(chan *AgentMsgReport, 100),
			Msg:               make(chan *AgentMsgPostPlus, 100),
			Command:           make(chan *AgentMgmtPostPlus, 100),
			DebugCommand:      make(chan *AgentMgmtPostPlus, 100),
			SynchedDataUpdate: make(chan *SynchedDataUpdate, 100),
			SynchedDataCmd:    make(chan *SynchedDataCmd, 100),
		}
	}

	switch Globals.App.Type {
	case AppTypeImr, AppTypeServer:
		conf.Internal.ValidatorCh = make(chan ValidatorRequest, 10)
		go ValidatorEngine(conf, conf.Internal.StopCh)
		log.Printf("TDNS %s (%s): starting: validatorengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	default:
		log.Printf("TDNS %s (%s): not starting: validatorengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	conf.Internal.NotifyQ = make(chan NotifyRequest, 10)
	go Notifier(conf.Internal.NotifyQ)

	// if Globals.Debug {
	//	log.Printf("*** MainInit: 5 ***")
	// }

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
		conf.Internal.AgentRegistry = conf.NewAgentRegistry()
		// dump.P(conf.Internal.AgentRegistry)
	case AppTypeServer, AppTypeCombiner:
		// ... existing server/combiner setup ...
	default:
		// ... existing server/agent/combiner setup ...
	}

	if Globals.Debug {
		log.Printf("*** MainInit: DONE ***")
	}

	return nil
}

func MainStartThreads(ctx context.Context, conf *Config, apirouter *mux.Router) error {
	kdb := conf.Internal.KeyDB
	stopch := conf.Internal.StopCh

	conf.Internal.APIStopCh = make(chan struct{})

	conf.Internal.ScannerQ = make(chan ScanRequest, 5)
	conf.Internal.DnsUpdateQ = make(chan DnsUpdateRequest, 100)
	conf.Internal.DnsNotifyQ = make(chan DnsNotifyRequest, 100)
	conf.Internal.AuthQueryQ = make(chan AuthQueryRequest, 100)

	// Everyone has the mgmt API dispatcher
	err := APIdispatcher(conf, apirouter, conf.Internal.APIStopCh)
	if err != nil {
		return fmt.Errorf("Error starting API dispatcher: %v", err)
	}

	switch Globals.App.Type {
	case AppTypeAgent:
		// we pass the HelloQ and HeartbeatQ channels to the HsyncEngine to ensure they are created before
		// the HsyncEngine starts listening for incoming connections
        go HsyncEngine(ctx, conf, conf.Internal.AgentQs, conf.Internal.StopCh) // Only used by agent
        go conf.SynchedDataEngine(ctx, conf.Internal.AgentQs, conf.Internal.StopCh)
		syncrtr, err := SetupAgentSyncRouter(conf)
		if err != nil {
			return fmt.Errorf("Error setting up agent-to-agent sync router: %v", err)
		}
		log.Printf("TDNS %s (%s): starting agent-to-agent sync engine", Globals.App.Name, AppTypeToString[Globals.App.Type])
		go APIdispatcherNG(conf, syncrtr, conf.Agent.Api.Addresses.Listen, conf.Agent.Api.CertFile, conf.Agent.Api.KeyFile, conf.Internal.APIStopCh)
		log.Printf("TDNS %s (%s): starting: hsyncengine, synceddataengine, apidispatcherNG", Globals.App.Name, AppTypeToString[Globals.App.Type])
	default:
		log.Printf("TDNS %s (%s): not starting: hsyncengine, synceddataengine, apidispatcherNG", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	switch Globals.App.Type {
	case AppTypeServer, AppTypeAgent:
        go AuthQueryEngine(ctx, conf.Internal.AuthQueryQ)
        go ScannerEngine(ctx, conf.Internal.ScannerQ, conf.Internal.AuthQueryQ)

		kdb.UpdateQ = make(chan UpdateRequest, 10)
		conf.Internal.UpdateQ = kdb.UpdateQ
		kdb.DeferredUpdateQ = make(chan DeferredUpdate, 10)
		conf.Internal.DeferredUpdateQ = kdb.DeferredUpdateQ

        go kdb.ZoneUpdaterEngine(ctx, stopch)
        go kdb.DeferredUpdaterEngine(ctx, stopch)

        go UpdateHandler(ctx, conf)
        go kdb.DelegationSyncher(ctx, conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ)
		log.Printf("TDNS %s (%s): starting: authquery, scanner, zoneupdater, deferredupdater, updatehandler, delegation syncher", Globals.App.Name, AppTypeToString[Globals.App.Type])
	default:
		log.Printf("TDNS %s (%s): not starting: authquery, scanner, zoneupdater, deferredupdater, updatehandler, delegation syncher", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	switch Globals.App.Type {
	case AppTypeServer, AppTypeAgent, AppTypeCombiner:
        go NotifyHandler(ctx, conf)
        go DnsEngine(ctx, conf)
		log.Printf("TDNS %s (%s): starting: notifyhandler, dnsengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	default:
		log.Printf("TDNS %s (%s): not starting: notifyhandler, dnsengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	switch Globals.App.Type {
	case AppTypeServer:
		// Only tdns-server runs the resigner engine
		conf.Internal.ResignQ = make(chan *ZoneData, 10)
        go ResignerEngine(ctx, conf.Internal.ResignQ, stopch)
		log.Printf("TDNS %s (%s): starting: resignerengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	default:
		log.Printf("TDNS %s (%s): not starting: resignerengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	switch Globals.App.Type {
	case AppTypeImr:
		conf.Internal.RecursorCh = make(chan ImrRequest, 10)
		stopCh := make(chan struct{}, 10)
        go conf.RecursorEngine(ctx, stopCh)
		// go ImrEngine(conf, stopCh) // ImrEngine is now started from RecursorEngine, as they share cache
		log.Printf("TDNS %s (%s): starting: recursorengine, imrengine", Globals.App.Name, AppTypeToString[Globals.App.Type])

	default:
		log.Printf("TDNS %s (%s): not starting: recursorengine, imrengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	return nil
}

func Shutdowner(conf *Config, msg string) {
	log.Printf("%s: shutting down: %s", Globals.App.Name, msg)
	conf.Internal.StopCh <- struct{}{}
	time.Sleep(2 * time.Second)
	os.Exit(0)
}
