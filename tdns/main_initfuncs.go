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
	"runtime/debug"
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
	for {
		select {
		case <-ctx.Done():
			log.Println("mainloop: context cancelled. Cleaning up.")
			return
		case <-conf.Internal.APIStopCh:
			log.Println("mainloop: Stop command received. Cleaning up.")
			cancel()
			return
		}
	}
}

func (conf *Config) MainInit(ctx context.Context, defaultcfg string) error {
	if ctx == nil {
		ctx = context.Background()
	}
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
		}

	default:
		log.Printf("TDNS %s (%s): not initializing KeyDB", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	err = Globals.Validate()
	if err != nil {
		return fmt.Errorf("Error validating TDNS globals: %v", err)
	}

	fmt.Printf("TDNS %s version %s starting.\n", Globals.App.Name, Globals.App.Version)

	conf.Internal.BumpZoneCh = make(chan BumperData, 10)
	conf.Internal.DelegationSyncQ = make(chan DelegationSyncRequest, 10)
	conf.Internal.SyncQ = make(chan SyncRequest, 10)           // Only used by agent
	conf.Internal.MusicSyncQ = make(chan MusicSyncRequest, 10) // Only used by sidecar.
	// RefreshEngine now started in Start* functions with ctx, but the channel must exist before ParseZones
	if conf.Internal.RefreshZoneCh == nil {
		conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	}

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
		log.Printf("TDNS %s (%s): validator channel initialized (engine starts in starter)", Globals.App.Name, AppTypeToString[Globals.App.Type])
	default:
		log.Printf("TDNS %s (%s): not starting: validatorengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	conf.Internal.NotifyQ = make(chan NotifyRequest, 10)
	// Notifier now started in Start* functions with ctx

	// if Globals.Debug {
	//	log.Printf("*** MainInit: 5 ***")
	// }

	// Parse all configured zones
	all_zones, err := conf.ParseZones(ctx, false) // false = initial load, not reload
	if err != nil {
		return fmt.Errorf("Error parsing zones: %v", err)
	}
	// Provide the complete zone list to engines that need cross-zone post-initialization
	conf.Internal.AllZones = all_zones

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
		go HsyncEngine(ctx, conf, conf.Internal.AgentQs) // Only used by agent
		go conf.SynchedDataEngine(ctx, conf.Internal.AgentQs)
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
		go ScannerEngine(ctx, conf)

		kdb.UpdateQ = make(chan UpdateRequest, 10)
		conf.Internal.UpdateQ = kdb.UpdateQ
		kdb.DeferredUpdateQ = make(chan DeferredUpdate, 10)
		conf.Internal.DeferredUpdateQ = kdb.DeferredUpdateQ

		go kdb.ZoneUpdaterEngine(ctx)
		go kdb.DeferredUpdaterEngine(ctx)

		go UpdateHandler(ctx, conf)
		go kdb.DelegationSyncher(ctx, conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ, conf.Internal.ImrEngine)
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
		go ResignerEngine(ctx, conf.Internal.ResignQ)
		log.Printf("TDNS %s (%s): starting: resignerengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	default:
		log.Printf("TDNS %s (%s): not starting: resignerengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	switch Globals.App.Type {
	case AppTypeImr:
		conf.Internal.RecursorCh = make(chan ImrRequest, 10)
		go conf.ImrEngine(ctx, false) // Server mode: not quiet
		// go ImrEngine(conf, stopCh) // ImrEngine is now started from ImrEngine, as they share cache
		log.Printf("TDNS %s (%s): starting: imrengine", Globals.App.Name, AppTypeToString[Globals.App.Type])

	default:
		log.Printf("TDNS %s (%s): not starting: imrengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	return nil
}

// StartImr starts subsystems for tdns-imr
func StartImr(ctx context.Context, conf *Config, apirouter *mux.Router) error {
	conf.Internal.APIStopCh = make(chan struct{})
	if err := APIdispatcher(conf, apirouter, conf.Internal.APIStopCh); err != nil {
		return fmt.Errorf("Error starting API dispatcher: %v", err)
	}
	if conf.Internal.ValidatorCh == nil {
		conf.Internal.ValidatorCh = make(chan ValidatorRequest, 10)
	}
	go ValidatorEngine(ctx, conf)
	conf.Internal.RecursorCh = make(chan ImrRequest, 10)
	go conf.ImrEngine(ctx, false) // Server mode: not quiet
	log.Printf("TDNS %s (%s): starting: imrengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	return nil
}

// StartCombiner starts subsystems for tdns-combiner
func StartCombiner(ctx context.Context, conf *Config, apirouter *mux.Router) error {
	conf.Internal.APIStopCh = make(chan struct{})
	if err := APIdispatcher(conf, apirouter, conf.Internal.APIStopCh); err != nil {
		return fmt.Errorf("Error starting API dispatcher: %v", err)
	}

	if conf.Internal.RefreshZoneCh == nil {
		conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	}
	conf.Internal.DnsNotifyQ = make(chan DnsNotifyRequest, 100)
	go RefreshEngine(ctx, conf)
	go Notifier(ctx, conf.Internal.NotifyQ)
	go NotifyHandler(ctx, conf)
	go DnsEngine(ctx, conf)
	log.Printf("TDNS %s (%s): starting: notifyhandler, dnsengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	return nil
}

// StartServer starts subsystems for tdns-server
func StartServer(ctx context.Context, conf *Config, apirouter *mux.Router) error {
	if conf.Internal.ValidatorCh == nil {
		conf.Internal.ValidatorCh = make(chan ValidatorRequest, 10)
	}
	go ValidatorEngine(ctx, conf)

	// IMR is active by default unless explicitly set to false
	isActive := conf.Imr.Active == nil || *conf.Imr.Active
	if isActive {
		conf.Internal.RecursorCh = make(chan ImrRequest, 10)
		go conf.ImrEngine(ctx, false) // Server mode: not quiet
		log.Printf("TDNS %s (%s): starting: imrengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	} else {
		log.Printf("TDNS %s (%s): NOT starting: imrengine (imrengine.active explicitly set to false)", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	kdb := conf.Internal.KeyDB
	conf.Internal.APIStopCh = make(chan struct{})
	if conf.Internal.RefreshZoneCh == nil {
		conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	}
	conf.Internal.ScannerQ = make(chan ScanRequest, 5)
	conf.Internal.DnsUpdateQ = make(chan DnsUpdateRequest, 100)
	conf.Internal.DnsNotifyQ = make(chan DnsNotifyRequest, 100)
	conf.Internal.AuthQueryQ = make(chan AuthQueryRequest, 100)
	if err := APIdispatcher(conf, apirouter, conf.Internal.APIStopCh); err != nil {
		return fmt.Errorf("Error starting API dispatcher: %v", err)
	}

	go RefreshEngine(ctx, conf)
	go Notifier(ctx, conf.Internal.NotifyQ)
	go AuthQueryEngine(ctx, conf.Internal.AuthQueryQ)
	go ScannerEngine(ctx, conf)
	kdb.UpdateQ = make(chan UpdateRequest, 10)
	conf.Internal.UpdateQ = kdb.UpdateQ
	kdb.DeferredUpdateQ = make(chan DeferredUpdate, 10)
	conf.Internal.DeferredUpdateQ = kdb.DeferredUpdateQ
	go kdb.ZoneUpdaterEngine(ctx)
	go kdb.DeferredUpdaterEngine(ctx)
	go UpdateHandler(ctx, conf)
	go kdb.DelegationSyncher(ctx, conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ, conf.Internal.ImrEngine)
	go NotifyHandler(ctx, conf)
	go DnsEngine(ctx, conf)
	conf.Internal.ResignQ = make(chan *ZoneData, 10)
	go ResignerEngine(ctx, conf.Internal.ResignQ)
	log.Printf("TDNS %s (%s): starting: refreshengine, authquery, scanner, zoneupdater, deferredupdater, updatehandler, delegation syncher, notifyhandler, dnsengine, resignerengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	return nil
}

// StartAgent starts subsystems for tdns-agent
func StartAgent(ctx context.Context, conf *Config, apirouter *mux.Router) error {
	kdb := conf.Internal.KeyDB
	conf.Internal.APIStopCh = make(chan struct{})
	if conf.Internal.RefreshZoneCh == nil {
		conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	}
	conf.Internal.ScannerQ = make(chan ScanRequest, 5)
	conf.Internal.DnsUpdateQ = make(chan DnsUpdateRequest, 100)
	conf.Internal.DnsNotifyQ = make(chan DnsNotifyRequest, 100)
	conf.Internal.AuthQueryQ = make(chan AuthQueryRequest, 100)
	if err := APIdispatcher(conf, apirouter, conf.Internal.APIStopCh); err != nil {
		return fmt.Errorf("Error starting API dispatcher: %v", err)
	}
	// Common engines
	go RefreshEngine(ctx, conf)
	go Notifier(ctx, conf.Internal.NotifyQ)
	// Agent-specific
	go HsyncEngine(ctx, conf, conf.Internal.AgentQs)
	go conf.SynchedDataEngine(ctx, conf.Internal.AgentQs)
	syncrtr, err := SetupAgentSyncRouter(conf)
	if err != nil {
		return fmt.Errorf("Error setting up agent-to-agent sync router: %v", err)
	}
	go APIdispatcherNG(conf, syncrtr, conf.Agent.Api.Addresses.Listen, conf.Agent.Api.CertFile, conf.Agent.Api.KeyFile, conf.Internal.APIStopCh)
	log.Printf("TDNS %s (%s): starting: agent-to-agent sync engines", Globals.App.Name, AppTypeToString[Globals.App.Type])
	// Common engines
	go AuthQueryEngine(ctx, conf.Internal.AuthQueryQ)
	go ScannerEngine(ctx, conf)
	kdb.UpdateQ = make(chan UpdateRequest, 10)
	conf.Internal.UpdateQ = kdb.UpdateQ
	kdb.DeferredUpdateQ = make(chan DeferredUpdate, 10)
	conf.Internal.DeferredUpdateQ = kdb.DeferredUpdateQ
	go kdb.ZoneUpdaterEngine(ctx)
	go kdb.DeferredUpdaterEngine(ctx)
	go UpdateHandler(ctx, conf)
	go kdb.DelegationSyncher(ctx, conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ, conf.Internal.ImrEngine)
	go NotifyHandler(ctx, conf)
	go DnsEngine(ctx, conf)
	log.Printf("TDNS %s (%s): starting: refreshengine, authquery, scanner, zoneupdater, deferredupdater, updatehandler, delegation syncher, notifyhandler, dnsengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	return nil
}

// StartImr starts subsystems for tdns-imr
func StartScanner(ctx context.Context, conf *Config, apirouter *mux.Router) error {
	conf.Internal.APIStopCh = make(chan struct{})
	if err := APIdispatcher(conf, apirouter, conf.Internal.APIStopCh); err != nil {
		return fmt.Errorf("Error starting API dispatcher: %v", err)
	}
	if conf.Internal.ValidatorCh == nil {
		conf.Internal.ValidatorCh = make(chan ValidatorRequest, 10)
	}
	go ValidatorEngine(ctx, conf)
	conf.Internal.RecursorCh = make(chan ImrRequest, 10)
	go conf.ImrEngine(ctx, false) // Server mode: not quiet
	log.Printf("TDNS %s (%s): starting: imrengine", Globals.App.Name, AppTypeToString[Globals.App.Type])
	return nil
}

func Shutdowner(conf *Config, msg string) {
	log.Printf("%s: shutting down: %s", Globals.App.Name, msg)
	// Prefer closing APIStopCh once as a broadcast to MainLoop and all listeners
	if conf.Internal.APIStopCh != nil {
		conf.Internal.StopOnce.Do(func() {
			// small delay can help in-flight API responses complete before close is observed
			time.Sleep(200 * time.Millisecond)
			close(conf.Internal.APIStopCh)
		})
	}
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}
