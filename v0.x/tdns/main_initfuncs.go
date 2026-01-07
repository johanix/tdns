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
	"sync"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/pflag"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	// "github.com/johanix/tdns/v0.x/tdns"
	// "github.com/orcaman/concurrent-map/v2"
)

var engineWg sync.WaitGroup

// startEngine wraps engine functions in a goroutine with error handling.
// It logs errors if the engine function returns an error, preventing silent failures.
func startEngine(app *AppDetails, name string, engineFunc func() error) {
	engineWg.Add(1)
	go func() {
		defer engineWg.Done()
		log.Printf("TDNS %s (%s): starting: %s", app.Name, AppTypeToString[app.Type], name)
		if err := engineFunc(); err != nil {
			log.Printf("Error from %s engine: %v", name, err)
		}
	}()
}

// startEngineNoError wraps engine functions that don't return errors.
// This is for engines that handle errors internally or never fail during startup.
func startEngineNoError(app *AppDetails, name string, engineFunc func()) {
	engineWg.Add(1)
	go func() {
		defer engineWg.Done()
		log.Printf("TDNS %s (%s): starting: %s", app.Name, AppTypeToString[app.Type], name)
		engineFunc()
	}()
}

func (conf *Config) MainLoop(ctx context.Context, cancel context.CancelFunc) {
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
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner, AppTypeScanner, AppTypeReporter, AppTypeKdc, AppTypeKrs:
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
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner, AppTypeImr, AppTypeScanner, AppTypeReporter, AppTypeCli, AppTypeKdc, AppTypeKrs:
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
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner, AppTypeScanner:
		// Note that AppTypeAuth and AppTypeAgent feel though into here as well.
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

	// Initialize QueryHandlers map for registration API
	conf.Internal.QueryHandlers = make(map[uint16][]QueryHandlerFunc)
	
	// Copy any handlers registered before MainInit (from global storage)
	globalQueryHandlersMutex.RLock()
	for qtype, handlers := range globalQueryHandlers {
		conf.Internal.QueryHandlers[qtype] = append(conf.Internal.QueryHandlers[qtype], handlers...)
	}
	globalQueryHandlersMutex.RUnlock()

	// Initialize NOTIFY handlers map
	conf.Internal.NotifyHandlers = make(map[uint16][]NotifyHandlerFunc)
	
	// Copy any handlers registered before MainInit (from global storage)
	globalNotifyHandlersMutex.RLock()
	for qtype, handlers := range globalNotifyHandlers {
		conf.Internal.NotifyHandlers[qtype] = append(conf.Internal.NotifyHandlers[qtype], handlers...)
	}
	globalNotifyHandlersMutex.RUnlock()

	// Register default query handlers (default zone-based handler)
	// The default handler is registered with qtype=0, so it catches all queries that aren't handled by other handlers.
	// It's only registered if zones are configured (TDNS-internal check).
	// Note: .server. queries are automatically handled by createAuthDnsHandler() as a fallback before returning REFUSED.
	if err := RegisterDefaultQueryHandlers(conf); err != nil {
		return fmt.Errorf("failed to register default query handlers: %v", err)
	}

	// Create all channels unconditionally to simplify code and reduce conditional complexity.
	// Channels containing pointers have minimal memory overhead, so unused channels are acceptable.
	conf.Internal.APIStopCh = make(chan struct{}) // Used for shutdown coordination
	conf.Internal.BumpZoneCh = make(chan BumperData, 10)
	conf.Internal.DelegationSyncQ = make(chan DelegationSyncRequest, 10)
	conf.Internal.SyncQ = make(chan SyncRequest, 10)
	conf.Internal.MusicSyncQ = make(chan MusicSyncRequest, 10)
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	conf.Internal.NotifyQ = make(chan NotifyRequest, 10)
	conf.Internal.ValidatorCh = make(chan ValidatorRequest, 10)
	conf.Internal.RecursorCh = make(chan ImrRequest, 10)

	// Used by tdns-auth, tdns-agent and tdns-combiner
	conf.Internal.ScannerQ = make(chan ScanRequest, 5)
	conf.Internal.DnsUpdateQ = make(chan DnsUpdateRequest, 100)
	conf.Internal.DnsNotifyQ = make(chan DnsNotifyRequest, 100)
	conf.Internal.AuthQueryQ = make(chan AuthQueryRequest, 100)

	// Only used by tdns-auth
	conf.Internal.ResignQ = make(chan *ZoneData, 10)

	// Create AgentQs unconditionally (even if not used by this app type)
	conf.Internal.AgentQs = &AgentQs{
		Hello:             make(chan *AgentMsgReport, 100),
		Beat:              make(chan *AgentMsgReport, 100),
		Msg:               make(chan *AgentMsgPostPlus, 100),
		Command:           make(chan *AgentMgmtPostPlus, 100),
		DebugCommand:      make(chan *AgentMgmtPostPlus, 100),
		SynchedDataUpdate: make(chan *SynchedDataUpdate, 100),
		SynchedDataCmd:    make(chan *SynchedDataCmd, 100),
	}

	// Create KeyDB channels if KeyDB exists
	if conf.Internal.KeyDB != nil {
		kdb := conf.Internal.KeyDB
		kdb.UpdateQ = make(chan UpdateRequest, 10)
		conf.Internal.UpdateQ = kdb.UpdateQ
		kdb.DeferredUpdateQ = make(chan DeferredUpdate, 10)
		conf.Internal.DeferredUpdateQ = kdb.DeferredUpdateQ
	}

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
	case AppTypeAuth, AppTypeCombiner:
		// ... existing auth/combiner setup ...
	default:
		// ... existing auth/agent/combiner setup ...
	}

	if Globals.Debug {
		log.Printf("*** MainInit: DONE ***")
	}

	return nil
}

// StartCombiner starts subsystems for tdns-combiner
func (conf *Config) StartCombiner(ctx context.Context, apirouter *mux.Router) error {
	startEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })
	startEngineNoError(&Globals.App, "RefreshEngine", func() { RefreshEngine(ctx, conf) })
	startEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf.Internal.NotifyQ) })
	startEngine(&Globals.App, "NotifyHandler", func() error { return NotifyHandler(ctx, conf) })
	startEngine(&Globals.App, "DnsEngine", func() error { return DnsEngine(ctx, conf) })
	return nil
}

// StartImr starts subsystems for tdns-imr
func (conf *Config) StartImr(ctx context.Context, apirouter *mux.Router) error {
	startEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })
	startEngineNoError(&Globals.App, "ValidatorEngine", func() { ValidatorEngine(ctx, conf) })
	startEngine(&Globals.App, "ImrEngine", func() error { return conf.ImrEngine(ctx, false) })
	return nil
}

// StartScanner starts subsystems for tdns-scanner
func (conf *Config) StartScanner(ctx context.Context, apirouter *mux.Router) error {
	startEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })
	startEngine(&Globals.App, "ScannerEngine", func() error { return ScannerEngine(ctx, conf) })
	startEngineNoError(&Globals.App, "ValidatorEngine", func() { ValidatorEngine(ctx, conf) })
	startEngine(&Globals.App, "ImrEngine", func() error { return conf.ImrEngine(ctx, false) })
	return nil
}

// StartAuth starts subsystems for tdns-auth
func (conf *Config) StartAuth(ctx context.Context, apirouter *mux.Router) error {
	startEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })
	startEngineNoError(&Globals.App, "ValidatorEngine", func() { ValidatorEngine(ctx, conf) })

	// In tdns-auth, IMR is active by default unless explicitly set to false
	imrActive := conf.Imr.Active == nil || *conf.Imr.Active
	if imrActive {
		startEngine(&Globals.App, "ImrEngine", func() error { return conf.ImrEngine(ctx, true) })
	} else {
		log.Printf("TDNS %s (%s): NOT starting: imrengine (imrengine.active explicitly set to false)", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	kdb := conf.Internal.KeyDB
	startEngineNoError(&Globals.App, "RefreshEngine", func() { RefreshEngine(ctx, conf) })
	startEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf.Internal.NotifyQ) })
	startEngineNoError(&Globals.App, "AuthQueryEngine", func() { AuthQueryEngine(ctx, conf.Internal.AuthQueryQ) })
	startEngine(&Globals.App, "ScannerEngine", func() error { return ScannerEngine(ctx, conf) })
	startEngine(&Globals.App, "ZoneUpdaterEngine", func() error { return kdb.ZoneUpdaterEngine(ctx) })
	startEngine(&Globals.App, "DeferredUpdaterEngine", func() error { return kdb.DeferredUpdaterEngine(ctx) })
	startEngine(&Globals.App, "UpdateHandler", func() error { return UpdateHandler(ctx, conf) })
	startEngine(&Globals.App, "DelegationSyncher", func() error {
		return kdb.DelegationSyncher(ctx, conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ, conf)
	})
	startEngine(&Globals.App, "NotifyHandler", func() error { return NotifyHandler(ctx, conf) })
	startEngine(&Globals.App, "DnsEngine", func() error { return DnsEngine(ctx, conf) })
	startEngineNoError(&Globals.App, "ResignerEngine", func() { ResignerEngine(ctx, conf.Internal.ResignQ) })
	return nil
}

// StartAgent starts subsystems for tdns-agent
func (conf *Config) StartAgent(ctx context.Context, apirouter *mux.Router) error {
	startEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })

	// In tdns-agent, IMR is active by default unless explicitly set to false
	imrActive := conf.Imr.Active == nil || *conf.Imr.Active
	if imrActive {
		startEngine(&Globals.App, "ImrEngine", func() error { return conf.ImrEngine(ctx, true) })
	} else {
		log.Printf("TDNS %s (%s): NOT starting: imrengine (imrengine.active explicitly set to false)", Globals.App.Name, AppTypeToString[Globals.App.Type])
	}

	kdb := conf.Internal.KeyDB
	startEngineNoError(&Globals.App, "RefreshEngine", func() { RefreshEngine(ctx, conf) })
	startEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf.Internal.NotifyQ) })

	// Agent-specific
	//log.Printf("TDNS %s (%s): starting: hsyncengine, synceddataengine, apidispatcherNG", Globals.App.Name, AppTypeToString[Globals.App.Type])
	startEngineNoError(&Globals.App, "HsyncEngine", func() { HsyncEngine(ctx, conf, conf.Internal.AgentQs) })
	startEngineNoError(&Globals.App, "SynchedDataEngine", func() { conf.SynchedDataEngine(ctx, conf.Internal.AgentQs) })

	syncrtr, err := conf.SetupAgentSyncRouter(ctx)
	if err != nil {
		return fmt.Errorf("Error setting up agent-to-agent sync router: %v", err)
	}

	startEngine(&Globals.App, "APIdispatcherNG", func() error {
		log.Printf("TDNS %s (%s): starting agent-to-agent sync engine", Globals.App.Name, AppTypeToString[Globals.App.Type])
		return APIdispatcherNG(conf, syncrtr, conf.Agent.Api.Addresses.Listen, conf.Agent.Api.CertFile, conf.Agent.Api.KeyFile, conf.Internal.APIStopCh)
	})

	startEngineNoError(&Globals.App, "AuthQueryEngine", func() { AuthQueryEngine(ctx, conf.Internal.AuthQueryQ) })
	startEngine(&Globals.App, "ScannerEngine", func() error { return ScannerEngine(ctx, conf) })
	startEngine(&Globals.App, "ZoneUpdaterEngine", func() error { return kdb.ZoneUpdaterEngine(ctx) })
	startEngine(&Globals.App, "DeferredUpdaterEngine", func() error { return kdb.DeferredUpdaterEngine(ctx) })
	startEngine(&Globals.App, "UpdateHandler", func() error { return UpdateHandler(ctx, conf) })
	startEngine(&Globals.App, "DelegationSyncher", func() error {
		return kdb.DelegationSyncher(ctx, conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ, conf)
	})
	startEngine(&Globals.App, "NotifyHandler", func() error { return NotifyHandler(ctx, conf) })
	startEngine(&Globals.App, "DnsEngine", func() error { return DnsEngine(ctx, conf) })
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
	engineWg.Wait() // Wait for all engines to finish (let's see if this works
	log.Printf("%s: all engines finished", Globals.App.Name)
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}
