/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	// "flag"
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	flag "github.com/spf13/pflag"
)

var engineWg sync.WaitGroup

// startEngine wraps engine functions in a goroutine with error handling.
// It logs errors if the engine function returns an error, preventing silent failures.
func StartEngine(app *AppDetails, name string, engineFunc func() error) {
	engineWg.Add(1)
	go func() {
		defer engineWg.Done()
		lgConfig.Info("starting engine", "app", app.Name, "mode", AppTypeToString[app.Type], "engine", name)
		if err := engineFunc(); err != nil {
			lgConfig.Error("engine error", "engine", name, "err", err)
		}
	}()
}

// startEngineNoError wraps engine functions that don't return errors.
// This is for engines that handle errors internally or never fail during startup.
func StartEngineNoError(app *AppDetails, name string, engineFunc func()) {
	engineWg.Add(1)
	go func() {
		defer engineWg.Done()
		lgConfig.Info("starting engine", "app", app.Name, "mode", AppTypeToString[app.Type], "engine", name)
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
			lgConfig.Info("mainloop: context cancelled, cleaning up")
			return
		case <-conf.Internal.APIStopCh:
			lgConfig.Info("mainloop: stop command received, cleaning up")
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
	// If defaultcfg is empty, derive it from Globals.App.Name
	if defaultcfg == "" {
		defaultcfg = GetDefaultConfigFile()
		if defaultcfg == "" {
			return fmt.Errorf("cannot determine default config file: Globals.App.Name is not set")
		}
	}
	// --version is accepted by every daemon: it prints the exact
	// version and the algorithms this binary supports (from the
	// in-process registry — no config, DB, or server needed) and exits.
	// Registered on the shared flag set so it works for imr too, which
	// otherwise parses no flags.
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "print version and supported algorithms, then exit")

	// Imr uses the default config file directly. Every other app
	// type accepts flag-driven overrides. This inversion avoids
	// enumerating AppType values defined in downstream packages
	// (tdns-mp, tdns-nm, tdns-es).
	if Globals.App.Type == AppTypeImr {
		conf.Internal.CfgFile = defaultcfg
		flag.Parse() // only --version is registered for imr
	} else {
		flag.StringVar(&conf.Internal.CfgFile, "config", defaultcfg, "config file path")
		flag.BoolVarP(&Globals.Debug, "debug", "", false, "run in debug mode (may activate dangerous tests)")
		flag.BoolVarP(&Globals.Verbose, "verbose", "v", false, "Verbose mode")
		flag.Parse()
		flag.Usage = func() {
			flag.PrintDefaults()
		}
	}
	if showVersion {
		PrintVersionAndExit()
	}
	// Defensive: catch an unset Globals.App.Type. Every binary's
	// main() must set this before calling MainInit.
	if Globals.App.Type == 0 {
		return fmt.Errorf("*** TDNS %s: Error: Globals.App.Type not set",
			Globals.App.Name)
	}
	// Long-running daemons keep the startup banner. CLI prints it
	// only when -v / --verbose is set; otherwise the banner clutters
	// every short command invocation.
	if Globals.App.Type != AppTypeCli || Globals.Verbose {
		fmt.Printf("*** TDNS %s version %s mode of operation: %q (verbose: %t, debug: %t)\n",
			Globals.App.Name, Globals.App.Version, AppTypeToString[Globals.App.Type], Globals.Verbose, Globals.Debug)
	}
	// Set up logging BEFORE ParseConfig so the parse and its hooks have
	// a live logger. SetupLogging reads the log: block directly from the
	// config file (it doesn't resolve includes) and hard-fails if the
	// log: block isn't at the top level — preventing silent fallback to
	// defaults. See tdns/docs/2026-05-27-early-logging-setup.md.
	logConf, err := SetupLogging(conf.Internal.CfgFile)
	if err != nil {
		return fmt.Errorf("error setting up logging: %w", err)
	}
	lgConfig.Debug("MainInit starting", "defaultcfg", defaultcfg, "cfgfile", conf.Internal.CfgFile)
	if Globals.App.Type != AppTypeCli || Globals.Verbose {
		fmt.Printf("Logging to file: %s\n", logConf.File)
	}
	err = conf.ParseConfig(false) // false = initial config, not reload
	if err != nil {
		return fmt.Errorf("error parsing config %q: %w", conf.Internal.CfgFile, err)
	}
	// KeyDB must exist before TSIG load so LoadTsigKeys can sync keys.tsig into
	// TsigKeystore and populate the cache from the DB (Auth/Agent init KeyDB in
	// ParseConfig; Scanner only here).
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeScanner:
		if conf.Internal.KeyDB == nil {
			err = conf.InitializeKeyDB()
			if err != nil {
				return fmt.Errorf("error initializing KeyDB: %w", err)
			}
		}
	default:
		lgConfig.Info("not initializing KeyDB", "app", Globals.App.Name, "mode", AppTypeToString[Globals.App.Type])
	}
	// Build the replication TSIG store before zones are parsed so primary/notify/ACL
	// key names validate against it. Bad keys.tsig entries are non-fatal (skipped).
	if err := conf.LoadTsigKeys(); err != nil {
		lgConfig.Error("TSIG keys: config error (affected keys skipped; zones referencing them are quarantined)", "err", err)
	}
	err = Globals.Validate()
	if err != nil {
		return fmt.Errorf("error validating TDNS globals: %w", err)
	}
	if Globals.App.Type != AppTypeCli || Globals.Verbose {
		fmt.Printf("TDNS %s version %s starting.\n", Globals.App.Name, Globals.App.Version)
	}
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
	// Initialize UPDATE handlers slice
	conf.Internal.UpdateHandlers = make([]UpdateHandlerRegistration, 0)
	// Copy any handlers registered before MainInit (from global storage)
	globalUpdateHandlersMutex.RLock()
	conf.Internal.UpdateHandlers = append(conf.Internal.UpdateHandlers, globalUpdateHandlers...)
	globalUpdateHandlersMutex.RUnlock()
	// Register default query handlers (default zone-based handler)
	// The default handler is registered with qtype=0, so it catches all queries that aren't handled by other handlers.
	// It's only registered if zones are configured (TDNS-internal check).
	// Note: .server. queries are automatically handled by createAuthDnsHandler() as a fallback before returning REFUSED.
	if err := RegisterDefaultQueryHandlers(conf); err != nil {
		return fmt.Errorf("failed to register default query handlers: %w", err)
	}
	// Create all channels unconditionally to simplify code and reduce conditional complexity.
	// Channels containing pointers have minimal memory overhead, so unused channels are acceptable.
	conf.Internal.APIStopCh = make(chan struct{}) // Used for shutdown coordination
	conf.Internal.BumpZoneCh = make(chan BumperData, 10)
	conf.Internal.DelegationSyncQ = make(chan DelegationSyncRequest, 10)
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, max(10, len(conf.Zones)))
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
	// Create KeyDB channels if KeyDB exists
	if conf.Internal.KeyDB != nil {
		kdb := conf.Internal.KeyDB
		kdb.UpdateQ = make(chan UpdateRequest, 50)
		conf.Internal.UpdateQ = kdb.UpdateQ
	}
	// if Globals.Debug {
	//	log.Printf("*** MainInit: 5 ***")
	// }
	// D1: hostname primaries are resolved at REFRESH time (zd.Refresh re-resolves
	// PrimariesConf each cycle), not at parse/load time — so the IMR is no longer
	// primed synchronously here. The per-app StartXxx brings up the ImrEngine
	// goroutine, and the first refresh of a hostname-primary zone resolves once it
	// is up (retrying until then). This removes a boot-time stall on a live
	// root-NS fetch, and a primary that is briefly unresolvable at startup no
	// longer quarantines its zone (it surfaces as a retryable refresh error).

	// Parse all configured zones
	all_zones, _, err := conf.ParseZones(ctx, false) // false = initial load, not reload
	if err != nil {
		return fmt.Errorf("error parsing zones: %w", err)
	}
	// Provide the complete zone list to engines that need cross-zone post-initialization
	conf.Internal.AllZones = all_zones
	// NOTE: dynamic zones are intentionally NOT loaded here. Their enqueue is a
	// blocking send to RefreshZoneCh, which is only drained once RefreshEngine is
	// running — so the load is deferred to StartAuth/StartAgent (after the engine
	// starts) via loadDynamicZonesIfConfigured(). Loading here (pre-engine) would
	// block on a channel already full of static zones, which previously dropped
	// the dynamic zones after a 5s timeout.
	lgConfig.Debug("MainInit complete")
	return nil
}

// loadDynamicZonesIfConfigured loads persisted dynamic zones from the dynamic
// config file (if one is configured) and enqueues each for refresh. It MUST be
// called after RefreshEngine has been started: the enqueue is a blocking send
// (like the static-zone enqueue in ParseZones), so it relies on the engine
// draining RefreshZoneCh. A load failure is logged, not fatal.
func (conf *Config) loadDynamicZonesIfConfigured(ctx context.Context) {
	if conf.DynamicZones.ConfigFile == "" {
		return
	}
	if err := conf.LoadDynamicZoneFiles(ctx); err != nil {
		lgConfig.Warn("failed to load dynamic zones", "err", err)
	}
}

// StartImr starts subsystems for tdns-imr
func (conf *Config) StartImr(ctx context.Context, apirouter *mux.Router) error {
	StartEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })
	StartEngineNoError(&Globals.App, "ValidatorEngine", func() { ValidatorEngine(ctx, conf) })
	StartEngine(&Globals.App, "ImrEngine", func() error { return conf.ImrEngine(ctx, false) })
	return nil
}

// StartScanner starts subsystems for tdns-scanner
func (conf *Config) StartScanner(ctx context.Context, apirouter *mux.Router) error {
	StartEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })
	StartEngine(&Globals.App, "ScannerEngine", func() error { return ScannerEngine(ctx, conf) })
	StartEngineNoError(&Globals.App, "ValidatorEngine", func() { ValidatorEngine(ctx, conf) })
	StartEngine(&Globals.App, "ImrEngine", func() error { return conf.ImrEngine(ctx, false) })
	return nil
}

// StartAuth starts subsystems for tdns-auth
func (conf *Config) StartAuth(ctx context.Context, apirouter *mux.Router) error {
	StartEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })
	StartEngineNoError(&Globals.App, "ValidatorEngine", func() { ValidatorEngine(ctx, conf) })
	// In tdns-auth, IMR is active by default unless explicitly set to false
	imrActive := conf.Imr.Active == nil || *conf.Imr.Active
	if imrActive {
		StartEngine(&Globals.App, "ImrEngine", func() error { return conf.ImrEngine(ctx, true) })
	} else {
		lgConfig.Info("NOT starting imrengine (explicitly set to false)", "app", Globals.App.Name, "mode", AppTypeToString[Globals.App.Type])
	}
	kdb := conf.Internal.KeyDB
	StartEngineNoError(&Globals.App, "RefreshEngine", func() { RefreshEngine(ctx, conf) })
	StartEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf, conf.Internal.NotifyQ) })
	StartEngineNoError(&Globals.App, "AuthQueryEngine", func() { AuthQueryEngine(ctx, conf.Internal.AuthQueryQ) })
	StartEngine(&Globals.App, "ScannerEngine", func() error { return ScannerEngine(ctx, conf) })
	StartEngine(&Globals.App, "ZoneUpdaterEngine", func() error { return kdb.ZoneUpdaterEngine(ctx) })
	StartEngine(&Globals.App, "UpdateHandler", func() error { return UpdateHandler(ctx, conf) })
	StartEngine(&Globals.App, "KeyBootstrapper", func() error { return kdb.KeyBootstrapper(ctx) })
	StartEngine(&Globals.App, "DelegationSyncher", func() error {
		return kdb.DelegationSyncher(ctx, conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ, conf)
	})
	// DNS engines (needed by all auth-like apps including MPSigner)
	StartEngine(&Globals.App, "NotifyHandler", func() error { return NotifyHandler(ctx, conf) })
	StartEngine(&Globals.App, "DnsEngine", func() error { return DnsEngine(ctx, conf) })
	StartEngineNoError(&Globals.App, "ResignerEngine", func() { ResignerEngine(ctx, conf.Internal.ResignQ) })
	StartEngine(&Globals.App, "KeyStateWorker", func() error { return KeyStateWorker(ctx, conf) })

	// RefreshEngine is now running and draining RefreshZoneCh, so persisted
	// dynamic zones can be loaded with a blocking enqueue (no drop).
	conf.loadDynamicZonesIfConfigured(ctx)

	return nil
}

// StartAgent starts subsystems for tdns-agent
func (conf *Config) StartAgent(ctx context.Context, apirouter *mux.Router) error {
	StartEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })
	// In tdns-agent, IMR is active by default unless explicitly set to false
	imrActive := conf.Imr.Active == nil || *conf.Imr.Active
	if imrActive {
		StartEngine(&Globals.App, "ImrEngine", func() error { return conf.ImrEngine(ctx, true) })
	} else {
		lgConfig.Info("NOT starting imrengine (explicitly set to false)", "app", Globals.App.Name, "mode", AppTypeToString[Globals.App.Type])
	}
	kdb := conf.Internal.KeyDB
	StartEngineNoError(&Globals.App, "RefreshEngine", func() { RefreshEngine(ctx, conf) })
	StartEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf, conf.Internal.NotifyQ) })

	// MP engines (CHUNK, heartbeats, discovery, SDE, leader election, etc.)
	// removed — for MP functionality use tdns-mp/v2/start_agent.go.

	StartEngineNoError(&Globals.App, "AuthQueryEngine", func() { AuthQueryEngine(ctx, conf.Internal.AuthQueryQ) })
	StartEngine(&Globals.App, "ScannerEngine", func() error { return ScannerEngine(ctx, conf) })
	StartEngine(&Globals.App, "ZoneUpdaterEngine", func() error { return kdb.ZoneUpdaterEngine(ctx) })
	StartEngine(&Globals.App, "UpdateHandler", func() error { return UpdateHandler(ctx, conf) })
	StartEngine(&Globals.App, "DelegationSyncher", func() error {
		return kdb.DelegationSyncher(ctx, conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ, conf)
	})
	StartEngine(&Globals.App, "NotifyHandler", func() error { return NotifyHandler(ctx, conf) })
	StartEngine(&Globals.App, "DnsEngine", func() error { return DnsEngine(ctx, conf) })

	// RefreshEngine is now running and draining RefreshZoneCh, so persisted
	// dynamic zones can be loaded with a blocking enqueue (no drop).
	conf.loadDynamicZonesIfConfigured(ctx)

	return nil
}

func Shutdowner(conf *Config, msg string) {
	lgConfig.Info("shutting down", "app", Globals.App.Name, "reason", msg)
	fmt.Printf("%s: shutting down: %s\n", Globals.App.Name, msg)
	// Prefer closing APIStopCh once as a broadcast to MainLoop and all listeners
	if conf.Internal.APIStopCh != nil {
		conf.Internal.StopOnce.Do(func() {
			// small delay can help in-flight API responses complete before close is observed
			time.Sleep(200 * time.Millisecond)
			close(conf.Internal.APIStopCh)
		})
	}
	engineWg.Wait() // Wait for all engines to finish (let's see if this works
	lgConfig.Info("all engines finished", "app", Globals.App.Name)
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}
