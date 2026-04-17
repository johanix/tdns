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
	"github.com/spf13/viper"
)

var engineWg sync.WaitGroup

/*
// buildChunkQueryEndpoint returns "host:port" for the agent's DNS service so the receiver of a NOTIFY(CHUNK) knows where to send the CHUNK query. Prefers Publish so the combiner can reach the agent.
func buildChunkQueryEndpoint(conf *Config) string {
	if conf.MultiProvider == nil {
		return ""
	}
	dns := &conf.MultiProvider.Dns
	port := dns.Port
	if port == 0 {
		port = 53
	}
	var host string
	if len(dns.Addresses.Publish) > 0 {
		host = strings.TrimSpace(dns.Addresses.Publish[0])
	}
	if host == "" && len(dns.Addresses.Listen) > 0 {
		host = strings.TrimSpace(dns.Addresses.Listen[0])
	}
	if host == "" {
		return ""
	}
	// If host already contains a port, use as-is
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}
	*/

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
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeScanner, AppTypeReporter, AppTypeKdc, AppTypeKrs,
		AppTypeMPSigner, AppTypeMPAgent, AppTypeMPCombiner, AppTypeMPAuditor:
		flag.StringVar(&conf.Internal.CfgFile, "config", defaultcfg, "config file path")
		flag.BoolVarP(&Globals.Debug, "debug", "", false, "run in debug mode (may activate dangerous tests)")
		flag.BoolVarP(&Globals.Verbose, "verbose", "v", false, "Verbose mode")
		flag.Parse()
		flag.Usage = func() {
			flag.PrintDefaults()
		}
	case AppTypeImr:
		conf.Internal.CfgFile = defaultcfg
	}
	lgConfig.Debug("MainInit starting", "defaultcfg", defaultcfg, "cfgfile", conf.Internal.CfgFile)
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeImr, AppTypeScanner, AppTypeReporter, AppTypeCli, AppTypeKdc, AppTypeKrs,
		AppTypeMPSigner, AppTypeMPAgent, AppTypeMPCombiner, AppTypeMPAuditor:
		fmt.Printf("*** TDNS %s version %s mode of operation: %q (verbose: %t, debug: %t)\n",
			Globals.App.Name, Globals.App.Version, AppTypeToString[Globals.App.Type], Globals.Verbose, Globals.Debug)
	default:
		return fmt.Errorf("*** TDNS %s: Error: unknown mode of operation: %q",
			Globals.App.Name, Globals.App.Type)
	}
	err := conf.ParseConfig(false) // false = initial config, not reload
	if err != nil {
		return fmt.Errorf("error parsing config %q: %v", conf.Internal.CfgFile, err)
	}
	logfile := viper.GetString("log.file")
	err = SetupLogging(logfile, Conf.Log)
	if err != nil {
		return fmt.Errorf("error setting up logging: %v", err)
	}
	fmt.Printf("Logging to file: %s\n", logfile)
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeScanner:
		kdb := conf.Internal.KeyDB
		if kdb == nil {
			err = conf.InitializeKeyDB()
			if err != nil {
				return fmt.Errorf("error initializing KeyDB: %v", err)
			}
		}
	default:
		lgConfig.Info("not initializing KeyDB", "app", Globals.App.Name, "mode", AppTypeToString[Globals.App.Type])
	}
	err = Globals.Validate()
	if err != nil {
		return fmt.Errorf("error validating TDNS globals: %v", err)
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
		return fmt.Errorf("failed to register default query handlers: %v", err)
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
		kdb.DeferredUpdateQ = make(chan DeferredUpdate, 10)
		conf.Internal.DeferredUpdateQ = kdb.DeferredUpdateQ
	}
	// if Globals.Debug {
	//	log.Printf("*** MainInit: 5 ***")
	// }
	// Parse all configured zones
	all_zones, err := conf.ParseZones(ctx, false) // false = initial load, not reload
	if err != nil {
		return fmt.Errorf("error parsing zones: %v", err)
	}
	// Provide the complete zone list to engines that need cross-zone post-initialization
	conf.Internal.AllZones = all_zones
	// Load dynamic zones from dynamic config file (if configured and included)
	// This must happen after ParseZones so that main config zones take precedence
	if conf.DynamicZones.ConfigFile != "" {
		// Check if dynamic config file is included (warns if not)
		// Note: includedFiles are tracked during ParseConfig, but we don't have access here
		// The warning was already logged during ParseConfig validation
		// For now, we'll try to load it anyway (it may have been included)
		if err := conf.LoadDynamicZoneFiles(ctx); err != nil {
			lgConfig.Warn("failed to load dynamic zones", "err", err)
			// Don't fail startup, just log the warning
		}
	}
	lgConfig.Debug("MainInit complete")
	return nil
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
	StartEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf.Internal.NotifyQ) })
	StartEngineNoError(&Globals.App, "AuthQueryEngine", func() { AuthQueryEngine(ctx, conf.Internal.AuthQueryQ) })
	StartEngine(&Globals.App, "ScannerEngine", func() error { return ScannerEngine(ctx, conf) })
	StartEngine(&Globals.App, "ZoneUpdaterEngine", func() error { return kdb.ZoneUpdaterEngine(ctx) })
	StartEngine(&Globals.App, "DeferredUpdaterEngine", func() error { return kdb.DeferredUpdaterEngine(ctx) })
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
	StartEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf.Internal.NotifyQ) })

	// MP engines (CHUNK, heartbeats, discovery, SDE, leader election, etc.)
	// removed — for MP functionality use tdns-mp/v2/start_agent.go.

	StartEngineNoError(&Globals.App, "AuthQueryEngine", func() { AuthQueryEngine(ctx, conf.Internal.AuthQueryQ) })
	StartEngine(&Globals.App, "ScannerEngine", func() error { return ScannerEngine(ctx, conf) })
	StartEngine(&Globals.App, "ZoneUpdaterEngine", func() error { return kdb.ZoneUpdaterEngine(ctx) })
	StartEngine(&Globals.App, "DeferredUpdaterEngine", func() error { return kdb.DeferredUpdaterEngine(ctx) })
	StartEngine(&Globals.App, "UpdateHandler", func() error { return UpdateHandler(ctx, conf) })
	StartEngine(&Globals.App, "DelegationSyncher", func() error {
		return kdb.DelegationSyncher(ctx, conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ, conf)
	})
	StartEngine(&Globals.App, "NotifyHandler", func() error { return NotifyHandler(ctx, conf) })
	StartEngine(&Globals.App, "DnsEngine", func() error { return DnsEngine(ctx, conf) })
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
