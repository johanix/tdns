/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	// "flag"

	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/johanix/tdns/v2/agent/transport"
	"github.com/johanix/tdns/v2/crypto"
	"github.com/johanix/tdns/v2/crypto/jose"
)

var engineWg sync.WaitGroup

// buildChunkQueryEndpoint returns "host:port" for the agent's DNS service so the receiver of a NOTIFY(CHUNK) knows where to send the CHUNK query. Prefers Publish so the combiner can reach the agent.
func buildChunkQueryEndpoint(conf *Config) string {
	if conf.Agent == nil {
		return ""
	}
	dns := &conf.Agent.Dns
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

	// If defaultcfg is empty, derive it from Globals.App.Name
	if defaultcfg == "" {
		defaultcfg = GetDefaultConfigFile()
		if defaultcfg == "" {
			return fmt.Errorf("cannot determine default config file: Globals.App.Name is not set")
		}
	}

	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner, AppTypeScanner, AppTypeReporter, AppTypeKdc, AppTypeKrs:
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
		return fmt.Errorf("error parsing config %q: %v", conf.Internal.CfgFile, err)
	}

	logfile := viper.GetString("log.file")
	err = SetupLogging(logfile)
	if err != nil {
		return fmt.Errorf("error setting up logging: %v", err)
	}
	fmt.Printf("Logging to file: %s\n", logfile)

	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner, AppTypeScanner:
		// Note that AppTypeAuth and AppTypeAgent feel though into here as well.
		kdb := conf.Internal.KeyDB
		if kdb == nil {
			err = conf.InitializeKeyDB()
			if err != nil {
				return fmt.Errorf("error initializing KeyDB: %v", err)
			}
		}

	default:
		log.Printf("TDNS %s (%s): not initializing KeyDB", Globals.App.Name, AppTypeToString[Globals.App.Type])
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
			log.Printf("DYNAMIC-ZONES: Warning: Failed to load dynamic zones: %v", err)
			// Don't fail startup, just log the warning
		}
	}

	switch Globals.App.Type {
	case AppTypeAgent:
		if conf.Agent == nil {
			return fmt.Errorf("agent config block is required for agent app type")
		}
		// Setup agent identity and publish records
		err = conf.SetupAgent(all_zones)
		if err != nil {
			return fmt.Errorf("error setting up agent: %v", err)
		}
		// Initialize AgentRegistry for agent mode only
		conf.Internal.AgentRegistry = conf.NewAgentRegistry()
		// Initialize CombinerChunkHandler for CHUNK-based combiner updates (in-process)
		// Use combiner identity from config, or default to "combiner" for backwards compatibility
		combinerID := "combiner"
		if conf.Agent.Combiner != nil && conf.Agent.Combiner.Identity != "" {
			combinerID = conf.Agent.Combiner.Identity
		}
		conf.Internal.CombinerHandler = NewCombinerChunkHandler(combinerID)

		// Initialize HSYNC database tables (peer state, sync operations, confirmations)
		if conf.Internal.KeyDB != nil {
			if err := conf.Internal.KeyDB.InitHsyncTables(); err != nil {
				return fmt.Errorf("InitHsyncTables: %w", err)
			}
			log.Printf("MainInit: HSYNC database tables initialized")
		}

		// Distribution cache for "agent distrib list": keep completed distributions for 5 minutes, then GC purges them; incomplete are never auto-purged
		if conf.Internal.DistributionCache == nil {
			conf.Internal.DistributionCache = NewDistributionCache()
			StartDistributionGC(conf.Internal.DistributionCache, 1*time.Minute)
			log.Printf("MainInit: distribution cache initialized (GC every 1m; completed kept 5m)")
		}

		// Create TransportManager for API + DNS mode with fallback
		controlZone := conf.Agent.Dns.ControlZone
		if controlZone == "" {
			controlZone = conf.Agent.Identity
		}
		chunkMode := conf.Agent.Dns.ChunkMode
		if chunkMode == "" {
			chunkMode = "edns0"
		}
		var chunkStore ChunkPayloadStore
		var chunkQueryEndpoint string
		var chunkQueryEndpointInNotify bool
		if chunkMode == "query" {
			cep := strings.TrimSpace(conf.Agent.Dns.ChunkQueryEndpoint)
			if cep != "include" && cep != "none" {
				return fmt.Errorf("agent.dns.chunk_mode=query requires agent.dns.chunk_query_endpoint to be \"include\" or \"none\" (got %q)", conf.Agent.Dns.ChunkQueryEndpoint)
			}
			chunkQueryEndpointInNotify = (cep == "include")
			chunkStore = NewMemChunkPayloadStore(5 * time.Minute)
			conf.Internal.ChunkPayloadStore = chunkStore
			if err := RegisterChunkQueryHandler(chunkStore); err != nil {
				log.Printf("MainInit: failed to register CHUNK query handler: %v", err)
			} else {
				log.Printf("MainInit: CHUNK query handler registered (chunk_mode=query)")
			}
			// Build CHUNK query endpoint (host:port) so receiver knows where to send CHUNK query; prefer Publish so combiner can reach us
			chunkQueryEndpoint = buildChunkQueryEndpoint(conf)
			if chunkQueryEndpoint == "" {
				log.Printf("MainInit: chunk_mode=query but no agent.dns address/port; CHUNK query endpoint will be empty")
			}
		}

		// Initialize PayloadCrypto for secure CHUNK transport (optional)
		// Config validation already checked that key files exist
		var payloadCrypto *transport.PayloadCrypto
		if strings.TrimSpace(conf.Agent.LongTermJosePrivKey) != "" {
			pc, err := initPayloadCrypto(conf)
			if err != nil {
				return fmt.Errorf("failed to initialize agent crypto: %w", err)
			}
			payloadCrypto = pc
			log.Printf("MainInit: PayloadCrypto initialized (encryption enabled)")
		} else {
			log.Printf("MainInit: Agent crypto not configured - CHUNK payloads will be unencrypted")
		}

		tm := NewTransportManager(&TransportManagerConfig{
			LocalID:                    conf.Agent.Identity,
			ControlZone:                controlZone,
			APITimeout:                 10 * time.Second,
			DNSTimeout:                 5 * time.Second,
			AgentRegistry:              conf.Internal.AgentRegistry,
			AgentQs:                    conf.Internal.AgentQs,
			ChunkMode:                  chunkMode,
			ChunkPayloadStore:          chunkStore,
			ChunkQueryEndpoint:         chunkQueryEndpoint,
			ChunkQueryEndpointInNotify: chunkQueryEndpointInNotify,
			PayloadCrypto:              payloadCrypto,
			DistributionCache:          conf.Internal.DistributionCache,
			SupportedMechanisms:        conf.Agent.SupportedMechanisms,
			CombinerID:                 combinerID,
		})
		conf.Internal.TransportManager = tm
		conf.Internal.AgentRegistry.TransportManager = tm
		log.Printf("MainInit: TransportManager created (control zone: %s, chunk_mode: %s)", controlZone, chunkMode)

		// Register peer agents from static config
		if err := registerPeerAgents(conf, tm); err != nil {
			return fmt.Errorf("failed to register peer agents: %w", err)
		}
	case AppTypeAuth, AppTypeCombiner:
		// ... existing auth/combiner setup ...
		if Globals.App.Type == AppTypeCombiner {
			if conf.Combiner == nil {
				return fmt.Errorf("combiner config block is required for combiner app type")
			}
			chunkMode := strings.TrimSpace(conf.Combiner.ChunkMode)
			if chunkMode == "query" {
				cep := strings.TrimSpace(conf.Combiner.ChunkQueryEndpoint)
				if cep != "include" && cep != "none" {
					return fmt.Errorf("combiner.chunk_mode=query requires combiner.chunk_query_endpoint to be \"include\" or \"none\" (got %q)", conf.Combiner.ChunkQueryEndpoint)
				}
			}
			// Initialize combiner crypto for decrypting agent payloads
			// Config validation already checked that key files exist
			var secureWrapper *transport.SecurePayloadWrapper
			if strings.TrimSpace(conf.Combiner.LongTermJosePrivKey) != "" {
				var err error
				secureWrapper, err = initCombinerCrypto(conf)
				if err != nil {
					return fmt.Errorf("failed to initialize combiner crypto: %w", err)
				}
				log.Printf("MainInit: Combiner crypto initialized for decrypting agent payloads")
			} else {
				log.Printf("MainInit: Combiner crypto not configured - encrypted payloads will be rejected")
			}
			// Register CHUNK handler with combiner's identity from config
			if conf.Combiner.Identity == "" {
				return fmt.Errorf("combiner.identity is required in config")
			}
			if err := RegisterCombinerChunkHandler(conf.Combiner.Identity, secureWrapper); err != nil {
				return fmt.Errorf("RegisterCombinerChunkHandler: %w", err)
			}
			log.Printf("MainInit: Combiner CHUNK handler registered for identity %s", conf.Combiner.Identity)
			Globals.CombinerConf = conf.Combiner
			if conf.Combiner.AddSignature {
				log.Printf("MainInit: Combiner signature TXT enabled")
			}
		}
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

	// Register CHUNK NOTIFY handler and start incoming DNS message router (must be before NotifyHandler)
	if conf.Internal.TransportManager != nil {
		if err := conf.Internal.TransportManager.RegisterChunkNotifyHandler(); err != nil {
			log.Printf("StartAgent: failed to register CHUNK NOTIFY handler: %v", err)
		} else {
			conf.Internal.TransportManager.StartIncomingMessageRouter(ctx)
		}
	}

	// Initialize combiner as a virtual peer so HsyncEngine can manage heartbeats
	if err := conf.Internal.AgentRegistry.InitializeCombinerAsPeer(conf); err != nil {
		log.Printf("StartAgent: WARNING: Failed to initialize combiner as peer: %v", err)
		log.Printf("StartAgent: Continuing without combiner heartbeat monitoring")
	}

	// Start the reliable message queue (must be after combiner peer initialization)
	if conf.Internal.TransportManager != nil {
		conf.Internal.TransportManager.StartReliableQueue(ctx)
	}

	// Agent-specific
	//log.Printf("TDNS %s (%s): starting: hsyncengine, synceddataengine, apidispatcherNG", Globals.App.Name, AppTypeToString[Globals.App.Type])
	startEngineNoError(&Globals.App, "HsyncEngine", func() { HsyncEngine(ctx, conf, conf.Internal.AgentQs) })
	startEngineNoError(&Globals.App, "DiscoveryRetrierNG", func() {
		conf.Internal.AgentRegistry.DiscoveryRetrierNG(ctx)
	})
	startEngineNoError(&Globals.App, "SynchedDataEngine", func() { conf.SynchedDataEngine(ctx, conf.Internal.AgentQs) })

	syncrtr, err := conf.SetupAgentSyncRouter(ctx)
	if err != nil {
		return fmt.Errorf("error setting up agent-to-agent sync router: %v", err)
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
	log.Printf("%s: all engines finished", Globals.App.Name)
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}

// initPayloadCrypto initializes PayloadCrypto from the agent config.
// Loads the local JOSE private key and the combiner's public key (if configured).
func initPayloadCrypto(conf *Config) (*transport.PayloadCrypto, error) {
	if conf.Agent == nil {
		return nil, fmt.Errorf("agent config is not set")
	}

	// Use JOSE backend for key operations
	backend := jose.NewBackend()

	// Load local private key (trim path so trailing whitespace/newlines from config do not cause "file not found")
	privKeyPath := strings.TrimSpace(conf.Agent.LongTermJosePrivKey)
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("private key file not found: %q: %w", privKeyPath, err)
		}
		return nil, fmt.Errorf("read private key %q: %w", privKeyPath, err)
	}
	privKeyData = StripKeyFileComments(privKeyData)

	privKey, err := backend.ParsePrivateKey(privKeyData)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// Derive public key from private key
	joseBackend, ok := backend.(*jose.Backend)
	if !ok {
		return nil, fmt.Errorf("backend is not JOSE")
	}
	pubKey, err := joseBackend.PublicFromPrivate(privKey)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	// Create PayloadCrypto instance
	pc, err := transport.NewPayloadCrypto(&transport.PayloadCryptoConfig{
		Backend: backend.(crypto.Backend),
		Enabled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("create PayloadCrypto: %w", err)
	}

	// Set local keys
	pc.SetLocalKeys(privKey, pubKey)
	log.Printf("initPayloadCrypto: Loaded local JOSE key from %s", privKeyPath)

	// Load combiner's public key if configured
	if conf.Agent.Combiner != nil && strings.TrimSpace(conf.Agent.Combiner.LongTermJosePubKey) != "" {
		combinerPubKeyPath := strings.TrimSpace(conf.Agent.Combiner.LongTermJosePubKey)
		combinerPubKeyData, err := os.ReadFile(combinerPubKeyPath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("initPayloadCrypto: combiner public key file not found %q: %v (combiner encryption disabled)", combinerPubKeyPath, err)
			} else {
				log.Printf("initPayloadCrypto: failed to read combiner public key %q: %v (combiner encryption disabled)", combinerPubKeyPath, err)
			}
		} else {
			combinerPubKeyData = StripKeyFileComments(combinerPubKeyData)
			combinerPubKey, err := backend.ParsePublicKey(combinerPubKeyData)
			if err != nil {
				log.Printf("initPayloadCrypto: failed to parse combiner public key: %v (combiner encryption disabled)", err)
			} else {
				// Add combiner as peer for both encryption and verification
				pc.AddPeerKey("combiner", combinerPubKey)
				pc.AddPeerVerificationKey("combiner", combinerPubKey)
				log.Printf("initPayloadCrypto: Loaded combiner public key from %s", combinerPubKeyPath)
			}
		}
	}

	// DNS-39: Peer keys come from DNS discovery, not config files
	// Old agent.peers map with embedded keys is no longer supported
	if len(conf.Agent.AuthorizedPeers) > 0 {
		log.Printf("initPayloadCrypto: Using agent.authorized_peers - peer keys will be discovered via DNS")
	} else {
		log.Printf("initPayloadCrypto: No agent.authorized_peers configured - no peer crypto available")
	}

	return pc, nil
}

// initCombinerCrypto initializes crypto for the combiner to decrypt agent payloads.
// Returns a SecurePayloadWrapper configured with the combiner's private key and agent's public key.
func initCombinerCrypto(conf *Config) (*transport.SecurePayloadWrapper, error) {
	// Use the JOSE backend
	backend := jose.NewBackend()

	// Load combiner's private key (trim path so trailing whitespace/newlines from config do not cause "file not found")
	privKeyPath := strings.TrimSpace(conf.Combiner.LongTermJosePrivKey)
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("combiner private key file not found: %q: %w", privKeyPath, err)
		}
		return nil, fmt.Errorf("failed to read combiner private key %q: %w", privKeyPath, err)
	}
	privKeyData = StripKeyFileComments(privKeyData)
	localPrivKey, err := backend.ParsePrivateKey(privKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse combiner private key: %w", err)
	}
	log.Printf("initCombinerCrypto: Loaded combiner private key from %s", privKeyPath)

	// Derive public key from private key
	joseBackend, ok := backend.(*jose.Backend)
	if !ok {
		return nil, fmt.Errorf("backend is not JOSE")
	}
	localPubKey, err := joseBackend.PublicFromPrivate(localPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Load agent's public key for signature verification
	if conf.Combiner.Agent == nil || strings.TrimSpace(conf.Combiner.Agent.LongTermJosePubKey) == "" {
		return nil, fmt.Errorf("combiner.agent.long_term_jose_pub_key not configured")
	}
	agentPubKeyPath := strings.TrimSpace(conf.Combiner.Agent.LongTermJosePubKey)
	agentPubKeyData, err := os.ReadFile(agentPubKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("agent public key file not found: %q: %w", agentPubKeyPath, err)
		}
		return nil, fmt.Errorf("failed to read agent public key %q: %w", agentPubKeyPath, err)
	}
	agentPubKeyData = StripKeyFileComments(agentPubKeyData)
	agentVerifyKey, err := backend.ParsePublicKey(agentPubKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse agent public key: %w", err)
	}
	log.Printf("initCombinerCrypto: Loaded agent public key from %s", agentPubKeyPath)

	// Create PayloadCrypto instance using the generic transport infrastructure
	pc, err := transport.NewPayloadCrypto(&transport.PayloadCryptoConfig{
		Backend: backend.(crypto.Backend),
		Enabled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create PayloadCrypto: %w", err)
	}

	// Set local keys for decryption
	pc.SetLocalKeys(localPrivKey, localPubKey)

	// Add agent as peer for verification (agent sends to combiner, combiner verifies)
	pc.AddPeerKey("agent", agentVerifyKey)
	pc.AddPeerVerificationKey("agent", agentVerifyKey)

	return transport.NewSecurePayloadWrapper(pc), nil
}

// registerPeerAgents registers peer agents from the static config into the TransportManager.
//
// DNS-39: Peer addresses come from DNS discovery, not static config.
// The old agent.peers map with embedded addresses is no longer supported.
func registerPeerAgents(conf *Config, tm *TransportManager) error {
	if conf.Agent == nil {
		return nil // No agent config
	}

	// DNS-39: All peer addresses come from DNS discovery
	if len(conf.Agent.AuthorizedPeers) > 0 {
		log.Printf("registerPeerAgents: Using agent.authorized_peers - peer addresses will be discovered via DNS")
	} else {
		log.Printf("registerPeerAgents: No agent.authorized_peers configured - no peers available")
	}

	return nil
}
