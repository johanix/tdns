/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	// "flag"
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/johanix/tdns/v2/agent/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/crypto/jose"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

var engineWg sync.WaitGroup

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

// startEngine wraps engine functions in a goroutine with error handling.
// It logs errors if the engine function returns an error, preventing silent failures.
func startEngine(app *AppDetails, name string, engineFunc func() error) {
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
func startEngineNoError(app *AppDetails, name string, engineFunc func()) {
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
	lgConfig.Debug("MainInit starting", "defaultcfg", defaultcfg, "cfgfile", conf.Internal.CfgFile)
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner, AppTypeImr, AppTypeScanner, AppTypeReporter, AppTypeCli, AppTypeKdc, AppTypeKrs:
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
	conf.Internal.SyncQ = make(chan SyncRequest, 10)
	conf.Internal.MusicSyncQ = make(chan MusicSyncRequest, 10)
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
	// Create MsgQs unconditionally (even if not used by this app type)
	conf.Internal.MsgQs = &MsgQs{
		Hello:             make(chan *AgentMsgReport, 100),
		Beat:              make(chan *AgentMsgReport, 100),
		Ping:              make(chan *AgentMsgReport, 100),
		Msg:               make(chan *AgentMsgPostPlus, 100),
		Command:           make(chan *AgentMgmtPostPlus, 100),
		DebugCommand:      make(chan *AgentMgmtPostPlus, 100),
		SynchedDataUpdate: make(chan *SynchedDataUpdate, 100),
		SynchedDataCmd:    make(chan *SynchedDataCmd, 100),
		Confirmation:      make(chan *ConfirmationDetail, 100),
		KeystateInventory: make(chan *KeystateInventoryMsg, 10),
		KeystateSignal:    make(chan *KeystateSignalMsg, 10),
		EditsResponse:     make(chan *EditsResponseMsg, 10),
		ConfigResponse:    make(chan *ConfigResponseMsg, 10),
		AuditResponse:     make(chan *AuditResponseMsg, 10),
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
			lgConfig.Warn("failed to load dynamic zones", "err", err)
			// Don't fail startup, just log the warning
		}
	}
	switch Globals.App.Type {
	case AppTypeAgent:
		if conf.MultiProvider == nil {
			return fmt.Errorf("agent config block is required for agent app type")
		}
		// Setup agent identity and publish records
		err = conf.SetupAgent(all_zones)
		if err != nil {
			return fmt.Errorf("error setting up agent: %v", err)
		}
		// Initialize AgentRegistry for agent mode only
		conf.Internal.AgentRegistry = conf.NewAgentRegistry()
		// Initialize CombinerState for in-process combiner updates
		// Use combiner identity from config, or default to "combiner"
		combinerID := "combiner"
		if conf.MultiProvider.Combiner != nil && conf.MultiProvider.Combiner.Identity != "" {
			combinerID = dns.Fqdn(conf.MultiProvider.Combiner.Identity)
			// Inject combiner into authorized_peers so IsPeerAuthorized() accepts it
			conf.MultiProvider.AuthorizedPeers = append(conf.MultiProvider.AuthorizedPeers, combinerID)
			lgConfig.Info("added combiner to authorized_peers", "combiner", combinerID)
		}
		conf.Internal.CombinerState = &CombinerState{
			ErrorJournal: NewErrorJournal(1000, 24*time.Hour),
		}
		_ = combinerID // used above for authorized_peers injection
		// Initialize HSYNC database tables (peer state, sync operations, confirmations)
		if conf.Internal.KeyDB != nil {
			if err := conf.Internal.KeyDB.InitHsyncTables(); err != nil {
				return fmt.Errorf("InitHsyncTables: %w", err)
			}
			lgConfig.Info("HSYNC database tables initialized")
		}
		// Distribution cache for "agent distrib list": keep completed distributions for 5 minutes, then GC purges them; incomplete are never auto-purged
		if conf.Internal.DistributionCache == nil {
			conf.Internal.DistributionCache = NewDistributionCache()
			StartDistributionGC(conf.Internal.DistributionCache, 1*time.Minute, conf.Internal.StopCh)
			lgConfig.Info("distribution cache initialized (GC every 1m, completed kept 5m)")
		}
		// Create TransportManager for API + DNS mode with fallback
		controlZone := conf.MultiProvider.Dns.ControlZone
		if controlZone == "" {
			controlZone = conf.MultiProvider.Identity
		}
		chunkMode := conf.MultiProvider.Dns.ChunkMode
		if chunkMode == "" {
			chunkMode = "edns0"
		}
		var chunkStore ChunkPayloadStore
		var chunkQueryEndpoint string
		var chunkQueryEndpointInNotify bool
		if chunkMode == "query" {
			cep := strings.TrimSpace(conf.MultiProvider.Dns.ChunkQueryEndpoint)
			if cep != "include" && cep != "none" {
				return fmt.Errorf("agent.dns.chunk_mode=query requires agent.dns.chunk_query_endpoint to be \"include\" or \"none\" (got %q)", conf.MultiProvider.Dns.ChunkQueryEndpoint)
			}
			chunkQueryEndpointInNotify = (cep == "include")
			chunkStore = NewMemChunkPayloadStore(5 * time.Minute)
			conf.Internal.ChunkPayloadStore = chunkStore
			if err := RegisterChunkQueryHandler(chunkStore); err != nil {
				lgConfig.Error("failed to register CHUNK query handler", "err", err)
			} else {
				lgConfig.Info("CHUNK query handler registered", "chunkMode", "query")
			}
			// Build CHUNK query endpoint (host:port) so receiver knows where to send CHUNK query; prefer Publish so combiner can reach us
			chunkQueryEndpoint = buildChunkQueryEndpoint(conf)
			if chunkQueryEndpoint == "" {
				lgConfig.Warn("chunk_mode=query but no agent.dns address/port, CHUNK query endpoint will be empty")
			}
		}
		// Initialize PayloadCrypto for secure CHUNK transport (optional)
		// Config validation already checked that key files exist
		var payloadCrypto *transport.PayloadCrypto
		if strings.TrimSpace(conf.MultiProvider.LongTermJosePrivKey) != "" {
			pc, err := initPayloadCrypto(conf)
			if err != nil {
				return fmt.Errorf("failed to initialize agent crypto: %w", err)
			}
			payloadCrypto = pc
			lgConfig.Info("PayloadCrypto initialized (encryption enabled)")
		} else {
			lgConfig.Info("agent crypto not configured, CHUNK payloads will be unencrypted")
		}
		// Extract signer peer config for KEYSTATE signaling (Phase 6)
		var signerID, signerAddress string
		if conf.MultiProvider.Signer != nil {
			signerID = dns.Fqdn(conf.MultiProvider.Signer.Identity)
			signerAddress = conf.MultiProvider.Signer.Address
			lgConfig.Info("signer peer configured", "identity", signerID, "address", signerAddress)
		}
		tm := NewTransportManager(&TransportManagerConfig{
			LocalID:                    dns.Fqdn(conf.MultiProvider.Identity),
			ControlZone:                dns.Fqdn(controlZone),
			APITimeout:                 10 * time.Second,
			DNSTimeout:                 5 * time.Second,
			AgentRegistry:              conf.Internal.AgentRegistry,
			MsgQs:                      conf.Internal.MsgQs,
			ChunkMode:                  chunkMode,
			ChunkPayloadStore:          chunkStore,
			ChunkQueryEndpoint:         chunkQueryEndpoint,
			ChunkQueryEndpointInNotify: chunkQueryEndpointInNotify,
			ChunkMaxSize:               conf.MultiProvider.Dns.ChunkMaxSize,
			PayloadCrypto:              payloadCrypto,
			DistributionCache:          conf.Internal.DistributionCache,
			SupportedMechanisms:        conf.MultiProvider.SupportedMechanisms,
			CombinerID:                 combinerID,
			SignerID:                   signerID,
			SignerAddress:              signerAddress,
			AuthorizedPeers: func() []string {
				var peers []string
				for _, p := range conf.MultiProvider.AuthorizedPeers {
					peers = append(peers, dns.Fqdn(p))
				}
				if conf.MultiProvider.Combiner != nil && conf.MultiProvider.Combiner.Identity != "" {
					peers = append(peers, dns.Fqdn(conf.MultiProvider.Combiner.Identity))
				}
				if conf.MultiProvider.Signer != nil && conf.MultiProvider.Signer.Identity != "" {
					peers = append(peers, dns.Fqdn(conf.MultiProvider.Signer.Identity))
				}
				return peers
			},
			MessageRetention: func(operation string) int {
				return conf.MultiProvider.Dns.MessageRetention.GetRetentionForMessageType(operation)
			},
			GetImrEngine:   func() *Imr { return conf.Internal.ImrEngine },
			ClientCertFile: conf.MultiProvider.Api.CertFile,
			ClientKeyFile:  conf.MultiProvider.Api.KeyFile,
		})
		conf.Internal.TransportManager = tm
		conf.Internal.AgentRegistry.TransportManager = tm
		lgConfig.Info("TransportManager created", "controlZone", controlZone, "chunkMode", chunkMode)
		// Register peer agents from static config
		if err := registerPeerAgents(conf, tm); err != nil {
			return fmt.Errorf("failed to register peer agents: %w", err)
		}
	case AppTypeAuth, AppTypeCombiner:
		// Auth: initialize TransportManager for multi-provider DNSSEC (only when multi-provider.active)
		if Globals.App.Type == AppTypeAuth && conf.MultiProvider != nil && conf.MultiProvider.Active {
			mp := conf.MultiProvider
			if mp.Identity == "" {
				return fmt.Errorf("multi-provider.identity is required when multi-provider.active is true")
			}
			if len(mp.Agents) == 0 {
				return fmt.Errorf("multi-provider.agents is required when multi-provider.active is true")
			}
			// Initialize PayloadCrypto for secure CHUNK transport (optional)
			var signerPayloadCrypto *transport.PayloadCrypto
			if strings.TrimSpace(mp.LongTermJosePrivKey) != "" {
				pc, err := initSignerCrypto(conf)
				if err != nil {
					return fmt.Errorf("failed to initialize signer crypto: %w", err)
				}
				signerPayloadCrypto = pc
				lgConfig.Info("signer PayloadCrypto initialized (encryption enabled)")
			} else {
				lgConfig.Info("signer crypto not configured, CHUNK payloads will be unencrypted")
			}
			// Initialize distribution cache for outbound tracking
			if conf.Internal.DistributionCache == nil {
				conf.Internal.DistributionCache = NewDistributionCache()
				StartDistributionGC(conf.Internal.DistributionCache, 1*time.Minute, conf.Internal.StopCh)
				lgConfig.Info("signer distribution cache initialized")
			}
			// Create TransportManager for signer↔agent communication.
			// Created before the router so it can serve as the Authorizer.
			chunkMode := strings.TrimSpace(mp.ChunkMode)
			if chunkMode == "" {
				chunkMode = "edns0"
			}
			controlZone := dns.Fqdn(mp.Identity)
			tm := NewTransportManager(&TransportManagerConfig{
				LocalID:             dns.Fqdn(mp.Identity),
				ControlZone:         controlZone,
				APITimeout:          10 * time.Second,
				DNSTimeout:          5 * time.Second,
				ChunkMode:           chunkMode,
				ChunkMaxSize:        mp.ChunkMaxSize,
				PayloadCrypto:       signerPayloadCrypto,
				DistributionCache:   conf.Internal.DistributionCache,
				SupportedMechanisms: []string{"dns"},
				MsgQs:               conf.Internal.MsgQs,
				AuthorizedPeers: func() []string {
					var peers []string
					for _, a := range mp.Agents {
						if a != nil && a.Identity != "" {
							peers = append(peers, dns.Fqdn(a.Identity))
						}
					}
					return peers
				},
			})
			conf.Internal.TransportManager = tm
			lgConfig.Info("signer TransportManager created", "identity", dns.Fqdn(mp.Identity), "chunkMode", chunkMode)
			// Create SecurePayloadWrapper for decrypting incoming CHUNK payloads
			var signerSecureWrapper *transport.SecurePayloadWrapper
			if signerPayloadCrypto != nil {
				signerSecureWrapper = transport.NewSecurePayloadWrapper(signerPayloadCrypto)
			}
			// Register CHUNK handler first (router set later via SetRouter)
			signerState, err := RegisterSignerChunkHandler(mp.Identity, signerSecureWrapper)
			if err != nil {
				return fmt.Errorf("RegisterSignerChunkHandler: %w", err)
			}
			conf.Internal.CombinerState = signerState
			lgConfig.Info("signer CHUNK handler registered", "identity", mp.Identity)
			// Wire chunk handler into TM so StartIncomingMessageRouter can route messages
			tm.ChunkHandler = signerState.ChunkHandler()
			// Initialize signer router with TM as authorizer and IncomingChan for message routing
			signerRouter := transport.NewDNSMessageRouter()
			signerRouterCfg := &transport.SignerRouterConfig{
				Authorizer:       tm,
				PeerRegistry:     tm.PeerRegistry,
				AllowUnencrypted: true,
				IncomingChan:     signerState.ChunkHandler().IncomingChan,
			}
			if signerPayloadCrypto != nil {
				signerRouterCfg.PayloadCrypto = signerPayloadCrypto
				signerRouterCfg.AllowUnencrypted = false
			}
			if err := transport.InitializeSignerRouter(signerRouter, signerRouterCfg); err != nil {
				return fmt.Errorf("InitializeSignerRouter: %w", err)
			}
			signerState.SetRouter(signerRouter)
			lgConfig.Info("signer router initialized with authorization and message routing middleware")
			// Register agent peers in the TransportManager
			for _, agentConf := range mp.Agents {
				if agentConf.Identity == "" {
					return fmt.Errorf("multi-provider.agents: entry missing identity")
				}
				peerID := dns.Fqdn(agentConf.Identity)
				agentPeer := transport.NewPeer(peerID)
				agentPeer.SetState(transport.PeerStateKnown, "configured")
				if agentConf.Address != "" {
					host, portStr, err := net.SplitHostPort(agentConf.Address)
					if err != nil {
						return fmt.Errorf("multi-provider.agents: invalid address %q for %s: %w", agentConf.Address, peerID, err)
					}
					port, err := strconv.Atoi(portStr)
					if err != nil {
						return fmt.Errorf("multi-provider.agents: invalid port in %q for %s: %w", agentConf.Address, peerID, err)
					}
					agentPeer.SetDiscoveryAddress(&transport.Address{
						Host:      host,
						Port:      uint16(port),
						Transport: "udp",
					})
				}
				if agentConf.ApiBaseUrl != "" {
					agentPeer.APIEndpoint = agentConf.ApiBaseUrl
				}
				if err := tm.PeerRegistry.Add(agentPeer); err != nil {
					return fmt.Errorf("failed to register agent peer %s: %w", peerID, err)
				}
				lgConfig.Info("registered agent peer", "peer", peerID, "address", agentConf.Address)
			}
		}
		if Globals.App.Type == AppTypeCombiner {
			if conf.MultiProvider == nil {
				return fmt.Errorf("multi-provider config block is required for combiner app type")
			}
			// Initialize only the combiner edit tables (not the full HSYNC schema)
			if conf.Internal.KeyDB != nil {
				if err := conf.Internal.KeyDB.InitCombinerEditTables(); err != nil {
					return fmt.Errorf("InitCombinerEditTables: %w", err)
				}
				lgConfig.Info("combiner edit tables initialized")
			}
			chunkMode := strings.TrimSpace(conf.MultiProvider.ChunkMode)
			if chunkMode == "query" {
				cep := strings.TrimSpace(conf.MultiProvider.ChunkQueryEndpoint)
				if cep != "include" && cep != "none" {
					return fmt.Errorf("multi-provider.chunk_mode=query requires multi-provider.chunk_query_endpoint to be \"include\" or \"none\" (got %q)", conf.MultiProvider.ChunkQueryEndpoint)
				}
			}
			// Initialize combiner crypto for decrypting agent payloads
			// Config validation already checked that key files exist
			var secureWrapper *transport.SecurePayloadWrapper
			if strings.TrimSpace(conf.MultiProvider.LongTermJosePrivKey) != "" {
				var err error
				secureWrapper, err = initCombinerCrypto(conf)
				if err != nil {
					return fmt.Errorf("failed to initialize combiner crypto: %w", err)
				}
				lgConfig.Info("combiner crypto initialized for decrypting agent payloads")
			} else {
				lgConfig.Info("combiner crypto not configured, encrypted payloads will be rejected")
			}
			// Register CHUNK handler with combiner's identity from config
			if conf.MultiProvider.Identity == "" {
				return fmt.Errorf("multi-provider.identity is required in config")
			}
			combinerState, err := RegisterCombinerChunkHandler(conf.MultiProvider.Identity, secureWrapper)
			if err != nil {
				return fmt.Errorf("RegisterCombinerChunkHandler: %w", err)
			}
			combinerState.ProtectedNamespaces = conf.MultiProvider.ProtectedNamespaces
			if len(combinerState.ProtectedNamespaces) > 0 {
				lgConfig.Info("combiner protected namespaces", "namespaces", combinerState.ProtectedNamespaces)
			}
			conf.Internal.CombinerState = combinerState
			lgConfig.Info("combiner CHUNK handler registered", "identity", conf.MultiProvider.Identity)
			// Initialize distribution cache for combiner outbound tracking
			if conf.Internal.DistributionCache == nil {
				conf.Internal.DistributionCache = NewDistributionCache()
				StartDistributionGC(conf.Internal.DistributionCache, 1*time.Minute, conf.Internal.StopCh)
				lgConfig.Info("combiner distribution cache initialized")
			}
			// Create TransportManager for combiner.
			// Created before the router so it can serve as the Authorizer.
			var combinerPayloadCrypto *transport.PayloadCrypto
			if secureWrapper != nil {
				combinerPayloadCrypto = secureWrapper.GetCrypto()
			}
			if chunkMode == "" {
				chunkMode = "edns0"
			}
			tm := NewTransportManager(&TransportManagerConfig{
				LocalID:             dns.Fqdn(conf.MultiProvider.Identity),
				ControlZone:         dns.Fqdn(conf.MultiProvider.Identity),
				DNSTimeout:          5 * time.Second,
				APITimeout:          10 * time.Second,
				ChunkMode:           chunkMode,
				ChunkMaxSize:        conf.MultiProvider.ChunkMaxSize,
				PayloadCrypto:       combinerPayloadCrypto,
				DistributionCache:   conf.Internal.DistributionCache,
				SupportedMechanisms: []string{"dns"},
				MsgQs:               conf.Internal.MsgQs,
				AuthorizedPeers: func() []string {
					var peers []string
					for _, a := range conf.MultiProvider.Agents {
						if a != nil && a.Identity != "" {
							peers = append(peers, dns.Fqdn(a.Identity))
						}
					}
					return peers
				},
			})
			conf.Internal.TransportManager = tm
			// Register combiner agent peers in TransportManager's PeerRegistry
			for _, agentConf := range conf.MultiProvider.Agents {
				if agentConf.Identity == "" {
					return fmt.Errorf("multi-provider.agents: entry missing identity")
				}
				peerID := dns.Fqdn(agentConf.Identity)
				agentPeer := transport.NewPeer(peerID)
				agentPeer.SetState(transport.PeerStateKnown, "configured")
				if agentConf.Address != "" {
					host, portStr, parseErr := net.SplitHostPort(agentConf.Address)
					if parseErr != nil {
						return fmt.Errorf("multi-provider.agents: invalid address %q for %s: %w", agentConf.Address, peerID, parseErr)
					}
					port, parseErr := strconv.Atoi(portStr)
					if parseErr != nil {
						return fmt.Errorf("multi-provider.agents: invalid port in %q for %s: %w", agentConf.Address, peerID, parseErr)
					}
					agentPeer.SetDiscoveryAddress(&transport.Address{
						Host:      host,
						Port:      uint16(port),
						Transport: "udp",
					})
				}
				if agentConf.ApiBaseUrl != "" {
					agentPeer.APIEndpoint = agentConf.ApiBaseUrl
					agentPeer.PreferredTransport = "API"
				} else {
					agentPeer.PreferredTransport = "DNS"
				}
				if addErr := tm.PeerRegistry.Add(agentPeer); addErr != nil {
					return fmt.Errorf("failed to register combiner agent peer %s: %w", peerID, addErr)
				}
				lgConfig.Info("combiner registered agent peer", "peer", peerID, "address", agentConf.Address, "transport", agentPeer.PreferredTransport)
			}
			lgConfig.Info("combiner TransportManager initialized", "agentPeers", len(conf.MultiProvider.Agents))
			// Wire GetPeerAddress callback for chunk_mode=query fallback (uses TM PeerRegistry)
			combinerState.SetGetPeerAddress(func(senderID string) (string, bool) {
				peer, ok := tm.PeerRegistry.Get(senderID)
				if !ok || peer.CurrentAddress() == nil {
					return "", false
				}
				addr := peer.CurrentAddress()
				return fmt.Sprintf("%s:%d", addr.Host, addr.Port), true
			})
			// Wire chunk handler into TM so StartIncomingMessageRouter can route messages
			tm.ChunkHandler = combinerState.ChunkHandler()
			// Initialize combiner router with handler closures and authorization
			combinerRouter := transport.NewDNSMessageRouter()
			combinerRouterCfg := &transport.CombinerRouterConfig{
				Authorizer:   tm,
				PeerRegistry: tm.PeerRegistry,
				HandleUpdate: NewCombinerSyncHandler(),
				IncomingChan: combinerState.ChunkHandler().IncomingChan,
			}
			// Add crypto middleware if secure wrapper is available
			if combinerPayloadCrypto != nil {
				combinerRouterCfg.PayloadCrypto = combinerPayloadCrypto
			}
			if err := transport.InitializeCombinerRouter(combinerRouter, combinerRouterCfg); err != nil {
				return fmt.Errorf("InitializeCombinerRouter: %w", err)
			}
			combinerState.SetRouter(combinerRouter)
			lgConfig.Info("combiner router initialized with authorization middleware")
			if conf.MultiProvider.AddSignature {
				lgConfig.Info("combiner signature TXT enabled")
			}
		}
	default:
		// ... existing auth/agent/combiner setup ...
	}
	lgConfig.Debug("MainInit complete")
	return nil
}

// StartCombiner starts subsystems for tdns-combiner
func (conf *Config) StartCombiner(ctx context.Context, apirouter *mux.Router) error {
	// Attach OnFirstLoad callbacks to zone stubs created by ParseZones.
	// Stubs already exist in Zones with FirstZoneLoad=true.
	kdb := conf.Internal.KeyDB
	for _, zoneName := range conf.Internal.AllZones {
		zd, exists := Zones.Get(zoneName)
		if !exists {
			lgConfig.Error("zone stub not found, skipping callback attachment", "zone", zoneName)
			continue
		}
		if kdb != nil {
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *ZoneData) {
				if !zd.Options[OptMultiProvider] {
					return
				}
				// Set PersistContributions callback
				if zd.PersistContributions == nil && zd.KeyDB != nil {
					zd.PersistContributions = zd.KeyDB.SaveContributions
					lgConfig.Info("PersistContributions callback set", "zone", zd.ZoneName)
				}
				// Hydrate AgentContributions from persistent storage
				if zd.AgentContributions == nil && zd.KeyDB != nil {
					allContribs, err := zd.KeyDB.LoadAllContributions()
					if err != nil {
						lgConfig.Error("failed to load contributions snapshot", "zone", zd.ZoneName, "err", err)
						return
					}
					if zoneContribs, ok := allContribs[zd.ZoneName]; ok {
						zd.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
						for senderID, ownerMap := range zoneContribs {
							zd.AgentContributions[senderID] = ownerMap
						}
						zd.rebuildCombinerData()
						lgConfig.Info("hydrated AgentContributions from snapshot",
							"zone", zd.ZoneName, "agents", len(zoneContribs))
					}
				}
				// Re-apply combined data now that contributions are loaded
				if zd.Options[OptAllowCombine] {
					success, err := zd.CombineWithLocalChanges()
					if err != nil {
						lgConfig.Error("CombineWithLocalChanges failed in OnFirstLoad", "zone", zd.ZoneName, "err", err)
					} else if success {
						lgConfig.Info("re-applied local changes after hydration", "zone", zd.ZoneName)
					}
				}
			})
		}
		// Provider zones: re-apply stored _signal KEY publish instructions on startup.
		if kdb != nil && GetProviderZoneRRtypes(zoneName) != nil {
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *ZoneData) {
				applyPendingSignalKeys(zd, kdb)
			})
		}
	}
	startEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })
	startEngineNoError(&Globals.App, "RefreshEngine", func() { RefreshEngine(ctx, conf) })
	startEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf.Internal.NotifyQ) })
	// Start incoming message router for beat/hello processing
	if conf.Internal.TransportManager != nil {
		conf.Internal.TransportManager.StartIncomingMessageRouter(ctx)
		lgConfig.Info("combiner incoming message router started")
	}
	// Start combiner message handler for beat/hello/sync consumption from MsgQs
	var protectedNS []string
	var errJournal *ErrorJournal
	if conf.Internal.CombinerState != nil {
		protectedNS = conf.Internal.CombinerState.ProtectedNamespaces
		errJournal = conf.Internal.CombinerState.ErrorJournal
	}
	startEngineNoError(&Globals.App, "CombinerMsgHandler",
		func() { CombinerMsgHandler(ctx, conf, conf.Internal.MsgQs, protectedNS, errJournal) })
	startEngine(&Globals.App, "NotifyHandler", func() error { return NotifyHandler(ctx, conf) })
	startEngine(&Globals.App, "DnsEngine", func() error { return DnsEngine(ctx, conf) })
	// Start combiner sync API router (for agent→combiner HELLO/BEAT/PING over HTTPS)
	if conf.MultiProvider != nil && len(conf.MultiProvider.SyncApi.Addresses.Listen) > 0 {
		combinerSyncRtr, err := conf.SetupCombinerSyncRouter(ctx)
		if err != nil {
			lgConfig.Error("failed to set up combiner sync router", "err", err)
		} else {
			startEngine(&Globals.App, "CombinerAPIdispatcherNG", func() error {
				lgConfig.Info("starting combiner sync API", "addresses", conf.MultiProvider.SyncApi.Addresses.Listen)
				return APIdispatcherNG(conf, combinerSyncRtr,
					conf.MultiProvider.SyncApi.Addresses.Listen,
					conf.MultiProvider.SyncApi.CertFile,
					conf.MultiProvider.SyncApi.KeyFile,
					conf.Internal.APIStopCh)
			})
		}
	}
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
		lgConfig.Info("NOT starting imrengine (explicitly set to false)", "app", Globals.App.Name, "mode", AppTypeToString[Globals.App.Type])
	}
	kdb := conf.Internal.KeyDB
	startEngineNoError(&Globals.App, "RefreshEngine", func() { RefreshEngine(ctx, conf) })
	startEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf.Internal.NotifyQ) })
	startEngineNoError(&Globals.App, "AuthQueryEngine", func() { AuthQueryEngine(ctx, conf.Internal.AuthQueryQ) })
	startEngine(&Globals.App, "ScannerEngine", func() error { return ScannerEngine(ctx, conf) })
	startEngine(&Globals.App, "ZoneUpdaterEngine", func() error { return kdb.ZoneUpdaterEngine(ctx) })
	startEngine(&Globals.App, "DeferredUpdaterEngine", func() error { return kdb.DeferredUpdaterEngine(ctx) })
	startEngine(&Globals.App, "UpdateHandler", func() error { return UpdateHandler(ctx, conf) })
	startEngine(&Globals.App, "KeyBootstrapper", func() error { return kdb.KeyBootstrapper(ctx) })
	startEngine(&Globals.App, "DelegationSyncher", func() error {
		return kdb.DelegationSyncher(ctx, conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ, conf)
	})
	// Start incoming message router for beat/hello processing
	// (CHUNK NOTIFY handler was already registered in MainInit via RegisterSignerChunkHandler)
	if conf.Internal.TransportManager != nil {
		conf.Internal.TransportManager.StartIncomingMessageRouter(ctx)
		lgConfig.Info("signer incoming message router started")
	}
	// Start signer message handler for beat/hello consumption from MsgQs
	startEngineNoError(&Globals.App, "SignerMsgHandler",
		func() { SignerMsgHandler(ctx, conf, conf.Internal.MsgQs) })
	startEngine(&Globals.App, "NotifyHandler", func() error { return NotifyHandler(ctx, conf) })
	startEngine(&Globals.App, "DnsEngine", func() error { return DnsEngine(ctx, conf) })
	startEngineNoError(&Globals.App, "ResignerEngine", func() { ResignerEngine(ctx, conf.Internal.ResignQ) })
	// Start key state worker for automatic DNSSEC key lifecycle transitions
	startEngine(&Globals.App, "KeyStateWorker", func() error { return KeyStateWorker(ctx, conf) })
	// Start signer sync API router (for agent→signer HELLO/BEAT/PING over HTTPS)
	if conf.MultiProvider != nil && len(conf.MultiProvider.SyncApi.Addresses.Listen) > 0 {
		signerSyncRtr, err := conf.SetupSignerSyncRouter(ctx)
		if err != nil {
			lgConfig.Error("failed to set up signer sync router", "err", err)
		} else {
			startEngine(&Globals.App, "SignerAPIdispatcherNG", func() error {
				lgConfig.Info("starting signer sync API", "addresses", conf.MultiProvider.SyncApi.Addresses.Listen)
				return APIdispatcherNG(conf, signerSyncRtr,
					conf.MultiProvider.SyncApi.Addresses.Listen,
					conf.MultiProvider.SyncApi.CertFile,
					conf.MultiProvider.SyncApi.KeyFile,
					conf.Internal.APIStopCh)
			})
		}
	}
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
		lgConfig.Info("NOT starting imrengine (explicitly set to false)", "app", Globals.App.Name, "mode", AppTypeToString[Globals.App.Type])
	}
	kdb := conf.Internal.KeyDB
	startEngineNoError(&Globals.App, "RefreshEngine", func() { RefreshEngine(ctx, conf) })
	startEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf.Internal.NotifyQ) })
	// Register CHUNK NOTIFY handler and start incoming DNS message router (must be before NotifyHandler)
	if conf.Internal.TransportManager != nil {
		if err := conf.Internal.TransportManager.RegisterChunkNotifyHandler(); err != nil {
			lgConfig.Error("failed to register CHUNK NOTIFY handler", "err", err)
		} else {
			conf.Internal.TransportManager.StartIncomingMessageRouter(ctx)
		}
	}
	// Initialize combiner as a virtual peer so HsyncEngine can manage heartbeats
	if err := conf.Internal.AgentRegistry.InitializeCombinerAsPeer(conf); err != nil {
		lgConfig.Warn("failed to initialize combiner as peer, continuing without combiner heartbeat monitoring", "err", err)
	}
	// Initialize signer as a virtual peer so it shows in "agent peer list" and can be pinged
	if err := conf.Internal.AgentRegistry.InitializeSignerAsPeer(conf); err != nil {
		lgConfig.Warn("failed to initialize signer as peer, continuing without signer peer registration", "err", err)
	}
	// Start the reliable message queue (must be after combiner peer initialization)
	if conf.Internal.TransportManager != nil {
		conf.Internal.TransportManager.StartReliableQueue(ctx)
	}
	// Leader election manager for coordinated parent delegation sync (DDNS)
	leaderTTL := viper.GetDuration("delegationsync.leader-election-ttl")
	if leaderTTL == 0 {
		leaderTTL = 60 * time.Minute
	}
	lem := NewLeaderElectionManager(
		AgentId(conf.MultiProvider.Identity), leaderTTL,
		func(zone ZoneName, rfiType string, records map[string][]string) error {
			return conf.Internal.AgentRegistry.broadcastElectToZone(zone, rfiType, records)
		},
	)
	conf.Internal.LeaderElectionManager = lem
	conf.Internal.AgentRegistry.LeaderElectionManager = lem
	// Wire operational peers counter for re-election decisions
	lem.SetOperationalPeersFunc(func(zone ZoneName) int {
		zad, err := conf.Internal.AgentRegistry.GetZoneAgentData(zone)
		if err != nil {
			return 0
		}
		count := 0
		for _, agent := range zad.Agents {
			if agent.Identity != AgentId(conf.MultiProvider.Identity) && agent.IsAnyTransportOperational() {
				count++
			}
		}
		return count
	})
	// Wire configured peers counter — elections require ALL configured peers.
	lem.SetConfiguredPeersFunc(func(zone ZoneName) int {
		zd, exists := Zones.Get(string(zone))
		if !exists || zd == nil {
			return 0
		}
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil || apex == nil {
			return 0
		}
		hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
		if !exists {
			return 0
		}
		// HSYNC3 records include self, so configured peers = count - 1
		count := len(hsync3RRset.RRs) - 1
		if count < 0 {
			count = 0
		}
		return count
	})
	// Attach leader election OnFirstLoad callbacks to zone stubs.
	// Must happen here (not in ParseZones) because LeaderElectionManager
	// doesn't exist until StartAgent runs.
	for _, zoneName := range conf.Internal.AllZones {
		zd, exists := Zones.Get(zoneName)
		if !exists {
			continue
		}
		if zd.Options[OptDelSyncChild] || zd.Options[OptMultiProvider] {
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *ZoneData) {
				if !zd.Options[OptDelSyncChild] {
					return
				}
				zone := ZoneName(zd.ZoneName)
				configured := lem.configuredPeers(zone)
				if configured == 0 {
					// Single agent — self-elect immediately
					lem.StartElection(zone, 0)
				} else {
					// Multi-agent — require all configured peers to be operational
					operational := 0
					if lem.operationalPeersFunc != nil {
						operational = lem.operationalPeersFunc(zone)
					}
					if operational >= configured {
						lem.StartElection(zone, configured)
					} else {
						lem.DeferElection(zone)
					}
				}
			})
		}
	}
	// When the local agent wins leader election: ensure we have a SIG(0) key,
	// then publish KEY to combiner and sync to remote agents.
	// Flow: check DSYNC → check local keystore → ask peers via RFI CONFIG → generate if nobody has it → publish.
	tm := conf.Internal.TransportManager
	lem.SetOnLeaderElected(func(zone ZoneName) error {
		zd, ok := Zones.Get(string(zone))
		if !ok || zd == nil {
			return fmt.Errorf("onLeaderElected: zone %s not found", zone)
		}
		if !zd.Options[OptDelSyncChild] {
			lgElect.Info("onLeaderElected: zone does not have OptDelSyncChild, skipping", "zone", zone)
			return nil
		}
		lgElect.Info("onLeaderElected: processing", "zone", zone)

		// Guard: parent must advertise DSYNC UPDATE scheme
		_, err := Globals.ImrEngine.LookupDSYNCTarget(context.Background(), string(zone), dns.TypeANY, core.SchemeUpdate)
		if err != nil {
			lgElect.Info("onLeaderElected: parent does not advertise DSYNC UPDATE scheme, skipping SIG(0) key setup",
				"zone", zone, "err", err)
			return nil
		}

		kdb := conf.Internal.KeyDB
		keyName := string(zone)
		// Step a: check local keystore
		sak, err := kdb.GetSig0Keys(keyName, Sig0StateActive)
		if err == nil && len(sak.Keys) > 0 {
			lgElect.Info("leader has local SIG(0) key, proceeding to publish",
				"zone", zone, "keyid", sak.Keys[0].KeyId)
			goto publish
		}
		// Step b: ask peers via RFI CONFIG subtype=sig0key (two-phase)
		{
			ar := conf.Internal.AgentRegistry
			zad, err := ar.GetZoneAgentData(zone)
			if err == nil {
				for _, agent := range zad.Agents {
					if agent.Identity == AgentId(ar.LocalAgent.Identity) {
						continue
					}
					if !agent.IsAnyTransportOperational() {
						continue
					}
					lgElect.Info("asking peer for SIG(0) key", "zone", zone, "peer", agent.Identity)
					configResp := RequestAndWaitForConfig(ar, agent, string(zone), "sig0key")
					if configResp == nil {
						lgElect.Info("peer did not respond to CONFIG sig0key", "zone", zone, "peer", agent.Identity)
						continue
					}
					if len(configResp.ConfigData) > 0 && configResp.ConfigData["status"] != "no sig0 key for zone" {
						if err := importSig0KeyFromPeer(kdb, keyName, configResp.ConfigData); err != nil {
							lgElect.Error("failed to import SIG(0) key from peer",
								"zone", zone, "peer", agent.Identity, "err", err)
							continue
						}
						lgElect.Info("imported SIG(0) key from peer", "zone", zone, "peer", agent.Identity)
						goto publish
					}
					lgElect.Info("peer does not have SIG(0) key", "zone", zone, "peer", agent.Identity)
				}
			}
		}
		// Step c: no peer has the key — generate a new keypair
		lgElect.Info("no peer has SIG(0) key, will generate new keypair", "zone", zone)
		{
			alg, err := parseKeygenAlgorithm("delegationsync.child.update.keygen.algorithm", dns.ED25519)
			if err != nil {
				return fmt.Errorf("onLeaderElected: parseKeygenAlgorithm: %v", err)
			}
			kp := KeystorePost{
				Command:    "sig0-mgmt",
				SubCommand: "generate",
				Zone:       zd.ZoneName,
				Keyname:    keyName,
				Algorithm:  alg,
				State:      Sig0StateActive,
				Creator:    "leader-election",
			}
			resp, err := kdb.Sig0KeyMgmt(nil, kp)
			if err != nil {
				return fmt.Errorf("onLeaderElected: failed to generate SIG(0) keypair: %v", err)
			}
			lgElect.Info("generated SIG(0) keypair", "zone", zone, "msg", resp.Msg)
		}
	publish:
		// Step d: get the active key and publish to combiner + remote agents
		sak, err = kdb.GetSig0Keys(keyName, Sig0StateActive)
		if err != nil || len(sak.Keys) == 0 {
			return fmt.Errorf("onLeaderElected: no active SIG(0) key after generation for zone %s", zone)
		}
		keyRR := &sak.Keys[0].KeyRR
		lgElect.Info("publishing KEY to combiner with PublishInstruction", "zone", zone, "keyid", sak.Keys[0].KeyId)

		// Send KEY + PublishInstruction to combiner in a single UPDATE.
		// The combiner handles at-apex (zone data) and at-ns (_signal names) publication.
		zu := &ZoneUpdate{
			Zone: zone,
			Operations: []core.RROperation{{
				Operation: "replace",
				RRtype:    "KEY",
				Records:   []string{keyRR.String()},
			}},
			Publish: &core.PublishInstruction{
				KEYRRs:    []string{keyRR.String()},
				Locations: []string{"at-apex", "at-ns"},
			},
		}
		distID, err := tm.EnqueueForCombiner(zone, zu, "")
		if err != nil {
			lgElect.Error("failed to publish KEY to combiner", "zone", zone, "err", err)
			return err
		}
		lgElect.Info("KEY + PublishInstruction sent to combiner", "zone", zone, "distID", distID)

		// Also sync KEY to remote agents so they publish via their combiners
		agentUpdate := &ZoneUpdate{
			Zone: zone,
			Operations: []core.RROperation{{
				Operation: "replace",
				RRtype:    "KEY",
				Records:   []string{keyRR.String()},
			}},
		}
		if err := tm.EnqueueForZoneAgents(zone, agentUpdate, distID); err != nil {
			lgElect.Error("failed to enqueue KEY for remote agents", "zone", zone, "err", err)
		}

		// Step e: trigger KeyState inquiry + bootstrap with parent (async).
		// Only if HSYNCPARAM says parentsync=agent.
		if zd.Options[OptDelSyncChild] {
			keyid := uint16(sak.Keys[0].KeyRR.KeyTag())
			algorithm := sak.Keys[0].KeyRR.Algorithm
			go conf.parentSyncAfterKeyPublication(zone, keyName, keyid, algorithm)
		}

		return nil
	})
	// Agent-specific
	startEngineNoError(&Globals.App, "HsyncEngine", func() { HsyncEngine(ctx, conf, conf.Internal.MsgQs) })
	startEngineNoError(&Globals.App, "InfraBeatLoop", func() {
		conf.Internal.AgentRegistry.StartInfraBeatLoop(ctx)
	})
	startEngineNoError(&Globals.App, "DiscoveryRetrierNG", func() {
		conf.Internal.AgentRegistry.DiscoveryRetrierNG(ctx)
	})
	startEngineNoError(&Globals.App, "SynchedDataEngine", func() { conf.SynchedDataEngine(ctx, conf.Internal.MsgQs) })
	syncrtr, err := conf.SetupAgentSyncRouter(ctx)
	if err != nil {
		return fmt.Errorf("error setting up agent-to-agent sync router: %v", err)
	}
	startEngine(&Globals.App, "APIdispatcherNG", func() error {
		lgConfig.Info("starting agent-to-agent sync engine", "app", Globals.App.Name, "mode", AppTypeToString[Globals.App.Type])
		return APIdispatcherNG(conf, syncrtr, conf.MultiProvider.Api.Addresses.Listen, conf.MultiProvider.Api.CertFile, conf.MultiProvider.Api.KeyFile, conf.Internal.APIStopCh)
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

// initPayloadCrypto initializes PayloadCrypto from the agent config.
// Loads the local JOSE private key and the combiner's public key (if configured).
func initPayloadCrypto(conf *Config) (*transport.PayloadCrypto, error) {
	if conf.MultiProvider == nil {
		return nil, fmt.Errorf("agent config is not set")
	}
	// Use JOSE backend for key operations
	backend := jose.NewBackend()
	// Load local private key (trim path so trailing whitespace/newlines from config do not cause "file not found")
	privKeyPath := strings.TrimSpace(conf.MultiProvider.LongTermJosePrivKey)
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
		Backend: backend,
		Enabled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("create PayloadCrypto: %w", err)
	}
	// Set local keys
	pc.SetLocalKeys(privKey, pubKey)
	lgConfig.Info("loaded local JOSE key", "path", privKeyPath)
	// Load combiner's public key if configured
	if conf.MultiProvider.Combiner != nil && strings.TrimSpace(conf.MultiProvider.Combiner.LongTermJosePubKey) != "" {
		combinerPubKeyPath := strings.TrimSpace(conf.MultiProvider.Combiner.LongTermJosePubKey)
		combinerPubKeyData, err := os.ReadFile(combinerPubKeyPath)
		if err != nil {
			if os.IsNotExist(err) {
				lgConfig.Warn("combiner public key file not found, encryption disabled", "path", combinerPubKeyPath, "err", err)
			} else {
				lgConfig.Warn("failed to read combiner public key, encryption disabled", "path", combinerPubKeyPath, "err", err)
			}
		} else {
			combinerPubKeyData = StripKeyFileComments(combinerPubKeyData)
			combinerPubKey, err := backend.ParsePublicKey(combinerPubKeyData)
			if err != nil {
				lgConfig.Warn("failed to parse combiner public key, encryption disabled", "err", err)
			} else {
				// Add combiner as peer for both encryption and verification
				pc.AddPeerKey("combiner", combinerPubKey)
				pc.AddPeerVerificationKey("combiner", combinerPubKey)
				lgConfig.Info("loaded combiner public key", "path", combinerPubKeyPath)
			}
		}
	}
	// DNS-39: Peer keys come from DNS discovery, not config files
	// Old agent.peers map with embedded keys is no longer supported
	if len(conf.MultiProvider.AuthorizedPeers) > 0 {
		lgConfig.Info("using agent.authorized_peers, peer keys will be discovered via DNS")
	} else {
		lgConfig.Info("no agent.authorized_peers configured, no peer crypto available")
	}
	return pc, nil
}

// initCombinerCrypto initializes crypto for the combiner to decrypt agent payloads.
// Returns a SecurePayloadWrapper configured with the combiner's private key and agent's public key.
func initCombinerCrypto(conf *Config) (*transport.SecurePayloadWrapper, error) {
	// Use the JOSE backend
	backend := jose.NewBackend()
	// Load combiner's private key (trim path so trailing whitespace/newlines from config do not cause "file not found")
	privKeyPath := strings.TrimSpace(conf.MultiProvider.LongTermJosePrivKey)
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
	lgConfig.Info("loaded combiner private key", "path", privKeyPath)
	// Derive public key from private key
	joseBackend, ok := backend.(*jose.Backend)
	if !ok {
		return nil, fmt.Errorf("backend is not JOSE")
	}
	localPubKey, err := joseBackend.PublicFromPrivate(localPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}
	// Create PayloadCrypto instance using the generic transport infrastructure
	pc, err := transport.NewPayloadCrypto(&transport.PayloadCryptoConfig{
		Backend: backend,
		Enabled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create PayloadCrypto: %w", err)
	}
	// Set local keys for decryption
	pc.SetLocalKeys(localPrivKey, localPubKey)
	// Load public keys for all configured agents
	if len(conf.MultiProvider.Agents) == 0 {
		return nil, fmt.Errorf("multi-provider.agents not configured (need at least one agent)")
	}
	for _, agent := range conf.MultiProvider.Agents {
		if strings.TrimSpace(agent.Identity) == "" {
			return nil, fmt.Errorf("multi-provider.agents: agent entry missing required identity field")
		}
		if strings.TrimSpace(agent.LongTermJosePubKey) == "" {
			return nil, fmt.Errorf("multi-provider.agents[%s]: long_term_jose_pub_key not configured", agent.Identity)
		}
		agentPubKeyPath := strings.TrimSpace(agent.LongTermJosePubKey)
		agentPubKeyData, err := os.ReadFile(agentPubKeyPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("agent public key file not found for %s: %q: %w", agent.Identity, agentPubKeyPath, err)
			}
			return nil, fmt.Errorf("failed to read agent public key for %s: %q: %w", agent.Identity, agentPubKeyPath, err)
		}
		agentPubKeyData = StripKeyFileComments(agentPubKeyData)
		agentVerifyKey, err := backend.ParsePublicKey(agentPubKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse agent public key for %s: %w", agent.Identity, err)
		}
		// Register agent with its identity as the peer key ID
		pc.AddPeerKey(agent.Identity, agentVerifyKey)
		pc.AddPeerVerificationKey(agent.Identity, agentVerifyKey)
		lgConfig.Info("loaded public key for agent", "agent", agent.Identity, "path", agentPubKeyPath)
	}
	return transport.NewSecurePayloadWrapper(pc), nil
}

// registerPeerAgents registers peer agents from the static config into the TransportManager.
//
// DNS-39: Peer addresses come from DNS discovery, not static config.
// The old agent.peers map with embedded addresses is no longer supported.
func registerPeerAgents(conf *Config, tm *TransportManager) error {
	if conf.MultiProvider == nil {
		return nil // No agent config
	}
	// DNS-39: All peer addresses come from DNS discovery
	if len(conf.MultiProvider.AuthorizedPeers) > 0 {
		lgConfig.Info("using agent.authorized_peers, peer addresses will be discovered via DNS")
	} else {
		lgConfig.Info("no agent.authorized_peers configured, no peers available")
	}
	return nil
}
