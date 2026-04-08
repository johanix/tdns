/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	// "flag"
	"context"
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/johanix/tdns-transport/v2/crypto/jose"
	"github.com/johanix/tdns-transport/v2/transport"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
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
		StatusUpdate:      make(chan *StatusUpdateMsg, 10),
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
	conf.Internal.MPZoneNames = nil
	all_zones, err := conf.ParseZones(ctx, false) // false = initial load, not reload
	if err != nil {
		return fmt.Errorf("error parsing zones: %v", err)
	}
	// Provide the complete zone list to engines that need cross-zone post-initialization
	conf.Internal.AllZones = all_zones
	lgConfig.Info("multi-provider zones from config", "count", len(conf.Internal.MPZoneNames), "zones", conf.Internal.MPZoneNames)
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
	/*
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
			tm := NewMPTransportBridge(&MPTransportBridgeConfig{
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
				GetZone:        Zones.Get,
				GetZoneNames:   Zones.Keys,
				ClientCertFile: conf.MultiProvider.Api.CertFile,
				ClientKeyFile:  conf.MultiProvider.Api.KeyFile,
			})
			conf.Internal.TransportManager = tm.TransportManager
			conf.Internal.MPTransport = tm
			conf.Internal.AgentRegistry.TransportManager = tm.TransportManager
			conf.Internal.AgentRegistry.MPTransport = tm
			lgConfig.Info("TransportManager created", "controlZone", controlZone, "chunkMode", chunkMode)
			// Register peer agents from static config
			if err := registerPeerAgents(conf, tm); err != nil {
				return fmt.Errorf("failed to register peer agents: %w", err)
			}
	*/
	case AppTypeAuth:
		/*
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
				tm := NewMPTransportBridge(&MPTransportBridgeConfig{
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
				conf.Internal.TransportManager = tm.TransportManager
				conf.Internal.MPTransport = tm
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
					IncomingChan:     nil, // routing via RouteToCallback, not IncomingChan
				}
				if signerPayloadCrypto != nil {
					signerRouterCfg.PayloadCrypto = signerPayloadCrypto
					signerRouterCfg.AllowUnencrypted = false
				}
				if err := transport.InitializeSignerRouter(signerRouter, signerRouterCfg); err != nil {
					return fmt.Errorf("InitializeSignerRouter: %w", err)
				}
				signerState.SetRouter(signerRouter)
				tm.Router = signerRouter // ensure StartIncomingMessageRouter registers on the active router
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
		*/
		/*
			if Globals.App.Type == AppTypeCombiner {
				if conf.MultiProvider == nil {
					return fmt.Errorf("multi-provider config block is required for combiner app type")
				}
				// Initialize only the combiner edit tables (not the full HSYNC schema)
				if conf.Internal.KeyDB != nil {
					if err := InitCombinerEditTables(conf.Internal.KeyDB); err != nil {
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
					secureWrapper, err = InitCombinerCrypto(conf)
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
				tm := NewMPTransportBridge(&MPTransportBridgeConfig{
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
				conf.Internal.TransportManager = tm.TransportManager
				conf.Internal.MPTransport = tm
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
					IncomingChan: nil, // routing via RouteToCallback, not IncomingChan
				}
				// Add crypto middleware if secure wrapper is available
				if combinerPayloadCrypto != nil {
					combinerRouterCfg.PayloadCrypto = combinerPayloadCrypto
				}
				if err := transport.InitializeCombinerRouter(combinerRouter, combinerRouterCfg); err != nil {
					return fmt.Errorf("InitializeCombinerRouter: %w", err)
				}
				combinerState.SetRouter(combinerRouter)
				tm.Router = combinerRouter // ensure StartIncomingMessageRouter registers on the active router
				lgConfig.Info("combiner router initialized with authorization middleware")
				if conf.MultiProvider.CombinerOptions[CombinerOptAddSignature] {
					lgConfig.Info("combiner signature TXT enabled")
				}
			}
		*/
	default:
		// ... existing auth/agent/combiner setup ...
	}
	lgConfig.Debug("MainInit complete")
	return nil
}

/*
// StartCombiner starts subsystems for tdns-combiner
func (conf *Config) StartCombiner(ctx context.Context, apirouter *mux.Router) error {
	// Attach OnFirstLoad callbacks to zone stubs created by ParseZones.
	// Stubs already exist in Zones with FirstZoneLoad=true.
	kdb := conf.Internal.KeyDB

	// Pre-load all contributions once (instead of per-zone in each OnFirstLoad).
	var allContribs map[string]map[string]map[string]map[uint16]core.RRset
	if kdb != nil {
		var err error
		allContribs, err = LoadAllContributions(kdb)
		if err != nil {
			lgConfig.Error("StartCombiner: failed to pre-load contributions snapshot", "err", err)
			// Continue — individual zones will just skip hydration
		}
	}

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

				zd.EnsureMP()

				// Set PersistContributions callback
				if zd.MP.PersistContributions == nil && zd.KeyDB != nil {
					kdb := zd.KeyDB
					zd.MP.PersistContributions = func(zone, senderID string, contribs map[string]map[uint16]core.RRset) error {
						return SaveContributions(kdb, zone, senderID, contribs)
					}
					lgConfig.Info("PersistContributions callback set", "zone", zd.ZoneName)
				}
				// Hydrate AgentContributions from pre-loaded snapshot
				if zd.MP.AgentContributions == nil && allContribs != nil {
					if zoneContribs, ok := allContribs[zd.ZoneName]; ok {
						zd.mu.Lock()
						zd.MP.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
						for senderID, ownerMap := range zoneContribs {
							zd.MP.AgentContributions[senderID] = ownerMap
						}
						RebuildCombinerData(zd)
						zd.mu.Unlock()
						lgConfig.Info("hydrated AgentContributions from snapshot",
							"zone", zd.ZoneName, "agents", len(zoneContribs))
					}
				}
				// Re-apply combined data now that contributions are loaded
				if zd.Options[OptAllowEdits] {
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
	StartEngine(&Globals.App, "APIdispatcher", func() error { return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh) })
	StartEngineNoError(&Globals.App, "RefreshEngine", func() { RefreshEngine(ctx, conf) })
	StartEngine(&Globals.App, "Notifier", func() error { return Notifier(ctx, conf.Internal.NotifyQ) })
	// MP combiner engines — skipped for AppTypeMPCombiner (tdns-mp provides its own)
	if Globals.App.Type != AppTypeMPCombiner {
		// Start incoming message router for beat/hello processing
		if conf.Internal.TransportManager != nil {
			conf.Internal.MPTransport.StartIncomingMessageRouter(ctx)
			lgConfig.Info("combiner incoming message router started")
		}
		// Start combiner message handler for beat/hello/sync consumption from MsgQs
		var protectedNS []string
		var errJournal *ErrorJournal
		if conf.Internal.CombinerState != nil {
			protectedNS = conf.Internal.CombinerState.ProtectedNamespaces
			errJournal = conf.Internal.CombinerState.ErrorJournal
		}
		StartEngineNoError(&Globals.App, "CombinerMsgHandler",
			func() { CombinerMsgHandler(ctx, conf, conf.Internal.MsgQs, protectedNS, errJournal) })
	}
	StartEngine(&Globals.App, "NotifyHandler", func() error { return NotifyHandler(ctx, conf) })
	StartEngine(&Globals.App, "DnsEngine", func() error { return DnsEngine(ctx, conf) })
	// Start combiner sync API router (for agent→combiner HELLO/BEAT/PING over HTTPS)
	if Globals.App.Type != AppTypeMPCombiner && conf.MultiProvider != nil && len(conf.MultiProvider.SyncApi.Addresses.Listen) > 0 {
		combinerSyncRtr, err := conf.SetupCombinerSyncRouter(ctx)
		if err != nil {
			lgConfig.Error("failed to set up combiner sync router", "err", err)
		} else {
			StartEngine(&Globals.App, "CombinerAPIdispatcherNG", func() error {
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
*/

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
func InitCombinerCrypto(conf *Config) (*transport.SecurePayloadWrapper, error) {
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
		peerID := dns.Fqdn(strings.TrimSpace(agent.Identity))
		pc.AddPeerKey(peerID, agentVerifyKey)
		pc.AddPeerVerificationKey(peerID, agentVerifyKey)
		lgConfig.Info("loaded public key for agent", "agent", peerID, "path", agentPubKeyPath)
	}
	return transport.NewSecurePayloadWrapper(pc), nil
}

// registerPeerAgents registers peer agents from the static config into the TransportManager.
//
// DNS-39: Peer addresses come from DNS discovery, not static config.
// The old agent.peers map with embedded addresses is no longer supported.
func registerPeerAgents(conf *Config, tm *MPTransportBridge) error {
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
