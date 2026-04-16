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
