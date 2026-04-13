/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Transport integration for HsyncEngine.
 * Bridges the transport abstraction package with the existing hsyncengine.
 */

package tdns

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var lgTransport = Logger("transport")
var lgConnRetry = Logger("conn-retry")

// generatePingNonce returns a random nonce for ping requests.
// Panics if the system CSPRNG fails, as this indicates a critical system problem.
func generatePingNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes for ping nonce: %v", err))
	}
	return hex.EncodeToString(b)
}

// MPTransportBridge manages multiple transports for agent communication.
// MPTransportBridge aggregates MP-specific transport state and methods.
// It holds a reference to the generic transport.TransportManager and
// adds multi-provider functionality (message routing, authorization,
// agent discovery, DNSKEY propagation, reliable delivery wrappers).
type MPTransportBridge struct {
	*transport.TransportManager // generic (fields promoted via embedding)

	agentRegistry *AgentRegistry
	msgQs         *MsgQs

	// SupportedMechanisms lists active transports ("api", "dns")
	SupportedMechanisms []string

	// combinerID is the AgentId of the combiner (from config), used by EnqueueForCombiner.
	combinerID AgentId

	// signerID is the identity of the local signer (tdns-auth) for KEYSTATE signaling.
	signerID string
	// signerAddress is the DNS address (host:port) of the local signer.
	signerAddress string

	// pendingDnskeyPropagations tracks DNSKEY distributions awaiting confirmation from all remote agents.
	// Key: distributionID. When all expected agents confirm, KEYSTATE "propagated" is sent to signer.
	pendingDnskeyPropagations map[string]*PendingDnskeyPropagation
	dnskeyPropMu              sync.Mutex

	// authorizedPeers returns the list of peer identities authorized via config.
	// Injected at config time; role-specific (each role provides its own list).
	authorizedPeers func() []string

	// messageRetention returns retention seconds for a given message type.
	// Used by distribution cache for expiration. If nil, default retention is used.
	messageRetention func(operation string) int

	// getImrEngine returns the IMR resolver for DNS-based agent discovery (optional).
	// Uses a closure because ImrEngine starts asynchronously after TM creation.
	getImrEngine func() *Imr

	// getZone returns zone data by name. Injected to avoid coupling to global Zones.
	// Used by HSYNC3-based authorization in agent_authorization.go.
	getZone func(name string) (*ZoneData, bool)
	// getZoneNames returns all known zone names. Same purpose as getZone.
	getZoneNames func() []string

	keystateRfiMu    sync.Mutex
	keystateRfiState map[string]chan *KeystateInventoryMsg // key: zone name
}

func (tm *MPTransportBridge) setKeystateRfi(zone string, ch chan *KeystateInventoryMsg) {
	tm.keystateRfiMu.Lock()
	defer tm.keystateRfiMu.Unlock()
	if tm.keystateRfiState == nil {
		tm.keystateRfiState = make(map[string]chan *KeystateInventoryMsg)
	}
	tm.keystateRfiState[zone] = ch
}

func (tm *MPTransportBridge) deleteKeystateRfi(zone string) {
	tm.keystateRfiMu.Lock()
	defer tm.keystateRfiMu.Unlock()
	delete(tm.keystateRfiState, zone)
}

// isTransportReady returns true if the transport details indicate a reachable agent.
func isTransportReady(details *AgentDetails) bool {
	if details == nil {
		return false
	}
	switch details.State {
	case AgentStateOperational, AgentStateIntroduced, AgentStateLegacy,
		AgentStateDegraded, AgentStateInterrupted:
		return true
	default:
		return false
	}
}

func (tm *MPTransportBridge) getKeystateRfi(zone string) (chan *KeystateInventoryMsg, bool) {
	tm.keystateRfiMu.Lock()
	defer tm.keystateRfiMu.Unlock()
	ch, ok := tm.keystateRfiState[zone]
	return ch, ok
}

// MPTransportBridgeConfig holds configuration for creating a MPTransportBridge.
type MPTransportBridgeConfig struct {
	LocalID       string
	ControlZone   string
	APITimeout    time.Duration
	DNSTimeout    time.Duration
	AgentRegistry *AgentRegistry
	MsgQs         *MsgQs
	// ChunkMode: "edns0" or "query"; when "query", agent stores payload and sends NOTIFY without EDNS0; receiver fetches via CHUNK query
	ChunkMode         string
	ChunkPayloadStore ChunkPayloadStore
	// ChunkQueryEndpoint: for query mode, address (host:port) where agent answers CHUNK queries
	ChunkQueryEndpoint string
	// ChunkQueryEndpointInNotify: when true, include endpoint in NOTIFY (EDNS0 option 65005); when false, receiver uses static config (e.g. combiner.agents[].address)
	ChunkQueryEndpointInNotify bool
	// ChunkMaxSize: maximum data chunk size in bytes for PrepareDistributionChunks.
	// 0 = default (60000). Set small (e.g. 500) for fragmentation testing.
	ChunkMaxSize int

	// PayloadCrypto enables JWS/JWE encryption for CHUNK payloads (optional)
	// If set and Enabled, all outgoing CHUNK payloads will be encrypted and signed
	PayloadCrypto *transport.PayloadCrypto

	// DistributionCache: when set, outgoing CHUNK operations (ping, hello, etc.) are registered for "agent distrib list"
	DistributionCache *DistributionCache

	// SupportedMechanisms lists active transports ("api", "dns"); default: both if configured
	SupportedMechanisms []string

	// CombinerID is the identity of the combiner for this agent (from config).
	// Used by EnqueueForCombiner to know which AgentRegistry entry is the combiner.
	CombinerID string

	// SignerID is the identity of the local signer for KEYSTATE signaling (Phase 6).
	SignerID string
	// SignerAddress is the DNS address (host:port) of the local signer.
	SignerAddress string

	// AuthorizedPeers returns the list of peer identities authorized via config.
	// Called at runtime during authorization. Each role provides its own implementation.
	// If nil, only HSYNC-based and LEGACY-based authorization is used.
	AuthorizedPeers func() []string

	// MessageRetention returns retention seconds for a given message type (operation).
	// Used by distribution cache for expiration. If nil, default retention is used.
	MessageRetention func(operation string) int

	// GetImrEngine returns the IMR resolver for DNS-based agent discovery (optional).
	// Uses a closure because ImrEngine starts asynchronously after TM creation.
	// Only the agent needs this; combiner/signer/external apps pass nil.
	GetImrEngine func() *Imr

	// GetZone returns zone data by name. Injected to decouple from global Zones.
	// Only needed by roles that use HSYNC3-based authorization (agent).
	GetZone func(name string) (*ZoneData, bool)
	// GetZoneNames returns all known zone names.
	GetZoneNames func() []string

	// ClientCertFile and ClientKeyFile are the TLS client certificate presented when
	// connecting to peers' sync API servers. Required when peers enforce mutual TLS
	// (e.g. combiner/signer sync routers verify client cert against agent's TLSA record).
	ClientCertFile string
	ClientKeyFile  string
}

// NewTransportManager creates a new MPTransportBridge with both API and DNS transports.
func NewMPTransportBridge(cfg *MPTransportBridgeConfig) *MPTransportBridge {
	// Default to both transports if not specified (backward compatibility for tests)
	// Production configs MUST specify supported_mechanisms explicitly (validated at config load)
	supportedMechanisms := cfg.SupportedMechanisms
	if len(supportedMechanisms) == 0 {
		lgTransport.Warn("created without supported_mechanisms, defaulting to [api, dns]")
		supportedMechanisms = []string{"api", "dns"}
	}

	tm := &MPTransportBridge{
		TransportManager: &transport.TransportManager{
			PeerRegistry: transport.NewPeerRegistry(),
			Router:       transport.NewDNSMessageRouter(),
			ReliableQueue: transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{
				IsRecipientReady: func(recipientID string) bool {
					if cfg.AgentRegistry == nil {
						return true
					}
					agent, exists := cfg.AgentRegistry.S.Get(AgentId(recipientID))
					if !exists {
						return false
					}
					return isTransportReady(agent.DnsDetails) || isTransportReady(agent.ApiDetails)
				},
			}),
			LocalID:     cfg.LocalID,
			ControlZone: cfg.ControlZone,
		},
		agentRegistry:             cfg.AgentRegistry,
		msgQs:                     cfg.MsgQs,
		SupportedMechanisms:       supportedMechanisms,
		combinerID:                AgentId(cfg.CombinerID),
		signerID:                  cfg.SignerID,
		signerAddress:             cfg.SignerAddress,
		pendingDnskeyPropagations: make(map[string]*PendingDnskeyPropagation),
		authorizedPeers:           cfg.AuthorizedPeers,
		messageRetention:          cfg.MessageRetention,
		getImrEngine:              cfg.GetImrEngine,
		getZone:                   cfg.GetZone,
		getZoneNames:              cfg.GetZoneNames,
	}

	// Always create API client transport — it's a pure HTTP client with no server-side
	// implications. An agent that only serves DNS can still act as an API client to
	// remote agents that serve API. supported_mechanisms controls the server role, not
	// the client role.
	apiTLSConfig := &tls.Config{
		// Peer certificates are validated against TLSA records (discovered via DNS),
		// not against the system CA store. Self-signed certs are the norm here.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS13,
	}
	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			lgTransport.Error("failed to load API client certificate, outbound mTLS will not work",
				"certFile", cfg.ClientCertFile, "keyFile", cfg.ClientKeyFile, "err", err)
		} else {
			apiTLSConfig.Certificates = []tls.Certificate{clientCert}
			lgTransport.Info("API client certificate loaded", "certFile", cfg.ClientCertFile)
		}
	}
	tm.APITransport = transport.NewAPITransport(&transport.APITransportConfig{
		LocalID:        cfg.LocalID,
		DefaultTimeout: cfg.APITimeout,
		TLSConfig:      apiTLSConfig,
	})
	lgTransport.Info("API client transport enabled")

	// Create DNS transport if control zone is configured AND supported
	if cfg.ControlZone != "" && tm.isTransportSupported("dns") {
		dnsCfg := &transport.DNSTransportConfig{
			LocalID:                    cfg.LocalID,
			ControlZone:                cfg.ControlZone,
			Timeout:                    cfg.DNSTimeout,
			ChunkMode:                  cfg.ChunkMode,
			ChunkQueryEndpoint:         cfg.ChunkQueryEndpoint,
			ChunkQueryEndpointInNotify: cfg.ChunkQueryEndpointInNotify,
			ChunkMaxSize:               cfg.ChunkMaxSize,
			PayloadCrypto:              cfg.PayloadCrypto,
		}
		if cfg.ChunkPayloadStore != nil {
			store := cfg.ChunkPayloadStore
			dnsCfg.ChunkPayloadGet = func(qname string) ([]byte, uint8, bool) { return store.Get(qname) }
			dnsCfg.ChunkPayloadSet = func(qname string, payload []byte, format uint8) { store.Set(qname, payload, format) }
			dnsCfg.ChunkPayloadSetChunks = func(qname string, chunks []*core.CHUNK) { store.SetChunks(qname, chunks) }
		}
		if cfg.DistributionCache != nil {
			cache := cfg.DistributionCache
			dnsCfg.DistributionAdd = func(qname string, senderID string, receiverID string, operation string, distributionID string, payloadSize int) {
				now := time.Now()

				// Calculate expiration time based on message type (operation)
				// Use config retention times with sensible defaults
				var retentionSecs int
				if tm.messageRetention != nil {
					retentionSecs = tm.messageRetention(operation)
				} else {
					var m MessageRetentionConf
					retentionSecs = m.GetRetentionForMessageType(operation)
				}
				expiresAt := now.Add(time.Duration(retentionSecs) * time.Second)

				cache.Add(qname, &DistributionInfo{
					DistributionID: distributionID,
					SenderID:       senderID,
					ReceiverID:     receiverID,
					Operation:      operation,
					ContentType:    "",
					State:          "pending",
					PayloadSize:    payloadSize,
					CreatedAt:      now,
					CompletedAt:    nil,
					ExpiresAt:      &expiresAt,
					QNAME:          qname,
				})
			}
			dnsCfg.DistributionMarkCompleted = func(qname string) { cache.MarkCompleted(qname) }
		}
		tm.DNSTransport = transport.NewDNSTransport(dnsCfg)

		// Create CHUNK NOTIFY handler
		tm.ChunkHandler = transport.NewChunkNotifyHandler(
			cfg.ControlZone,
			cfg.LocalID,
			tm.DNSTransport,
		)
		// Attach router to handler for new routing path
		tm.ChunkHandler.Router = tm.Router

		// In chunk_mode=query without EDNS0 CHUNK_QUERY_ENDPOINT, use configured peer address (e.g. agent.peers)
		tm.ChunkHandler.GetPeerAddress = func(senderID string) (string, bool) {
			peer, ok := tm.PeerRegistry.Get(senderID)
			if !ok || peer.CurrentAddress() == nil {
				return "", false
			}
			addr := peer.CurrentAddress()
			return fmt.Sprintf("%s:%d", addr.Host, addr.Port), true
		}

		// DoS mitigation: Check authorization BEFORE expensive operations (decryption, query fetch)
		tm.ChunkHandler.IsPeerAuthorized = func(senderID string, zone string) (bool, string) {
			return tm.IsPeerAuthorized(senderID, zone)
		}

		// Wire confirmation callback for reliable message queue and per-RR tracking
		tm.ChunkHandler.OnConfirmationReceived = func(distributionID string, senderID string, status transport.ConfirmStatus,
			zone string, applied []string, removed []string, rejected []transport.RejectedItemDTO, ignored []string, truncated bool, nonce string) {
			lgTransport.Debug("confirmation received", "distributionID", distributionID, "sender", senderID, "nonce", nonce)

			// Stop retrying on any definitive answer (success, failure, or rejected).
			// Only keep retrying for transient states (pending, partial).
			if tm.ReliableQueue != nil && (status == transport.ConfirmSuccess || status == transport.ConfirmFailed || status == transport.ConfirmRejected) {
				tm.ReliableQueue.MarkConfirmed(distributionID, senderID)
			}

			// Phase 6: Check if this confirmation is for a pending DNSKEY propagation
			var rejItems []RejectedItemInfo
			for _, ri := range rejected {
				rejItems = append(rejItems, RejectedItemInfo{Record: ri.Record, Reason: ri.Reason})
			}
			tm.ProcessDnskeyConfirmation(distributionID, senderID, status.String(), rejItems)

			// Forward per-RR detail to SynchedDataEngine
			if tm.msgQs != nil && tm.msgQs.Confirmation != nil {
				detail := &ConfirmationDetail{
					DistributionID: distributionID,
					Zone:           ZoneName(zone),
					Source:         senderID,
					Status:         status.String(),
					AppliedRecords: applied,
					RemovedRecords: removed,
					RejectedItems:  rejItems,
					Truncated:      truncated,
					Timestamp:      time.Now(),
				}
				select {
				case tm.msgQs.Confirmation <- detail:
				default:
					lgTransport.Warn("confirmation channel full, dropping detail", "distributionID", distributionID)
				}
			}
		}

		// Wire remote confirmation callback (two-phase protocol: Phase 7).
		// When this agent's combiner confirms a sync that originated from another agent,
		// send the final confirmation NOTIFY back to the originating agent.
		if tm.msgQs != nil {
			tm.msgQs.OnRemoteConfirmationReady = func(detail *RemoteConfirmationDetail) {
				go tm.sendRemoteConfirmation(detail)
			}
		}

		// Trigger discovery when we receive messages from authorized but undiscovered peers.
		// This is the "discovery kick" (Phase 4 gossip): when a beat arrives from a sender
		// whose verification key we don't have, flush IMR cache for that identity's discovery
		// names and retry. This unsticks the UNKNOWN→KNOWN transition when cached NXDOMAIN
		// is blocking discovery.
		tm.ChunkHandler.OnPeerDiscoveryNeeded = func(peerID string) {
			lgTransport.Info("discovery kick: flushing IMR cache and triggering discovery", "peer", peerID)

			// Flush IMR cache for this peer's discovery names before re-discovery
			if tm.getImrEngine != nil {
				if imr := tm.getImrEngine(); imr != nil && imr.Cache != nil {
					removed, err := imr.Cache.FlushDomain(peerID, false)
					if err == nil && removed > 0 {
						lgTransport.Info("flushed IMR cache for peer discovery", "peer", peerID, "removed", removed)
					}
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := tm.DiscoverAndRegisterAgent(ctx, peerID)
			if err != nil {
				lgTransport.Warn("discovery incomplete for peer", "peer", peerID, "err", err)
			} else {
				lgTransport.Info("successfully discovered peer, verification key now available", "peer", peerID)
			}
		}

		// Provide gossip for beat responses: when we receive a beat,
		// include our gossip state in the response so peers get
		// bidirectional state exchange on every beat round-trip.
		tm.ChunkHandler.GossipForPeer = func(peerID string) json.RawMessage {
			if tm.agentRegistry == nil || tm.agentRegistry.GossipStateTable == nil || tm.agentRegistry.ProviderGroupManager == nil {
				return nil
			}
			gossipMsgs := tm.agentRegistry.GossipStateTable.BuildGossipForPeer(
				peerID, tm.agentRegistry.ProviderGroupManager, tm.agentRegistry.LeaderElectionManager)
			if len(gossipMsgs) == 0 {
				return nil
			}
			data, _ := json.Marshal(gossipMsgs)
			return data
		}

		// Initialize router with handlers and middleware
		routerCfg := &transport.RouterConfig{
			TransportManager:             tm,
			PeerRegistry:                 tm.PeerRegistry,
			PayloadCrypto:                cfg.PayloadCrypto,
			IncomingChan:                 nil, // routing via RouteToCallback, not IncomingChan
			TriggerDiscoveryOnMissingKey: true,
			AllowUnencrypted:             false,
			VerboseStats:                 false, // Set to true for verbose statistics logging
		}
		lgTransport.Debug("router config", "peerRegistry", routerCfg.PeerRegistry, "peerRegistryNil", routerCfg.PeerRegistry == nil)
		if err := transport.InitializeRouter(tm.Router, routerCfg); err != nil {
			lgTransport.Warn("router initialization failed", "err", err)
		}

		lgTransport.Info("DNS transport enabled")
	} else if cfg.ControlZone == "" {
		lgTransport.Info("DNS transport not configured (no control zone)")
	} else {
		lgTransport.Info("DNS transport disabled by configuration")
	}

	return tm
}

// isTransportSupported checks if a transport mechanism is enabled in configuration.
func (tm *MPTransportBridge) isTransportSupported(mechanism string) bool {
	if len(tm.SupportedMechanisms) == 0 {
		return true // Default: all transports supported
	}
	for _, m := range tm.SupportedMechanisms {
		if m == mechanism {
			return true
		}
	}
	return false
}

// RegisterChunkNotifyHandler registers the CHUNK NOTIFY handler with tdns.
// This should be called during agent initialization.
func (tm *MPTransportBridge) RegisterChunkNotifyHandler() error {
	if tm.ChunkHandler == nil {
		return fmt.Errorf("DNS transport not configured (no control zone)")
	}

	// Register the handler for CHUNK type NOTIFYs
	// RouteViaRouter routes through the DNSMessageRouter with middleware
	err := RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *DnsNotifyRequest) error {
		return tm.ChunkHandler.RouteViaRouter(ctx, req.Qname, req.Msg, req.ResponseWriter)
	})
	if err != nil {
		return fmt.Errorf("failed to register CHUNK NOTIFY handler: %w", err)
	}

	lgTransport.Info("registered CHUNK NOTIFY handler", "controlZone", tm.ControlZone)
	return nil
}

// StartIncomingMessageRouter starts a goroutine that routes incoming DNS messages
// to the appropriate hsyncengine channels.
// ctx is intentionally unused: kept in the signature for API stability and future use.
func (tm *MPTransportBridge) StartIncomingMessageRouter(ctx context.Context) {
	if tm.ChunkHandler == nil {
		lgTransport.Info("DNS transport not configured, skipping incoming message router")
		return
	}

	// Register RouteToCallback middleware on the Router.
	// When a message arrives via CHUNK NOTIFY, the Router runs the handler
	// chain (auth, crypto, parse) and then calls our callback with the
	// parsed IncomingMessage. The callback dispatches to typed MsgQs
	// channels based on message type.
	//
	// This replaces the old pattern of reading from a single IncomingChan
	// in a dedicated goroutine. Each message type now fans out directly
	// to its own channel without a shared bottleneck.
	tm.Router.Use(transport.RouteToCallback(func(msg *transport.IncomingMessage) {
		tm.routeIncomingMessage(msg)
	}))

	lgTransport.Info("incoming message router registered via RouteToCallback")
}

// routeIncomingMessage routes an incoming DNS message to the appropriate hsyncengine channel.
func (tm *MPTransportBridge) routeIncomingMessage(msg *transport.IncomingMessage) {
	lgTransport.Debug("routing message", "type", msg.Type, "sender", msg.SenderID)

	switch msg.Type {
	case "hello":
		tm.routeHelloMessage(msg)
	case "beat":
		tm.routeBeatMessage(msg)
	case "ping":
		tm.routePingMessage(msg)
	case "sync", "update", "rfi":
		tm.routeSyncMessage(msg)
	case "keystate":
		tm.routeKeystateMessage(msg)
	case "edits":
		tm.routeEditsMessage(msg)
	case "config":
		tm.routeConfigMessage(msg)
	case "audit":
		tm.routeAuditMessage(msg)
	case "relocate":
		tm.routeRelocateMessage(msg)
	case "status-update":
		tm.routeStatusUpdateMessage(msg)
	case "confirm":
		// Already handled by Router's HandleConfirmation handler — nothing to do here
	default:
		lgTransport.Warn("unknown message type", "type", msg.Type)
	}
}

// routeHelloMessage routes a hello message to the hello channel.
func (tm *MPTransportBridge) routeHelloMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseHelloPayload(msg.Payload)
	if err != nil {
		lgTransport.Error("failed to parse hello payload", "err", err)
		return
	}

	// Authorization already verified by AuthorizationMiddleware in the router.
	// Messages reaching routeHelloMessage have passed middleware auth.
	senderID := payload.GetSenderID()
	lgTransport.Debug("processing authorized DNS hello", "sender", senderID)

	// DNS-37: Update PeerRegistry state (DNS hello accepted → INTRODUCING state)
	peer := tm.PeerRegistry.GetOrCreate(senderID)
	peer.SetState(transport.PeerStateIntroducing, "DNS hello accepted and authorized")
	peer.LastHelloReceived = time.Now()

	// Also update AgentRegistry if available (for backward compatibility)
	if tm.agentRegistry != nil {
		agent, exists := tm.agentRegistry.S.Get(AgentId(senderID))
		if exists {
			// Only transition to INTRODUCED if not already OPERATIONAL or better
			// This prevents Hello messages from downgrading state (e.g., after peer restart)
			if agent.DnsDetails.State < AgentStateIntroduced {
				agent.DnsDetails.State = AgentStateIntroduced
				lgTransport.Info("updated agent DNS state to INTRODUCED after receiving Hello", "agent", senderID)
			}
			agent.DnsDetails.HelloTime = time.Now()
			agent.DnsDetails.LastContactTime = time.Now()
			tm.agentRegistry.S.Set(agent.Identity, agent)
		} else {
			// DNS-56: Agent not in registry but authorized - trigger discovery
			// This ensures receiver can send beats back to sender
			lgTransport.Info("authorized Hello from unknown agent, triggering discovery", "agent", senderID)
			go func(peerID string) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				err := tm.DiscoverAndRegisterAgent(ctx, peerID)
				if err != nil {
					lgTransport.Error("discovery failed for agent", "agent", peerID, "err", err)
				} else {
					lgTransport.Info("successfully discovered agent, now in registry", "agent", peerID)
					// Update the newly discovered agent's DNS state to INTRODUCED
					if discoveredAgent, ok := tm.agentRegistry.S.Get(AgentId(peerID)); ok {
						discoveredAgent.DnsDetails.State = AgentStateIntroduced
						discoveredAgent.DnsDetails.HelloTime = time.Now()
						discoveredAgent.DnsDetails.LastContactTime = time.Now()
						tm.agentRegistry.S.Set(discoveredAgent.Identity, discoveredAgent)
						lgTransport.Info("updated discovered agent DNS state to INTRODUCED", "agent", peerID)
					}
				}
			}(senderID)
		}
	}

	// Convert to AgentMsgReport for the existing hsyncengine
	report := &AgentMsgReport{
		MessageType:    AgentMsgHello,
		Identity:       AgentId(senderID),
		DistributionID: msg.DistributionID,
	}

	if tm.msgQs == nil {
		lgTransport.Debug("hello authorized but no agent queues (signer mode), ignoring", "sender", senderID)
		return
	}

	select {
	case tm.msgQs.Hello <- report:
		lgTransport.Debug("routed DNS hello to hsyncengine", "sender", senderID, "state", "INTRODUCING", "distributionID", msg.DistributionID)
	default:
		lgTransport.Warn("hello channel full, dropping message", "sender", senderID)
	}
}

// routeBeatMessage routes a beat message to the heartbeat channel.
func (tm *MPTransportBridge) routeBeatMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseBeatPayload(msg.Payload)
	if err != nil {
		lgTransport.Error("failed to parse beat payload", "err", err)
		return
	}

	senderID := payload.GetSenderID() // Use helper method to get sender ID from either format

	// DNS-51: Authorization check for Beat messages
	// Beat includes Zones field (list of zones sender believes are shared)
	// Authorization already verified by AuthorizationMiddleware in the router.
	// Messages reaching routeBeatMessage have passed middleware auth.
	lgTransport.Debug("processing authorized DNS beat", "sender", senderID, "zones", payload.Zones)

	// DNS-37: Update peer state on successful beat
	peer := tm.PeerRegistry.GetOrCreate(senderID)
	peer.LastBeatReceived = time.Now()
	peer.SetState(transport.PeerStateOperational, "Beat received from operational peer")

	// Also update AgentRegistry if available
	if tm.agentRegistry != nil {
		agent, exists := tm.agentRegistry.S.Get(AgentId(senderID))
		if exists {
			wasOperational := agent.DnsDetails.State == AgentStateOperational
			agent.DnsDetails.State = AgentStateOperational
			agent.DnsDetails.LastContactTime = time.Now()
			tm.agentRegistry.S.Set(agent.Identity, agent)

			// When a peer first becomes operational, check if all configured peers
			// are now operational. Elections require full participation.
			if !wasOperational && tm.agentRegistry.LeaderElectionManager != nil {
				// NotifyPeerOperational handles both deferred elections and
				// new elections — it checks configured vs operational counts.
				tm.agentRegistry.LeaderElectionManager.NotifyPeerOperational(agent.Zones)
			}
		}
	}

	// Process gossip data if present
	if len(payload.Gossip) > 0 && tm.agentRegistry != nil && tm.agentRegistry.GossipStateTable != nil {
		var gossipMsgs []GossipMessage
		if err := json.Unmarshal(payload.Gossip, &gossipMsgs); err == nil {
			for i := range gossipMsgs {
				tm.agentRegistry.GossipStateTable.MergeGossip(&gossipMsgs[i])
			}
			lgTransport.Debug("merged gossip from incoming DNS beat", "sender", senderID, "groups", len(gossipMsgs))

			// Check group operational state after merge
			if tm.agentRegistry.ProviderGroupManager != nil {
				for i := range gossipMsgs {
					pg := tm.agentRegistry.ProviderGroupManager.GetGroup(gossipMsgs[i].GroupHash)
					if pg != nil {
						tm.agentRegistry.GossipStateTable.CheckGroupState(pg.GroupHash, pg.Members)
					}
				}
			}
		}
	}

	beatInterval := payload.MyBeatInterval
	if beatInterval == 0 {
		beatInterval = 30 // Default if not provided
	}

	// Propagate distribution ID from CHUNK qname into the report
	// (same pattern as DNS-87 fix for sync messages).
	distributionID := msg.DistributionID

	report := &AgentMsgReport{
		MessageType:    AgentMsgBeat,
		Identity:       AgentId(senderID),
		BeatInterval:   beatInterval,
		DistributionID: distributionID,
	}

	if tm.msgQs == nil {
		lgTransport.Debug("beat authorized but no agent queues (signer mode), ignoring", "sender", senderID)
		return
	}

	select {
	case tm.msgQs.Beat <- report:
		lgTransport.Debug("routed DNS beat to hsyncengine", "sender", senderID, "state", "OPERATIONAL", "distributionID", distributionID)
	default:
		lgTransport.Warn("beat channel full, dropping message", "sender", senderID)
	}
}

// routePingMessage updates peer liveness and routes to MsgQs.Ping.
// The DNS response was already sent synchronously by SendResponseMiddleware;
// this routing is for peer liveness tracking and counting.
func (tm *MPTransportBridge) routePingMessage(msg *transport.IncomingMessage) {
	senderID := msg.SenderID
	lgTransport.Debug("processing ping", "sender", senderID)

	// Update PeerRegistry liveness
	peer := tm.PeerRegistry.GetOrCreate(senderID)
	peer.LastBeatReceived = time.Now()
	peer.SetState(transport.PeerStateOperational, "ping received")

	report := &AgentMsgReport{
		MessageType:    AgentMsgPing,
		Identity:       AgentId(senderID),
		DistributionID: msg.DistributionID,
	}

	if tm.msgQs == nil {
		return
	}

	select {
	case tm.msgQs.Ping <- report:
		lgTransport.Debug("routed ping to MsgQs", "sender", senderID)
	default:
		lgTransport.Warn("ping channel full, dropping message", "sender", senderID)
	}
}

// routeSyncMessage routes a sync message to the message channel.
func (tm *MPTransportBridge) routeSyncMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseSyncPayload(msg.Payload)
	if err != nil {
		lgTransport.Error("failed to parse sync payload", "err", err)
		return
	}

	// The distribution ID is extracted from the CHUNK qname, not the JSON payload.
	// Propagate it into the parsed payload so downstream code (AgentMsgPost,
	// sendImmediateConfirmation) can access it uniformly.
	if msg.DistributionID != "" && payload.DistributionID == "" {
		payload.DistributionID = msg.DistributionID
	}

	senderID := payload.GetSenderID() // Use helper method to get sender ID from either format
	if senderID == "" && msg.TransportSender != "" {
		senderID = msg.TransportSender // Fallback to transport-level sender (from QNAME)
		lgTransport.Debug("payload had empty sender, using transport sender", "sender", senderID)
	}
	records := payload.GetRecords() // Use helper method to get records from either format
	zone := payload.Zone

	// Determine message type (sync, update, rfi, or status)
	messageType := AgentMsgNotify // Default to sync
	if payload.MessageType != "" {
		messageType = AgentMsg(payload.MessageType)
	}
	msgTypeStr := core.AgentMsgToString[core.AgentMsg(messageType)]

	// Authorization already verified by AuthorizationMiddleware in the router.
	// Messages reaching routeSyncMessage have passed middleware auth.
	lgTransport.Debug("processing authorized DNS message", "msgType", msgTypeStr, "sender", senderID, "zone", zone, "transportSender", msg.TransportSender)

	// Update peer state on successful message
	peer := tm.PeerRegistry.GetOrCreate(senderID)
	peer.SetState(transport.PeerStateOperational, fmt.Sprintf("%s received from operational peer", msgTypeStr))

	// Also update AgentRegistry if available
	if tm.agentRegistry != nil {
		agent, exists := tm.agentRegistry.S.Get(AgentId(senderID))
		if exists {
			agent.DnsDetails.LastContactTime = time.Now()
			tm.agentRegistry.S.Set(agent.Identity, agent)
		}
	}

	// DeliveredBy is the transport-level sender (from QNAME), which may differ from
	// the originator for forwarded messages. The combiner needs this to send confirmations
	// back to the agent that actually delivered the message, not the original author.
	deliveredBy := msg.TransportSender
	if deliveredBy == "" {
		deliveredBy = senderID // Fallback for direct delivery
	}

	// Ensure the transport sender (deliverer) has a PeerRegistry entry with an address.
	// For forwarded messages, the deliverer may be a remote agent not pre-registered in this
	// combiner's config. Trigger async discovery so the address is available for confirmation.
	if deliveredBy != senderID {
		deliverPeer := tm.PeerRegistry.GetOrCreate(deliveredBy)
		deliverPeer.SetState(transport.PeerStateOperational, fmt.Sprintf("delivered %s for %s", msgTypeStr, senderID))
		if deliverPeer.CurrentAddress() == nil {
			lgTransport.Info("transport sender has no address, triggering async discovery", "sender", deliveredBy)
			go func(peerID string) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := tm.DiscoverAndRegisterAgent(ctx, peerID); err != nil {
					lgTransport.Error("discovery failed for transport sender", "sender", peerID, "err", err)
				} else {
					lgTransport.Info("discovered transport sender", "sender", peerID)
				}
			}(deliveredBy)
		}
	}

	msgPost := &AgentMsgPostPlus{
		AgentMsgPost: AgentMsgPost{
			MessageType:    messageType,
			OriginatorID:   AgentId(senderID),
			DeliveredBy:    AgentId(deliveredBy),
			Zone:           ZoneName(zone),
			Records:        records,
			Operations:     payload.GetOperations(),
			Time:           time.Unix(payload.Timestamp, 0),
			RfiType:        payload.RfiType,        // Include RfiType for RFI messages
			RfiSubtype:     payload.RfiSubtype,     // Include RfiSubtype for CONFIG RFI messages
			DistributionID: payload.DistributionID, // Originating distID from sending agent
			Nonce:          msg.Nonce,              // Echo nonce from incoming message for confirmation
			ZoneClass:      payload.ZoneClass,
			Publish:        payload.GetPublish(),
		},
	}

	if tm.msgQs == nil {
		lgTransport.Debug("message authorized but no agent queues (signer mode), ignoring", "msgType", msgTypeStr, "sender", senderID)
		return
	}

	select {
	case tm.msgQs.Msg <- msgPost:
		lgTransport.Debug("routed DNS message to hsyncengine", "msgType", msgTypeStr, "sender", senderID, "zone", zone)

		// Send immediate "pending" confirmation back to originating agent (two-phase protocol).
		// This tells the originator "I received your sync" so it doesn't need to resend.
		// Only agents acting as relay (with an agentRegistry) send this — the combiner already
		// returned a "pending" ACK inline in the DNS response.
		if tm.agentRegistry != nil {
			go tm.sendImmediateConfirmation(payload)
		}
	default:
		lgTransport.Warn("message channel full, dropping message", "msgType", msgTypeStr, "sender", senderID)
	}
}

// routeKeystateMessage routes an incoming KEYSTATE message.
// For "inventory" signals, delivers the full key inventory to MsgQs.KeystateInventory
// so RequestAndWaitForKeyInventory can pick it up.
func (tm *MPTransportBridge) routeKeystateMessage(msg *transport.IncomingMessage) {
	var payload transport.DnsKeystatePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		lgTransport.Error("failed to parse keystate payload", "err", err)
		return
	}

	senderID := payload.GetSenderID()
	lgTransport.Debug("processing KEYSTATE", "signal", payload.Signal, "sender", senderID, "zone", payload.Zone)

	if payload.Signal != "inventory" {
		// Per-key signals (propagated/rejected/removed) go to the dedicated KeystateSignal channel
		// so the SignerMsgHandler can process them. Falls back to routeSyncMessage if the channel
		// is not available (e.g. on an agent where this signal doesn't apply).
		if tm.msgQs != nil && tm.msgQs.KeystateSignal != nil {
			sigMsg := &KeystateSignalMsg{
				SenderID: senderID,
				Zone:     payload.Zone,
				KeyTag:   payload.KeyTag,
				Signal:   payload.Signal,
				Message:  payload.Message,
			}
			select {
			case tm.msgQs.KeystateSignal <- sigMsg:
				lgTransport.Info("routed KEYSTATE signal", "signal", payload.Signal, "sender", senderID, "zone", payload.Zone, "keyTag", payload.KeyTag)
			default:
				lgTransport.Warn("KeystateSignal channel full, dropping", "signal", payload.Signal, "sender", senderID)
			}
		} else {
			lgTransport.Debug("non-inventory KEYSTATE, no KeystateSignal channel, routing to Msg queue", "signal", payload.Signal, "sender", senderID)
			tm.routeSyncMessage(msg)
		}
		return
	}

	if tm.msgQs == nil {
		lgTransport.Debug("KEYSTATE inventory but no MsgQs, ignoring", "sender", senderID)
		return
	}

	// Convert transport.KeyInventoryEntry → KeyInventoryItem for the channel
	items := make([]KeyInventoryItem, len(payload.KeyInventory))
	for i, e := range payload.KeyInventory {
		items[i] = KeyInventoryItem{
			KeyTag:    e.KeyTag,
			Algorithm: e.Algorithm,
			Flags:     e.Flags,
			State:     e.State,
			KeyRR:     e.KeyRR,
		}
	}

	inventoryMsg := &KeystateInventoryMsg{
		SenderID:  senderID,
		Zone:      payload.Zone,
		Inventory: items,
	}

	// If there's a pending RFI request waiting for this zone's inventory,
	// route there. Zone mismatches fall through to the shared channel.
	if ch, ok := tm.getKeystateRfi(payload.Zone); ok {
		select {
		case ch <- inventoryMsg:
			lgTransport.Info("routed KEYSTATE inventory to RFI requester", "sender", senderID, "zone", payload.Zone, "keys", len(items))
		default:
			lgTransport.Warn("keystateRfiChan full, dropping inventory", "sender", senderID)
		}
		return
	}

	select {
	case tm.msgQs.KeystateInventory <- inventoryMsg:
		lgTransport.Info("routed KEYSTATE inventory to agent", "sender", senderID, "zone", payload.Zone, "keys", len(items))
	default:
		lgTransport.Warn("KeystateInventory channel full, dropping inventory", "sender", senderID)
	}
}

// routeEditsMessage routes an incoming EDITS message from the combiner.
// Delivers the contributions to MsgQs.EditsResponse so RequestAndWaitForEdits can pick it up.
// Modeled on routeKeystateMessage.
func (tm *MPTransportBridge) routeEditsMessage(msg *transport.IncomingMessage) {
	var payload transport.DnsEditsPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		lgTransport.Error("failed to parse edits payload", "err", err)
		return
	}

	senderID := payload.GetSenderID()
	lgTransport.Debug("processing EDITS", "sender", senderID, "zone", payload.Zone)

	if tm.msgQs == nil {
		lgTransport.Debug("EDITS received but no MsgQs, ignoring", "sender", senderID)
		return
	}

	editsMsg := &EditsResponseMsg{
		SenderID:     senderID,
		Zone:         payload.Zone,
		AgentRecords: payload.AgentRecords,
	}

	select {
	case tm.msgQs.EditsResponse <- editsMsg:
		lgTransport.Info("routed EDITS response to agent", "sender", senderID, "zone", payload.Zone, "agents", len(payload.AgentRecords))
	default:
		lgTransport.Warn("EditsResponse channel full, dropping edits", "sender", senderID)
	}
}

// routeConfigMessage routes an incoming CONFIG response message from a peer agent.
// Delivers the config data to MsgQs.ConfigResponse so RequestAndWaitForConfig can pick it up.
func (tm *MPTransportBridge) routeConfigMessage(msg *transport.IncomingMessage) {
	var payload transport.DnsConfigPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		lgTransport.Error("failed to parse config payload", "err", err)
		return
	}

	senderID := payload.GetSenderID()
	lgTransport.Debug("processing CONFIG response", "sender", senderID, "zone", payload.Zone, "subtype", payload.Subtype)

	if tm.msgQs == nil {
		lgTransport.Debug("CONFIG received but no MsgQs, ignoring", "sender", senderID)
		return
	}

	configMsg := &ConfigResponseMsg{
		SenderID:   senderID,
		Zone:       payload.Zone,
		Subtype:    payload.Subtype,
		ConfigData: payload.ConfigData,
	}

	select {
	case tm.msgQs.ConfigResponse <- configMsg:
		lgTransport.Info("routed CONFIG response to agent", "sender", senderID, "zone", payload.Zone, "subtype", payload.Subtype)
	default:
		lgTransport.Warn("ConfigResponse channel full, dropping config", "sender", senderID)
	}
}

// sendConfigToAgent gathers config data for the given subtype and sends it as a separate
// CONFIG message back to the requesting agent. Called asynchronously from MsgHandler when
// an RFI CONFIG is received.
func sendConfigToAgent(tm *MPTransportBridge, ar *AgentRegistry, requesterID string, zone string, subtype string, configData map[string]string) {
	if tm == nil || tm.DNSTransport == nil {
		lgTransport.Warn("sendConfigToAgent: no DNSTransport available", "requester", requesterID)
		return
	}

	peer, peerExists := tm.PeerRegistry.Get(requesterID)
	if !peerExists || peer == nil {
		lgTransport.Warn("sendConfigToAgent: requester not in PeerRegistry", "requester", requesterID)
		return
	}

	req := &transport.ConfigRequest{
		SenderID:   ar.LocalAgent.Identity,
		Zone:       zone,
		Subtype:    subtype,
		ConfigData: configData,
		Timestamp:  time.Now(),
	}

	sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tm.DNSTransport.Config(sendCtx, peer, req)
	if err != nil {
		lgTransport.Error("sendConfigToAgent: failed to send", "requester", requesterID, "zone", zone, "subtype", subtype, "err", err)
		return
	}

	if !resp.Accepted {
		lgTransport.Error("sendConfigToAgent: config not accepted", "requester", requesterID, "zone", zone, "subtype", subtype, "accepted", resp.Accepted)
		return
	}
	lgTransport.Info("sendConfigToAgent: sent config to requester", "requester", requesterID, "zone", zone, "subtype", subtype)
}

// routeAuditMessage routes an incoming AUDIT response message from a peer agent.
// Delivers the audit data to MsgQs.AuditResponse so RequestAndWaitForAudit can pick it up.
func (tm *MPTransportBridge) routeAuditMessage(msg *transport.IncomingMessage) {
	var payload transport.DnsAuditPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		lgTransport.Error("failed to parse audit payload", "err", err)
		return
	}

	senderID := payload.GetSenderID()
	lgTransport.Debug("processing AUDIT response", "sender", senderID, "zone", payload.Zone)

	if tm.msgQs == nil {
		lgTransport.Debug("AUDIT received but no MsgQs, ignoring", "sender", senderID)
		return
	}

	auditMsg := &AuditResponseMsg{
		SenderID:  senderID,
		Zone:      payload.Zone,
		AuditData: payload.AuditData,
	}

	select {
	case tm.msgQs.AuditResponse <- auditMsg:
		lgTransport.Info("routed AUDIT response to agent", "sender", senderID, "zone", payload.Zone)
	default:
		lgTransport.Warn("AuditResponse channel full, dropping audit", "sender", senderID)
	}
}

// routeStatusUpdateMessage routes an incoming STATUS-UPDATE notification.
// Delivers to MsgQs.StatusUpdate for processing by the role-specific message handler.
func (tm *MPTransportBridge) routeStatusUpdateMessage(msg *transport.IncomingMessage) {
	var payload transport.DnsStatusUpdatePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		lgTransport.Error("failed to parse status-update payload", "err", err)
		return
	}

	senderID := payload.GetSenderID()
	lgTransport.Debug("processing STATUS-UPDATE", "sender", senderID, "zone", payload.Zone, "subtype", payload.SubType)

	if tm.msgQs == nil {
		lgTransport.Debug("STATUS-UPDATE received but no MsgQs, ignoring", "sender", senderID)
		return
	}

	statusMsg := &StatusUpdateMsg{
		SenderID:  senderID,
		Zone:      payload.Zone,
		SubType:   payload.SubType,
		NSRecords: payload.NSRecords,
		DSRecords: payload.DSRecords,
		Result:    payload.Result,
		Msg:       payload.Msg,
	}

	select {
	case tm.msgQs.StatusUpdate <- statusMsg:
		lgTransport.Info("routed STATUS-UPDATE to handler", "sender", senderID, "zone", payload.Zone, "subtype", payload.SubType)
	default:
		lgTransport.Warn("StatusUpdate channel full, dropping status-update", "sender", senderID)
	}
}

// sendAuditToAgent gathers audit data and sends it as a separate AUDIT message
// back to the requesting agent. Called asynchronously from MsgHandler when
// an RFI AUDIT is received.
func sendAuditToAgent(tm *MPTransportBridge, ar *AgentRegistry, requesterID string, zone string, auditData interface{}) {
	if tm == nil || tm.DNSTransport == nil {
		lgTransport.Warn("sendAuditToAgent: no DNSTransport available", "requester", requesterID)
		return
	}

	peer, peerExists := tm.PeerRegistry.Get(requesterID)
	if !peerExists || peer == nil {
		lgTransport.Warn("sendAuditToAgent: requester not in PeerRegistry", "requester", requesterID)
		return
	}

	req := &transport.AuditRequest{
		SenderID:  ar.LocalAgent.Identity,
		Zone:      zone,
		AuditData: auditData,
		Timestamp: time.Now(),
	}

	sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tm.DNSTransport.Audit(sendCtx, peer, req)
	if err != nil {
		lgTransport.Error("sendAuditToAgent: failed to send", "requester", requesterID, "zone", zone, "err", err)
		return
	}

	if !resp.Accepted {
		lgTransport.Error("sendAuditToAgent: audit not accepted", "requester", requesterID, "zone", zone, "accepted", resp.Accepted)
		return
	}
	lgTransport.Info("sendAuditToAgent: sent audit to requester", "requester", requesterID, "zone", zone)
}

// routeRelocateMessage handles a relocate request.
func (tm *MPTransportBridge) routeRelocateMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseRelocatePayload(msg.Payload)
	if err != nil {
		lgTransport.Error("failed to parse relocate payload", "err", err)
		return
	}

	// Authorization already verified by AuthorizationMiddleware in the router.
	// Messages reaching routeRelocateMessage have passed middleware auth.
	lgTransport.Debug("processing authorized DNS relocate", "sender", payload.SenderID)

	// Update peer's operational address
	peer, exists := tm.PeerRegistry.Get(payload.SenderID)
	if !exists {
		peer = tm.PeerRegistry.GetOrCreate(payload.SenderID)
	}

	peer.SetOperationalAddress(&transport.Address{
		Host:      payload.NewAddress.Host,
		Port:      payload.NewAddress.Port,
		Transport: payload.NewAddress.Transport,
		Path:      payload.NewAddress.Path,
	})

	lgTransport.Info("updated operational address", "peer", payload.SenderID, "host", payload.NewAddress.Host, "port", payload.NewAddress.Port, "reason", payload.Reason)
}

// sendSyncConfirmation sends a confirmation for a received sync message.
func (tm *MPTransportBridge) sendSyncConfirmation(msg *transport.IncomingMessage, payload *transport.DnsSyncPayload) {
	if tm.DNSTransport == nil {
		return
	}

	// Get or create peer
	senderID := payload.GetSenderID()
	peer, exists := tm.PeerRegistry.Get(senderID)
	if !exists {
		lgTransport.Warn("cannot send confirmation, peer not in registry", "peer", senderID)
		return
	}

	// Send confirmation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tm.DNSTransport.Confirm(ctx, peer, &transport.ConfirmRequest{
		SenderID:       tm.LocalID,
		Zone:           payload.Zone,
		DistributionID: payload.DistributionID,
		Status:         transport.ConfirmSuccess,
		Message:        "Sync received and processed",
		Timestamp:      time.Now(),
	})

	if err != nil {
		lgTransport.Error("failed to send confirmation", "distributionID", payload.DistributionID, "err", err)
	} else {
		lgTransport.Debug("sent confirmation for sync", "distributionID", payload.DistributionID)
	}
}

// sendImmediateConfirmation sends a "pending" confirmation back to the originating agent
// to indicate that the sync was received and is being processed. This is the first of two
// NOTIFYs in the two-phase remote confirmation protocol (Phase 5).
func (tm *MPTransportBridge) sendImmediateConfirmation(payload *transport.DnsSyncPayload) {
	if tm.DNSTransport == nil {
		return
	}

	senderID := payload.GetSenderID()
	if payload.DistributionID == "" {
		lgTransport.Warn("cannot send immediate confirmation, no distribution ID", "sender", senderID)
		return
	}

	peer, exists := tm.PeerRegistry.Get(senderID)
	if !exists {
		lgTransport.Warn("cannot send immediate confirmation, peer not in registry", "peer", senderID)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tm.DNSTransport.Confirm(ctx, peer, &transport.ConfirmRequest{
		SenderID:       tm.LocalID,
		Zone:           payload.Zone,
		DistributionID: payload.DistributionID,
		Nonce:          payload.Nonce,
		Status:         transport.ConfirmPending,
		Message:        "Sync received, forwarding to combiner",
		Timestamp:      time.Now(),
	})

	if err != nil {
		lgTransport.Error("failed to send immediate confirmation", "distributionID", payload.DistributionID, "peer", senderID, "err", err)
	} else {
		lgTransport.Debug("sent immediate (pending) confirmation", "distributionID", payload.DistributionID, "peer", senderID)
	}
}

// sendRemoteConfirmation sends the final confirmation NOTIFY back to the originating agent
// after the remote agent's combiner has confirmed the sync. This is the second of two
// NOTIFYs in the two-phase remote confirmation protocol (Phase 7).
func (tm *MPTransportBridge) sendRemoteConfirmation(detail *RemoteConfirmationDetail) {
	if tm.DNSTransport == nil {
		return
	}

	peer, exists := tm.PeerRegistry.Get(detail.OriginatingSender)
	if !exists {
		lgTransport.Warn("cannot send remote confirmation, peer not in registry", "peer", detail.OriginatingSender)
		return
	}

	var rejItems []transport.RejectedItemDTO
	for _, ri := range detail.RejectedItems {
		rejItems = append(rejItems, transport.RejectedItemDTO{Record: ri.Record, Reason: ri.Reason})
	}

	// Map status string back to ConfirmStatus
	status := transport.ConfirmSuccess
	switch detail.Status {
	case "PARTIAL":
		status = transport.ConfirmPartial
	case "FAILED":
		status = transport.ConfirmFailed
	case "REJECTED":
		status = transport.ConfirmRejected
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tm.DNSTransport.Confirm(ctx, peer, &transport.ConfirmRequest{
		SenderID:       tm.LocalID,
		Zone:           string(detail.Zone),
		DistributionID: detail.OriginatingDistID, // Use the originating agent's distID
		Status:         status,
		Message:        detail.Message,
		AppliedRecords: detail.AppliedRecords,
		RemovedRecords: detail.RemovedRecords,
		RejectedItems:  rejItems,
		Truncated:      detail.Truncated,
		Timestamp:      time.Now(),
	})

	if err != nil {
		lgTransport.Error("failed to send remote confirmation", "distributionID", detail.OriginatingDistID, "peer", detail.OriginatingSender, "err", err)
	} else {
		lgTransport.Info("sent remote confirmation", "distributionID", detail.OriginatingDistID, "peer", detail.OriginatingSender,
			"applied", len(detail.AppliedRecords), "removed", len(detail.RemovedRecords), "rejected", len(detail.RejectedItems))
	}
}

// SelectTransport selects the appropriate transport for communicating with a peer.
func (tm *MPTransportBridge) SelectTransport(peer *transport.Peer) transport.Transport {
	// Check peer's preferred transport
	switch peer.PreferredTransport {
	case "DNS":
		if tm.DNSTransport != nil && peer.CurrentAddress() != nil {
			return tm.DNSTransport
		}
	case "API":
		if tm.APITransport != nil && peer.APIEndpoint != "" {
			return tm.APITransport
		}
	}

	// Default: try API first (more reliable), then DNS
	if tm.APITransport != nil && peer.APIEndpoint != "" {
		return tm.APITransport
	}
	if tm.DNSTransport != nil && peer.CurrentAddress() != nil {
		return tm.DNSTransport
	}

	return nil
}

// SendWithFallback sends a message using the preferred transport, falling back if it fails.
func (tm *MPTransportBridge) SendSyncWithFallback(ctx context.Context, peer *transport.Peer, req *transport.SyncRequest) (*transport.SyncResponse, error) {
	// Try primary transport
	primary := tm.SelectTransport(peer)
	if primary != nil {
		resp, err := primary.Sync(ctx, peer, req)
		if err == nil {
			return resp, nil
		}
		lgConnRetry.Warn("primary transport failed", "transport", primary.Name(), "peer", peer.ID, "err", err)
	}

	// Try fallback transport
	var fallback transport.Transport
	if primary == tm.APITransport && tm.DNSTransport != nil {
		fallback = tm.DNSTransport
	} else if primary == tm.DNSTransport && tm.APITransport != nil {
		fallback = tm.APITransport
	}

	if fallback != nil {
		lgTransport.Debug("trying fallback transport", "transport", fallback.Name(), "peer", peer.ID)
		return fallback.Sync(ctx, peer, req)
	}

	return nil, fmt.Errorf("all transports failed for peer %s", peer.ID)
}

// SyncPeerFromAgent creates or updates a transport.Peer from an existing Agent.
func (tm *MPTransportBridge) SyncPeerFromAgent(agent *Agent) *transport.Peer {
	peer := tm.PeerRegistry.GetOrCreate(string(agent.Identity))

	// Sync API details
	if agent.ApiDetails != nil {
		peer.APIEndpoint = agent.ApiDetails.BaseUri
		if agent.ApiDetails.TlsaRR != nil {
			// Store TLSA for TLS verification
			peer.TLSARecord = []byte{} // Would need to serialize TLSA
		}
	}

	// Sync DNS details
	if agent.DnsDetails != nil && len(agent.DnsDetails.Addrs) > 0 {
		peer.SetDiscoveryAddress(&transport.Address{
			Host:      agent.DnsDetails.Addrs[0],
			Port:      agent.DnsDetails.Port,
			Transport: "udp",
		})
	}

	// Sync state
	if agent.ApiDetails != nil {
		peer.SetState(tm.agentStateToTransportState(agent.ApiDetails.State), "")
	}

	// Sync zones
	for zone := range agent.Zones {
		peer.AddSharedZone(string(zone), "", "")
	}

	return peer
}

// agentStateToTransportState converts AgentState to transport.PeerState.
func (tm *MPTransportBridge) agentStateToTransportState(state AgentState) transport.PeerState {
	switch state {
	case AgentStateNeeded:
		return transport.PeerStateNeeded
	case AgentStateKnown:
		return transport.PeerStateKnown
	case AgentStateIntroduced:
		return transport.PeerStateIntroducing
	case AgentStateOperational:
		return transport.PeerStateOperational
	case AgentStateDegraded:
		return transport.PeerStateDegraded
	case AgentStateInterrupted:
		return transport.PeerStateInterrupted
	case AgentStateError:
		return transport.PeerStateError
	default:
		return transport.PeerStateNeeded
	}
}

// SendHelloWithFallback sends a Hello handshake to a peer with transport fallback (legacy name).
// UPDATED: Now sends Hello on ALL supported transports independently when both are configured.
// Returns success if ANY transport succeeds. Updates per-transport state in Agent struct.
func (tm *MPTransportBridge) SendHelloWithFallback(ctx context.Context, agent *Agent, sharedZones []string) (*transport.HelloResponse, error) {
	peer := tm.SyncPeerFromAgent(agent)

	req := &transport.HelloRequest{
		SenderID:     tm.LocalID,
		Capabilities: []string{"sync", "beat", "relocate"},
		SharedZones:  sharedZones,
		Timestamp:    time.Now(),
	}

	var apiResp *transport.HelloResponse
	var dnsResp *transport.HelloResponse
	var apiErr error
	var dnsErr error

	// Try API transport if locally supported, available, has valid endpoint, and actually needs Hello (state == KNOWN).
	// Skip if already INTRODUCED or OPERATIONAL — no point sending Hello to an already-established transport.
	if tm.APITransport != nil && tm.isTransportSupported("api") && agent.ApiMethod && agent.ApiDetails != nil && agent.ApiDetails.BaseUri != "" && agent.ApiDetails.State == AgentStateKnown {
		apiResp, apiErr = tm.APITransport.Hello(ctx, peer, req)
		agent.Mu.Lock()
		if apiErr != nil {
			lgConnRetry.Warn("API Hello failed", "peer", peer.ID, "err", apiErr)
			agent.ApiDetails.LatestError = apiErr.Error()
			agent.ApiDetails.LatestErrorTime = time.Now()
		} else if apiResp != nil && !apiResp.Accepted {
			lgTransport.Warn("API Hello not accepted", "peer", peer.ID, "reason", apiResp.RejectReason)
			agent.ApiDetails.LatestError = apiResp.RejectReason
			agent.ApiDetails.LatestErrorTime = time.Now()
		} else {
			lgTransport.Info("API Hello succeeded", "peer", peer.ID)
			// Only transition to INTRODUCED if not already OPERATIONAL or better
			// This prevents Hello messages from downgrading state (e.g., after retry or peer restart)
			if agent.ApiDetails.State < AgentStateIntroduced {
				agent.ApiDetails.State = AgentStateIntroduced
				lgTransport.Info("updated agent API state to INTRODUCED after successful Hello", "agent", peer.ID)
			}
			agent.ApiDetails.HelloTime = time.Now()
			agent.ApiDetails.LastContactTime = time.Now()
			agent.ApiDetails.LatestError = ""
		}
		agent.Mu.Unlock()
	}

	// Try DNS transport if supported and actually needs Hello (state == KNOWN).
	// Skip if already INTRODUCED or OPERATIONAL — no point sending Hello to an already-established transport.
	if tm.DNSTransport != nil && agent.DnsMethod && tm.isTransportSupported("dns") && agent.DnsDetails.State == AgentStateKnown {
		dnsResp, dnsErr = tm.DNSTransport.Hello(ctx, peer, req)
		agent.Mu.Lock()
		if dnsErr != nil {
			lgConnRetry.Warn("DNS Hello failed", "peer", peer.ID, "err", dnsErr)
			agent.DnsDetails.LatestError = dnsErr.Error()
			agent.DnsDetails.LatestErrorTime = time.Now()
		} else if dnsResp != nil && !dnsResp.Accepted {
			lgTransport.Warn("DNS Hello not accepted", "peer", peer.ID, "reason", dnsResp.RejectReason)
			agent.DnsDetails.LatestError = dnsResp.RejectReason
			agent.DnsDetails.LatestErrorTime = time.Now()
		} else {
			lgTransport.Info("DNS Hello succeeded", "peer", peer.ID)
			// Only transition to INTRODUCED if not already OPERATIONAL or better
			// This prevents Hello messages from downgrading state (e.g., after retry or peer restart)
			if agent.DnsDetails.State < AgentStateIntroduced {
				agent.DnsDetails.State = AgentStateIntroduced
				lgTransport.Info("updated agent DNS state to INTRODUCED after successful Hello", "agent", peer.ID)
			}
			agent.DnsDetails.HelloTime = time.Now()
			agent.DnsDetails.LastContactTime = time.Now()
			agent.DnsDetails.LatestError = ""
		}
		agent.Mu.Unlock()
	}

	// Return success if ANY transport succeeded this call.
	if apiErr == nil && apiResp != nil && apiResp.Accepted {
		return apiResp, nil
	}
	if dnsErr == nil && dnsResp != nil && dnsResp.Accepted {
		return dnsResp, nil
	}

	// If a transport was skipped (already past KNOWN) and no transport actively failed,
	// treat that as success — the peer is already introduced on that transport.
	if agent.DnsDetails != nil && agent.DnsDetails.State >= AgentStateIntroduced && dnsErr == nil {
		return nil, nil
	}
	if agent.ApiDetails != nil && agent.ApiDetails.State >= AgentStateIntroduced && apiErr == nil {
		return nil, nil
	}

	// Both failed or skipped with nothing established
	if apiResp == nil && dnsResp == nil && apiErr == nil && dnsErr == nil {
		// No transport was in KNOWN state — nothing to do
		return nil, fmt.Errorf("no transports in KNOWN state for Hello to peer %s (API: %s, DNS: %s)",
			peer.ID, AgentStateToString[agent.ApiDetails.State], AgentStateToString[agent.DnsDetails.State])
	}
	return nil, fmt.Errorf("all transports failed for Hello to peer %s (API: %v, DNS: %v)", peer.ID, apiErr, dnsErr)
}

// SendPing sends a ping to a peer, preferring API transport when available.
func (tm *MPTransportBridge) SendPing(ctx context.Context, peer *transport.Peer) (*transport.PingResponse, error) {
	req := &transport.PingRequest{
		SenderID:  tm.LocalID,
		Nonce:     generatePingNonce(),
		Timestamp: time.Now(),
	}
	if tm.APITransport != nil && peer.APIEndpoint != "" {
		return tm.APITransport.Ping(ctx, peer, req)
	}
	if tm.DNSTransport != nil && peer.CurrentAddress() != nil {
		return tm.DNSTransport.Ping(ctx, peer, req)
	}
	return nil, fmt.Errorf("no transport available for ping to %s", peer.ID)
}

// SendBeatWithFallback sends a heartbeat to a peer with transport fallback.
// SendBeatWithFallback sends a Beat heartbeat to a peer (legacy name).
// UPDATED: Now sends Beat on ALL supported transports independently when both are configured.
// Returns success if ANY transport succeeds. Updates per-transport LastContactTime in Agent struct.
func (tm *MPTransportBridge) SendBeatWithFallback(ctx context.Context, agent *Agent, sequence uint64) (*transport.BeatResponse, error) {
	peer := tm.SyncPeerFromAgent(agent)

	// Build gossip for this peer
	var gossipData json.RawMessage
	if tm.agentRegistry != nil && tm.agentRegistry.GossipStateTable != nil && tm.agentRegistry.ProviderGroupManager != nil {
		gossipMsgs := tm.agentRegistry.GossipStateTable.BuildGossipForPeer(
			string(agent.Identity), tm.agentRegistry.ProviderGroupManager, tm.agentRegistry.LeaderElectionManager)
		if len(gossipMsgs) > 0 {
			gossipData, _ = json.Marshal(gossipMsgs)
		}
	}

	req := &transport.BeatRequest{
		SenderID:  tm.LocalID,
		Timestamp: time.Now(),
		Sequence:  sequence,
		State:     string(agent.State),
		Gossip:    gossipData,
	}

	var apiResp *transport.BeatResponse
	var dnsResp *transport.BeatResponse
	var apiErr error
	var dnsErr error

	// Try API transport if locally supported, available, has valid endpoint, and OPERATIONAL/LEGACY
	if tm.APITransport != nil && tm.isTransportSupported("api") && agent.ApiMethod && agent.ApiDetails != nil && agent.ApiDetails.BaseUri != "" {
		if agent.ApiDetails.State == AgentStateOperational || agent.ApiDetails.State == AgentStateIntroduced || agent.ApiDetails.State == AgentStateLegacy {
			apiResp, apiErr = tm.APITransport.Beat(ctx, peer, req)
			agent.Mu.Lock()
			if apiErr != nil {
				lgConnRetry.Debug("API Beat failed", "peer", peer.ID, "err", apiErr)
				agent.ApiDetails.LatestError = apiErr.Error()
				agent.ApiDetails.LatestErrorTime = time.Now()
			} else if apiResp != nil && !apiResp.Ack {
				lgTransport.Debug("API Beat no confirmation (Ack=false)", "peer", peer.ID)
				agent.ApiDetails.LatestError = "beat sent but not confirmed by peer"
				agent.ApiDetails.LatestErrorTime = time.Now()
			} else {
				lgTransport.Debug("API Beat succeeded", "peer", peer.ID)
				agent.ApiDetails.State = AgentStateOperational
				agent.ApiDetails.LastContactTime = time.Now()
				agent.ApiDetails.LatestRBeat = time.Now()
				agent.ApiDetails.ReceivedBeats++
				agent.ApiDetails.LatestError = ""
			}
			agent.Mu.Unlock()
		}
	}

	// Try DNS transport if supported and OPERATIONAL/LEGACY
	if tm.DNSTransport != nil && agent.DnsMethod && tm.isTransportSupported("dns") {
		if agent.DnsDetails.State == AgentStateOperational || agent.DnsDetails.State == AgentStateIntroduced || agent.DnsDetails.State == AgentStateLegacy {
			dnsResp, dnsErr = tm.DNSTransport.Beat(ctx, peer, req)
			agent.Mu.Lock()
			if dnsErr != nil {
				lgConnRetry.Debug("DNS Beat failed", "peer", peer.ID, "err", dnsErr)
				agent.DnsDetails.LatestError = dnsErr.Error()
				agent.DnsDetails.LatestErrorTime = time.Now()
			} else if dnsResp != nil && !dnsResp.Ack {
				// Beat() returns nil error but Ack:false when EDNS0 confirmation is missing.
				// This means the DNS response was received but the peer didn't confirm processing.
				lgTransport.Debug("DNS Beat no confirmation (Ack=false)", "peer", peer.ID)
				agent.DnsDetails.LatestError = "beat sent but not confirmed by peer"
				agent.DnsDetails.LatestErrorTime = time.Now()
			} else {
				lgTransport.Debug("DNS Beat succeeded", "peer", peer.ID)
				agent.DnsDetails.State = AgentStateOperational
				agent.DnsDetails.LastContactTime = time.Now()
				agent.DnsDetails.LatestRBeat = time.Now()
				agent.DnsDetails.ReceivedBeats++
				agent.DnsDetails.LatestError = ""
			}
			agent.Mu.Unlock()
		}
	}

	// Merge gossip from beat responses (bidirectional gossip exchange)
	if tm.agentRegistry != nil && tm.agentRegistry.GossipStateTable != nil && tm.agentRegistry.ProviderGroupManager != nil {
		for _, resp := range []*transport.BeatResponse{apiResp, dnsResp} {
			if resp == nil || len(resp.Gossip) == 0 {
				continue
			}
			var gossipMsgs []GossipMessage
			if err := json.Unmarshal(resp.Gossip, &gossipMsgs); err == nil {
				for i := range gossipMsgs {
					tm.agentRegistry.GossipStateTable.MergeGossip(&gossipMsgs[i])
					// Re-evaluate group state after merge (may trigger elections)
					pg := tm.agentRegistry.ProviderGroupManager.GetGroup(gossipMsgs[i].GroupHash)
					if pg != nil {
						tm.agentRegistry.GossipStateTable.CheckGroupState(gossipMsgs[i].GroupHash, pg.Members)
					}
				}
				lgTransport.Debug("merged gossip from beat response EDNS(0) CHUNK", "peer", peer.ID, "groups", len(gossipMsgs))
			}
		}
	}

	// Return success if ANY transport succeeded
	if apiErr == nil && apiResp != nil {
		return apiResp, nil
	}
	if dnsErr == nil && dnsResp != nil {
		return dnsResp, nil
	}

	// Both failed
	return nil, fmt.Errorf("all transports failed for Beat to peer %s (API: %v, DNS: %v)", peer.ID, apiErr, dnsErr)
}

// OnAgentDiscoveryComplete is called when agent discovery completes.
// It syncs the Agent to a transport.Peer and sets preferred transport.
func (tm *MPTransportBridge) OnAgentDiscoveryComplete(agent *Agent) {
	peer := tm.SyncPeerFromAgent(agent)

	// Set preferred transport based on what's available
	if agent.ApiMethod && agent.DnsMethod {
		// Both available - prefer API (more reliable)
		peer.PreferredTransport = "API"
		lgTransport.Info("agent has both API and DNS, preferring API", "agent", agent.Identity)
	} else if agent.ApiMethod {
		peer.PreferredTransport = "API"
		lgTransport.Info("agent has API only", "agent", agent.Identity)
	} else if agent.DnsMethod {
		peer.PreferredTransport = "DNS"
		lgTransport.Info("agent has DNS only", "agent", agent.Identity)
	}

	// Update peer state
	peer.SetState(transport.PeerStateKnown, "discovery complete")

	lgTransport.Info("agent discovery complete, peer synced", "agent", agent.Identity, "preferredTransport", peer.PreferredTransport)
}

// GetPreferredTransportName returns the preferred transport name for an agent.
func (tm *MPTransportBridge) GetPreferredTransportName(agent *Agent) string {
	if agent.ApiMethod && agent.DnsMethod {
		return "API" // Prefer API when both available
	} else if agent.ApiMethod {
		return "API"
	} else if agent.DnsMethod {
		return "DNS"
	}
	return "none"
}

// HasDNSTransport returns true if DNS transport is available for an agent.
func (tm *MPTransportBridge) HasDNSTransport(agent *Agent) bool {
	return tm.DNSTransport != nil && agent.DnsMethod
}

// HasAPITransport returns true if API transport is available for an agent.
func (tm *MPTransportBridge) HasAPITransport(agent *Agent) bool {
	return tm.APITransport != nil && agent.ApiMethod
}

// --- Reliable message queue integration ---

// StartReliableQueue wires up the sendFunc and starts the queue's background worker.
// Must be called after MPTransportBridge is fully initialized (transports, combiner peer, etc.).
func (tm *MPTransportBridge) StartReliableQueue(ctx context.Context) {
	if tm.ReliableQueue == nil {
		lgTransport.Info("no reliable queue configured, skipping")
		return
	}

	// Wire sendFunc: adapts generic transport.OutgoingMessage to MP delivery logic.
	tm.TransportManager.StartReliableQueue(ctx, func(ctx context.Context, msg *transport.OutgoingMessage) error {
		return tm.deliverGenericMessage(ctx, msg)
	})
}

// deliverGenericMessage is the sendFunc for the generic RMQ.
// It adapts a transport.OutgoingMessage to the existing MP delivery logic.
func (tm *MPTransportBridge) deliverGenericMessage(ctx context.Context, msg *transport.OutgoingMessage) error {
	update, ok := msg.Payload.(*ZoneUpdate)
	if !ok {
		lgTransport.Warn("deliverGenericMessage: payload is not *ZoneUpdate", "recipient", msg.RecipientID, "payloadType", fmt.Sprintf("%T", msg.Payload))
	}

	if tm.agentRegistry == nil {
		return fmt.Errorf("no agent registry")
	}

	agent, exists := tm.agentRegistry.S.Get(AgentId(msg.RecipientID))
	if !exists {
		return fmt.Errorf("recipient %q not found in AgentRegistry", msg.RecipientID)
	}

	peer := tm.SyncPeerFromAgent(agent)
	isCombiner := AgentId(msg.RecipientID) == tm.combinerID

	// Build sync request
	senderID := tm.LocalID
	messageType := "sync"
	if isCombiner {
		messageType = "update"
		if update != nil && update.AgentId != "" {
			senderID = string(update.AgentId)
		}
	}

	syncReq := &transport.SyncRequest{
		SenderID:       senderID,
		Zone:           msg.Zone,
		Timestamp:      msg.CreatedAt,
		DistributionID: msg.DistributionID,
		Nonce:          msg.Nonce,
		MessageType:    messageType,
	}
	if update != nil {
		syncReq.Operations = update.Operations
		if isCombiner {
			syncReq.ZoneClass = update.ZoneClass
			if update.Publish != nil {
				syncReq.Publish = update.Publish
			}
		}
	}

	syncResp, err := tm.SendSyncWithFallback(ctx, peer, syncReq)

	// Forward per-RR detail from inline confirmation to SynchedDataEngine (combiner only)
	if isCombiner && syncResp != nil && tm.msgQs != nil && tm.msgQs.Confirmation != nil {
		var rejItems []RejectedItemInfo
		for _, ri := range syncResp.RejectedItems {
			rejItems = append(rejItems, RejectedItemInfo{Record: ri.Record, Reason: ri.Reason})
		}
		detail := &ConfirmationDetail{
			DistributionID: msg.DistributionID,
			Zone:           ZoneName(msg.Zone),
			Source:         msg.RecipientID,
			Status:         syncResp.Status.String(),
			Message:        syncResp.Message,
			AppliedRecords: syncResp.AppliedRecords,
			RemovedRecords: syncResp.RemovedRecords,
			RejectedItems:  rejItems,
			Truncated:      syncResp.Truncated,
			Timestamp:      time.Now(),
		}
		select {
		case tm.msgQs.Confirmation <- detail:
		default:
			lgTransport.Warn("confirmation channel full, dropping inline detail", "distributionID", msg.DistributionID)
		}
	}

	return err
}

// EnqueueForCombiner enqueues a zone update for reliable delivery to the combiner.
// Called by SynchedDataEngine when a zone update needs to reach the combiner.
// If distID is non-empty, it is used as the distribution ID; otherwise a new one is generated.
// Returns the distributionID for tracking and any error.
func (tm *MPTransportBridge) EnqueueForCombiner(zone ZoneName, update *ZoneUpdate, distID string) (string, error) {
	combinerID, err := tm.getCombinerID()
	if err != nil {
		return "", fmt.Errorf("EnqueueForCombiner: %w", err)
	}

	if distID == "" {
		distID = transport.GenerateDistributionID()
	}
	msg := &transport.OutgoingMessage{
		DistributionID: distID,
		RecipientID:    string(combinerID),
		Zone:           string(zone),
		Payload:        update,
		Priority:       transport.PriorityHigh,
	}

	return distID, tm.ReliableQueue.Enqueue(msg)
}

// EnqueueForZoneAgents enqueues a zone update for reliable delivery to all
// remote agents involved with this zone (as determined by AgentRegistry).
// Called by SynchedDataEngine when a locally-originated update needs to
// reach all peer agents. Uses the same distID for all agents so the
// originating agent can correlate confirmations from combiner and agents.
func (tm *MPTransportBridge) EnqueueForZoneAgents(zone ZoneName, update *ZoneUpdate, distID string) error {
	agents, err := tm.getAllAgentsForZone(zone)
	if err != nil {
		return fmt.Errorf("EnqueueForZoneAgents: %w", err)
	}

	if len(agents) == 0 {
		lgTransport.Debug("no remote agents for zone, nothing to enqueue", "zone", zone)
		return nil
	}

	var enqueueErrors []string
	for _, agentID := range agents {
		msg := &transport.OutgoingMessage{
			DistributionID: distID,
			RecipientID:    string(agentID),
			Zone:           string(zone),
			Payload:        update,
			Priority:       transport.PriorityNormal,
		}

		if err := tm.ReliableQueue.Enqueue(msg); err != nil {
			enqueueErrors = append(enqueueErrors, fmt.Sprintf("%s: %v", agentID, err))
		}
	}

	if len(enqueueErrors) > 0 {
		return fmt.Errorf("failed to enqueue for some agents: %v", enqueueErrors)
	}

	lgTransport.Info("enqueued zone update for agents", "count", len(agents), "zone", zone, "distributionID", distID)
	return nil
}

// EnqueueForSpecificAgent enqueues a zone update for a single agent.
// Used by "resync-targeted" to respond only to the requesting agent.
func (tm *MPTransportBridge) EnqueueForSpecificAgent(zone ZoneName, agentID AgentId, update *ZoneUpdate, distID string) error {
	if tm.ReliableQueue == nil {
		return fmt.Errorf("EnqueueForSpecificAgent: reliable queue not configured")
	}

	msg := &transport.OutgoingMessage{
		DistributionID: distID,
		RecipientID:    string(agentID),
		Zone:           string(zone),
		Payload:        update,
		Priority:       transport.PriorityNormal,
	}

	if err := tm.ReliableQueue.Enqueue(msg); err != nil {
		return fmt.Errorf("EnqueueForSpecificAgent: %s: %w", agentID, err)
	}

	lgTransport.Info("enqueued zone update for specific agent", "agent", agentID, "zone", zone, "distributionID", distID)
	return nil
}

// GetQueueStats returns statistics from the reliable message queue.
func (tm *MPTransportBridge) GetQueueStats() transport.QueueStats {
	if tm.ReliableQueue == nil {
		return transport.QueueStats{}
	}
	return tm.ReliableQueue.GetStats()
}

// GetQueuePendingMessages returns a snapshot of all pending messages in the queue.
func (tm *MPTransportBridge) GetQueuePendingMessages() []transport.PendingMessageInfo {
	if tm.ReliableQueue == nil {
		return nil
	}
	return tm.ReliableQueue.GetPendingMessages()
}

// MarkDeliveryConfirmed marks a queued message as confirmed by the recipient.
// senderID is the identity of the confirming party (= the original message recipient).
func (tm *MPTransportBridge) MarkDeliveryConfirmed(distributionID string, senderID string) bool {
	if tm.ReliableQueue == nil {
		return false
	}
	return tm.ReliableQueue.MarkConfirmed(distributionID, senderID)
}

// --- Helper methods ---

// getCombinerID returns the combiner's AgentId, set at construction time from config.
func (tm *MPTransportBridge) getCombinerID() (AgentId, error) {
	if tm.combinerID != "" {
		return tm.combinerID, nil
	}
	return "", fmt.Errorf("combiner ID not configured")
}

// getAllAgentsForZone returns the AgentIds of all remote agents for a zone.
// Uses AgentRegistry.GetZoneAgentData() which reads the HSYNC RRset.
func (tm *MPTransportBridge) getAllAgentsForZone(zone ZoneName) ([]AgentId, error) {
	if tm.agentRegistry == nil {
		return nil, fmt.Errorf("no agent registry")
	}

	zad, err := tm.agentRegistry.GetZoneAgentData(zone)
	if err != nil {
		return nil, err
	}

	var agents []AgentId
	for _, agent := range zad.Agents {
		agents = append(agents, agent.Identity)
	}

	return agents, nil
}

// GetDistributionRecipients returns the list of recipient identities that will
// receive an update for the given zone. This is used by the SynchedDataEngine to
// populate TrackedRR.ExpectedRecipients so that ProcessConfirmation knows who
// must confirm before transitioning Pending → Accepted.
// If skipCombiner is true, the combiner is excluded from the list.
func (tm *MPTransportBridge) GetDistributionRecipients(zone ZoneName, skipCombiner bool) []string {
	var recipients []string

	// Add combiner unless skipped
	if !skipCombiner && tm.combinerID != "" {
		recipients = append(recipients, string(tm.combinerID))
	}

	// Add all remote agents for this zone
	agents, err := tm.getAllAgentsForZone(zone)
	if err != nil {
		lgTransport.Error("failed to get zone agents", "zone", zone, "err", err)
	} else {
		for _, a := range agents {
			recipients = append(recipients, string(a))
		}
	}

	return recipients
}

// groupRRStringsByOwner converts a flat list of RR strings to records grouped by owner name.
// Used when converting from management commands (AgentMgmtPost.RRs []string) to the
// grouped format used by AgentMsgPost.Records and SyncRequest.Records.
func groupRRStringsByOwner(rrStrings []string) map[string][]string {
	records := make(map[string][]string)
	for _, rrStr := range rrStrings {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			lgTransport.Warn("skipping unparseable RR", "rr", rrStr, "err", err)
			continue
		}
		owner := rr.Header().Name
		records[owner] = append(records[owner], rrStr)
	}
	return records
}

// --- Phase 6: DNSKEY Propagation Tracking and KEYSTATE Signaling ---

// PendingDnskeyPropagation tracks a DNSKEY distribution awaiting confirmation from all remote agents.
type PendingDnskeyPropagation struct {
	Zone           ZoneName
	DistributionID string
	KeyTags        []uint16         // DNSKEY key tags being propagated
	ExpectedAgents map[AgentId]bool // Agents we're waiting for (true = confirmed)
	Rejected       bool             // True if any agent rejected
	RejectionMsg   string           // First rejection reason
	CreatedAt      time.Time
}

// TrackDnskeyPropagation registers a DNSKEY distribution for confirmation tracking.
// Called by SynchedDataEngine after enqueueing DNSKEY changes for remote agents.
func (tm *MPTransportBridge) TrackDnskeyPropagation(zone ZoneName, distID string, keyTags []uint16, agents []AgentId) {
	tm.dnskeyPropMu.Lock()
	defer tm.dnskeyPropMu.Unlock()

	expected := make(map[AgentId]bool, len(agents))
	for _, a := range agents {
		expected[a] = false // false = not yet confirmed
	}

	tm.pendingDnskeyPropagations[distID] = &PendingDnskeyPropagation{
		Zone:           zone,
		DistributionID: distID,
		KeyTags:        keyTags,
		ExpectedAgents: expected,
		CreatedAt:      time.Now(),
	}

	lgTransport.Info("tracking DNSKEY propagation", "zone", zone, "distributionID", distID, "agents", len(agents), "keyTags", len(keyTags))
}

// ProcessDnskeyConfirmation checks if a confirmation is for a pending DNSKEY propagation.
// If so, marks the agent as confirmed. When all agents have confirmed, sends KEYSTATE
// "propagated" to the signer. If any agent rejects, sends KEYSTATE "rejected".
// Returns true if this confirmation was for a DNSKEY propagation (handled here).
func (tm *MPTransportBridge) ProcessDnskeyConfirmation(distID string, source string, status string, rejectedItems []RejectedItemInfo) bool {
	tm.dnskeyPropMu.Lock()
	defer tm.dnskeyPropMu.Unlock()

	prop, exists := tm.pendingDnskeyPropagations[distID]
	if !exists {
		return false // Not a DNSKEY propagation confirmation
	}

	agentID := AgentId(source)

	// Check for rejection
	if len(rejectedItems) > 0 {
		prop.Rejected = true
		if prop.RejectionMsg == "" {
			prop.RejectionMsg = rejectedItems[0].Reason
		}
		lgTransport.Warn("DNSKEY confirmation rejected", "zone", prop.Zone, "distributionID", distID, "agent", source, "reason", prop.RejectionMsg)
	}

	// Mark this agent as confirmed
	if _, expected := prop.ExpectedAgents[agentID]; expected {
		prop.ExpectedAgents[agentID] = true
		lgTransport.Info("DNSKEY confirmation received", "zone", prop.Zone, "distributionID", distID, "agent", source, "status", status)
	}

	// Check if all agents have confirmed
	allConfirmed := true
	for _, confirmed := range prop.ExpectedAgents {
		if !confirmed {
			allConfirmed = false
			break
		}
	}

	if !allConfirmed {
		return true // Still waiting for more confirmations
	}

	// All agents confirmed — send KEYSTATE to signer
	lgTransport.Info("all agents confirmed DNSKEY propagation", "zone", prop.Zone, "distributionID", distID, "agents", len(prop.ExpectedAgents), "rejected", prop.Rejected)

	// Send KEYSTATE asynchronously (don't hold the mutex)
	zone := prop.Zone
	keyTags := prop.KeyTags
	rejected := prop.Rejected
	rejectionMsg := prop.RejectionMsg
	delete(tm.pendingDnskeyPropagations, distID)

	go func() {
		if rejected {
			tm.sendKeystateToSigner(zone, keyTags, "rejected", rejectionMsg)
		} else {
			tm.sendKeystateToSigner(zone, keyTags, "propagated", "all remote agents confirmed")
		}
	}()

	return true
}

// sendKeystateToSigner sends a KEYSTATE message to the local signer.
// signal is "propagated", "rejected", or "removed".
func (tm *MPTransportBridge) sendKeystateToSigner(zone ZoneName, keyTags []uint16, signal string, message string) {
	if tm.signerID == "" || tm.signerAddress == "" {
		lgTransport.Warn("no signer configured, cannot send KEYSTATE", "zone", zone, "signerID", tm.signerID, "signerAddress", tm.signerAddress, "signal", signal)
		return
	}

	if tm.DNSTransport == nil {
		lgTransport.Warn("no DNS transport available, cannot send KEYSTATE", "zone", zone, "signal", signal)
		return
	}

	// Get or create signer peer
	peer := tm.PeerRegistry.GetOrCreate(tm.signerID)
	// Parse address into host:port
	host, port := parseHostPort(tm.signerAddress, 53)
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      port,
		Transport: "udp",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Send one KEYSTATE per key tag
	for _, keyTag := range keyTags {
		req := &transport.KeystateRequest{
			SenderID:  tm.LocalID,
			Zone:      string(zone),
			KeyTag:    keyTag,
			Signal:    signal,
			Message:   message,
			Timestamp: time.Now(),
		}

		resp, err := tm.DNSTransport.Keystate(ctx, peer, req)
		if err != nil {
			lgTransport.Error("KEYSTATE send to signer failed", "zone", zone, "keyTag", keyTag, "signal", signal, "err", err)
			continue
		}

		lgTransport.Info("KEYSTATE sent to signer", "zone", zone, "keyTag", keyTag, "signal", signal, "signer", tm.signerID, "accepted", resp.Accepted, "msg", resp.Message)
	}
}

// parseHostPort splits an address into host and port, defaulting to defaultPort.
func parseHostPort(addr string, defaultPort uint16) (string, uint16) {
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		host := addr[:idx]
		portStr := addr[idx+1:]
		var port uint16
		if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil {
			return host, port
		}
	}
	return addr, defaultPort
}

// sendRfiToSigner sends an RFI message to the signer (e.g. RFI KEYSTATE to request inventory).
// Returns the ACK from the signer. The actual data comes back as a separate KEYSTATE message.
func (tm *MPTransportBridge) sendRfiToSigner(zone string, rfiType string) error {
	if tm.signerID == "" || tm.signerAddress == "" {
		return fmt.Errorf("no signer configured (signerID=%q, signerAddress=%q)", tm.signerID, tm.signerAddress)
	}

	// Get or create signer peer with address
	peer := tm.PeerRegistry.GetOrCreate(tm.signerID)
	host, port := parseHostPort(tm.signerAddress, 53)
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      port,
		Transport: "udp",
	})

	syncReq := &transport.SyncRequest{
		SenderID:    tm.LocalID,
		Zone:        zone,
		Timestamp:   time.Now(),
		MessageType: "rfi",
		RfiType:     rfiType,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tm.SendSyncWithFallback(ctx, peer, syncReq)
	if err != nil {
		return fmt.Errorf("RFI %s to signer %s failed: %w", rfiType, tm.signerID, err)
	}

	lgTransport.Info("RFI sent to signer", "rfiType", rfiType, "zone", zone, "signer", tm.signerID, "status", resp.Status)
	return nil
}

// sendRfiToCombiner sends an RFI message to the combiner (e.g. RFI EDITS to request contributions).
// Modeled on sendRfiToSigner. Uses agentRegistry for peer lookup (same as deliverToCombiner).
func (tm *MPTransportBridge) sendRfiToCombiner(zone string, rfiType string) error {
	if tm.agentRegistry == nil {
		return fmt.Errorf("no agent registry")
	}

	combinerID, err := tm.getCombinerID()
	if err != nil {
		return fmt.Errorf("RFI %s: %w", rfiType, err)
	}

	combiner, exists := tm.agentRegistry.S.Get(combinerID)
	if !exists {
		return fmt.Errorf("combiner %q not found in AgentRegistry", combinerID)
	}

	peer := tm.SyncPeerFromAgent(combiner)

	syncReq := &transport.SyncRequest{
		SenderID:    tm.LocalID,
		Zone:        zone,
		Timestamp:   time.Now(),
		MessageType: "rfi",
		RfiType:     rfiType,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tm.SendSyncWithFallback(ctx, peer, syncReq)
	if err != nil {
		return fmt.Errorf("RFI %s to combiner %s failed: %w", rfiType, combinerID, err)
	}

	lgTransport.Info("RFI sent to combiner", "rfiType", rfiType, "zone", zone, "combiner", combinerID, "status", resp.Status)
	return nil
}
