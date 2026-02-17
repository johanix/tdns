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
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// generatePingNonce returns a random nonce for ping requests.
func generatePingNonce() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// TransportManager manages multiple transports for agent communication.
type TransportManager struct {
	// APITransport is the HTTPS-based transport
	APITransport *transport.APITransport

	// DNSTransport is the DNS NOTIFY-based transport
	DNSTransport *transport.DNSTransport

	// ChunkHandler handles incoming NOTIFY(CHUNK) messages
	ChunkHandler *transport.ChunkNotifyHandler

	// Router handles DNS message routing and middleware
	Router *transport.DNSMessageRouter

	// PeerRegistry tracks all known peers
	PeerRegistry *transport.PeerRegistry

	// LocalID is our agent identity
	LocalID string

	// ControlZone for DNS transport
	ControlZone string

	// AgentRegistry for integration with existing code
	agentRegistry *AgentRegistry

	// AgentQs for routing messages to hsyncengine
	agentQs *AgentQs

	// SupportedMechanisms lists active transports ("api", "dns")
	SupportedMechanisms []string

	// combinerID is the AgentId of the combiner (from config), used by EnqueueForCombiner.
	combinerID AgentId

	// reliableQueue handles retry-until-confirmed delivery for outgoing sync messages.
	reliableQueue *ReliableMessageQueue
}

// TransportManagerConfig holds configuration for creating a TransportManager.
type TransportManagerConfig struct {
	LocalID       string
	ControlZone   string
	APITimeout    time.Duration
	DNSTimeout    time.Duration
	AgentRegistry *AgentRegistry
	AgentQs       *AgentQs
	// ChunkMode: "edns0" or "query"; when "query", agent stores payload and sends NOTIFY without EDNS0; receiver fetches via CHUNK query
	ChunkMode         string
	ChunkPayloadStore ChunkPayloadStore
	// ChunkQueryEndpoint: for query mode, address (host:port) where agent answers CHUNK queries
	ChunkQueryEndpoint string
	// ChunkQueryEndpointInNotify: when true, include endpoint in NOTIFY (EDNS0 option 65005); when false, receiver uses static config (e.g. combiner.agents[].address)
	ChunkQueryEndpointInNotify bool

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
}

// NewTransportManager creates a new TransportManager with both API and DNS transports.
func NewTransportManager(cfg *TransportManagerConfig) *TransportManager {
	// Default to both transports if not specified (backward compatibility for tests)
	// Production configs MUST specify supported_mechanisms explicitly (validated at config load)
	supportedMechanisms := cfg.SupportedMechanisms
	if len(supportedMechanisms) == 0 {
		log.Printf("WARNING: TransportManager created without supported_mechanisms - defaulting to [api, dns]")
		supportedMechanisms = []string{"api", "dns"}
	}

	tm := &TransportManager{
		LocalID:             cfg.LocalID,
		ControlZone:         cfg.ControlZone,
		PeerRegistry:        transport.NewPeerRegistry(),
		Router:              transport.NewDNSMessageRouter(),
		agentRegistry:       cfg.AgentRegistry,
		agentQs:             cfg.AgentQs,
		SupportedMechanisms: supportedMechanisms,
		combinerID:          AgentId(cfg.CombinerID),
	}

	// Create reliable message queue for outgoing sync messages
	tm.reliableQueue = NewReliableMessageQueue(&ReliableMessageQueueConfig{
		AgentRegistry: cfg.AgentRegistry,
	})

	// Always create API client transport — it's a pure HTTP client with no server-side
	// implications. An agent that only serves DNS can still act as an API client to
	// remote agents that serve API. supported_mechanisms controls the server role, not
	// the client role.
	tm.APITransport = transport.NewAPITransport(&transport.APITransportConfig{
		LocalID:        cfg.LocalID,
		DefaultTimeout: cfg.APITimeout,
	})
	log.Printf("TransportManager: API client transport enabled")

	// Create DNS transport if control zone is configured AND supported
	if cfg.ControlZone != "" && tm.isTransportSupported("dns") {
		dnsCfg := &transport.DNSTransportConfig{
			LocalID:                    cfg.LocalID,
			ControlZone:                cfg.ControlZone,
			Timeout:                    cfg.DNSTimeout,
			ChunkMode:                  cfg.ChunkMode,
			ChunkQueryEndpoint:         cfg.ChunkQueryEndpoint,
			ChunkQueryEndpointInNotify: cfg.ChunkQueryEndpointInNotify,
			PayloadCrypto:              cfg.PayloadCrypto,
		}
		if cfg.ChunkPayloadStore != nil {
			store := cfg.ChunkPayloadStore
			dnsCfg.ChunkPayloadGet = func(qname string) ([]byte, uint8, bool) { return store.Get(qname) }
			dnsCfg.ChunkPayloadSet = func(qname string, payload []byte, format uint8) { store.Set(qname, payload, format) }
		}
		if cfg.DistributionCache != nil {
			cache := cfg.DistributionCache
			dnsCfg.DistributionAdd = func(qname string, senderID string, receiverID string, operation string, distributionID string) {
				now := time.Now()

				// Calculate expiration time based on message type (operation)
				// Use config retention times with sensible defaults
				retentionSecs := Conf.Agent.Dns.MessageRetention.GetRetentionForMessageType(operation)
				expiresAt := now.Add(time.Duration(retentionSecs) * time.Second)

				cache.Add(qname, &DistributionInfo{
					DistributionID: distributionID,
					SenderID:       senderID,
					ReceiverID:     receiverID,
					Operation:      operation,
					ContentType:    "",
					State:          "pending",
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
			zone string, applied []string, removed []string, rejected []transport.RejectedItemDTO, truncated bool) {
			if tm.reliableQueue != nil && status == transport.ConfirmSuccess {
				tm.reliableQueue.MarkConfirmed(distributionID, senderID)
			}
			// Forward per-RR detail to SynchedDataEngine
			if tm.agentQs != nil && tm.agentQs.Confirmation != nil {
				var rejItems []RejectedItemInfo
				for _, ri := range rejected {
					rejItems = append(rejItems, RejectedItemInfo{Record: ri.Record, Reason: ri.Reason})
				}
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
				case tm.agentQs.Confirmation <- detail:
				default:
					log.Printf("TransportManager: Confirmation channel full, dropping detail for %s", distributionID)
				}
			}
		}

		// Wire remote confirmation callback (two-phase protocol: Phase 7).
		// When this agent's combiner confirms a sync that originated from another agent,
		// send the final confirmation NOTIFY back to the originating agent.
		if tm.agentQs != nil {
			tm.agentQs.OnRemoteConfirmationReady = func(detail *RemoteConfirmationDetail) {
				go tm.sendRemoteConfirmation(detail)
			}
		}

		// Trigger discovery when we receive messages from authorized but undiscovered peers
		tm.ChunkHandler.OnPeerDiscoveryNeeded = func(peerID string) {
			log.Printf("TransportManager: Triggering discovery for peer %s (missing verification key)", peerID)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := tm.DiscoverAndRegisterAgent(ctx, peerID)
			if err != nil {
				log.Printf("TransportManager: Discovery failed for peer %s: %v", peerID, err)
			} else {
				log.Printf("TransportManager: Successfully discovered peer %s, verification key now available", peerID)
			}
		}

		// Initialize router with handlers and middleware
		routerCfg := &transport.RouterConfig{
			TransportManager:             tm,
			PeerRegistry:                 tm.PeerRegistry,
			PayloadCrypto:                cfg.PayloadCrypto,
			IncomingChan:                 tm.ChunkHandler.IncomingChan,
			TriggerDiscoveryOnMissingKey: true,
			AllowUnencrypted:             false,
			VerboseStats:                 false, // Set to true for verbose statistics logging
		}
		log.Printf("InitializeTransport: RouterConfig.PeerRegistry = %v (nil=%t)",
			routerCfg.PeerRegistry, routerCfg.PeerRegistry == nil)
		if err := transport.InitializeRouter(tm.Router, routerCfg); err != nil {
			log.Printf("TransportManager: Warning - router initialization failed: %v", err)
		}

		log.Printf("TransportManager: DNS transport enabled")
	} else if cfg.ControlZone == "" {
		log.Printf("TransportManager: DNS transport not configured (no control zone)")
	} else {
		log.Printf("TransportManager: DNS transport disabled by configuration")
	}

	return tm
}

// isTransportSupported checks if a transport mechanism is enabled in configuration.
func (tm *TransportManager) isTransportSupported(mechanism string) bool {
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
func (tm *TransportManager) RegisterChunkNotifyHandler() error {
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

	log.Printf("TransportManager: Registered CHUNK NOTIFY handler for control zone %s", tm.ControlZone)
	return nil
}

// StartIncomingMessageRouter starts a goroutine that routes incoming DNS messages
// to the appropriate hsyncengine channels.
func (tm *TransportManager) StartIncomingMessageRouter(ctx context.Context) {
	if tm.ChunkHandler == nil {
		log.Printf("TransportManager: DNS transport not configured, skipping incoming message router")
		return
	}

	go func() {
		log.Printf("TransportManager: Starting incoming DNS message router")
		for {
			select {
			case <-ctx.Done():
				log.Printf("TransportManager: Incoming message router stopped")
				return

			case msg := <-tm.ChunkHandler.IncomingChan:
				tm.routeIncomingMessage(msg)
			}
		}
	}()
}

// routeIncomingMessage routes an incoming DNS message to the appropriate hsyncengine channel.
func (tm *TransportManager) routeIncomingMessage(msg *transport.IncomingMessage) {
	log.Printf("TransportManager: Routing %s message from %s", msg.Type, msg.SenderID)

	switch msg.Type {
	case "hello":
		tm.routeHelloMessage(msg)
	case "beat":
		tm.routeBeatMessage(msg)
	case "sync", "rfi":
		tm.routeSyncMessage(msg)
	case "relocate":
		tm.routeRelocateMessage(msg)
	default:
		log.Printf("TransportManager: Unknown message type: %s", msg.Type)
	}
}

// routeHelloMessage routes a hello message to the hello channel.
func (tm *TransportManager) routeHelloMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseHelloPayload(msg.Payload)
	if err != nil {
		log.Printf("TransportManager: Failed to parse hello payload: %v", err)
		return
	}

	// DNS-38: Authorization check BEFORE routing to hsyncengine
	// This prevents discovery amplification attacks by rejecting unauthorized senders
	// Use helper method to get zones from either old or new format
	sharedZones := payload.GetSharedZones()
	var zone string
	if len(sharedZones) > 0 {
		zone = sharedZones[0] // Use first shared zone for HSYNC check
	}
	senderID := payload.GetSenderID() // Use helper method to get sender ID from either format
	authorized, reason := tm.IsPeerAuthorized(senderID, zone)
	if !authorized {
		log.Printf("TransportManager: REJECTED DNS hello from %s: %s", senderID, reason)
		// Security audit log - this may indicate attack attempt
		log.Printf("TransportManager: Security: Unauthorized Hello attempt from %s (zone: %q)", senderID, zone)
		return
	}
	log.Printf("TransportManager: DNS hello from %s authorized: %s", senderID, reason)

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
				log.Printf("TransportManager: Updated agent %s DNS state to INTRODUCED after receiving Hello", senderID)
			}
			agent.DnsDetails.HelloTime = time.Now()
			agent.DnsDetails.LastContactTime = time.Now()
			tm.agentRegistry.S.Set(agent.Identity, agent)
		} else {
			// DNS-56: Agent not in registry but authorized - trigger discovery
			// This ensures receiver can send beats back to sender
			log.Printf("TransportManager: Authorized Hello from unknown agent %s - triggering discovery", senderID)
			go func(peerID string) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				err := tm.DiscoverAndRegisterAgent(ctx, peerID)
				if err != nil {
					log.Printf("TransportManager: Discovery failed for agent %s: %v", peerID, err)
				} else {
					log.Printf("TransportManager: Successfully discovered agent %s, now in registry", peerID)
					// Update the newly discovered agent's DNS state to INTRODUCED
					if discoveredAgent, ok := tm.agentRegistry.S.Get(AgentId(peerID)); ok {
						discoveredAgent.DnsDetails.State = AgentStateIntroduced
						discoveredAgent.DnsDetails.HelloTime = time.Now()
						discoveredAgent.DnsDetails.LastContactTime = time.Now()
						tm.agentRegistry.S.Set(discoveredAgent.Identity, discoveredAgent)
						log.Printf("TransportManager: Updated discovered agent %s DNS state to INTRODUCED", peerID)
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

	select {
	case tm.agentQs.Hello <- report:
		log.Printf("TransportManager: Routed DNS hello from %s to hsyncengine (now INTRODUCING, distrib=%s)", senderID, msg.DistributionID)
	default:
		log.Printf("TransportManager: Hello channel full, dropping message from %s", senderID)
	}
}

// routeBeatMessage routes a beat message to the heartbeat channel.
func (tm *TransportManager) routeBeatMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseBeatPayload(msg.Payload)
	if err != nil {
		log.Printf("TransportManager: Failed to parse beat payload: %v", err)
		return
	}

	senderID := payload.GetSenderID() // Use helper method to get sender ID from either format

	// DNS-51: Authorization check for Beat messages
	// Beat includes Zones field (list of zones sender believes are shared)
	// Authorization succeeds if:
	// 1. Sender in authorized_peers config, OR
	// 2. Sender in HSYNC for any zone in Zones list, OR
	// 3. Zones list empty AND sender previously authorized (agent in OPERATIONAL state)

	var authorized bool
	var reason string

	// Try config path first (works for all cases)
	if tm.isInAuthorizedPeers(senderID) {
		authorized = true
		reason = "found in agent.authorized_peers"
	} else if len(payload.Zones) > 0 {
		// Try HSYNC path for each zone in the Beat
		for _, zone := range payload.Zones {
			if auth, rsn := tm.IsPeerAuthorized(senderID, zone); auth {
				authorized = true
				reason = rsn
				break
			}
		}
	} else {
		// Empty zone list - check if agent exists and was previously authorized
		if tm.agentRegistry != nil {
			agent, exists := tm.agentRegistry.S.Get(AgentId(senderID))
			if exists && agent.State == AgentStateOperational {
				authorized = true
				reason = "previously authorized agent (OPERATIONAL state, empty zone list)"
			}
		}
	}

	if !authorized {
		log.Printf("TransportManager: REJECTED DNS beat from %s: not authorized (zones: %v)", senderID, payload.Zones)
		log.Printf("TransportManager: Security: Unauthorized Beat attempt from %s", senderID)
		return
	}
	log.Printf("TransportManager: DNS beat from %s authorized: %s (zones: %v)", senderID, reason, payload.Zones)

	// DNS-37: Update peer state on successful beat
	peer := tm.PeerRegistry.GetOrCreate(senderID)
	peer.LastBeatReceived = time.Now()
	peer.SetState(transport.PeerStateOperational, "Beat received from operational peer")

	// Also update AgentRegistry if available
	if tm.agentRegistry != nil {
		agent, exists := tm.agentRegistry.S.Get(AgentId(senderID))
		if exists {
			agent.DnsDetails.State = AgentStateOperational
			agent.DnsDetails.LastContactTime = time.Now()
			tm.agentRegistry.S.Set(agent.Identity, agent)
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

	select {
	case tm.agentQs.Beat <- report:
		log.Printf("TransportManager: Routed DNS beat from %s to hsyncengine (now OPERATIONAL, distrib=%s)", senderID, distributionID)
	default:
		log.Printf("TransportManager: Beat channel full, dropping message from %s", senderID)
	}
}

// routeSyncMessage routes a sync message to the message channel.
func (tm *TransportManager) routeSyncMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseSyncPayload(msg.Payload)
	if err != nil {
		log.Printf("TransportManager: Failed to parse sync payload: %v", err)
		return
	}

	// The distribution ID is extracted from the CHUNK qname, not the JSON payload.
	// Propagate it into the parsed payload so downstream code (AgentMsgPost,
	// sendImmediateConfirmation) can access it uniformly.
	if msg.DistributionID != "" && payload.DistributionID == "" {
		payload.DistributionID = msg.DistributionID
	}

	senderID := payload.GetSenderID() // Use helper method to get sender ID from either format
	records := payload.GetRecords()   // Use helper method to get records from either format
	zone := payload.Zone

	// Determine message type (sync, rfi, or status)
	messageType := AgentMsgNotify // Default to sync for backward compatibility
	if payload.MessageType != "" {
		messageType = AgentMsg(payload.MessageType)
	}
	msgTypeStr := core.AgentMsgToString[core.AgentMsg(messageType)]

	// DNS-51: Authorization check for Sync/Notify/RFI/Status messages
	// Check if sender is authorized for this zone (via config or HSYNC)
	authorized, reason := tm.IsPeerAuthorized(senderID, zone)
	if !authorized {
		log.Printf("TransportManager: REJECTED DNS %s from %s for zone %s: %s", msgTypeStr, senderID, zone, reason)
		log.Printf("TransportManager: Security: Unauthorized %s attempt from %s for zone %s", msgTypeStr, senderID, zone)
		return
	}
	log.Printf("TransportManager: DNS %s from %s for zone %s authorized: %s", msgTypeStr, senderID, zone, reason)

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

	msgPost := &AgentMsgPostPlus{
		AgentMsgPost: AgentMsgPost{
			MessageType:    messageType,
			MyIdentity:     AgentId(senderID),
			Zone:           ZoneName(zone),
			Records:        records,
			Time:           time.Unix(payload.Timestamp, 0),
			RfiType:        payload.RfiType,        // Include RfiType for RFI messages
			DistributionID: payload.DistributionID, // Originating distID from sending agent
		},
	}

	select {
	case tm.agentQs.Msg <- msgPost:
		log.Printf("TransportManager: Routed DNS %s from %s (zone: %s) to hsyncengine",
			msgTypeStr, senderID, zone)

		// Send immediate "pending" confirmation back to originating agent (two-phase protocol).
		// This tells the originator "I received your sync" so it doesn't need to resend.
		go tm.sendImmediateConfirmation(payload)
	default:
		log.Printf("TransportManager: Message channel full, dropping %s from %s", msgTypeStr, senderID)
	}
}

// routeRelocateMessage handles a relocate request.
func (tm *TransportManager) routeRelocateMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseRelocatePayload(msg.Payload)
	if err != nil {
		log.Printf("TransportManager: Failed to parse relocate payload: %v", err)
		return
	}

	// Authorization check: relocate changes the address we communicate with,
	// so only authorized agents should be able to issue this.
	authorized, reason := tm.IsPeerAuthorized(payload.SenderID, "")
	if !authorized {
		log.Printf("TransportManager: REJECTED DNS relocate from %s: %s", payload.SenderID, reason)
		log.Printf("TransportManager: Security: Unauthorized Relocate attempt from %s", payload.SenderID)
		return
	}
	log.Printf("TransportManager: DNS relocate from %s authorized: %s", payload.SenderID, reason)

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

	log.Printf("TransportManager: Updated operational address for %s to %s:%d (reason: %s)",
		payload.SenderID, payload.NewAddress.Host, payload.NewAddress.Port, payload.Reason)
}

// sendSyncConfirmation sends a confirmation for a received sync message.
func (tm *TransportManager) sendSyncConfirmation(msg *transport.IncomingMessage, payload *transport.DnsSyncPayload) {
	if tm.DNSTransport == nil {
		return
	}

	// Get or create peer
	senderID := payload.GetSenderID()
	peer, exists := tm.PeerRegistry.Get(senderID)
	if !exists {
		log.Printf("TransportManager: Cannot send confirmation - peer %s not in registry", senderID)
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
		log.Printf("TransportManager: Failed to send confirmation for %s: %v", payload.DistributionID, err)
	} else {
		log.Printf("TransportManager: Sent confirmation for sync %s", payload.DistributionID)
	}
}

// sendImmediateConfirmation sends a "pending" confirmation back to the originating agent
// to indicate that the sync was received and is being processed. This is the first of two
// NOTIFYs in the two-phase remote confirmation protocol (Phase 5).
func (tm *TransportManager) sendImmediateConfirmation(payload *transport.DnsSyncPayload) {
	if tm.DNSTransport == nil {
		return
	}

	senderID := payload.GetSenderID()
	if payload.DistributionID == "" {
		log.Printf("TransportManager: Cannot send immediate confirmation — no distribution ID from %s", senderID)
		return
	}

	peer, exists := tm.PeerRegistry.Get(senderID)
	if !exists {
		log.Printf("TransportManager: Cannot send immediate confirmation — peer %s not in registry", senderID)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tm.DNSTransport.Confirm(ctx, peer, &transport.ConfirmRequest{
		SenderID:       tm.LocalID,
		Zone:           payload.Zone,
		DistributionID: payload.DistributionID,
		Status:         transport.ConfirmPending,
		Message:        "Sync received, forwarding to combiner",
		Timestamp:      time.Now(),
	})

	if err != nil {
		log.Printf("TransportManager: Failed to send immediate confirmation for %s to %s: %v",
			payload.DistributionID, senderID, err)
	} else {
		log.Printf("TransportManager: Sent immediate (pending) confirmation for %s to %s",
			payload.DistributionID, senderID)
	}
}

// sendRemoteConfirmation sends the final confirmation NOTIFY back to the originating agent
// after the remote agent's combiner has confirmed the sync. This is the second of two
// NOTIFYs in the two-phase remote confirmation protocol (Phase 7).
func (tm *TransportManager) sendRemoteConfirmation(detail *RemoteConfirmationDetail) {
	if tm.DNSTransport == nil {
		return
	}

	peer, exists := tm.PeerRegistry.Get(detail.OriginatingSender)
	if !exists {
		log.Printf("TransportManager: Cannot send remote confirmation — peer %s not in registry", detail.OriginatingSender)
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
		log.Printf("TransportManager: Failed to send remote confirmation for originating distID %s to %s: %v",
			detail.OriginatingDistID, detail.OriginatingSender, err)
	} else {
		log.Printf("TransportManager: Sent remote confirmation for originating distID %s to %s (applied=%d removed=%d rejected=%d)",
			detail.OriginatingDistID, detail.OriginatingSender,
			len(detail.AppliedRecords), len(detail.RemovedRecords), len(detail.RejectedItems))
	}
}

// SelectTransport selects the appropriate transport for communicating with a peer.
func (tm *TransportManager) SelectTransport(peer *transport.Peer) transport.Transport {
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
func (tm *TransportManager) SendSyncWithFallback(ctx context.Context, peer *transport.Peer, req *transport.SyncRequest) (*transport.SyncResponse, error) {
	// Try primary transport
	primary := tm.SelectTransport(peer)
	if primary != nil {
		resp, err := primary.Sync(ctx, peer, req)
		if err == nil {
			return resp, nil
		}
		log.Printf("TransportManager: Primary transport %s failed for %s: %v",
			primary.Name(), peer.ID, err)
	}

	// Try fallback transport
	var fallback transport.Transport
	if primary == tm.APITransport && tm.DNSTransport != nil {
		fallback = tm.DNSTransport
	} else if primary == tm.DNSTransport && tm.APITransport != nil {
		fallback = tm.APITransport
	}

	if fallback != nil {
		log.Printf("TransportManager: Trying fallback transport %s for %s", fallback.Name(), peer.ID)
		return fallback.Sync(ctx, peer, req)
	}

	return nil, fmt.Errorf("all transports failed for peer %s", peer.ID)
}

// SyncPeerFromAgent creates or updates a transport.Peer from an existing Agent.
func (tm *TransportManager) SyncPeerFromAgent(agent *Agent) *transport.Peer {
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
func (tm *TransportManager) agentStateToTransportState(state AgentState) transport.PeerState {
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
func (tm *TransportManager) SendHelloWithFallback(ctx context.Context, agent *Agent, sharedZones []string) (*transport.HelloResponse, error) {
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

	// Try API transport if available, has valid endpoint, and actually needs Hello (state == KNOWN).
	// Skip if already INTRODUCED or OPERATIONAL — no point sending Hello to an already-established transport.
	if tm.APITransport != nil && agent.ApiMethod && agent.ApiDetails != nil && agent.ApiDetails.BaseUri != "" && agent.ApiDetails.State == AgentStateKnown {
		apiResp, apiErr = tm.APITransport.Hello(ctx, peer, req)
		agent.mu.Lock()
		if apiErr != nil {
			log.Printf("TransportManager: API Hello to %s failed: %v", peer.ID, apiErr)
			agent.ApiDetails.LatestError = apiErr.Error()
			agent.ApiDetails.LatestErrorTime = time.Now()
		} else if apiResp != nil && !apiResp.Accepted {
			log.Printf("TransportManager: API Hello to %s not accepted: %s", peer.ID, apiResp.RejectReason)
			agent.ApiDetails.LatestError = apiResp.RejectReason
			agent.ApiDetails.LatestErrorTime = time.Now()
		} else {
			log.Printf("TransportManager: API Hello to %s succeeded", peer.ID)
			// Only transition to INTRODUCED if not already OPERATIONAL or better
			// This prevents Hello messages from downgrading state (e.g., after retry or peer restart)
			if agent.ApiDetails.State < AgentStateIntroduced {
				agent.ApiDetails.State = AgentStateIntroduced
				log.Printf("TransportManager: Updated agent %s API state to INTRODUCED after successful Hello", peer.ID)
			}
			agent.ApiDetails.HelloTime = time.Now()
			agent.ApiDetails.LastContactTime = time.Now()
			agent.ApiDetails.LatestError = ""
		}
		agent.mu.Unlock()
	}

	// Try DNS transport if supported and actually needs Hello (state == KNOWN).
	// Skip if already INTRODUCED or OPERATIONAL — no point sending Hello to an already-established transport.
	if tm.DNSTransport != nil && agent.DnsMethod && tm.isTransportSupported("dns") && agent.DnsDetails.State == AgentStateKnown {
		dnsResp, dnsErr = tm.DNSTransport.Hello(ctx, peer, req)
		agent.mu.Lock()
		if dnsErr != nil {
			log.Printf("TransportManager: DNS Hello to %s failed: %v", peer.ID, dnsErr)
			agent.DnsDetails.LatestError = dnsErr.Error()
			agent.DnsDetails.LatestErrorTime = time.Now()
		} else if dnsResp != nil && !dnsResp.Accepted {
			log.Printf("TransportManager: DNS Hello to %s not accepted: %s", peer.ID, dnsResp.RejectReason)
			agent.DnsDetails.LatestError = dnsResp.RejectReason
			agent.DnsDetails.LatestErrorTime = time.Now()
		} else {
			log.Printf("TransportManager: DNS Hello to %s succeeded", peer.ID)
			// Only transition to INTRODUCED if not already OPERATIONAL or better
			// This prevents Hello messages from downgrading state (e.g., after retry or peer restart)
			if agent.DnsDetails.State < AgentStateIntroduced {
				agent.DnsDetails.State = AgentStateIntroduced
				log.Printf("TransportManager: Updated agent %s DNS state to INTRODUCED after successful Hello", peer.ID)
			}
			agent.DnsDetails.HelloTime = time.Now()
			agent.DnsDetails.LastContactTime = time.Now()
			agent.DnsDetails.LatestError = ""
		}
		agent.mu.Unlock()
	}

	// Return success if ANY transport succeeded
	if apiErr == nil && apiResp != nil && apiResp.Accepted {
		return apiResp, nil
	}
	if dnsErr == nil && dnsResp != nil && dnsResp.Accepted {
		return dnsResp, nil
	}

	// Both failed or skipped
	if apiResp == nil && dnsResp == nil && apiErr == nil && dnsErr == nil {
		// No transport was in KNOWN state — nothing to do
		return nil, fmt.Errorf("no transports in KNOWN state for Hello to peer %s (API: %s, DNS: %s)",
			peer.ID, AgentStateToString[agent.ApiDetails.State], AgentStateToString[agent.DnsDetails.State])
	}
	return nil, fmt.Errorf("all transports failed for Hello to peer %s (API: %v, DNS: %v)", peer.ID, apiErr, dnsErr)
}

// SendPing sends a CHUNK-based ping to a peer; prefers DNS transport (API does not implement ping).
func (tm *TransportManager) SendPing(ctx context.Context, peer *transport.Peer) (*transport.PingResponse, error) {
	req := &transport.PingRequest{
		SenderID:  tm.LocalID,
		Nonce:     generatePingNonce(),
		Timestamp: time.Now(),
	}
	// Prefer DNS for ping (API transport returns "not implemented")
	if tm.DNSTransport != nil && peer.CurrentAddress() != nil {
		return tm.DNSTransport.Ping(ctx, peer, req)
	}
	if tm.APITransport != nil && peer.APIEndpoint != "" {
		return tm.APITransport.Ping(ctx, peer, req)
	}
	return nil, fmt.Errorf("no transport available for ping to %s", peer.ID)
}

// SendBeatWithFallback sends a heartbeat to a peer with transport fallback.
// SendBeatWithFallback sends a Beat heartbeat to a peer (legacy name).
// UPDATED: Now sends Beat on ALL supported transports independently when both are configured.
// Returns success if ANY transport succeeds. Updates per-transport LastContactTime in Agent struct.
func (tm *TransportManager) SendBeatWithFallback(ctx context.Context, agent *Agent, sequence uint64) (*transport.BeatResponse, error) {
	peer := tm.SyncPeerFromAgent(agent)

	req := &transport.BeatRequest{
		SenderID:  tm.LocalID,
		Timestamp: time.Now(),
		Sequence:  sequence,
		State:     string(agent.State),
	}

	var apiResp *transport.BeatResponse
	var dnsResp *transport.BeatResponse
	var apiErr error
	var dnsErr error

	// Try API transport if available, has valid endpoint, and OPERATIONAL/LEGACY
	if tm.APITransport != nil && agent.ApiMethod && agent.ApiDetails != nil && agent.ApiDetails.BaseUri != "" {
		if agent.ApiDetails.State == AgentStateOperational || agent.ApiDetails.State == AgentStateIntroduced || agent.ApiDetails.State == AgentStateLegacy {
			apiResp, apiErr = tm.APITransport.Beat(ctx, peer, req)
			agent.mu.Lock()
			if apiErr != nil {
				log.Printf("TransportManager: API Beat to %s failed: %v", peer.ID, apiErr)
				agent.ApiDetails.LatestError = apiErr.Error()
				agent.ApiDetails.LatestErrorTime = time.Now()
			} else if apiResp != nil && !apiResp.Ack {
				log.Printf("TransportManager: API Beat to %s: no confirmation (Ack=false)", peer.ID)
				agent.ApiDetails.LatestError = "beat sent but not confirmed by peer"
				agent.ApiDetails.LatestErrorTime = time.Now()
			} else {
				log.Printf("TransportManager: API Beat to %s succeeded", peer.ID)
				agent.ApiDetails.State = AgentStateOperational
				agent.ApiDetails.LastContactTime = time.Now()
				agent.ApiDetails.LatestRBeat = time.Now()
				agent.ApiDetails.ReceivedBeats++
				agent.ApiDetails.LatestError = ""
			}
			agent.mu.Unlock()
		}
	}

	// Try DNS transport if supported and OPERATIONAL/LEGACY
	if tm.DNSTransport != nil && agent.DnsMethod && tm.isTransportSupported("dns") {
		if agent.DnsDetails.State == AgentStateOperational || agent.DnsDetails.State == AgentStateIntroduced || agent.DnsDetails.State == AgentStateLegacy {
			dnsResp, dnsErr = tm.DNSTransport.Beat(ctx, peer, req)
			agent.mu.Lock()
			if dnsErr != nil {
				log.Printf("TransportManager: DNS Beat to %s failed: %v", peer.ID, dnsErr)
				agent.DnsDetails.LatestError = dnsErr.Error()
				agent.DnsDetails.LatestErrorTime = time.Now()
			} else if dnsResp != nil && !dnsResp.Ack {
				// Beat() returns nil error but Ack:false when EDNS0 confirmation is missing.
				// This means the DNS response was received but the peer didn't confirm processing.
				log.Printf("TransportManager: DNS Beat to %s: no confirmation (Ack=false)", peer.ID)
				agent.DnsDetails.LatestError = "beat sent but not confirmed by peer"
				agent.DnsDetails.LatestErrorTime = time.Now()
			} else {
				log.Printf("TransportManager: DNS Beat to %s succeeded", peer.ID)
				agent.DnsDetails.State = AgentStateOperational
				agent.DnsDetails.LastContactTime = time.Now()
				agent.DnsDetails.LatestRBeat = time.Now()
				agent.DnsDetails.ReceivedBeats++
				agent.DnsDetails.LatestError = ""
			}
			agent.mu.Unlock()
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
func (tm *TransportManager) OnAgentDiscoveryComplete(agent *Agent) {
	peer := tm.SyncPeerFromAgent(agent)

	// Set preferred transport based on what's available
	if agent.ApiMethod && agent.DnsMethod {
		// Both available - prefer API (more reliable)
		peer.PreferredTransport = "API"
		log.Printf("TransportManager: Agent %s has both API and DNS, preferring API", agent.Identity)
	} else if agent.ApiMethod {
		peer.PreferredTransport = "API"
		log.Printf("TransportManager: Agent %s has API only", agent.Identity)
	} else if agent.DnsMethod {
		peer.PreferredTransport = "DNS"
		log.Printf("TransportManager: Agent %s has DNS only", agent.Identity)
	}

	// Update peer state
	peer.SetState(transport.PeerStateKnown, "discovery complete")

	log.Printf("TransportManager: Agent %s discovery complete, peer synced with preferred transport: %s",
		agent.Identity, peer.PreferredTransport)
}

// GetPreferredTransportName returns the preferred transport name for an agent.
func (tm *TransportManager) GetPreferredTransportName(agent *Agent) string {
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
func (tm *TransportManager) HasDNSTransport(agent *Agent) bool {
	return tm.DNSTransport != nil && agent.DnsMethod
}

// HasAPITransport returns true if API transport is available for an agent.
func (tm *TransportManager) HasAPITransport(agent *Agent) bool {
	return tm.APITransport != nil && agent.ApiMethod
}

// --- Reliable message queue integration ---

// StartReliableQueue wires up the sendFunc and starts the queue's background worker.
// Must be called after TransportManager is fully initialized (transports, combiner peer, etc.).
func (tm *TransportManager) StartReliableQueue(ctx context.Context) {
	if tm.reliableQueue == nil {
		log.Printf("TransportManager: No reliable queue configured, skipping")
		return
	}

	// Wire sendFunc: the queue calls this to actually deliver a message.
	tm.reliableQueue.SetSendFunc(func(ctx context.Context, msg *OutgoingMessage) error {
		return tm.deliverMessage(ctx, msg)
	})

	go tm.reliableQueue.Start(ctx)
	log.Printf("TransportManager: Reliable message queue started")
}

// deliverMessage is the sendFunc implementation. It converts an OutgoingMessage
// into the appropriate transport format and sends it.
func (tm *TransportManager) deliverMessage(ctx context.Context, msg *OutgoingMessage) error {
	switch msg.RecipientType {
	case "combiner":
		return tm.deliverToCombiner(ctx, msg)
	case "agent":
		return tm.deliverToAgent(ctx, msg)
	default:
		return fmt.Errorf("unknown recipient type: %s", msg.RecipientType)
	}
}

// deliverToCombiner sends a sync message to the combiner via the transport layer.
// On success, forwards per-RR confirmation detail to the SynchedDataEngine.
func (tm *TransportManager) deliverToCombiner(ctx context.Context, msg *OutgoingMessage) error {
	if tm.agentRegistry == nil {
		return fmt.Errorf("no agent registry")
	}

	combiner, exists := tm.agentRegistry.S.Get(msg.RecipientID)
	if !exists {
		return fmt.Errorf("combiner %q not found in AgentRegistry", msg.RecipientID)
	}

	// Build transport peer and sync request
	peer := tm.SyncPeerFromAgent(combiner)

	// Convert ZoneUpdate to flat record list for transport
	records := zoneUpdateToGroupedRecords(msg.Update)

	// Use the original source agent ID so the combiner can attribute records correctly.
	// This preserves per-agent isolation in the combiner's AgentContributions.
	senderID := tm.LocalID
	if msg.Update != nil && msg.Update.AgentId != "" {
		senderID = string(msg.Update.AgentId)
	}

	syncReq := &transport.SyncRequest{
		SenderID:       senderID,
		Zone:           string(msg.Zone),
		Records:        records,
		Timestamp:      msg.CreatedAt,
		DistributionID: msg.DistributionID,
		MessageType:    "sync",
	}

	syncResp, err := tm.SendSyncWithFallback(ctx, peer, syncReq)

	// Forward per-RR detail from inline confirmation to SynchedDataEngine
	if syncResp != nil && tm.agentQs != nil && tm.agentQs.Confirmation != nil {
		var rejItems []RejectedItemInfo
		for _, ri := range syncResp.RejectedItems {
			rejItems = append(rejItems, RejectedItemInfo{Record: ri.Record, Reason: ri.Reason})
		}
		detail := &ConfirmationDetail{
			DistributionID: msg.DistributionID,
			Zone:           msg.Zone,
			Source:         string(msg.RecipientID),
			Status:         syncResp.Status.String(),
			Message:        syncResp.Message,
			AppliedRecords: syncResp.AppliedRecords,
			RemovedRecords: syncResp.RemovedRecords,
			RejectedItems:  rejItems,
			Truncated:      syncResp.Truncated,
			Timestamp:      time.Now(),
		}
		select {
		case tm.agentQs.Confirmation <- detail:
		default:
			log.Printf("TransportManager: Confirmation channel full, dropping inline detail for %s", msg.DistributionID)
		}
	}

	return err
}

// deliverToAgent sends a sync message to a remote agent via the transport layer.
func (tm *TransportManager) deliverToAgent(ctx context.Context, msg *OutgoingMessage) error {
	if tm.agentRegistry == nil {
		return fmt.Errorf("no agent registry")
	}

	agent, exists := tm.agentRegistry.S.Get(msg.RecipientID)
	if !exists {
		return fmt.Errorf("agent %q not found in AgentRegistry", msg.RecipientID)
	}

	peer := tm.SyncPeerFromAgent(agent)

	// Convert ZoneUpdate to flat record list for transport
	records := zoneUpdateToGroupedRecords(msg.Update)

	syncReq := &transport.SyncRequest{
		SenderID:       tm.LocalID,
		Zone:           string(msg.Zone),
		Records:        records,
		Timestamp:      msg.CreatedAt,
		DistributionID: msg.DistributionID,
		MessageType:    "sync",
	}

	_, err := tm.SendSyncWithFallback(ctx, peer, syncReq)
	return err
}

// EnqueueForCombiner enqueues a zone update for reliable delivery to the combiner.
// Called by SynchedDataEngine when a zone update needs to reach the combiner.
// If distID is non-empty, it is used as the distribution ID; otherwise a new one is generated.
// Returns the distributionID for tracking and any error.
func (tm *TransportManager) EnqueueForCombiner(zone ZoneName, update *ZoneUpdate, distID string) (string, error) {
	combinerID, err := tm.getCombinerID()
	if err != nil {
		return "", fmt.Errorf("EnqueueForCombiner: %w", err)
	}

	if distID == "" {
		distID = GenerateQueueDistributionID()
	}
	msg := &OutgoingMessage{
		DistributionID: distID,
		RecipientID:    combinerID,
		RecipientType:  "combiner",
		Zone:           zone,
		Update:         update,
		Priority:       PriorityHigh,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(tm.reliableQueue.expirationTimeout),
	}

	return distID, tm.reliableQueue.Enqueue(msg)
}

// EnqueueForZoneAgents enqueues a zone update for reliable delivery to all
// remote agents involved with this zone (as determined by AgentRegistry).
// Called by SynchedDataEngine when a locally-originated update needs to
// reach all peer agents. Uses the same distID for all agents so the
// originating agent can correlate confirmations from combiner and agents.
func (tm *TransportManager) EnqueueForZoneAgents(zone ZoneName, update *ZoneUpdate, distID string) error {
	agents, err := tm.getAllAgentsForZone(zone)
	if err != nil {
		return fmt.Errorf("EnqueueForZoneAgents: %w", err)
	}

	if len(agents) == 0 {
		log.Printf("TransportManager: No remote agents for zone %s, nothing to enqueue", zone)
		return nil
	}

	var enqueueErrors []string
	for _, agentID := range agents {
		msg := &OutgoingMessage{
			DistributionID: distID,
			RecipientID:    agentID,
			RecipientType:  "agent",
			Zone:           zone,
			Update:         update,
			Priority:       PriorityNormal,
			CreatedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(tm.reliableQueue.expirationTimeout),
		}

		if err := tm.reliableQueue.Enqueue(msg); err != nil {
			enqueueErrors = append(enqueueErrors, fmt.Sprintf("%s: %v", agentID, err))
		}
	}

	if len(enqueueErrors) > 0 {
		return fmt.Errorf("failed to enqueue for some agents: %v", enqueueErrors)
	}

	log.Printf("TransportManager: Enqueued zone update for %d agents (zone: %s, distID: %s)", len(agents), zone, distID)
	return nil
}

// GetQueueStats returns statistics from the reliable message queue.
func (tm *TransportManager) GetQueueStats() QueueStats {
	if tm.reliableQueue == nil {
		return QueueStats{}
	}
	return tm.reliableQueue.GetStats()
}

// GetQueuePendingMessages returns a snapshot of all pending messages in the queue.
func (tm *TransportManager) GetQueuePendingMessages() []PendingMessageInfo {
	if tm.reliableQueue == nil {
		return nil
	}
	return tm.reliableQueue.GetPendingMessages()
}

// MarkDeliveryConfirmed marks a queued message as confirmed by the recipient.
// senderID is the identity of the confirming party (= the original message recipient).
func (tm *TransportManager) MarkDeliveryConfirmed(distributionID string, senderID string) bool {
	if tm.reliableQueue == nil {
		return false
	}
	return tm.reliableQueue.MarkConfirmed(distributionID, senderID)
}

// --- Helper methods ---

// getCombinerID returns the combiner's AgentId, set at construction time from config.
func (tm *TransportManager) getCombinerID() (AgentId, error) {
	if tm.combinerID != "" {
		return tm.combinerID, nil
	}
	return "", fmt.Errorf("combiner ID not configured")
}

// getAllAgentsForZone returns the AgentIds of all remote agents for a zone.
// Uses AgentRegistry.GetZoneAgentData() which reads the HSYNC RRset.
func (tm *TransportManager) getAllAgentsForZone(zone ZoneName) ([]AgentId, error) {
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

// zoneUpdateToGroupedRecords converts a ZoneUpdate into records grouped by owner name,
// suitable for transport.SyncRequest.Records and core.AgentMsgPost.Records.
//
// ZoneUpdate has two fields: RRs (for local per-RR updates) and RRsets (for remote
// full-replace updates). Some callers populate both with the same data, so we use
// RRs if present, otherwise RRsets, to avoid duplicates.
func zoneUpdateToGroupedRecords(update *ZoneUpdate) map[string][]string {
	if update == nil {
		return nil
	}

	records := make(map[string][]string)

	if len(update.RRs) > 0 {
		// Local update: use individual RRs
		for _, rr := range update.RRs {
			owner := rr.Header().Name
			records[owner] = append(records[owner], rr.String())
		}
	} else {
		// Remote update: use RRsets
		for _, rrset := range update.RRsets {
			for _, rr := range rrset.RRs {
				owner := rr.Header().Name
				records[owner] = append(records[owner], rr.String())
			}
		}
	}

	return records
}

// groupRRStringsByOwner converts a flat list of RR strings to records grouped by owner name.
// Used when converting from management commands (AgentMgmtPost.RRs []string) to the
// grouped format used by AgentMsgPost.Records and SyncRequest.Records.
func groupRRStringsByOwner(rrStrings []string) map[string][]string {
	records := make(map[string][]string)
	for _, rrStr := range rrStrings {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			log.Printf("groupRRStringsByOwner: skipping unparseable RR %q: %v", rrStr, err)
			continue
		}
		owner := rr.Header().Name
		records[owner] = append(records[owner], rrStr)
	}
	return records
}
