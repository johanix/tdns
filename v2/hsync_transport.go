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
	// ChunkQueryEndpointInNotify: when true, include endpoint in NOTIFY (EDNS0 option 65005); when false, receiver uses static config (e.g. combiner.agent.address)
	ChunkQueryEndpointInNotify bool

	// PayloadCrypto enables JWS/JWE encryption for CHUNK payloads (optional)
	// If set and Enabled, all outgoing CHUNK payloads will be encrypted and signed
	PayloadCrypto *transport.PayloadCrypto

	// DistributionCache: when set, outgoing CHUNK operations (ping, hello, etc.) are registered for "agent distrib list"
	DistributionCache *DistributionCache

	// SupportedMechanisms lists active transports ("api", "dns"); default: both if configured
	SupportedMechanisms []string
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
		agentRegistry:       cfg.AgentRegistry,
		agentQs:             cfg.AgentQs,
		SupportedMechanisms: supportedMechanisms,
	}

	// Create API transport if supported
	if tm.isTransportSupported("api") {
		tm.APITransport = transport.NewAPITransport(&transport.APITransportConfig{
			LocalID:        cfg.LocalID,
			DefaultTimeout: cfg.APITimeout,
		})
		log.Printf("TransportManager: API transport enabled")
	} else {
		log.Printf("TransportManager: API transport disabled by configuration")
	}

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
			dnsCfg.DistributionAdd = func(qname string, senderID string, receiverID string, operation string, correlationID string) {
				cache.Add(qname, &DistributionInfo{
					DistributionID: correlationID,
					SenderID:       senderID,
					ReceiverID:     receiverID,
					Operation:      operation,
					ContentType:    "",
					State:          "pending",
					CreatedAt:      time.Now(),
					CompletedAt:    nil,
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
		tm.ChunkHandler.IsAgentAuthorized = func(senderID string, zone string) (bool, string) {
			return tm.IsAgentAuthorized(senderID, zone)
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
	err := RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *DnsNotifyRequest) error {
		return tm.ChunkHandler.HandleChunkNotify(ctx, req.Qname, req.Msg, req.ResponseWriter)
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
	case "sync":
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
	authorized, reason := tm.IsAgentAuthorized(senderID, zone)
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
			agent.DnsDetails.State = AgentStateIntroduced
			agent.DnsDetails.HelloTime = time.Now()
			agent.DnsDetails.LastContactTime = time.Now()
			tm.agentRegistry.S.Set(agent.Identity, agent)
		}
	}

	// Convert to AgentMsgReport for the existing hsyncengine
	report := &AgentMsgReport{
		MessageType: AgentMsgHello,
		Identity:    AgentId(senderID),
	}

	select {
	case tm.agentQs.Hello <- report:
		log.Printf("TransportManager: Routed DNS hello from %s to hsyncengine (now INTRODUCING)", payload.SenderID)
	default:
		log.Printf("TransportManager: Hello channel full, dropping message from %s", payload.SenderID)
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
			if auth, rsn := tm.IsAgentAuthorized(senderID, zone); auth {
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

	report := &AgentMsgReport{
		MessageType:  AgentMsgBeat,
		Identity:     AgentId(senderID),
		BeatInterval: beatInterval,
	}

	select{
	case tm.agentQs.Beat <- report:
		log.Printf("TransportManager: Routed DNS beat from %s to hsyncengine (now OPERATIONAL)", senderID)
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

	senderID := payload.GetSenderID()   // Use helper method to get sender ID from either format
	records := payload.GetRecords()      // Use helper method to get records from either format
	zone := payload.Zone

	// Determine message type (NOTIFY, RFI, or STATUS)
	messageType := AgentMsgNotify // Default to NOTIFY for backward compatibility
	if payload.MessageType != 0 {
		// New format includes MessageType field
		messageType = AgentMsg(payload.MessageType)
	}
	msgTypeStr := core.AgentMsgToString[core.AgentMsg(messageType)]

	// DNS-51: Authorization check for Sync/Notify/RFI/Status messages
	// Check if sender is authorized for this zone (via config or HSYNC)
	authorized, reason := tm.IsAgentAuthorized(senderID, zone)
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
			MessageType: messageType,
			MyIdentity:  AgentId(senderID),
			Zone:        ZoneName(zone),
			RRs:         records,
			Time:        time.Unix(payload.Timestamp, 0),
			RfiType:     payload.RfiType, // Include RfiType for RFI messages
		},
	}

	select {
	case tm.agentQs.Msg <- msgPost:
		log.Printf("TransportManager: Routed DNS %s from %s (zone: %s) to hsyncengine",
			msgTypeStr, senderID, zone)

		// Send confirmation back via DNS
		go tm.sendSyncConfirmation(msg, payload)
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
	peer, exists := tm.PeerRegistry.Get(payload.SenderID)
	if !exists {
		log.Printf("TransportManager: Cannot send confirmation - peer %s not in registry", payload.SenderID)
		return
	}

	// Send confirmation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tm.DNSTransport.Confirm(ctx, peer, &transport.ConfirmRequest{
		SenderID:      tm.LocalID,
		Zone:          payload.Zone,
		CorrelationID: payload.CorrelationID,
		Status:        transport.ConfirmSuccess,
		Message:       "Sync received and processed",
		Timestamp:     time.Now(),
	})

	if err != nil {
		log.Printf("TransportManager: Failed to send confirmation for %s: %v", payload.CorrelationID, err)
	} else {
		log.Printf("TransportManager: Sent confirmation for sync %s", payload.CorrelationID)
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
		peer.APIEndpoint = agent.ApiDetails.Endpoint
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

	// Try API transport if supported
	if tm.APITransport != nil && agent.ApiMethod && tm.isTransportSupported("api") {
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
			agent.ApiDetails.State = AgentStateIntroduced
			agent.ApiDetails.HelloTime = time.Now()
			agent.ApiDetails.LastContactTime = time.Now()
			agent.ApiDetails.LatestError = ""
		}
		agent.mu.Unlock()
	}

	// Try DNS transport if supported
	if tm.DNSTransport != nil && agent.DnsMethod && tm.isTransportSupported("dns") {
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
			agent.DnsDetails.State = AgentStateIntroduced
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

	// Both failed
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

	// Try API transport if supported and OPERATIONAL
	if tm.APITransport != nil && agent.ApiMethod && tm.isTransportSupported("api") {
		if agent.ApiDetails.State == AgentStateOperational || agent.ApiDetails.State == AgentStateIntroduced {
			apiResp, apiErr = tm.APITransport.Beat(ctx, peer, req)
			agent.mu.Lock()
			if apiErr != nil {
				log.Printf("TransportManager: API Beat to %s failed: %v", peer.ID, apiErr)
				agent.ApiDetails.LatestError = apiErr.Error()
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

	// Try DNS transport if supported and OPERATIONAL
	if tm.DNSTransport != nil && agent.DnsMethod && tm.isTransportSupported("dns") {
		if agent.DnsDetails.State == AgentStateOperational || agent.DnsDetails.State == AgentStateIntroduced {
			dnsResp, dnsErr = tm.DNSTransport.Beat(ctx, peer, req)
			agent.mu.Lock()
			if dnsErr != nil {
				log.Printf("TransportManager: DNS Beat to %s failed: %v", peer.ID, dnsErr)
				agent.DnsDetails.LatestError = dnsErr.Error()
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
