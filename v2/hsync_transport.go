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
}

// NewTransportManager creates a new TransportManager with both API and DNS transports.
func NewTransportManager(cfg *TransportManagerConfig) *TransportManager {
	tm := &TransportManager{
		LocalID:       cfg.LocalID,
		ControlZone:   cfg.ControlZone,
		PeerRegistry:  transport.NewPeerRegistry(),
		agentRegistry: cfg.AgentRegistry,
		agentQs:       cfg.AgentQs,
	}

	// Create API transport
	tm.APITransport = transport.NewAPITransport(&transport.APITransportConfig{
		LocalID:        cfg.LocalID,
		DefaultTimeout: cfg.APITimeout,
	})

	// Create DNS transport if control zone is configured
	if cfg.ControlZone != "" {
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
	}

	return tm
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

	// Convert to AgentMsgReport for the existing hsyncengine
	report := &AgentMsgReport{
		MessageType: AgentMsgHello,
		Identity:    AgentId(payload.SenderID),
	}

	select {
	case tm.agentQs.Hello <- report:
		log.Printf("TransportManager: Routed DNS hello from %s to hsyncengine", payload.SenderID)
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

	// Convert to AgentMsgReport for the existing hsyncengine
	report := &AgentMsgReport{
		MessageType:  AgentMsgBeat,
		Identity:     AgentId(payload.SenderID),
		BeatInterval: uint32(30), // Default, could be extracted from payload
	}

	select {
	case tm.agentQs.Beat <- report:
		log.Printf("TransportManager: Routed DNS beat from %s to hsyncengine", payload.SenderID)
	default:
		log.Printf("TransportManager: Beat channel full, dropping message from %s", payload.SenderID)
	}
}

// routeSyncMessage routes a sync message to the message channel.
func (tm *TransportManager) routeSyncMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseSyncPayload(msg.Payload)
	if err != nil {
		log.Printf("TransportManager: Failed to parse sync payload: %v", err)
		return
	}

	// Convert to AgentMsgPostPlus for the existing hsyncengine
	msgPost := &AgentMsgPostPlus{
		AgentMsgPost: AgentMsgPost{
			MessageType: AgentMsgNotify,
			MyIdentity:  AgentId(payload.SenderID),
			Zone:        ZoneName(payload.Zone),
			RRs:         payload.Records,
			Time:        time.Unix(payload.Timestamp, 0),
		},
	}

	select {
	case tm.agentQs.Msg <- msgPost:
		log.Printf("TransportManager: Routed DNS sync from %s (zone: %s) to hsyncengine",
			payload.SenderID, payload.Zone)

		// Send confirmation back via DNS
		go tm.sendSyncConfirmation(msg, payload)
	default:
		log.Printf("TransportManager: Message channel full, dropping sync from %s", payload.SenderID)
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

// SendHelloWithFallback sends a Hello handshake to a peer with transport fallback.
// Tries API first (if available), then DNS, with retry logic.
func (tm *TransportManager) SendHelloWithFallback(ctx context.Context, agent *Agent, sharedZones []string) (*transport.HelloResponse, error) {
	peer := tm.SyncPeerFromAgent(agent)

	req := &transport.HelloRequest{
		SenderID:     tm.LocalID,
		Capabilities: []string{"sync", "beat", "relocate"},
		SharedZones:  sharedZones,
		Timestamp:    time.Now(),
	}

	// Try primary transport (API first if available)
	primary := tm.SelectTransport(peer)
	if primary != nil {
		resp, err := primary.Hello(ctx, peer, req)
		if err == nil {
			log.Printf("TransportManager: Hello to %s succeeded via %s", peer.ID, primary.Name())
			return resp, nil
		}
		log.Printf("TransportManager: Hello via %s failed for %s: %v", primary.Name(), peer.ID, err)
	}

	// Try fallback transport
	var fallback transport.Transport
	if primary == tm.APITransport && tm.DNSTransport != nil && agent.DnsMethod {
		fallback = tm.DNSTransport
	} else if primary == tm.DNSTransport && tm.APITransport != nil && agent.ApiMethod {
		fallback = tm.APITransport
	} else if primary == nil {
		// No primary, try whatever is available
		if tm.APITransport != nil && agent.ApiMethod {
			fallback = tm.APITransport
		} else if tm.DNSTransport != nil && agent.DnsMethod {
			fallback = tm.DNSTransport
		}
	}

	if fallback != nil {
		log.Printf("TransportManager: Trying fallback transport %s for Hello to %s", fallback.Name(), peer.ID)
		resp, err := fallback.Hello(ctx, peer, req)
		if err == nil {
			return resp, nil
		}
		log.Printf("TransportManager: Hello via fallback %s failed for %s: %v", fallback.Name(), peer.ID, err)
	}

	return nil, fmt.Errorf("all transports failed for Hello to peer %s", peer.ID)
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
func (tm *TransportManager) SendBeatWithFallback(ctx context.Context, agent *Agent, sequence uint64) (*transport.BeatResponse, error) {
	peer := tm.SyncPeerFromAgent(agent)

	req := &transport.BeatRequest{
		SenderID:  tm.LocalID,
		Timestamp: time.Now(),
		Sequence:  sequence,
		State:     string(agent.State),
	}

	// Try primary transport
	primary := tm.SelectTransport(peer)
	if primary != nil {
		resp, err := primary.Beat(ctx, peer, req)
		if err == nil {
			return resp, nil
		}
		log.Printf("TransportManager: Beat via %s failed for %s: %v", primary.Name(), peer.ID, err)
	}

	// Try fallback transport
	var fallback transport.Transport
	if primary == tm.APITransport && tm.DNSTransport != nil && agent.DnsMethod {
		fallback = tm.DNSTransport
	} else if primary == tm.DNSTransport && tm.APITransport != nil && agent.ApiMethod {
		fallback = tm.APITransport
	}

	if fallback != nil {
		log.Printf("TransportManager: Trying fallback transport %s for Beat to %s", fallback.Name(), peer.ID)
		return fallback.Beat(ctx, peer, req)
	}

	return nil, fmt.Errorf("all transports failed for Beat to peer %s", peer.ID)
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
