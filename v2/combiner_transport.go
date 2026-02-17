/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CombinerTransport gives the combiner the ability to send messages to agents.
 * Wraps DNSTransport + optional APITransport with a peer map built from config.
 */

package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
)

// CombinerTransport manages outbound communication from combiner to agents.
// It holds a per-agent peer map (built from config) and one or more transports.
type CombinerTransport struct {
	mu sync.RWMutex

	// LocalID is the combiner's identity (FQDN).
	LocalID string

	// Peers maps agent identity (FQDN) → *transport.Peer.
	// Built from combiner.agents config at startup.
	Peers map[string]*transport.Peer

	// Transports
	DNS *transport.DNSTransport
	API *transport.APITransport

	// SecureWrapper for signing/encrypting outgoing payloads.
	// Shared with the DNSTransport (which uses it internally).
	SecureWrapper *transport.SecurePayloadWrapper
}

// CombinerTransportConfig holds the parameters for NewCombinerTransport.
type CombinerTransportConfig struct {
	// LocalID: combiner identity (FQDN)
	LocalID string

	// Agents: static list of agents from config
	Agents []*PeerConf

	// ListenAddr: combiner's dnsengine listen address (for DNSTransport)
	ListenAddr string

	// SecureWrapper: for JWS/JWE on outgoing payloads (optional)
	SecureWrapper *transport.SecurePayloadWrapper

	// DistributionCache: for tracking outgoing distributions (optional)
	DistributionCache *DistributionCache
}

// NewCombinerTransport creates a CombinerTransport from config.
// Builds the peer map from the agents list and creates a DNSTransport for sending.
func NewCombinerTransport(cfg *CombinerTransportConfig) (*CombinerTransport, error) {
	if cfg.LocalID == "" {
		return nil, fmt.Errorf("CombinerTransport requires LocalID")
	}
	if len(cfg.Agents) == 0 {
		return nil, fmt.Errorf("CombinerTransport requires at least one agent")
	}

	ct := &CombinerTransport{
		LocalID:       cfg.LocalID,
		Peers:         make(map[string]*transport.Peer),
		SecureWrapper: cfg.SecureWrapper,
	}

	// Build peer map from config
	for _, agentConf := range cfg.Agents {
		if agentConf.Identity == "" {
			return nil, fmt.Errorf("CombinerTransport: agent entry missing identity")
		}

		peer := transport.NewPeer(agentConf.Identity)
		peer.SetState(transport.PeerStateKnown, "configured")

		// Parse address into host:port
		if agentConf.Address != "" {
			host, portStr, err := net.SplitHostPort(agentConf.Address)
			if err != nil {
				return nil, fmt.Errorf("CombinerTransport: invalid address %q for agent %s: %w",
					agentConf.Address, agentConf.Identity, err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("CombinerTransport: invalid port in address %q for agent %s: %w",
					agentConf.Address, agentConf.Identity, err)
			}
			peer.SetDiscoveryAddress(&transport.Address{
				Host:      host,
				Port:      uint16(port),
				Transport: "udp",
			})
		}

		// Set API endpoint if configured
		if agentConf.ApiBaseUrl != "" {
			peer.APIEndpoint = agentConf.ApiBaseUrl
			peer.PreferredTransport = "API"
		} else {
			peer.PreferredTransport = "DNS"
		}

		ct.Peers[agentConf.Identity] = peer
		log.Printf("CombinerTransport: Registered agent peer %s (address=%s, transport=%s)",
			agentConf.Identity, agentConf.Address, peer.PreferredTransport)
	}

	// Create DNS transport for sending NOTIFY(CHUNK) to agents.
	// ControlZone = combiner identity (used as QNAME suffix: {distid}.{combiner-identity})
	var payloadCrypto *transport.PayloadCrypto
	if cfg.SecureWrapper != nil {
		payloadCrypto = cfg.SecureWrapper.GetCrypto()
	}

	var distAdd func(qname, senderID, receiverID, operation, distributionID string)
	var distComplete func(qname string)
	if cfg.DistributionCache != nil {
		distAdd = func(qname, senderID, receiverID, operation, distributionID string) {
			cfg.DistributionCache.Add(qname, &DistributionInfo{
				DistributionID: distributionID,
				SenderID:       senderID,
				ReceiverID:     receiverID,
				Operation:      operation,
				State:          "pending",
				CreatedAt:      time.Now(),
				QNAME:          qname,
			})
		}
		distComplete = func(qname string) {
			cfg.DistributionCache.MarkCompleted(qname)
		}
	}

	ct.DNS = transport.NewDNSTransport(&transport.DNSTransportConfig{
		LocalID:                   cfg.LocalID,
		ControlZone:               cfg.LocalID, // combiner identity as control zone
		ListenAddr:                cfg.ListenAddr,
		PayloadCrypto:             payloadCrypto,
		DistributionAdd:           distAdd,
		DistributionMarkCompleted: distComplete,
	})

	log.Printf("CombinerTransport: DNS transport created (controlZone=%s, listen=%s, crypto=%v)",
		cfg.LocalID, cfg.ListenAddr, payloadCrypto != nil)

	return ct, nil
}

// GetPeer returns the peer for the given agent identity, or nil if not found.
func (ct *CombinerTransport) GetPeer(agentID string) *transport.Peer {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.Peers[agentID]
}

// GetAllPeers returns a snapshot of all agent peers.
func (ct *CombinerTransport) GetAllPeers() []*transport.Peer {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	peers := make([]*transport.Peer, 0, len(ct.Peers))
	for _, p := range ct.Peers {
		peers = append(peers, p)
	}
	return peers
}

// selectTransport returns the best transport for the given peer.
// Prefers the peer's preferred transport, falls back to the other.
func (ct *CombinerTransport) selectTransport(peer *transport.Peer) transport.Transport {
	switch peer.PreferredTransport {
	case "API":
		if ct.API != nil && peer.APIEndpoint != "" {
			return ct.API
		}
		// Fall back to DNS
		if ct.DNS != nil && peer.CurrentAddress() != nil {
			return ct.DNS
		}
	default: // "DNS" or unset
		if ct.DNS != nil && peer.CurrentAddress() != nil {
			return ct.DNS
		}
		// Fall back to API
		if ct.API != nil && peer.APIEndpoint != "" {
			return ct.API
		}
	}
	return nil
}

// Ping sends a ping to the specified agent and returns the response.
func (ct *CombinerTransport) Ping(ctx context.Context, agentID string, req *transport.PingRequest) (*transport.PingResponse, error) {
	peer := ct.GetPeer(agentID)
	if peer == nil {
		return nil, fmt.Errorf("unknown agent %q", agentID)
	}
	t := ct.selectTransport(peer)
	if t == nil {
		return nil, fmt.Errorf("no transport available for agent %s", agentID)
	}
	return t.Ping(ctx, peer, req)
}

// Sync sends a sync message to the specified agent and returns the response.
func (ct *CombinerTransport) Sync(ctx context.Context, agentID string, req *transport.SyncRequest) (*transport.SyncResponse, error) {
	peer := ct.GetPeer(agentID)
	if peer == nil {
		return nil, fmt.Errorf("unknown agent %q", agentID)
	}
	t := ct.selectTransport(peer)
	if t == nil {
		return nil, fmt.Errorf("no transport available for agent %s", agentID)
	}
	return t.Sync(ctx, peer, req)
}

// Beat sends a beat to the specified agent and returns the response.
func (ct *CombinerTransport) Beat(ctx context.Context, agentID string, req *transport.BeatRequest) (*transport.BeatResponse, error) {
	peer := ct.GetPeer(agentID)
	if peer == nil {
		return nil, fmt.Errorf("unknown agent %q", agentID)
	}
	t := ct.selectTransport(peer)
	if t == nil {
		return nil, fmt.Errorf("no transport available for agent %s", agentID)
	}
	return t.Beat(ctx, peer, req)
}

// Confirm sends a confirmation to the specified agent.
func (ct *CombinerTransport) Confirm(ctx context.Context, agentID string, req *transport.ConfirmRequest) error {
	peer := ct.GetPeer(agentID)
	if peer == nil {
		return fmt.Errorf("unknown agent %q", agentID)
	}
	t := ct.selectTransport(peer)
	if t == nil {
		return fmt.Errorf("no transport available for agent %s", agentID)
	}
	return t.Confirm(ctx, peer, req)
}
