/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Peer management for multi-provider DNSSEC coordination (HSYNC).
 * Manages the state and addresses of remote agents.
 */

package transport

import (
	"crypto"
	"fmt"
	"sync"
	"time"
)

// PeerState represents the current state of a peer relationship.
type PeerState uint8

const (
	PeerStateNeeded      PeerState = iota // Peer is needed but not yet discovered
	PeerStateDiscovering                  // Discovery in progress
	PeerStateKnown                        // Discovered but not yet contacted
	PeerStateIntroducing                  // Hello handshake in progress
	PeerStateOperational                  // Fully operational
	PeerStateDegraded                     // Operational but with issues
	PeerStateInterrupted                  // Temporarily unreachable
	PeerStateError                        // Persistent error state
)

func (s PeerState) String() string {
	switch s {
	case PeerStateNeeded:
		return "NEEDED"
	case PeerStateDiscovering:
		return "DISCOVERING"
	case PeerStateKnown:
		return "KNOWN"
	case PeerStateIntroducing:
		return "INTRODUCING"
	case PeerStateOperational:
		return "OPERATIONAL"
	case PeerStateDegraded:
		return "DEGRADED"
	case PeerStateInterrupted:
		return "INTERRUPTED"
	case PeerStateError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Peer represents a remote agent that we communicate with.
type Peer struct {
	mu sync.RWMutex

	// Identity
	ID          string // Unique identifier (typically provider name)
	DisplayName string // Human-readable name

	// State
	State        PeerState // Current relationship state
	StateReason  string    // Reason for current state
	StateChanged time.Time // When state last changed

	// Addresses
	DiscoveryAddr   *Address // Address discovered via DNS (URI/SVCB records)
	OperationalAddr *Address // Private address from Relocate (for DDoS mitigation)
	APIEndpoint     string   // Full URL for API transport (when available)

	// Cryptographic identity
	LongTermPubKey crypto.PublicKey // Peer's long-term public key
	KeyType        string           // Algorithm of the key
	TLSARecord     []byte           // TLSA record for TLS verification

	// Capabilities
	Capabilities []string // What the peer supports

	// Shared zones
	SharedZones map[string]*ZoneRelation // Zones we share with this peer

	// Communication state
	LastHelloSent     time.Time // When we last sent a hello
	LastHelloReceived time.Time // When we last received a hello
	LastBeatSent      time.Time // When we last sent a beat
	LastBeatReceived  time.Time // When we last received a beat
	BeatSequence      uint64    // Current beat sequence number
	ConsecutiveFails  int       // Consecutive communication failures

	// Message statistics
	Stats MessageStats // Detailed per-message-type counters

	// Preferred transport
	PreferredTransport string // "API" or "DNS"
}

// MessageStats tracks detailed statistics for messages exchanged with a peer.
// Separate counters for sent/received and per message type.
type MessageStats struct {
	mu sync.RWMutex

	// Last contact time (updated on any message sent or received)
	LastUsed time.Time

	// Per-message-type counters
	HelloSent     uint64
	HelloReceived uint64
	BeatSent      uint64
	BeatReceived  uint64
	SyncSent      uint64
	SyncReceived  uint64
	PingSent      uint64
	PingReceived  uint64

	// Total distribution count (sum of all message types)
	TotalSent     uint64
	TotalReceived uint64
}

// ZoneRelation tracks the relationship for a specific zone.
type ZoneRelation struct {
	Zone        string    // Zone name (FQDN)
	Role        string    // Our role: "primary", "secondary", "multi-signer"
	PeerRole    string    // Peer's role for this zone
	LastSync    time.Time // Last successful sync for this zone
	SyncSerial  uint32    // Last synced serial
	SyncPending bool      // Whether a sync is pending
}

// NewPeer creates a new Peer with the given ID.
func NewPeer(id string) *Peer {
	return &Peer{
		ID:           id,
		State:        PeerStateNeeded,
		StateChanged: time.Now(),
		SharedZones:  make(map[string]*ZoneRelation),
	}
}

// SetState updates the peer's state with a reason.
func (p *Peer) SetState(state PeerState, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.State = state
	p.StateReason = reason
	p.StateChanged = time.Now()
}

// RecordMessageSent records statistics for an outgoing message.
func (ms *MessageStats) RecordMessageSent(msgType string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.LastUsed = time.Now()
	ms.TotalSent++

	switch msgType {
	case "hello":
		ms.HelloSent++
	case "beat":
		ms.BeatSent++
	case "sync", "update":
		ms.SyncSent++
	case "ping":
		ms.PingSent++
	}
}

// RecordMessageReceived records statistics for an incoming message.
func (ms *MessageStats) RecordMessageReceived(msgType string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.LastUsed = time.Now()
	ms.TotalReceived++

	switch msgType {
	case "hello":
		ms.HelloReceived++
	case "beat":
		ms.BeatReceived++
	case "sync", "update":
		ms.SyncReceived++
	case "ping":
		ms.PingReceived++
	}
}

// GetStats returns a snapshot of current statistics (thread-safe).
func (ms *MessageStats) GetStats() (lastUsed time.Time, sent, received uint64) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return ms.LastUsed, ms.TotalSent, ms.TotalReceived
}

// GetDetailedStats returns all per-message-type statistics.
func (ms *MessageStats) GetDetailedStats() (lastUsed time.Time, helloSent, helloRecv, beatSent, beatRecv, syncSent, syncRecv, pingSent, pingRecv, totalSent, totalRecv uint64) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return ms.LastUsed, ms.HelloSent, ms.HelloReceived, ms.BeatSent, ms.BeatReceived,
		ms.SyncSent, ms.SyncReceived, ms.PingSent, ms.PingReceived,
		ms.TotalSent, ms.TotalReceived
}

// GetState returns the peer's current state.
func (p *Peer) GetState() PeerState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.State
}

// CurrentAddress returns the address to use for communication.
// Prefers OperationalAddr if available (post-Relocate), falls back to DiscoveryAddr.
func (p *Peer) CurrentAddress() *Address {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.OperationalAddr != nil {
		return p.OperationalAddr
	}
	return p.DiscoveryAddr
}

// SetDiscoveryAddress sets the address discovered via DNS.
func (p *Peer) SetDiscoveryAddress(addr *Address) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.DiscoveryAddr = addr
}

// SetOperationalAddress sets the operational address (from Relocate).
func (p *Peer) SetOperationalAddress(addr *Address) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.OperationalAddr = addr
}

// AddSharedZone adds a zone that we share with this peer.
func (p *Peer) AddSharedZone(zone, ourRole, peerRole string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.SharedZones[zone] = &ZoneRelation{
		Zone:     zone,
		Role:     ourRole,
		PeerRole: peerRole,
	}
}

// GetSharedZone returns the zone relation for a specific zone.
func (p *Peer) GetSharedZone(zone string) *ZoneRelation {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.SharedZones[zone]
}

// GetSharedZones returns all shared zone names.
func (p *Peer) GetSharedZones() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	zones := make([]string, 0, len(p.SharedZones))
	for zone := range p.SharedZones {
		zones = append(zones, zone)
	}
	return zones
}

// RecordBeatSent records that a beat was sent.
func (p *Peer) RecordBeatSent() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastBeatSent = time.Now()
	p.BeatSequence++
}

// RecordBeatReceived records that a beat was received.
func (p *Peer) RecordBeatReceived() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastBeatReceived = time.Now()
	p.ConsecutiveFails = 0
}

// RecordFailure records a communication failure.
func (p *Peer) RecordFailure() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ConsecutiveFails++
}

// IsHealthy returns true if the peer is in a healthy state.
func (p *Peer) IsHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.State == PeerStateOperational || p.State == PeerStateDegraded
}

// PeerRegistry manages all known peers.
type PeerRegistry struct {
	mu    sync.RWMutex
	peers map[string]*Peer
}

// NewPeerRegistry creates a new PeerRegistry.
func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{
		peers: make(map[string]*Peer),
	}
}

// Get retrieves a peer by ID.
func (r *PeerRegistry) Get(id string) (*Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	peer, ok := r.peers[id]
	return peer, ok
}

// GetOrCreate retrieves a peer by ID, creating it if it doesn't exist.
func (r *PeerRegistry) GetOrCreate(id string) *Peer {
	r.mu.Lock()
	defer r.mu.Unlock()

	if peer, ok := r.peers[id]; ok {
		return peer
	}

	peer := NewPeer(id)
	r.peers[id] = peer
	return peer
}

// Add adds a peer to the registry.
func (r *PeerRegistry) Add(peer *Peer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.peers[peer.ID]; exists {
		return fmt.Errorf("peer %s already exists", peer.ID)
	}

	r.peers[peer.ID] = peer
	return nil
}

// Remove removes a peer from the registry.
func (r *PeerRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, id)
}

// All returns all peers in the registry.
func (r *PeerRegistry) All() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peers := make([]*Peer, 0, len(r.peers))
	for _, peer := range r.peers {
		peers = append(peers, peer)
	}
	return peers
}

// ByState returns all peers in a given state.
func (r *PeerRegistry) ByState(state PeerState) []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var peers []*Peer
	for _, peer := range r.peers {
		if peer.GetState() == state {
			peers = append(peers, peer)
		}
	}
	return peers
}

// ByZone returns all peers that share a given zone.
func (r *PeerRegistry) ByZone(zone string) []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var peers []*Peer
	for _, peer := range r.peers {
		if peer.GetSharedZone(zone) != nil {
			peers = append(peers, peer)
		}
	}
	return peers
}

// Count returns the number of peers in the registry.
func (r *PeerRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// HealthyCount returns the number of healthy peers.
func (r *PeerRegistry) HealthyCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, peer := range r.peers {
		if peer.IsHealthy() {
			count++
		}
	}
	return count
}
