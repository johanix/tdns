/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent distribution management API endpoints
 */
package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// DistributionInfo holds information about a distribution
type DistributionInfo struct {
	DistributionID string
	SenderID       string
	ReceiverID     string
	Operation      string
	ContentType    string
	State          string
	PayloadSize    int // Size of the final payload in bytes (after encryption, before chunking)
	CreatedAt      time.Time
	CompletedAt    *time.Time
	ExpiresAt      *time.Time // When this distribution should be cleaned up (nil = no expiration)
	QNAME          string     // The DNS QNAME used to retrieve this distribution
}

// PeerInfo holds information about a peer agent with established keys
type PeerInfo struct {
	PeerID       string
	PeerType     string // "combiner" or "agent"
	Transport    string // "API" or "DNS"
	Address      string
	CryptoType   string    // "JOSE" or "HPKE" (for DNS), "TLS" (for API), or "-"
	DistribSent  int       // Number of distributions sent to this peer (deprecated - use TotalReceived)
	LastUsed     time.Time // Last time this peer was used
	Addresses    []string  // IP addresses from discovery
	Port         uint16    // Port number
	JWKData      string    // JWK data if available
	KeyAlgorithm string    // Key algorithm (e.g., "ES256")
	HasJWK       bool      // Whether JWK is available
	HasKEY       bool      // Whether KEY record is available
	HasTLSA      bool      // Whether TLSA record is available
	APIUri       string    // Full API URI
	DNSUri       string    // Full DNS URI
	Partial      bool      // Whether discovery was partial
	State        string    // Agent state
	ContactInfo  string    // Contact info status

	// Per-message-type statistics
	HelloSent     uint64
	HelloReceived uint64
	BeatSent      uint64
	BeatReceived  uint64
	SyncSent      uint64
	SyncReceived  uint64
	PingSent      uint64
	PingReceived  uint64
	TotalSent     uint64
	TotalReceived uint64
}

// DistributionCache is an in-memory cache of distributions keyed by QNAME
type DistributionCache struct {
	dists core.ConcurrentMap[string, *DistributionInfo] // keyed by QNAME
}

// NewDistributionCache creates a new distribution cache
func NewDistributionCache() *DistributionCache {
	return &DistributionCache{
		dists: *core.NewCmap[*DistributionInfo](),
	}
}

// Add adds a distribution to the cache
func (dc *DistributionCache) Add(qname string, info *DistributionInfo) {
	dc.dists.Set(qname, info)
}

// Get retrieves a distribution by QNAME
func (dc *DistributionCache) Get(qname string) (*DistributionInfo, bool) {
	return dc.dists.Get(qname)
}

// MarkCompleted marks a distribution as completed
func (dc *DistributionCache) MarkCompleted(qname string) {
	if info, exists := dc.dists.Get(qname); exists {
		now := time.Now()
		info.CompletedAt = &now
		info.State = "confirmed"
		dc.dists.Set(qname, info) // Update in map
	}
}

// List returns all distributions for a given sender
func (dc *DistributionCache) List(senderID string) []*DistributionInfo {
	var results []*DistributionInfo

	for tuple := range dc.dists.IterBuffered() {
		info := tuple.Val
		if senderID == "" || info.SenderID == senderID {
			results = append(results, info)
		}
	}
	return results
}

// PurgeCompleted removes completed distributions older than the given duration.
// Incomplete distributions (CompletedAt == nil) are never purged; only explicit "purge --force" removes them.
func (dc *DistributionCache) PurgeCompleted(olderThan time.Duration) int {
	count := 0
	cutoff := time.Now().Add(-olderThan)

	for tuple := range dc.dists.IterBuffered() {
		qname := tuple.Key
		info := tuple.Val
		if info.CompletedAt != nil && info.CompletedAt.Before(cutoff) {
			dc.dists.Remove(qname)
			count++
		}
	}
	return count
}

// PurgeAll removes all distributions
func (dc *DistributionCache) PurgeAll() int {
	count := dc.dists.Count()
	dc.dists.Clear()
	return count
}

// PurgeExpired removes distributions that have passed their ExpiresAt time.
// This implements fast expiration for beat/ping messages to reduce clutter.
// Returns the number of distributions removed.
func (dc *DistributionCache) PurgeExpired() int {
	count := 0
	now := time.Now()

	for tuple := range dc.dists.IterBuffered() {
		qname := tuple.Key
		info := tuple.Val
		if info.ExpiresAt != nil && info.ExpiresAt.Before(now) {
			dc.dists.Remove(qname)
			count++
		}
	}
	return count
}

// StartCleanupGoroutine starts a background goroutine that periodically removes expired distributions.
// The cleanup runs every minute to keep the distribution list clean without excessive overhead.
func (dc *DistributionCache) StartCleanupGoroutine(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				lgApi.Info("cleanup goroutine stopping")
				return
			case <-ticker.C:
				removed := dc.PurgeExpired()
				if removed > 0 {
					lgApi.Info("purged expired distributions", "count", removed)
				}
			}
		}
	}()
	lgApi.Info("cleanup goroutine started", "interval", "1m")
}

// AgentDistribPost represents a request to the agent distrib API
type AgentDistribPost struct {
	Command       string `json:"command"`                  // "list", "purge", "peer-list", "peer-zones", "zone-agents", "op", "discover"
	Force         bool   `json:"force,omitempty"`          // for purge
	Op            string `json:"op,omitempty"`             // for op: operation name (e.g. "ping")
	To            string `json:"to,omitempty"`             // for op: recipient identity (e.g. "combiner", "agent.delta.dnslab.")
	PingTransport string `json:"ping_transport,omitempty"` // for op ping: "dns" (default) or "api"
	AgentId       string `json:"agent_id,omitempty"`       // for discover: agent identity to discover
	Zone          string `json:"zone,omitempty"`           // for zone-agents: zone name to list agents for
}

// DistributionSummary contains summary information about a distribution
type DistributionSummary struct {
	DistributionID string `json:"distribution_id"`
	SenderID       string `json:"sender_id"`
	ReceiverID     string `json:"receiver_id"`
	Operation      string `json:"operation"`
	ContentType    string `json:"content_type"`
	State          string `json:"state"`
	PayloadSize    int    `json:"payload_size"`
	CreatedAt      string `json:"created_at"`
	CompletedAt    string `json:"completed_at,omitempty"`
}

// AgentDistribResponse represents a response from the agent distrib API
type AgentDistribResponse struct {
	Time          time.Time              `json:"time"`
	Error         bool                   `json:"error,omitempty"`
	ErrorMsg      string                 `json:"error_msg,omitempty"`
	Msg           string                 `json:"msg,omitempty"`
	Summaries     []*DistributionSummary `json:"summaries,omitempty"`
	Distributions []string               `json:"distributions,omitempty"` // For backward compatibility
	Data          []interface{}          `json:"data,omitempty"`          // For peer-zones command
	Agents        []string               `json:"agents,omitempty"`        // For zone-agents command
}

func (conf *Config) APIagentDistrib(cache *DistributionCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req AgentDistribPost
		err := decoder.Decode(&req)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "agentDistrib", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /agent/distrib request", "cmd", req.Command, "from", r.RemoteAddr)

		resp := AgentDistribResponse{
			Time: time.Now(),
		}

		handledManually := false
		defer func() {
			if !handledManually {
				w.Header().Set("Content-Type", "application/json")
				sanitizedResp := SanitizeForJSON(resp)
				err := json.NewEncoder(w).Encode(sanitizedResp)
				if err != nil {
					lgApi.Error("json encode failed", "handler", "agentDistrib", "err", err)
				}
			}
		}()

		switch req.Command {
		case "peer-zones":
			// List shared zones for each peer agent (doesn't need cache)
			data := listPeerSharedZones(conf)
			resp.Msg = fmt.Sprintf("Found %d peer(s)", len(data))
			resp.Data = data
			return

		case "zone-agents":
			// List agents for a specific zone (doesn't need cache)
			zoneName := req.Zone
			if zoneName == "" {
				resp.Error = true
				resp.ErrorMsg = "zone parameter is required"
				return
			}
			agents := listAgentsForZone(conf, zoneName)

			// Get SOA serial for the zone if available
			var zoneSerial uint32
			if zd, exists := Zones.Get(zoneName); exists {
				if soa, err := zd.GetSOA(); err == nil {
					zoneSerial = soa.Serial
				}
			}

			resp.Msg = fmt.Sprintf("Found %d agent(s) for zone %q (serial: %d)", len(agents), zoneName, zoneSerial)
			resp.Agents = agents
			return
		}

		// Commands below this point require cache
		if cache == nil {
			resp.Error = true
			resp.ErrorMsg = "Distribution cache not configured"
			return
		}

		switch req.Command {
		case "list":
			// List all distributions from this agent
			senderID := string(conf.Agent.Identity)
			infos := cache.List(senderID)

			summaries := make([]*DistributionSummary, 0, len(infos))
			distIDs := make([]string, 0, len(infos))

			for _, info := range infos {
				summary := &DistributionSummary{
					DistributionID: info.DistributionID,
					SenderID:       info.SenderID,
					ReceiverID:     info.ReceiverID,
					Operation:      info.Operation,
					ContentType:    info.ContentType,
					State:          info.State,
					PayloadSize:    info.PayloadSize,
					CreatedAt:      info.CreatedAt.Format(time.RFC3339),
				}
				if info.CompletedAt != nil {
					summary.CompletedAt = info.CompletedAt.Format(time.RFC3339)
				}
				summaries = append(summaries, summary)
				distIDs = append(distIDs, info.DistributionID)
			}

			resp.Summaries = summaries
			resp.Distributions = distIDs
			resp.Msg = fmt.Sprintf("Found %d distribution(s)", len(summaries))

		case "purge":
			// Delete distributions
			var deleted int
			if req.Force {
				deleted = cache.PurgeAll()
				resp.Msg = fmt.Sprintf("Purged %d distribution(s) (force mode)", deleted)
			} else {
				// Purge completed distributions older than 5 minutes
				deleted = cache.PurgeCompleted(5 * time.Minute)
				resp.Msg = fmt.Sprintf("Purged %d completed distribution(s)", deleted)
			}

		case "peer-list":
			// List all known peers with working keys
			peers := listKnownPeers(conf)
			resp.Msg = fmt.Sprintf("Found %d peer(s) with working keys", len(peers))

			// Convert to generic map for JSON serialization
			peerMaps := make([]map[string]interface{}, len(peers))
			for i, peer := range peers {
				peerMaps[i] = map[string]interface{}{
					"peer_id":      peer.PeerID,
					"peer_type":    peer.PeerType,
					"transport":    peer.Transport,
					"address":      peer.Address,
					"crypto_type":  peer.CryptoType,
					"distrib_sent": peer.DistribSent,
				}

				// Add extended discovery information
				if peer.APIUri != "" {
					peerMaps[i]["api_uri"] = peer.APIUri
				}
				if peer.DNSUri != "" {
					peerMaps[i]["dns_uri"] = peer.DNSUri
				}
				if peer.Port > 0 {
					peerMaps[i]["port"] = peer.Port
				}
				if len(peer.Addresses) > 0 {
					peerMaps[i]["addresses"] = peer.Addresses
				}
				if peer.JWKData != "" {
					peerMaps[i]["jwk_data"] = peer.JWKData
					peerMaps[i]["has_jwk"] = true
				} else {
					peerMaps[i]["has_jwk"] = false
				}
				if peer.KeyAlgorithm != "" {
					peerMaps[i]["key_algorithm"] = peer.KeyAlgorithm
				}
				peerMaps[i]["has_key"] = peer.HasKEY
				peerMaps[i]["has_tlsa"] = peer.HasTLSA
				peerMaps[i]["partial"] = peer.Partial
				if peer.State != "" {
					peerMaps[i]["state"] = peer.State
				}
				if peer.ContactInfo != "" {
					peerMaps[i]["contact_info"] = peer.ContactInfo
				}

				if !peer.LastUsed.IsZero() {
					peerMaps[i]["last_used"] = peer.LastUsed.Format(time.RFC3339)
				}
			}

			// Add to response using a generic field
			respMap := SanitizeForJSON(resp).(AgentDistribResponse)
			w.Header().Set("Content-Type", "application/json")

			// Create response with peers field
			fullResp := map[string]interface{}{
				"time":  respMap.Time,
				"msg":   respMap.Msg,
				"error": respMap.Error,
				"peers": peerMaps,
			}
			if respMap.ErrorMsg != "" {
				fullResp["error_msg"] = respMap.ErrorMsg
			}

			handledManually = true
			json.NewEncoder(w).Encode(fullResp)
			return

		case "op":
			// Run operation toward a peer: distrib op {operation} --to {identity}
			if req.Op == "" || req.To == "" {
				resp.Error = true
				resp.ErrorMsg = "op and to are required (e.g. op=ping, to=combiner)"
				return
			}
			toIdentity := strings.TrimSpace(strings.ToLower(req.To))
			opName := strings.TrimSpace(strings.ToLower(req.Op))

			switch opName {
			case "ping":
				if toIdentity == "combiner" {
					useAPI := strings.TrimSpace(strings.ToLower(req.PingTransport)) == "api"
					pingResp := doPeerPing(conf, dns.Fqdn(req.To), useAPI)
					resp.Error = pingResp.Error
					resp.ErrorMsg = pingResp.ErrorMsg
					resp.Msg = pingResp.Msg
				} else {
					// Ping to peer agent: same mechanism as combiner (SendPing); lookup peer by FQDN identity
					if conf.Internal.TransportManager == nil {
						resp.Error = true
						resp.ErrorMsg = "TransportManager not configured"
						return
					}
					toFqdn := dns.Fqdn(req.To)
					peer, ok := conf.Internal.TransportManager.PeerRegistry.Get(toFqdn)
					if !ok {
						// DNS-42: Authorization check BEFORE discovery
						// Prevents DoS attack via discovery amplification
						authorized, reason := conf.Internal.TransportManager.IsPeerAuthorized(toFqdn, "")
						if !authorized {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("peer %q is not authorized", req.To)
							lgApi.Warn("rejected discovery for unauthorized agent", "agent", toFqdn, "reason", reason)
							return
						}

						// Attempt dynamic discovery for authorized but unknown agents
						lgApi.Info("agent not in PeerRegistry, attempting discovery", "agent", toFqdn, "reason", reason)
						discoveryCtx, discoveryCancel := context.WithTimeout(r.Context(), 10*time.Second)
						defer discoveryCancel()

						discErr := conf.Internal.TransportManager.DiscoverAndRegisterAgent(discoveryCtx, toFqdn)
						if discErr != nil {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("peer %q not found and discovery failed", req.To)
							lgApi.Warn("peer discovery failed", "peer", toFqdn, "err", discErr)
							return
						}

						// Try to get peer again after discovery
						peer, ok = conf.Internal.TransportManager.PeerRegistry.Get(toFqdn)
						if !ok {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("peer %q discovered but not registered properly", req.To)
							return
						}
						lgApi.Info("discovered and registered agent", "agent", toFqdn)
					}
					if peer.CurrentAddress() == nil {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("peer %q has no address configured", req.To)
						return
					}
					ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
					defer cancel()
					pingResp, err := conf.Internal.TransportManager.SendPing(ctx, peer)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("ping failed: %v", err)
						return
					}
					if !pingResp.OK {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("peer did not acknowledge (responder: %s)", pingResp.ResponderID)
						return
					}
					resp.Msg = fmt.Sprintf("dnsping ok: %s echoed nonce", pingResp.ResponderID)
				}
			default:
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("unknown operation %q (supported: ping)", req.Op)
			}

		case "discover":
			// Discover agent contact information via DNS
			if req.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "agent_id is required for discover command"
				return
			}
			if conf.Internal.TransportManager == nil {
				resp.Error = true
				resp.ErrorMsg = "TransportManager not configured"
				return
			}

			agentId := strings.TrimSpace(req.AgentId)
			agentFqdn := dns.Fqdn(agentId)

			// DNS-42: Authorization check BEFORE discovery
			// Prevents DoS attack via discovery amplification
			authorized, reason := conf.Internal.TransportManager.IsPeerAuthorized(agentFqdn, "")
			if !authorized {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent %q is not authorized", agentId)
				lgApi.Warn("rejected discovery for unauthorized agent", "agent", agentFqdn, "reason", reason)
				return
			}

			lgApi.Info("starting discovery", "agent", agentId, "reason", reason)

			discoveryCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()

			err := conf.Internal.TransportManager.DiscoverAndRegisterAgent(discoveryCtx, agentFqdn)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = "discovery failed"
				lgApi.Warn("agent discovery failed", "agent", agentFqdn, "err", err)
				return
			}

			// Get the peer to return discovery information
			peer, ok := conf.Internal.TransportManager.PeerRegistry.Get(dns.Fqdn(agentId))
			if !ok {
				resp.Error = true
				resp.ErrorMsg = "agent discovered but not found in registry"
				return
			}

			// Build discovery result for response
			discoveryInfo := map[string]interface{}{
				"identity": peer.ID,
			}
			if peer.APIEndpoint != "" {
				discoveryInfo["api_uri"] = peer.APIEndpoint
			}
			if addr := peer.CurrentAddress(); addr != nil {
				discoveryInfo["host"] = addr.Host
				discoveryInfo["port"] = addr.Port
				discoveryInfo["transport"] = addr.Transport
			}
			discoveryInfo["state"] = peer.GetState().String()
			discoveryInfo["preferred_transport"] = peer.PreferredTransport

			// Return result through handledManually
			respMap := SanitizeForJSON(resp).(AgentDistribResponse)
			w.Header().Set("Content-Type", "application/json")

			fullResp := map[string]interface{}{
				"time":      respMap.Time,
				"msg":       fmt.Sprintf("Successfully discovered agent %s", agentId),
				"error":     false,
				"discovery": discoveryInfo,
			}

			handledManually = true
			json.NewEncoder(w).Encode(fullResp)
			return

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", req.Command)
		}
	}
}

// StartDistributionGC starts a background goroutine that periodically purges:
// 1. Completed distributions older than 5 minutes
// 2. Expired distributions past their ExpiresAt time (based on message type retention)
// Incomplete distributions are never purged by GC (only "purge --force" removes them).
func StartDistributionGC(cache *DistributionCache, interval time.Duration, stopCh chan struct{}) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				completedCount := cache.PurgeCompleted(5 * time.Minute)
				if completedCount > 0 {
					lgApi.Info("GC purged completed distributions", "count", completedCount)
				}

				expiredCount := cache.PurgeExpired()
				if expiredCount > 0 {
					lgApi.Info("GC purged expired distributions", "count", expiredCount)
				}
			case <-stopCh:
				return
			}
		}
	}()
}

// listKnownPeers returns all peers that have working keys established
func listKnownPeers(conf *Config) []PeerInfo {
	var peers []PeerInfo

	// For combiners: list all configured agents
	if conf.Combiner != nil && len(conf.Combiner.Agents) > 0 {
		for _, agent := range conf.Combiner.Agents {
			peerID := agent.Identity
			if peerID == "" {
				peerID = agent.Address
			}
			peerInfo := PeerInfo{
				PeerID:      peerID,
				PeerType:    "agent",
				Transport:   "DNS",
				Address:     agent.Address,
				CryptoType:  "JOSE",
				DistribSent: 0, // TODO: track actual count
			}
			peers = append(peers, peerInfo)
		}
		return peers
	}

	// For agents: list remote agents from AgentRegistry
	// Note: The combiner is automatically included as it's registered as a virtual peer
	// during agent initialization (see InitializeCombinerAsPeer)

	// Add remote agents from AgentRegistry (discovered via DNS); use FQDN
	// Create separate entries for API and DNS transports
	seen := make(map[string]bool) // key: peerID+transport
	for _, p := range peers {
		seen[p.PeerID+":"+p.Transport] = true
	}
	if conf.Internal.AgentRegistry != nil {
		ar := conf.Internal.AgentRegistry

		// Use callback-based iterator to avoid channel/deadlock issues
		ar.S.IterCb(func(agentID AgentId, agent *Agent) {
			agentIDFqdn := dns.Fqdn(string(agent.Identity))

			// Special handling for combiner virtual peer
			// Check if this agent is the configured combiner (by identity)
			isCombiner := false
			if conf.Agent.Combiner != nil && conf.Agent.Combiner.Identity != "" {
				isCombiner = string(agent.Identity) == conf.Agent.Combiner.Identity ||
					dns.Fqdn(string(agent.Identity)) == dns.Fqdn(conf.Agent.Combiner.Identity)
			} else {
				isCombiner = agent.Identity == "combiner"
			}

			// Special handling for signer virtual peer
			isSigner := false
			if conf.Agent.Signer != nil && conf.Agent.Signer.Identity != "" {
				isSigner = string(agent.Identity) == conf.Agent.Signer.Identity ||
					dns.Fqdn(string(agent.Identity)) == dns.Fqdn(conf.Agent.Signer.Identity)
			}

			peerType := "agent"
			if isCombiner {
				peerType = "combiner"
			} else if isSigner {
				peerType = "signer"
			}

			// Add API transport entry if available
			if agent.ApiDetails != nil && agent.ApiDetails.BaseUri != "" {
				key := agentIDFqdn + ":API"
				if !seen[key] {
					seen[key] = true

					// Compute effective state: if agent has established relationship but no shared zones, show LEGACY
					// (but not for combiner/signer, which don't have shared zones by design)
					effectiveState := agent.ApiDetails.State
					if !isCombiner && !isSigner && len(agent.Zones) == 0 && (effectiveState == AgentStateOperational || effectiveState == AgentStateIntroduced || effectiveState == AgentStateKnown) {
						effectiveState = AgentStateLegacy
					}

					peerInfo := PeerInfo{
						PeerID:      agentIDFqdn,
						PeerType:    peerType,
						Transport:   "API",
						Address:     agent.ApiDetails.BaseUri,
						CryptoType:  "TLS",
						DistribSent: 0, // Will be updated from PeerRegistry below
						APIUri:      agent.ApiDetails.BaseUri,
						Port:        agent.ApiDetails.Port,
						Addresses:   agent.ApiDetails.Addrs,
						HasTLSA:     agent.ApiDetails.TlsaRR != nil,
						State:       AgentStateToString[effectiveState],
						ContactInfo: agent.ApiDetails.ContactInfo,
					}
					if !agent.ApiDetails.HelloTime.IsZero() {
						peerInfo.LastUsed = agent.ApiDetails.HelloTime
					}
					// Get statistics from PeerRegistry if available
					if conf.Internal.TransportManager != nil {
						if peer, ok := conf.Internal.TransportManager.PeerRegistry.Get(agentIDFqdn); ok {
							lastUsed, helloSent, helloRecv, beatSent, beatRecv, syncSent, syncRecv, pingSent, pingRecv, totalSent, totalRecv := peer.Stats.GetDetailedStats()
							peerInfo.HelloSent = helloSent
							peerInfo.HelloReceived = helloRecv
							peerInfo.BeatSent = beatSent
							peerInfo.BeatReceived = beatRecv
							peerInfo.SyncSent = syncSent
							peerInfo.SyncReceived = syncRecv
							peerInfo.PingSent = pingSent
							peerInfo.PingReceived = pingRecv
							peerInfo.TotalSent = totalSent
							peerInfo.TotalReceived = totalRecv
							peerInfo.DistribSent = int(totalRecv) // Backward compat
							if !lastUsed.IsZero() {
								peerInfo.LastUsed = lastUsed
							}
							lgApi.Debug("peer stats", "peer", agentIDFqdn, "lastUsed", lastUsed.Format("15:04:05"), "sent", totalSent, "received", totalRecv)
						} else {
							lgApi.Debug("peer not found in PeerRegistry", "peer", agentIDFqdn)
						}
					}
					peers = append(peers, peerInfo)
				}
			}

			// Add DNS transport entry if available
			if agent.DnsDetails != nil && agent.DnsDetails.BaseUri != "" {
				key := agentIDFqdn + ":DNS"
				if !seen[key] {
					seen[key] = true

					// Compute effective state: if agent has established relationship but no shared zones, show LEGACY
					// (but not for combiner/signer, which don't have shared zones by design)
					effectiveState := agent.DnsDetails.State
					if !isCombiner && !isSigner && len(agent.Zones) == 0 && (effectiveState == AgentStateOperational || effectiveState == AgentStateIntroduced || effectiveState == AgentStateKnown) {
						effectiveState = AgentStateLegacy
					}

					peerInfo := PeerInfo{
						PeerID:       agentIDFqdn,
						PeerType:     peerType,
						Transport:    "DNS",
						Address:      agent.DnsDetails.BaseUri,
						CryptoType:   "JOSE",
						DistribSent:  0, // Will be updated from PeerRegistry below
						DNSUri:       agent.DnsDetails.BaseUri,
						Port:         agent.DnsDetails.Port,
						Addresses:    agent.DnsDetails.Addrs,
						JWKData:      agent.DnsDetails.JWKData,
						KeyAlgorithm: agent.DnsDetails.KeyAlgorithm,
						HasJWK:       agent.DnsDetails.JWKData != "",
						HasKEY:       agent.DnsDetails.KeyRR != nil,
						State:        AgentStateToString[effectiveState],
						ContactInfo:  agent.DnsDetails.ContactInfo,
					}
					if !agent.DnsDetails.HelloTime.IsZero() {
						peerInfo.LastUsed = agent.DnsDetails.HelloTime
					}
					// Get statistics from PeerRegistry if available
					if conf.Internal.TransportManager != nil {
						if peer, ok := conf.Internal.TransportManager.PeerRegistry.Get(agentIDFqdn); ok {
							lastUsed, helloSent, helloRecv, beatSent, beatRecv, syncSent, syncRecv, pingSent, pingRecv, totalSent, totalRecv := peer.Stats.GetDetailedStats()
							peerInfo.HelloSent = helloSent
							peerInfo.HelloReceived = helloRecv
							peerInfo.BeatSent = beatSent
							peerInfo.BeatReceived = beatRecv
							peerInfo.SyncSent = syncSent
							peerInfo.SyncReceived = syncRecv
							peerInfo.PingSent = pingSent
							peerInfo.PingReceived = pingRecv
							peerInfo.TotalSent = totalSent
							peerInfo.TotalReceived = totalRecv
							peerInfo.DistribSent = int(totalRecv) // Backward compat
							if !lastUsed.IsZero() {
								peerInfo.LastUsed = lastUsed
							}
							lgApi.Debug("peer stats", "peer", agentIDFqdn, "lastUsed", lastUsed.Format("15:04:05"), "sent", totalSent, "received", totalRecv)
						} else {
							lgApi.Debug("peer not found in PeerRegistry", "peer", agentIDFqdn)
						}
					}
					peers = append(peers, peerInfo)
				}
			}
		})
	}

	// Add agents from authorized_peers that haven't been discovered yet
	if conf.Agent != nil && len(conf.Agent.AuthorizedPeers) > 0 {
		for _, peerID := range conf.Agent.AuthorizedPeers {
			peerIDFqdn := dns.Fqdn(peerID)

			// Check if already in peers list (discovered)
			alreadyListed := false
			for _, p := range peers {
				if p.PeerID == peerIDFqdn {
					alreadyListed = true
					break
				}
			}

			if !alreadyListed {
				// Add config-only entry
				peerInfo := PeerInfo{
					PeerID:      peerIDFqdn,
					PeerType:    "agent",
					Transport:   "-",
					Address:     "-",
					CryptoType:  "-",
					State:       "CONFIG",
					ContactInfo: "config only",
					DistribSent: 0, // Will be updated from PeerRegistry if peer exists
				}
				// Get statistics from PeerRegistry if available (peer may be known but not fully discovered)
				if conf.Internal.TransportManager != nil {
					if peer, ok := conf.Internal.TransportManager.PeerRegistry.Get(peerIDFqdn); ok {
						lastUsed, helloSent, helloRecv, beatSent, beatRecv, syncSent, syncRecv, pingSent, pingRecv, totalSent, totalRecv := peer.Stats.GetDetailedStats()
						peerInfo.HelloSent = helloSent
						peerInfo.HelloReceived = helloRecv
						peerInfo.BeatSent = beatSent
						peerInfo.BeatReceived = beatRecv
						peerInfo.SyncSent = syncSent
						peerInfo.SyncReceived = syncRecv
						peerInfo.PingSent = pingSent
						peerInfo.PingReceived = pingRecv
						peerInfo.TotalSent = totalSent
						peerInfo.TotalReceived = totalRecv
						peerInfo.DistribSent = int(totalRecv) // Backward compat
						if !lastUsed.IsZero() {
							peerInfo.LastUsed = lastUsed
						}
						lgApi.Debug("config-only peer stats", "peer", peerIDFqdn, "lastUsed", lastUsed.Format("15:04:05"), "sent", totalSent, "received", totalRecv)
					}
				}
				peers = append(peers, peerInfo)
			}
		}
	}

	// Add all peers from PeerRegistry that we haven't listed yet
	// This includes peers that sent unsolicited Hello messages or were contacted but not in AgentRegistry
	if conf.Internal.TransportManager != nil {
		allPeersFromRegistry := conf.Internal.TransportManager.PeerRegistry.All()
		for _, peer := range allPeersFromRegistry {
			peerID := peer.ID

			// Check if already in peers list
			alreadyListed := false
			for _, p := range peers {
				if p.PeerID == peerID {
					alreadyListed = true
					break
				}
			}

			if !alreadyListed {
				// Get detailed stats
				lastUsed, helloSent, helloRecv, beatSent, beatRecv, syncSent, syncRecv, pingSent, pingRecv, totalSent, totalRecv := peer.Stats.GetDetailedStats()

				// Determine state from statistics
				state := "UNKNOWN"
				if totalRecv > 0 || totalSent > 0 {
					// If we have any communication, it's at least contacted
					if beatRecv > 0 || beatSent > 0 {
						state = "CONTACTED" // Has exchanged heartbeats
					} else if helloRecv > 0 || helloSent > 0 {
						state = "HELLO" // Has exchanged hello messages
					} else {
						state = "CONTACTED" // Other communication
					}
				}

				peerInfo := PeerInfo{
					PeerID:        peerID,
					PeerType:      "agent",
					Transport:     "-", // Unknown transport
					Address:       "-",
					CryptoType:    "-",
					State:         state,
					ContactInfo:   "peer registry only",
					HelloSent:     helloSent,
					HelloReceived: helloRecv,
					BeatSent:      beatSent,
					BeatReceived:  beatRecv,
					SyncSent:      syncSent,
					SyncReceived:  syncRecv,
					PingSent:      pingSent,
					PingReceived:  pingRecv,
					TotalSent:     totalSent,
					TotalReceived: totalRecv,
					DistribSent:   int(totalRecv), // Backward compat
				}
				if !lastUsed.IsZero() {
					peerInfo.LastUsed = lastUsed
				}

				peers = append(peers, peerInfo)
				lgApi.Debug("added peer from PeerRegistry only", "peer", peerID, "state", state, "sent", totalSent, "received", totalRecv)
			}
		}
	}

	return peers
}

// listPeerSharedZones returns shared zones for each peer agent
func listPeerSharedZones(conf *Config) []interface{} {
	data := make([]interface{}, 0)

	if conf.Internal.AgentRegistry == nil {
		return data
	}

	// Use callback-based iterator to avoid holding shard locks during processing
	conf.Internal.AgentRegistry.S.IterCb(func(agentID AgentId, agent *Agent) {
		agent.mu.RLock()
		identity := agent.Identity
		state := agent.State

		// Skip combiner - it's a virtual peer for monitoring, not a real agent peer
		// Check against configured combiner identity (may be "combiner" or a specific FQDN)
		if conf.Agent != nil && conf.Agent.Combiner != nil {
			combinerID := conf.Agent.Combiner.Identity
			if combinerID == "" {
				combinerID = "combiner" // Default identity
			}
			if identity == AgentId(combinerID) {
				agent.mu.RUnlock()
				return
			}
		}

		// Copy zone names while holding lock
		zoneNames := make([]ZoneName, 0, len(agent.Zones))
		for zoneName := range agent.Zones {
			zoneNames = append(zoneNames, zoneName)
		}
		agent.mu.RUnlock()

		// Build zone list with SOA serials (AFTER releasing lock)
		zoneDetails := make([]map[string]interface{}, 0, len(zoneNames))
		for _, zoneName := range zoneNames {
			zoneInfo := map[string]interface{}{
				"name": string(zoneName),
			}

			// Try to get SOA serial for this zone (without holding agent lock)
			if zd, exists := Zones.Get(string(zoneName)); exists {
				if soa, err := zd.GetSOA(); err == nil {
					zoneInfo["serial"] = soa.Serial
				}
			}

			zoneDetails = append(zoneDetails, zoneInfo)
		}

		entry := map[string]interface{}{
			"peer_id": string(identity),
			"zones":   zoneDetails,
			"state":   AgentStateToString[state],
		}
		data = append(data, entry)
	})

	return data
}

// listAgentsForZone returns peer agents that share a specific zone
func listAgentsForZone(conf *Config, zoneName string) []string {
	agents := make([]string, 0)

	if conf.Internal.AgentRegistry == nil {
		return agents
	}

	// Use callback-based iterator to avoid holding shard locks during processing
	conf.Internal.AgentRegistry.S.IterCb(func(agentID AgentId, agent *Agent) {
		agent.mu.RLock()
		hasZone := agent.Zones[ZoneName(zoneName)]
		identity := agent.Identity
		agent.mu.RUnlock()

		// Skip combiner - it's a virtual peer for monitoring, not a real agent peer
		// Check against configured combiner identity (may be "combiner" or a specific FQDN)
		if conf.Agent != nil && conf.Agent.Combiner != nil {
			combinerID := conf.Agent.Combiner.Identity
			if combinerID == "" {
				combinerID = "combiner" // Default identity
			}
			if identity == AgentId(combinerID) {
				return
			}
		}

		if hasZone {
			agents = append(agents, string(identity))
		}
	})

	return agents
}
