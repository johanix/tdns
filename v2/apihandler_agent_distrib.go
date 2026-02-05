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
	"log"
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
	CreatedAt      time.Time
	CompletedAt    *time.Time
	QNAME          string // The DNS QNAME used to retrieve this distribution
}

// PeerInfo holds information about a peer agent with established keys
type PeerInfo struct {
	PeerID       string
	PeerType     string // "combiner" or "agent"
	Transport    string // "API" or "DNS"
	Address      string
	CryptoType   string    // "JOSE" or "HPKE" (for DNS), "TLS" (for API), or "-"
	DistribSent  int       // Number of distributions sent to this peer
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

// AgentDistribPost represents a request to the agent distrib API
type AgentDistribPost struct {
	Command       string `json:"command"`                  // "list", "purge", "peers", "op", "discover"
	Force         bool   `json:"force,omitempty"`          // for purge
	Op            string `json:"op,omitempty"`             // for op: operation name (e.g. "ping")
	To            string `json:"to,omitempty"`             // for op: recipient identity (e.g. "combiner", "agent.delta.dnslab.")
	PingTransport string `json:"ping_transport,omitempty"` // for op ping: "dns" (default) or "api"
	AgentId       string `json:"agent_id,omitempty"`       // for discover: agent identity to discover
}

// DistributionSummary contains summary information about a distribution
type DistributionSummary struct {
	DistributionID string `json:"distribution_id"`
	SenderID       string `json:"sender_id"`
	ReceiverID     string `json:"receiver_id"`
	Operation      string `json:"operation"`
	ContentType    string `json:"content_type"`
	State          string `json:"state"`
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
}

func (conf *Config) APIagentDistrib(cache *DistributionCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req AgentDistribPost
		err := decoder.Decode(&req)
		if err != nil {
			log.Println("APIagentDistrib: error decoding request:", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		log.Printf("API: received /agent/distrib request (cmd: %s) from %s.", req.Command, r.RemoteAddr)

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
					log.Printf("Error from json encoder: %v", err)
				}
			}
		}()

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

		case "peers":
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
					pingResp := doCombinerPing(conf, useAPI)
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
						authorized, reason := conf.Internal.TransportManager.IsAgentAuthorized(toFqdn, "")
						if !authorized {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("peer %q is not authorized (not in agent.authorized_peers config or HSYNC): %s", req.To, reason)
							log.Printf("API: REJECTED discovery attempt for unauthorized agent %q: %s", toFqdn, reason)
							return
						}

						// Attempt dynamic discovery for authorized but unknown agents
						log.Printf("API: agent %q not found in PeerRegistry, attempting discovery (authorized: %s)", toFqdn, reason)
						discoveryCtx, discoveryCancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer discoveryCancel()

						discErr := conf.Internal.TransportManager.DiscoverAndRegisterAgent(discoveryCtx, toFqdn)
						if discErr != nil {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("unknown peer identity %q and discovery failed: %v (use \"distrib peers\" to list known peers)", req.To, discErr)
							return
						}

						// Try to get peer again after discovery
						peer, ok = conf.Internal.TransportManager.PeerRegistry.Get(toFqdn)
						if !ok {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("peer %q discovered but not registered properly", req.To)
							return
						}
						log.Printf("API: Successfully discovered and registered agent %q", toFqdn)
					}
					if peer.CurrentAddress() == nil {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("peer %q has no address configured", req.To)
						return
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
			authorized, reason := conf.Internal.TransportManager.IsAgentAuthorized(agentFqdn, "")
			if !authorized {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent %q is not authorized (not in agent.authorized_peers config or HSYNC): %s", agentId, reason)
				log.Printf("API: REJECTED discovery attempt for unauthorized agent %q: %s", agentFqdn, reason)
				return
			}

			log.Printf("API: Starting discovery for agent %s (authorized: %s)", agentId, reason)

			discoveryCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			err := conf.Internal.TransportManager.DiscoverAndRegisterAgent(discoveryCtx, agentFqdn)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("discovery failed: %v", err)
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

// StartDistributionGC starts a background goroutine that periodically purges completed distributions
// older than 5 minutes. Incomplete distributions are never purged by GC (only "purge --force" removes them).
func StartDistributionGC(cache *DistributionCache, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			count := cache.PurgeCompleted(5 * time.Minute)
			if count > 0 {
				log.Printf("Distribution GC: purged %d completed distributions (kept ≥5m after completion)", count)
			}
		}
	}()
}

// listKnownPeers returns all peers that have working keys established
func listKnownPeers(conf *Config) []PeerInfo {
	var peers []PeerInfo

	// For combiners: only list the local agent (combiners never communicate with remote parties)
	if conf.Combiner != nil && conf.Combiner.Agent != nil {
		agent := conf.Combiner.Agent
		// Use Identity if set, otherwise fall back to Address
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
		return peers
	}

	// For agents: list the combiner (if configured) and remote agents

	// 1. Check if we have a combiner configured (identity is always "combiner" for CLI --to)
	if conf.Agent != nil && conf.Agent.Combiner != nil {
		combiner := conf.Agent.Combiner
		peerInfo := PeerInfo{
			PeerID:      "combiner",
			PeerType:    "combiner",
			Transport:   "DNS",
			Address:     combiner.Address,
			CryptoType:  "JOSE",
			DistribSent: 0, // TODO: track actual count
		}
		peers = append(peers, peerInfo)
	}

	// 2. Add remote agents from AgentRegistry (discovered via DNS); use FQDN
	// Create separate entries for API and DNS transports
	seen := make(map[string]bool) // key: peerID+transport
	for _, p := range peers {
		seen[p.PeerID+":"+p.Transport] = true
	}
	if conf.Internal.AgentRegistry != nil {
		ar := conf.Internal.AgentRegistry

		for tuple := range ar.S.IterBuffered() {
			agent := tuple.Val
			agentIDFqdn := dns.Fqdn(string(agent.Identity))

			// Add API transport entry if available
			if agent.ApiDetails != nil && agent.ApiDetails.BaseUri != "" {
				key := agentIDFqdn + ":API"
				if !seen[key] {
					seen[key] = true
					peerInfo := PeerInfo{
						PeerID:      agentIDFqdn,
						PeerType:    "agent",
						Transport:   "API",
						Address:     agent.ApiDetails.BaseUri,
						CryptoType:  "TLS",
						DistribSent: 0, // TODO: track actual count per transport
						APIUri:      agent.ApiDetails.BaseUri,
						Port:        agent.ApiDetails.Port,
						Addresses:   agent.ApiDetails.Addrs,
						HasTLSA:     agent.ApiDetails.TlsaRR != nil,
						State:       string(agent.State),
						ContactInfo: agent.ApiDetails.ContactInfo,
					}
					if !agent.ApiDetails.HelloTime.IsZero() {
						peerInfo.LastUsed = agent.ApiDetails.HelloTime
					}
					peers = append(peers, peerInfo)
				}
			}

			// Add DNS transport entry if available
			if agent.DnsDetails != nil && agent.DnsDetails.BaseUri != "" {
				key := agentIDFqdn + ":DNS"
				if !seen[key] {
					seen[key] = true
					peerInfo := PeerInfo{
						PeerID:       agentIDFqdn,
						PeerType:     "agent",
						Transport:    "DNS",
						Address:      agent.DnsDetails.BaseUri,
						CryptoType:   "JOSE",
						DistribSent:  0, // TODO: track actual count per transport
						DNSUri:       agent.DnsDetails.BaseUri,
						Port:         agent.DnsDetails.Port,
						Addresses:    agent.DnsDetails.Addrs,
						JWKData:      agent.DnsDetails.JWKData,
						KeyAlgorithm: agent.DnsDetails.KeyAlgorithm,
						HasJWK:       agent.DnsDetails.JWKData != "",
						HasKEY:       agent.DnsDetails.KeyRR != nil,
						State:        string(agent.State),
						ContactInfo:  agent.DnsDetails.ContactInfo,
					}
					if !agent.DnsDetails.HelloTime.IsZero() {
						peerInfo.LastUsed = agent.DnsDetails.HelloTime
					}
					peers = append(peers, peerInfo)
				}
			}
		}
	}

	return peers
}
