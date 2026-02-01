/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent distribution management API endpoints
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/johanix/tdns/v2/core"
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
	PeerID      string
	PeerType    string // "combiner" or "agent"
	Address     string
	CryptoType  string // "JOSE" or "HPKE"
	DistribSent int    // Number of distributions sent to this peer
	LastUsed    time.Time
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

// PurgeCompleted removes completed distributions older than the given duration
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
	Command string `json:"command"` // "list", "purge"
	Force   bool   `json:"force,omitempty"`
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
					"address":      peer.Address,
					"crypto_type":  peer.CryptoType,
					"distrib_sent": peer.DistribSent,
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

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", req.Command)
		}
	}
}

// StartDistributionGC starts a background goroutine that periodically purges old distributions
func StartDistributionGC(cache *DistributionCache, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			count := cache.PurgeCompleted(5 * time.Minute)
			if count > 0 {
				log.Printf("Distribution GC: purged %d completed distributions", count)
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
			Address:     agent.Address,
			CryptoType:  "JOSE",
			DistribSent: 0, // TODO: track actual count
		}
		peers = append(peers, peerInfo)
		return peers
	}

	// For agents: list the combiner (if configured) and remote agents

	// 1. Check if we have a combiner configured
	if conf.Agent != nil && conf.Agent.Combiner != nil {
		combiner := conf.Agent.Combiner
		// Use Identity if set, otherwise fall back to Address
		peerID := combiner.Identity
		if peerID == "" {
			peerID = combiner.Address
		}
		peerInfo := PeerInfo{
			PeerID:      peerID,
			PeerType:    "combiner",
			Address:     combiner.Address,
			CryptoType:  "JOSE",
			DistribSent: 0, // TODO: track actual count
		}
		peers = append(peers, peerInfo)
	}

	// 2. Check AgentRegistry for remote agents
	if conf.Internal.AgentRegistry != nil {
		ar := conf.Internal.AgentRegistry

		// Iterate through all agents in the registry
		for tuple := range ar.S.IterBuffered() {
			agent := tuple.Val

			// Get address from ApiDetails or DnsDetails
			address := ""
			if agent.ApiDetails != nil && agent.ApiDetails.BaseUri != "" {
				address = agent.ApiDetails.BaseUri
			} else if agent.DnsDetails != nil && agent.DnsDetails.BaseUri != "" {
				address = agent.DnsDetails.BaseUri
			}

			// Extract peer info from the agent
			peerInfo := PeerInfo{
				PeerID:      string(agent.Identity),
				PeerType:    "agent",
				Address:     address,
				CryptoType:  "JOSE", // Default assumption
				DistribSent: 0,      // TODO: track actual count
			}

			// Check if we have API or DNS contact info
			if agent.ApiDetails != nil && agent.ApiDetails.HelloTime != (time.Time{}) {
				peerInfo.LastUsed = agent.ApiDetails.HelloTime
			} else if agent.DnsDetails != nil && agent.DnsDetails.HelloTime != (time.Time{}) {
				peerInfo.LastUsed = agent.DnsDetails.HelloTime
			}

			peers = append(peers, peerInfo)
		}
	}

	return peers
}
