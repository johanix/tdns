/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Combiner distribution management API endpoints
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// CombinerDistribPost represents a request to the combiner distrib API
type CombinerDistribPost struct {
	Command string `json:"command"` // "list", "purge"
	Force   bool   `json:"force,omitempty"`
}

// CombinerDistribResponse represents a response from the combiner distrib API
type CombinerDistribResponse struct {
	Time          time.Time              `json:"time"`
	Error         bool                   `json:"error,omitempty"`
	ErrorMsg      string                 `json:"error_msg,omitempty"`
	Msg           string                 `json:"msg,omitempty"`
	Summaries     []*DistributionSummary `json:"summaries,omitempty"`
	Distributions []string               `json:"distributions,omitempty"` // For backward compatibility
}

func (conf *Config) APIcombinerDistrib(cache *DistributionCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req CombinerDistribPost
		err := decoder.Decode(&req)
		if err != nil {
			log.Println("APIcombinerDistrib: error decoding request:", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		log.Printf("API: received /combiner/distrib request (cmd: %s) from %s.", req.Command, r.RemoteAddr)

		resp := CombinerDistribResponse{
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
			// List all distributions from this combiner
			// For combiners, we might not have a specific identity, so list all
			infos := cache.List("")

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
					"address":      peer.Address,
					"crypto_type":  peer.CryptoType,
					"distrib_sent": peer.DistribSent,
				}
				if !peer.LastUsed.IsZero() {
					peerMaps[i]["last_used"] = peer.LastUsed.Format(time.RFC3339)
				}
			}

			// Add to response using a generic field
			respMap := SanitizeForJSON(resp).(CombinerDistribResponse)
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
