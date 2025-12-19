/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Debug API endpoints for tdns-kdc
 */

package kdc

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// KdcDebugPost represents a request to the KDC debug API
type KdcDebugPost struct {
	Command        string `json:"command"`         // "test-distribution", "list-distributions", "delete-distribution", "set-chunk-size"
	DistributionID string `json:"distribution_id"` // Distribution ID (hex, e.g., "a1b2")
	NodeID         string `json:"node_id"`         // Node ID
	TestText       string `json:"test_text"`       // Test text payload (for test-distribution)
	ContentType    string `json:"content_type"`    // "clear_text" or "encrypted_text" (default: "clear_text")
	ChunkSize      int    `json:"chunk_size"`      // Chunk size in bytes (for set-chunk-size)
}

// KdcDebugResponse represents a response from the KDC debug API
type KdcDebugResponse struct {
	Time           time.Time         `json:"time"`
	Error          bool              `json:"error,omitempty"`
	ErrorMsg       string            `json:"error_msg,omitempty"`
	Msg            string            `json:"msg,omitempty"`
	DistributionID string            `json:"distribution_id,omitempty"`
	ChunkCount     uint16            `json:"chunk_count,omitempty"`
	Distributions  []string          `json:"distributions,omitempty"` // For list-distributions (deprecated, use DistributionInfos)
	DistributionInfos []DistributionInfo `json:"distribution_infos,omitempty"` // For list-distributions (with node info)
	ChunkSize      int               `json:"chunk_size,omitempty"`   // For get/set-chunk-size
}

// APIKdcDebug handles debug API requests
func APIKdcDebug(kdcDB *KdcDB, kdcConf *KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KdcDebugPost
		resp := KdcDebugResponse{
			Time: time.Now(),
		}

		// Parse request body
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse request: %v", err))
			return
		}

		log.Printf("KDC Debug API: Received command: %s", req.Command)

		switch req.Command {
		case "test-distribution":
			if req.DistributionID == "" {
				resp.Error = true
				resp.ErrorMsg = "distribution_id is required"
			} else if req.NodeID == "" {
				resp.Error = true
				resp.ErrorMsg = "node_id is required"
			} else if req.TestText == "" {
				// Use default lorem ipsum if not provided
				req.TestText = `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.`
			}

			if !resp.Error {
				// Ensure node ID is FQDN
				nodeIDFQDN := dns.Fqdn(req.NodeID)
				// Determine content type (default to clear_text)
				contentType := req.ContentType
				if contentType == "" {
					contentType = "clear_text"
				}
				if contentType != "clear_text" && contentType != "encrypted_text" {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("invalid content_type: %s (must be 'clear_text' or 'encrypted_text')", contentType)
				} else {
					// Prepare text chunks
					prepared, err := kdcDB.PrepareTextChunks(nodeIDFQDN, req.DistributionID, req.TestText, contentType, kdcConf)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Test distribution %s created successfully for node %s", req.DistributionID, nodeIDFQDN)
						resp.DistributionID = req.DistributionID
						resp.ChunkCount = prepared.manifest.ChunkCount
						log.Printf("KDC Debug: Created test distribution %s with %d chunks", req.DistributionID, prepared.manifest.ChunkCount)
					}
				}
			}

		case "list-distributions":
			distributionInfos, err := kdcDB.GetAllDistributionInfos()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Found %d distribution(s)", len(distributionInfos))
				resp.DistributionInfos = distributionInfos
				// Also populate legacy Distributions field for backward compatibility
				distributionIDs := make([]string, len(distributionInfos))
				for i, info := range distributionInfos {
					distributionIDs[i] = info.DistributionID
				}
				resp.Distributions = distributionIDs
				log.Printf("KDC Debug: Listed %d distributions", len(distributionInfos))
			}

		case "delete-distribution":
			if req.DistributionID == "" {
				resp.Error = true
				resp.ErrorMsg = "distribution_id is required"
			} else {
				// Delete from database
				if err := kdcDB.DeleteDistribution(req.DistributionID); err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// Clear from cache
					ClearDistributionCache(req.DistributionID)
					resp.Msg = fmt.Sprintf("Distribution %s deleted successfully", req.DistributionID)
					resp.DistributionID = req.DistributionID
					log.Printf("KDC Debug: Deleted distribution %s", req.DistributionID)
				}
			}

		case "set-chunk-size":
			if req.ChunkSize <= 0 {
				resp.Error = true
				resp.ErrorMsg = "chunk_size must be greater than 0"
			} else {
				// Update config at runtime (only affects new distributions)
				kdcConf.JsonchunkMaxSize = req.ChunkSize
				resp.Msg = fmt.Sprintf("Chunk size updated to %d bytes (affects new distributions only)", req.ChunkSize)
				resp.ChunkSize = req.ChunkSize
				log.Printf("KDC Debug: Updated chunk size to %d bytes", req.ChunkSize)
			}

		case "get-chunk-size":
			resp.Msg = "Current chunk size"
			resp.ChunkSize = kdcConf.GetJsonchunkMaxSize()
			log.Printf("KDC Debug: Current chunk size: %d bytes", resp.ChunkSize)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("unknown command: %s", req.Command)
		}

		// Send response
		w.Header().Set("Content-Type", "application/json")
		if resp.Error {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("KDC Debug API: Error encoding response: %v", err)
		}
	}
}

