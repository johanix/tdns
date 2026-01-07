/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * API endpoints for tdns-krs management
 */

package krs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// KrsKeysPost represents a request to the KRS keys API
type KrsKeysPost struct {
	Command string `json:"command"` // "list", "get", "get-by-zone", "hash", "purge", "delete"
	KeyID   string `json:"key_id,omitempty"`
	ZoneID  string `json:"zone_id,omitempty"`
	ZoneName string `json:"zone_name,omitempty"` // For purge and delete commands
}

// KrsKeysResponse represents a response from the KRS keys API
type KrsKeysResponse struct {
	Time     time.Time      `json:"time"`
	Error    bool           `json:"error,omitempty"`
	ErrorMsg string         `json:"error_msg,omitempty"`
	Key      *ReceivedKey   `json:"key,omitempty"`
	Keys     []*ReceivedKey `json:"keys,omitempty"`
	Msg      string         `json:"msg,omitempty"` // For hash command
}

// KrsConfigPost represents a request to the KRS config API
type KrsConfigPost struct {
	Command string `json:"command"` // "get"
}

// KrsConfigResponse represents a response from the KRS config API
type KrsConfigResponse struct {
	Time     time.Time              `json:"time"`
	Error    bool                   `json:"error,omitempty"`
	ErrorMsg string                 `json:"error_msg,omitempty"`
	Config   map[string]interface{} `json:"config,omitempty"`
}

// KrsQueryPost represents a request to the KRS query API
type KrsQueryPost struct {
	Command       string `json:"command"`        // "query-kmreq"
	DistributionID string `json:"distribution_id,omitempty"`
	ZoneID        string `json:"zone_id,omitempty"`
}

// KrsQueryResponse represents a response from the KRS query API
type KrsQueryResponse struct {
	Time     time.Time `json:"time"`
	Error    bool      `json:"error,omitempty"`
	ErrorMsg string    `json:"error_msg,omitempty"`
	Msg      string    `json:"msg,omitempty"`
}

// KrsDebugPost represents a request to the KRS debug API
type KrsDebugPost struct {
	Command       string `json:"command"`        // "fetch-distribution"
	DistributionID string `json:"distribution_id,omitempty"`
}

// KrsDebugResponse represents a response from the KRS debug API
type KrsDebugResponse struct {
	Time     time.Time `json:"time"`
	Error    bool      `json:"error,omitempty"`
	ErrorMsg string    `json:"error_msg,omitempty"`
	Msg      string    `json:"msg,omitempty"`
	Content  string    `json:"content,omitempty"` // For clear_text or encrypted_text content
}

// sendJSONError sends a JSON-formatted error response
func sendJSONError(w http.ResponseWriter, statusCode int, errorMsg string) {
	resp := map[string]interface{}{
		"time":      time.Now(),
		"error":     true,
		"error_msg": errorMsg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

// SetupKrsAPIRoutes sets up API routes for KRS management
// tdnsConf is *tdns.Config passed as interface{} to avoid circular import
// pingHandler is the ping endpoint handler function
func SetupKrsAPIRoutes(router *mux.Router, krsDB *KrsDB, conf *KrsConf, tdnsConf interface{}, pingHandler http.HandlerFunc) {
	// Extract API key from config
	apikey := ""
	if configMap, ok := tdnsConf.(map[string]interface{}); ok {
		if apiServer, ok := configMap["ApiServer"].(map[string]interface{}); ok {
			if key, ok := apiServer["ApiKey"].(string); ok {
				apikey = key
			}
		}
	}
	
	// Create subrouter with API key requirement
	var sr *mux.Router
	if apikey != "" {
		sr = router.PathPrefix("/api/v1").Headers("X-API-Key", apikey).Subrouter()
	} else {
		sr = router.PathPrefix("/api/v1").Subrouter()
	}
	
	// Add ping endpoint
	if pingHandler != nil {
		sr.HandleFunc("/ping", pingHandler).Methods("POST")
	}
	
	sr.HandleFunc("/krs/keys", APIKrsKeys(krsDB)).Methods("POST")
	sr.HandleFunc("/krs/config", APIKrsConfig(krsDB, conf, tdnsConf)).Methods("POST")
	sr.HandleFunc("/krs/query", APIKrsQuery(krsDB, conf)).Methods("POST")
	sr.HandleFunc("/krs/debug", APIKrsDebug(krsDB, conf)).Methods("POST")
}

// APIKrsKeys handles key management endpoints
func APIKrsKeys(krsDB *KrsDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KrsKeysPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KrsKeysResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "list":
			keys, err := krsDB.GetAllReceivedKeys()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Keys = keys
			}

		case "get":
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for get command")
				return
			}
			key, err := krsDB.GetReceivedKey(req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Key = key
			}

		case "get-by-zone":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for get-by-zone command")
				return
			}
			keys, err := krsDB.GetReceivedKeysForZone(req.ZoneID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Keys = keys
			}

		case "hash":
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for hash command")
				return
			}
			key, err := krsDB.GetReceivedKey(req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				hash, err := computeKeyHash(key.PrivateKey)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = hash
				}
			}

		case "purge":
			// Purge keys in "removed" state
			// zone_name is optional - if provided, only purge keys for that zone
			deletedCount, err := krsDB.DeleteKeysByState("removed", req.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				if req.ZoneName != "" {
					resp.Msg = fmt.Sprintf("Deleted %d key(s) in 'removed' state for zone %s", deletedCount, req.ZoneName)
				} else {
					resp.Msg = fmt.Sprintf("Deleted %d key(s) in 'removed' state (all zones)", deletedCount)
				}
			}

		case "delete":
			// Delete a specific key by zone_name and key_id
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for delete command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for delete command")
				return
			}
			err := krsDB.DeleteReceivedKeyByZoneAndKeyID(req.ZoneName, req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Deleted key %s for zone %s", req.KeyID, req.ZoneName)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKrsConfig handles node configuration endpoints
// tdnsConf is *tdns.Config passed as interface{} to avoid circular import
func APIKrsConfig(krsDB *KrsDB, conf *KrsConf, tdnsConf interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KrsConfigPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KrsConfigResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "get":
			config, err := krsDB.GetNodeConfig()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				// Extract API addresses from tdns config
				apiAddresses := []string{}
				if configMap, ok := tdnsConf.(map[string]interface{}); ok {
					if apiServer, ok := configMap["ApiServer"].(map[string]interface{}); ok {
						if addrs, ok := apiServer["Addresses"].([]string); ok {
							apiAddresses = addrs
						}
					}
				}

				// Don't expose private keys in API response
				configResp := map[string]interface{}{
					"id":            config.ID,
					"kdc_address":   config.KdcAddress,
					"control_zone":   config.ControlZone,
					"registered_at":  config.RegisteredAt,
					"last_seen":      config.LastSeen,
					"dns_addresses":  conf.DnsEngine.Addresses,
					"api_addresses":  apiAddresses,
				}
				resp.Config = configResp
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKrsQuery handles KMREQ query endpoints (forces a query to KDC)
func APIKrsQuery(krsDB *KrsDB, conf *KrsConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KrsQueryPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KrsQueryResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "query-kmreq":
			if req.DistributionID == "" || req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "distribution_id and zone_id are required for query-kmreq command")
				return
			}

			// Trigger KMREQ query
			err := QueryKMREQ(krsDB, conf, req.DistributionID, req.ZoneID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("KMREQ query initiated for distribution %s, zone %s", req.DistributionID, req.ZoneID)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// computeKeyHash computes a SHA-256 hash of the private key material
// Returns hex-encoded hash string
func computeKeyHash(privateKey []byte) (string, error) {
	if len(privateKey) == 0 {
		return "", fmt.Errorf("private key is empty")
	}
	hash := sha256.Sum256(privateKey)
	return hex.EncodeToString(hash[:]), nil
}

// APIKrsDebug handles debug endpoints
func APIKrsDebug(krsDB *KrsDB, conf *KrsConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KrsDebugPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KrsDebugResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "fetch-distribution":
			if req.DistributionID == "" {
				sendJSONError(w, http.StatusBadRequest, "distribution_id is required for fetch-distribution command")
				return
			}

			// Process the distribution (this will fetch manifest, chunks, reassemble, and process)
			// Pass a pointer to store clear_text or encrypted_text content if present
			var textContent string
			err := ProcessDistribution(krsDB, conf, req.DistributionID, &textContent)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Successfully fetched and processed distribution %s", req.DistributionID)
				if textContent != "" {
					resp.Content = textContent
				}
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
