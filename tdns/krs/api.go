/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * API endpoints for tdns-krs management
 */

package krs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

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
func SetupKrsAPIRoutes(router *mux.Router, krsDB *KrsDB, conf *KrsConf) {
	router.HandleFunc("/krs/keys", APIKrsKeys(krsDB)).Methods("POST")
	router.HandleFunc("/krs/config", APIKrsConfig(krsDB, conf)).Methods("POST")
	router.HandleFunc("/krs/query", APIKrsQuery(krsDB, conf)).Methods("POST")
}

// APIKrsKeys handles key management endpoints
func APIKrsKeys(krsDB *KrsDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command string `json:"command"` // "list", "get", "get-by-zone"
			KeyID   string `json:"key_id,omitempty"`
			ZoneID  string `json:"zone_id,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := map[string]interface{}{
			"time": time.Now(),
		}

		switch req.Command {
		case "list":
			keys, err := krsDB.GetAllReceivedKeys()
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["keys"] = keys
			}

		case "get":
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for get command")
				return
			}
			key, err := krsDB.GetReceivedKey(req.KeyID)
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["key"] = key
			}

		case "get-by-zone":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for get-by-zone command")
				return
			}
			keys, err := krsDB.GetReceivedKeysForZone(req.ZoneID)
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["keys"] = keys
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
func APIKrsConfig(krsDB *KrsDB, conf *KrsConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command string `json:"command"` // "get"
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := map[string]interface{}{
			"time": time.Now(),
		}

		switch req.Command {
		case "get":
			config, err := krsDB.GetNodeConfig()
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				// Don't expose private keys in API response
				configResp := map[string]interface{}{
					"id":           config.ID,
					"kdc_address":  config.KdcAddress,
					"control_zone": config.ControlZone,
					"registered_at": config.RegisteredAt,
					"last_seen":    config.LastSeen,
				}
				resp["config"] = configResp
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
		var req struct {
			Command       string `json:"command"`        // "query-kmreq"
			DistributionID string `json:"distribution_id,omitempty"`
			ZoneID        string `json:"zone_id,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := map[string]interface{}{
			"time": time.Now(),
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
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["msg"] = fmt.Sprintf("KMREQ query initiated for distribution %s, zone %s", req.DistributionID, req.ZoneID)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

