/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * API endpoints for tdns-kdc management
 */

package kdc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
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

// APIKdcZone handles zone management endpoints
func APIKdcZone(kdcDB *KdcDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command   string `json:"command"`   // "add", "list", "get", "get-keys", "generate-key", "encrypt-key", "update", "delete"
			Zone      *Zone  `json:"zone,omitempty"`
			ZoneID    string `json:"zone_id,omitempty"`
			KeyID     string `json:"key_id,omitempty"`     // For encrypt-key: DNSSEC key ID
			NodeID    string `json:"node_id,omitempty"`    // For encrypt-key: node ID
			KeyType   string `json:"key_type,omitempty"`   // For generate-key: "KSK", "ZSK", or "CSK"
			Algorithm uint8  `json:"algorithm,omitempty"`  // For generate-key: DNSSEC algorithm
			Comment   string `json:"comment,omitempty"`    // For generate-key: optional comment
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := map[string]interface{}{
			"time": time.Now(),
		}

		switch req.Command {
		case "add":
			if req.Zone == nil {
				sendJSONError(w, http.StatusBadRequest, "zone is required for add command")
				return
			}
			if req.Zone.ID == "" {
				req.Zone.ID = req.Zone.Name // Use zone name as ID if not specified
			}
			if err := kdcDB.AddZone(req.Zone); err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["msg"] = fmt.Sprintf("Zone %s added successfully", req.Zone.ID)
			}

		case "list":
			zones, err := kdcDB.GetAllZones()
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["zones"] = zones
			}

		case "get":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for get command")
				return
			}
			zone, err := kdcDB.GetZone(req.ZoneID)
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["zone"] = zone
			}

		case "get-keys":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for get-keys command")
				return
			}
			keys, err := kdcDB.GetDNSSECKeysForZone(req.ZoneID)
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["keys"] = keys
			}

		case "encrypt-key":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for encrypt-key command")
				return
			}
			keyID := req.KeyID
			nodeID := req.NodeID
			if keyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for encrypt-key command")
				return
			}
			if nodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for encrypt-key command")
				return
			}

			// Get the DNSSEC key by ID
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneID, keyID)
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				// Get the node
				node, err := kdcDB.GetNode(nodeID)
				if err != nil {
					resp["error"] = true
					resp["error_msg"] = fmt.Sprintf("node %s not found: %v", nodeID, err)
				} else {
					// Encrypt the key
					encryptedKey, ephemeralPubKey, distributionID, err := kdcDB.EncryptKeyForNode(key, node)
					if err != nil {
						resp["error"] = true
						resp["error_msg"] = err.Error()
					} else {
						resp["msg"] = fmt.Sprintf("Key encrypted successfully")
						// Base64 encode binary data for JSON
						resp["encrypted_key"] = base64.StdEncoding.EncodeToString(encryptedKey)
						resp["ephemeral_pub_key"] = base64.StdEncoding.EncodeToString(ephemeralPubKey)
						resp["distribution_id"] = distributionID
					}
				}
			}

		case "generate-key":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for generate-key command")
				return
			}
			// Get zone to get zone name
			zone, err := kdcDB.GetZone(req.ZoneID)
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = fmt.Sprintf("zone not found: %v", err)
			} else {
				// Use default algorithm from config if not specified
				algorithm := req.Algorithm
				if algorithm == 0 {
					// TODO: Get from KDC config - for now use ED25519
					algorithm = dns.ED25519
				}
				keyType := KeyType(req.KeyType)
				if keyType == "" {
					keyType = KeyTypeZSK // Default to ZSK
				}
				key, err := kdcDB.GenerateDNSSECKey(req.ZoneID, zone.Name, keyType, algorithm, req.Comment)
				if err != nil {
					resp["error"] = true
					resp["error_msg"] = err.Error()
				} else {
					// Store the key in database
					if err := kdcDB.AddDNSSECKey(key); err != nil {
						resp["error"] = true
						resp["error_msg"] = err.Error()
					} else {
						resp["msg"] = fmt.Sprintf("Key %s generated successfully", key.ID)
						resp["key"] = key
					}
				}
			}

		case "update":
			if req.Zone == nil || req.Zone.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone with ID is required for update command")
				return
			}
			if err := kdcDB.UpdateZone(req.Zone); err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["msg"] = fmt.Sprintf("Zone %s updated successfully", req.Zone.ID)
			}

		case "delete":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for delete command")
				return
			}
			if err := kdcDB.DeleteZone(req.ZoneID); err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["msg"] = fmt.Sprintf("Zone %s deleted successfully", req.ZoneID)
			}

		default:
			http.Error(w, fmt.Sprintf("Unknown command: %s", req.Command), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKdcNode handles node management endpoints
func APIKdcNode(kdcDB *KdcDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command string `json:"command"` // "add", "list", "get", "update", "delete", "set-state"
			Node    *Node  `json:"node,omitempty"`
			NodeID  string `json:"node_id,omitempty"`
			State   string `json:"state,omitempty"` // For set-state command
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := map[string]interface{}{
			"time": time.Now(),
		}

		switch req.Command {
		case "add":
			if req.Node == nil {
				sendJSONError(w, http.StatusBadRequest, "node is required for add command")
				return
			}
			if req.Node.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "node.id is required")
				return
			}
			if len(req.Node.LongTermPubKey) != 32 {
				sendJSONError(w, http.StatusBadRequest, "node.long_term_pub_key must be 32 bytes (X25519)")
				return
			}
			if req.Node.State == "" {
				req.Node.State = NodeStateOnline // Default to online
			}
			if err := kdcDB.AddNode(req.Node); err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["msg"] = fmt.Sprintf("Node %s added successfully", req.Node.ID)
			}

		case "list":
			nodes, err := kdcDB.GetAllNodes()
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["nodes"] = nodes
			}

		case "get":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for get command")
				return
			}
			node, err := kdcDB.GetNode(req.NodeID)
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["node"] = node
			}

		case "update":
			if req.Node == nil || req.Node.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "node with ID is required for update command")
				return
			}
			if err := kdcDB.UpdateNode(req.Node); err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["msg"] = fmt.Sprintf("Node %s updated successfully", req.Node.ID)
			}

		case "set-state":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for set-state command")
				return
			}
			if req.State == "" {
				sendJSONError(w, http.StatusBadRequest, "state is required for set-state command")
				return
			}
			state := NodeState(req.State)
			if state != NodeStateOnline && state != NodeStateOffline && state != NodeStateCompromised && state != NodeStateSuspended {
				sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid state: %s (must be online, offline, compromised, or suspended)", req.State))
				return
			}
			if err := kdcDB.UpdateNodeState(req.NodeID, state); err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["msg"] = fmt.Sprintf("Node %s state set to %s", req.NodeID, state)
			}

		case "delete":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for delete command")
				return
			}
			if err := kdcDB.DeleteNode(req.NodeID); err != nil {
				resp["error"] = true
				resp["error_msg"] = err.Error()
			} else {
				resp["msg"] = fmt.Sprintf("Node %s deleted successfully", req.NodeID)
			}

		default:
			http.Error(w, fmt.Sprintf("Unknown command: %s", req.Command), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// SetupKdcAPIRoutes sets up KDC-specific API routes
func SetupKdcAPIRoutes(router *mux.Router, kdcDB *KdcDB) {
	if kdcDB == nil {
		log.Printf("SetupKdcAPIRoutes: KDC database not initialized, skipping KDC API routes")
		return
	}

	sr := router.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/kdc/zone", APIKdcZone(kdcDB)).Methods("POST")
	sr.HandleFunc("/kdc/node", APIKdcNode(kdcDB)).Methods("POST")
	
	log.Printf("KDC API routes registered: /api/v1/kdc/zone, /api/v1/kdc/node")
}

