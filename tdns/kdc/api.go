/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * API endpoints for tdns-kdc management
 */

package kdc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
)

// KdcZonePost represents a request to the KDC zone API
type KdcZonePost struct {
	Command   string   `json:"command"`   // "add", "list", "get", "get-keys", "generate-key", "encrypt-key", "update", "delete", "distribute-zsk", "distrib-multi", "transition", "setstate", "delete-key"
	Zone      *Zone    `json:"zone,omitempty"`
	ZoneID    string   `json:"zone_id,omitempty"`
	KeyID     string   `json:"key_id,omitempty"`     // For encrypt-key/distribute-zsk/transition/setstate/delete-key: DNSSEC key ID
	NodeID    string   `json:"node_id,omitempty"`    // For encrypt-key: node ID
	KeyType   string   `json:"key_type,omitempty"`   // For generate-key: "KSK", "ZSK", or "CSK"
	Algorithm uint8    `json:"algorithm,omitempty"`  // For generate-key: DNSSEC algorithm
	Comment   string   `json:"comment,omitempty"`    // For generate-key: optional comment
	NewState  string   `json:"new_state,omitempty"`  // For setstate: target state
	Zones     []string `json:"zones,omitempty"`     // For distrib-multi: list of zone IDs
}

// DistributionResult represents the result of distributing a key for a zone
type DistributionResult struct {
	ZoneID string `json:"zone_id"`
	KeyID  string `json:"key_id,omitempty"`
	Status string `json:"status"` // "success" or "error"
	Msg    string `json:"msg,omitempty"`
}

// KdcZoneResponse represents a response from the KDC zone API
type KdcZoneResponse struct {
	Time      time.Time              `json:"time"`
	Error     bool                   `json:"error,omitempty"`
	ErrorMsg  string                 `json:"error_msg,omitempty"`
	Msg       string                 `json:"msg,omitempty"`
	Zone      *Zone                  `json:"zone,omitempty"`
	Zones     []*Zone                `json:"zones,omitempty"`
	Key       *DNSSECKey             `json:"key,omitempty"`
	Keys      []*DNSSECKey           `json:"keys,omitempty"`
	EncryptedKey     string          `json:"encrypted_key,omitempty"`     // Base64-encoded
	EphemeralPubKey  string          `json:"ephemeral_pub_key,omitempty"` // Base64-encoded
	DistributionID   string          `json:"distribution_id,omitempty"`
	Results   []DistributionResult   `json:"results,omitempty"` // For distrib-multi: results per zone
}

// KdcNodePost represents a request to the KDC node API
type KdcNodePost struct {
	Command string `json:"command"` // "add", "list", "get", "update", "delete", "set-state"
	Node    *Node  `json:"node,omitempty"`
	NodeID  string `json:"node_id,omitempty"`
	State   string `json:"state,omitempty"` // For set-state command
}

// KdcNodeResponse represents a response from the KDC node API
type KdcNodeResponse struct {
	Time     time.Time   `json:"time"`
	Error    bool        `json:"error,omitempty"`
	ErrorMsg string      `json:"error_msg,omitempty"`
	Msg      string      `json:"msg,omitempty"`
	Node     *Node       `json:"node,omitempty"`
	Nodes    []*Node     `json:"nodes,omitempty"`
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

// APIKdcZone handles zone management endpoints
func APIKdcZone(kdcDB *KdcDB, kdcConf *KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KdcZonePost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcZoneResponse{
			Time: time.Now(),
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
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s added successfully", req.Zone.ID)
			}

		case "list":
			zones, err := kdcDB.GetAllZones()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Zones = zones
			}

		case "get":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for get command")
				return
			}
			zone, err := kdcDB.GetZone(req.ZoneID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Zone = zone
			}

		case "get-keys":
			var keys []*DNSSECKey
			var err error
			if req.ZoneID == "" {
				// List all keys for all zones
				keys, err = kdcDB.GetAllDNSSECKeys()
			} else {
				// List keys for a specific zone
				keys, err = kdcDB.GetDNSSECKeysForZone(req.ZoneID)
			}
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Keys = keys
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
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				// Get the node
				node, err := kdcDB.GetNode(nodeID)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("node %s not found: %v", nodeID, err)
				} else {
					// Encrypt the key
					encryptedKey, ephemeralPubKey, distributionID, err := kdcDB.EncryptKeyForNode(key, node)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Key encrypted successfully")
						// Base64 encode binary data for JSON
						resp.EncryptedKey = base64.StdEncoding.EncodeToString(encryptedKey)
						resp.EphemeralPubKey = base64.StdEncoding.EncodeToString(ephemeralPubKey)
						resp.DistributionID = distributionID
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
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("zone not found: %v", err)
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
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// Store the key in database
					if err := kdcDB.AddDNSSECKey(key); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Key %s generated successfully", key.ID)
						resp.Key = key
					}
				}
			}

		case "update":
			if req.Zone == nil || req.Zone.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone with ID is required for update command")
				return
			}
			if err := kdcDB.UpdateZone(req.Zone); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s updated successfully", req.Zone.ID)
			}

		case "delete":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for delete command")
				return
			}
			if err := kdcDB.DeleteZone(req.ZoneID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s deleted successfully", req.ZoneID)
			}

		case "distribute-zsk":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for distribute-zsk command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for distribute-zsk command")
				return
			}
			// Get the key and verify it's a ZSK in standby state
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneID, req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Key not found: %v", err)
			} else if key.KeyType != KeyTypeZSK {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Key %s is not a ZSK (type: %s)", req.KeyID, key.KeyType)
			} else if key.State != KeyStateStandby {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Key %s is not in standby state (current state: %s)", req.KeyID, key.State)
			} else {
				// Get distributionID for this key (before transitioning state)
				distributionID, err := kdcDB.GetOrCreateDistributionID(req.ZoneID, key)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Failed to get/create distribution ID: %v", err)
				} else {
					// Transition to distributed state
					if err := kdcDB.UpdateKeyState(req.ZoneID, req.KeyID, KeyStateDistributed); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						// Encrypt key for all active nodes and create distribution records
						nodes, err := kdcDB.GetActiveNodes()
						if err != nil {
							log.Printf("KDC: Warning: Failed to get active nodes: %v", err)
						} else {
							encryptedCount := 0
							for _, node := range nodes {
								if node.NotifyAddress == "" {
									log.Printf("KDC: Skipping node %s (no notify_address configured)", node.ID)
									continue
								}
								// Encrypt key for this node (creates distribution record)
								_, _, _, err := kdcDB.EncryptKeyForNode(key, node)
								if err != nil {
									log.Printf("KDC: Warning: Failed to encrypt key for node %s: %v", node.ID, err)
									continue
								}
								encryptedCount++
								log.Printf("KDC: Encrypted key %s for node %s (distribution ID: %s)", req.KeyID, node.ID, distributionID)
							}
							log.Printf("KDC: Encrypted key for %d/%d active nodes", encryptedCount, len(nodes))
						}

						// Send NOTIFY to all active nodes with distributionID
						if kdcConf != nil && kdcConf.ControlZone != "" {
							if err := kdcDB.SendNotifyWithDistributionID(distributionID, kdcConf.ControlZone); err != nil {
								log.Printf("KDC: Warning: Failed to send NOTIFYs: %v", err)
								// Don't fail the request, just log the warning
							}
						} else {
							log.Printf("KDC: Warning: Control zone not configured, skipping NOTIFY")
						}
						
						resp.Msg = fmt.Sprintf("Key %s transitioned to distributed state. Distribution ID: %s. NOTIFYs sent to nodes.", req.KeyID, distributionID)
						// Reload key to get updated state
						key, _ = kdcDB.GetDNSSECKeyByID(req.ZoneID, req.KeyID)
						resp.Key = key
					}
				}
			}

		case "transition":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for transition command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for transition command")
				return
			}
			
			// Get key and determine next state based on current state
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneID, req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Key not found: %v", err)
			} else {
				var toState KeyState
				switch key.State {
				case KeyStateCreated:
					toState = KeyStatePublished
				case KeyStateStandby:
					toState = KeyStateActive
				default:
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Key %s is in state %s, which has no automatic transition. Use 'setstate' for manual state changes.", req.KeyID, key.State)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(resp)
					return
				}
				
				if err := kdcDB.UpdateKeyState(req.ZoneID, req.KeyID, toState); err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Key %s transitioned from %s to %s", req.KeyID, key.State, toState)
					key, _ = kdcDB.GetDNSSECKeyByID(req.ZoneID, req.KeyID)
					resp.Key = key
				}
			}

		case "delete-key":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for delete-key command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for delete-key command")
				return
			}
			if err := kdcDB.DeleteDNSSECKey(req.ZoneID, req.KeyID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Key %s deleted successfully", req.KeyID)
			}

		case "setstate":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for setstate command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for setstate command")
				return
			}
			if req.NewState == "" {
				sendJSONError(w, http.StatusBadRequest, "new_state is required for setstate command")
				return
			}
			
			newState := KeyState(req.NewState)
			// Validate state
			validStates := []KeyState{
				KeyStateCreated, KeyStatePublished, KeyStateStandby, KeyStateActive,
				KeyStateDistributed, KeyStateEdgeSigner, KeyStateRetired, KeyStateRemoved, KeyStateRevoked,
			}
			valid := false
			for _, vs := range validStates {
				if newState == vs {
					valid = true
					break
				}
			}
			if !valid {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Invalid state: %s", req.NewState)
			} else {
				if err := kdcDB.UpdateKeyState(req.ZoneID, req.KeyID, newState); err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Key %s state set to %s", req.KeyID, newState)
					key, _ := kdcDB.GetDNSSECKeyByID(req.ZoneID, req.KeyID)
					resp.Key = key
				}
			}

		case "hash":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for hash command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for hash command")
				return
			}
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneID, req.KeyID)
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

		case "distrib-multi":
			if len(req.Zones) == 0 {
				sendJSONError(w, http.StatusBadRequest, "zones list is required for distrib-multi command")
				return
			}
			
			var results []DistributionResult
			successCount := 0
			errorCount := 0
			
			for _, zoneID := range req.Zones {
				result := DistributionResult{
					ZoneID: zoneID,
					Status: "error",
				}
				
				// Find a standby ZSK for this zone
				keys, err := kdcDB.GetDNSSECKeysForZone(zoneID)
				if err != nil {
					result.Msg = fmt.Sprintf("Failed to get keys: %v", err)
					results = append(results, result)
					errorCount++
					continue
				}
				
				// Find first standby ZSK
				var standbyZSK *DNSSECKey
				for _, key := range keys {
					if key.KeyType == KeyTypeZSK && key.State == KeyStateStandby {
						standbyZSK = key
						break
					}
				}
				
				if standbyZSK == nil {
					result.Msg = "No standby ZSK found for zone"
					results = append(results, result)
					errorCount++
					continue
				}
				
				// Distribute this key (same logic as distribute-zsk)
				distributionID, err := kdcDB.GetOrCreateDistributionID(zoneID, standbyZSK)
				if err != nil {
					result.Msg = fmt.Sprintf("Failed to get/create distribution ID: %v", err)
					results = append(results, result)
					errorCount++
					continue
				}
				
				// Transition to distributed state
				if err := kdcDB.UpdateKeyState(zoneID, standbyZSK.ID, KeyStateDistributed); err != nil {
					result.Msg = fmt.Sprintf("Failed to update key state: %v", err)
					results = append(results, result)
					errorCount++
					continue
				}
				
				// Encrypt key for all active nodes
				nodes, err := kdcDB.GetActiveNodes()
				if err != nil {
					log.Printf("KDC: Warning: Failed to get active nodes: %v", err)
				} else {
					encryptedCount := 0
					for _, node := range nodes {
						if node.NotifyAddress == "" {
							log.Printf("KDC: Skipping node %s (no notify_address configured)", node.ID)
							continue
						}
						_, _, _, err := kdcDB.EncryptKeyForNode(standbyZSK, node)
						if err != nil {
							log.Printf("KDC: Warning: Failed to encrypt key for node %s: %v", node.ID, err)
							continue
						}
						encryptedCount++
					}
					log.Printf("KDC: Encrypted key %s for %d/%d active nodes", standbyZSK.ID, encryptedCount, len(nodes))
				}
				
				// Send NOTIFY to all active nodes
				if kdcConf != nil && kdcConf.ControlZone != "" {
					if err := kdcDB.SendNotifyWithDistributionID(distributionID, kdcConf.ControlZone); err != nil {
						log.Printf("KDC: Warning: Failed to send NOTIFYs: %v", err)
					}
				}
				
				result.Status = "success"
				result.KeyID = standbyZSK.ID
				result.Msg = fmt.Sprintf("Key %s distributed (distribution ID: %s)", standbyZSK.ID, distributionID)
				results = append(results, result)
				successCount++
			}
			
			resp.Results = results
			if errorCount == 0 {
				resp.Msg = fmt.Sprintf("Successfully distributed keys for %d zone(s)", successCount)
			} else if successCount == 0 {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Failed to distribute keys for all %d zone(s)", errorCount)
			} else {
				resp.Msg = fmt.Sprintf("Distributed keys for %d/%d zone(s) (%d failed)", successCount, len(req.Zones), errorCount)
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
		var req KdcNodePost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcNodeResponse{
			Time: time.Now(),
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
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Node %s added successfully", req.Node.ID)
			}

		case "list":
			nodes, err := kdcDB.GetAllNodes()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Nodes = nodes
			}

		case "get":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for get command")
				return
			}
			node, err := kdcDB.GetNode(req.NodeID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Node = node
			}

		case "update":
			if req.Node == nil || req.Node.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "node with ID is required for update command")
				return
			}
			if err := kdcDB.UpdateNode(req.Node); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Node %s updated successfully", req.Node.ID)
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
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Node %s state set to %s", req.NodeID, state)
			}

		case "delete":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for delete command")
				return
			}
			if err := kdcDB.DeleteNode(req.NodeID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Node %s deleted successfully", req.NodeID)
			}

		default:
			http.Error(w, fmt.Sprintf("Unknown command: %s", req.Command), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// KdcConfigPost represents a request to the KDC config API
type KdcConfigPost struct {
	Command string `json:"command"` // "get"
}

// KdcConfigResponse represents a response from the KDC config API
type KdcConfigResponse struct {
	Time     time.Time              `json:"time"`
	Error    bool                   `json:"error,omitempty"`
	ErrorMsg string                 `json:"error_msg,omitempty"`
	Config   map[string]interface{} `json:"config,omitempty"`
}

// APIKdcConfig handles KDC configuration endpoints
// conf is *tdns.Config passed as interface{} to avoid circular import
// kdcConf is *KdcConf
func APIKdcConfig(kdcConf *KdcConf, tdnsConf interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KdcConfigPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcConfigResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "get":
			// Extract DNS and API addresses from tdns config
			dnsAddresses := []string{}
			apiAddresses := []string{}
			if configMap, ok := tdnsConf.(map[string]interface{}); ok {
				if dnsEngine, ok := configMap["DnsEngine"].(map[string]interface{}); ok {
					if addrs, ok := dnsEngine["Addresses"].([]string); ok {
						dnsAddresses = addrs
					}
				}
				if apiServer, ok := configMap["ApiServer"].(map[string]interface{}); ok {
					if addrs, ok := apiServer["Addresses"].([]string); ok {
						apiAddresses = addrs
					}
				}
			}

			configResp := map[string]interface{}{
				"control_zone":        kdcConf.ControlZone,
				"default_algorithm":   kdcConf.DefaultAlgorithm,
				"key_rotation_interval": kdcConf.KeyRotationInterval.String(),
				"standby_key_count":   kdcConf.StandbyKeyCount,
				"jsonchunk_max_size":  kdcConf.GetJsonchunkMaxSize(),
				"dns_addresses":       dnsAddresses,
				"api_addresses":        apiAddresses,
			}
			resp.Config = configResp

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// KdcDistribPost represents a request to the KDC distrib API
type KdcDistribPost struct {
	Command        string `json:"command"`         // "list", "state", "completed"
	DistributionID string `json:"distribution_id,omitempty"` // For state and completed commands
}

// DistributionStateInfo represents detailed information about a distribution
type DistributionStateInfo struct {
	DistributionID string   `json:"distribution_id"`
	ZoneID         string   `json:"zone_id"`
	KeyID          string   `json:"key_id"`
	KeyState       string   `json:"key_state"`
	CreatedAt      string   `json:"created_at"`
	TargetNodes   []string `json:"target_nodes"`   // All nodes that should receive this distribution
	ConfirmedNodes []string `json:"confirmed_nodes"` // Nodes that have confirmed
	PendingNodes   []string `json:"pending_nodes"`   // Nodes that haven't confirmed yet
	AllConfirmed   bool     `json:"all_confirmed"`
}

// KdcDistribResponse represents a response from the KDC distrib API
type KdcDistribResponse struct {
	Time      time.Time              `json:"time"`
	Error     bool                   `json:"error,omitempty"`
	ErrorMsg  string                 `json:"error_msg,omitempty"`
	Msg       string                 `json:"msg,omitempty"`
	Distributions []string           `json:"distributions,omitempty"` // For list command
	State     *DistributionStateInfo `json:"state,omitempty"`         // For state command
}

// APIKdcDistrib handles distribution management endpoints
func APIKdcDistrib(kdcDB *KdcDB, kdcConf *KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KdcDistribPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcDistribResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "list":
			// Get all distribution IDs
			distIDs, err := kdcDB.GetAllDistributionIDs()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Distributions = distIDs
				resp.Msg = fmt.Sprintf("Found %d distribution(s)", len(distIDs))
			}

		case "state":
			if req.DistributionID == "" {
				sendJSONError(w, http.StatusBadRequest, "distribution_id is required for state command")
				return
			}
			
			// Get distribution records
			records, err := kdcDB.GetDistributionRecordsForDistributionID(req.DistributionID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else if len(records) == 0 {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Distribution %s not found", req.DistributionID)
			} else {
				// Use first record to get zone/key info
				record := records[0]
				
				// Get key state
				key, err := kdcDB.GetDNSSECKeyByID(record.ZoneID, record.KeyID)
				keyState := "unknown"
				if err == nil {
					keyState = string(key.State)
				}
				
				// Get target nodes (active nodes with notify addresses)
				activeNodes, _ := kdcDB.GetActiveNodes()
				var targetNodes []string
				for _, node := range activeNodes {
					if node.NotifyAddress != "" {
						targetNodes = append(targetNodes, node.ID)
					}
				}
				
				// Get confirmed nodes
				confirmedNodes, _ := kdcDB.GetDistributionConfirmations(req.DistributionID)
				
				// Calculate pending nodes
				confirmedMap := make(map[string]bool)
				for _, nodeID := range confirmedNodes {
					confirmedMap[nodeID] = true
				}
				var pendingNodes []string
				for _, nodeID := range targetNodes {
					if !confirmedMap[nodeID] {
						pendingNodes = append(pendingNodes, nodeID)
					}
				}
				
				allConfirmed := len(pendingNodes) == 0 && len(targetNodes) > 0
				
				resp.State = &DistributionStateInfo{
					DistributionID: req.DistributionID,
					ZoneID:         record.ZoneID,
					KeyID:          record.KeyID,
					KeyState:       keyState,
					CreatedAt:      record.CreatedAt.Format(time.RFC3339),
					TargetNodes:    targetNodes,
					ConfirmedNodes: confirmedNodes,
					PendingNodes:   pendingNodes,
					AllConfirmed:   allConfirmed,
				}
				resp.Msg = fmt.Sprintf("Distribution %s: %d/%d nodes confirmed", req.DistributionID, len(confirmedNodes), len(targetNodes))
			}

		case "completed":
			if req.DistributionID == "" {
				sendJSONError(w, http.StatusBadRequest, "distribution_id is required for completed command")
				return
			}
			
			// Get distribution records to find zone/key
			records, err := kdcDB.GetDistributionRecordsForDistributionID(req.DistributionID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else if len(records) == 0 {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Distribution %s not found", req.DistributionID)
			} else {
				record := records[0]
				
				// Force transition key state from 'distributed' to 'edgesigner'
				if err := kdcDB.UpdateKeyState(record.ZoneID, record.KeyID, KeyStateEdgeSigner); err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Failed to update key state: %v", err)
				} else {
					resp.Msg = fmt.Sprintf("Distribution %s marked as completed. Key %s transitioned to 'edgesigner' state.", req.DistributionID, record.KeyID)
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

// computeKeyHash computes a SHA-256 hash of the private key material
// Returns hex-encoded hash string
func computeKeyHash(privateKey []byte) (string, error) {
	if len(privateKey) == 0 {
		return "", fmt.Errorf("private key is empty")
	}
	hash := sha256.Sum256(privateKey)
	return hex.EncodeToString(hash[:]), nil
}

// SetupKdcAPIRoutes sets up KDC-specific API routes
// conf is *tdns.Config passed as interface{} to avoid circular import
// pingHandler is the ping endpoint handler function
func SetupKdcAPIRoutes(router *mux.Router, kdcDB *KdcDB, conf interface{}, pingHandler http.HandlerFunc) {
	if kdcDB == nil {
		log.Printf("SetupKdcAPIRoutes: KDC database not initialized, skipping KDC API routes")
		return
	}

	// Extract API key and KDC config from config
	apikey := ""
	var kdcConf *KdcConf
	if configMap, ok := conf.(map[string]interface{}); ok {
		if apiServer, ok := configMap["ApiServer"].(map[string]interface{}); ok {
			if key, ok := apiServer["ApiKey"].(string); ok {
				apikey = key
			}
		}
		if kdcConfRaw, ok := configMap["KdcConf"]; ok {
			if kdcConfPtr, ok := kdcConfRaw.(*KdcConf); ok {
				kdcConf = kdcConfPtr
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
	
	sr.HandleFunc("/kdc/zone", APIKdcZone(kdcDB, kdcConf)).Methods("POST")
	sr.HandleFunc("/kdc/node", APIKdcNode(kdcDB)).Methods("POST")
	sr.HandleFunc("/kdc/distrib", APIKdcDistrib(kdcDB, kdcConf)).Methods("POST")
	if kdcConf != nil {
		sr.HandleFunc("/kdc/config", APIKdcConfig(kdcConf, conf)).Methods("POST")
		sr.HandleFunc("/kdc/debug", APIKdcDebug(kdcDB, kdcConf)).Methods("POST")
	}
	
	log.Printf("KDC API routes registered: /api/v1/ping, /api/v1/kdc/zone, /api/v1/kdc/node, /api/v1/kdc/config, /api/v1/kdc/debug")
}

