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

// KdcZonePost represents a request to the KDC zone API
type KdcZonePost struct {
	Command   string `json:"command"`   // "add", "list", "get", "get-keys", "generate-key", "encrypt-key", "update", "delete", "distribute-zsk", "transition", "setstate", "delete-key"
	Zone      *Zone  `json:"zone,omitempty"`
	ZoneID    string `json:"zone_id,omitempty"`
	KeyID     string `json:"key_id,omitempty"`     // For encrypt-key/distribute-zsk/transition/setstate/delete-key: DNSSEC key ID
	NodeID    string `json:"node_id,omitempty"`    // For encrypt-key: node ID
	KeyType   string `json:"key_type,omitempty"`   // For generate-key: "KSK", "ZSK", or "CSK"
	Algorithm uint8  `json:"algorithm,omitempty"`  // For generate-key: DNSSEC algorithm
	Comment   string `json:"comment,omitempty"`    // For generate-key: optional comment
	NewState  string `json:"new_state,omitempty"`  // For setstate: target state
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
				// Transition to distributed state
				if err := kdcDB.UpdateKeyState(req.ZoneID, req.KeyID, KeyStateDistributed); err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// Send NOTIFY to all active nodes
					if kdcConf != nil && kdcConf.ControlZone != "" {
						if err := kdcDB.SendNotifyToNodes(req.ZoneID, kdcConf.ControlZone); err != nil {
							log.Printf("KDC: Warning: Failed to send NOTIFYs: %v", err)
							// Don't fail the request, just log the warning
						}
					} else {
						log.Printf("KDC: Warning: Control zone not configured, skipping NOTIFY")
					}
					
					resp.Msg = fmt.Sprintf("Key %s transitioned to distributed state. NOTIFYs sent to nodes. Distribution will be triggered on next KMREQ.", req.KeyID)
					// Reload key to get updated state
					key, _ = kdcDB.GetDNSSECKeyByID(req.ZoneID, req.KeyID)
					resp.Key = key
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
	if kdcConf != nil {
		sr.HandleFunc("/kdc/config", APIKdcConfig(kdcConf, conf)).Methods("POST")
	}
	
	log.Printf("KDC API routes registered: /api/v1/ping, /api/v1/kdc/zone, /api/v1/kdc/node, /api/v1/kdc/config")
}

