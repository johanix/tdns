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
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
)

// KdcZonePost represents a request to the KDC zone API
type KdcZonePost struct {
	Command       string   `json:"command"`        // "add", "list", "get", "get-keys", "generate-key", "encrypt-key", "update", "delete", "distrib-single", "distrib-multi", "transition", "setstate", "delete-key", "purge-keys", "set-service", "set-component"
	Zone          *Zone    `json:"zone,omitempty"`
	ZoneName      string   `json:"zone_name,omitempty"`      // Zone name (replaces zone_id)
	ServiceID     string   `json:"service_id,omitempty"`     // For set-service command
	ServiceName   string   `json:"service_name,omitempty"`   // For set-service command (CLI convenience)
	ComponentID   string   `json:"component_id,omitempty"`   // For set-component command
	ComponentName string   `json:"component_name,omitempty"` // For set-component command (CLI convenience)
	KeyID         string   `json:"key_id,omitempty"`         // For encrypt-key/distrib-single/transition/setstate/delete-key: DNSSEC key ID
	NodeID        string   `json:"node_id,omitempty"`        // For encrypt-key: node ID
	KeyType       string   `json:"key_type,omitempty"`       // For generate-key: "KSK", "ZSK", or "CSK"
	Algorithm     uint8    `json:"algorithm,omitempty"`      // For generate-key: DNSSEC algorithm
	Comment       string   `json:"comment,omitempty"`        // For generate-key: optional comment
	NewState      string   `json:"new_state,omitempty"`      // For setstate: target state
	Zones         []string `json:"zones,omitempty"`           // For distrib-multi: list of zone names
}

// DistributionResult represents the result of distributing a key for a zone
type DistributionResult struct {
	ZoneName string `json:"zone_name"`
	KeyID    string `json:"key_id,omitempty"`
	Status   string `json:"status"` // "success" or "error"
	Msg      string `json:"msg,omitempty"`
}

// ZoneEnrichment contains additional information about a zone for display
type ZoneEnrichment struct {
	ServiceName     string   `json:"service_name,omitempty"`
	ComponentIDs    []string `json:"component_ids,omitempty"`
	ComponentNames  []string `json:"component_names,omitempty"`
	SigningComponentID string `json:"signing_component_id,omitempty"` // The sign_* component (for Signing Mode column)
	NodeIDs         []string `json:"node_ids,omitempty"` // For verbose mode
}

// KdcZoneResponse represents a response from the KDC zone API
type KdcZoneResponse struct {
	Time      time.Time              `json:"time"`
	Error     bool                   `json:"error,omitempty"`
	ErrorMsg  string                 `json:"error_msg,omitempty"`
	Msg       string                 `json:"msg,omitempty"`
	Zone      *Zone                  `json:"zone,omitempty"`
	Zones     []*Zone                `json:"zones,omitempty"`
	ZoneEnrichments map[string]*ZoneEnrichment `json:"zone_enrichments,omitempty"` // Keyed by zone name
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

// KdcServicePost represents a request to the KDC service API
type KdcServicePost struct {
	Command string   `json:"command"` // "add", "list", "get", "update", "delete"
	Service *Service `json:"service,omitempty"`
	ServiceID string `json:"service_id,omitempty"`
	ServiceName string `json:"service_name,omitempty"` // For CLI convenience
}

// KdcServiceResponse represents a response from the KDC service API
type KdcServiceResponse struct {
	Time     time.Time   `json:"time"`
	Error    bool        `json:"error,omitempty"`
	ErrorMsg string      `json:"error_msg,omitempty"`
	Msg      string      `json:"msg,omitempty"`
	Service  *Service    `json:"service,omitempty"`
	Services []*Service   `json:"services,omitempty"`
}

// KdcComponentPost represents a request to the KDC component API
type KdcComponentPost struct {
	Command string     `json:"command"` // "add", "list", "get", "update", "delete"
	Component *Component `json:"component,omitempty"`
	ComponentID string   `json:"component_id,omitempty"`
	ComponentName string `json:"component_name,omitempty"` // For CLI convenience
}

// KdcComponentResponse represents a response from the KDC component API
type KdcComponentResponse struct {
	Time      time.Time    `json:"time"`
	Error     bool         `json:"error,omitempty"`
	ErrorMsg  string       `json:"error_msg,omitempty"`
	Msg       string       `json:"msg,omitempty"`
	Component *Component   `json:"component,omitempty"`
	Components []*Component `json:"components,omitempty"`
}

// KdcServiceComponentPost represents a request for service-component assignment
type KdcServiceComponentPost struct {
	Command        string `json:"command"` // "add", "delete", "list", "replace"
	ServiceID      string `json:"service_id,omitempty"`
	ServiceName    string `json:"service_name,omitempty"` // For CLI convenience
	ComponentID    string `json:"component_id,omitempty"`
	ComponentName  string `json:"component_name,omitempty"` // For CLI convenience
	OldComponentID string `json:"old_component_id,omitempty"` // For replace command
	OldComponentName string `json:"old_component_name,omitempty"` // For replace command
	NewComponentID string `json:"new_component_id,omitempty"` // For replace command
	NewComponentName string `json:"new_component_name,omitempty"` // For replace command
}

// KdcServiceComponentResponse represents a response for service-component assignment
type KdcServiceComponentResponse struct {
	Time      time.Time   `json:"time"`
	Error     bool        `json:"error,omitempty"`
	ErrorMsg  string      `json:"error_msg,omitempty"`
	Msg       string      `json:"msg,omitempty"`
	Assignments []*ServiceComponentAssignment `json:"assignments,omitempty"`
}

// KdcServiceTransactionPost represents a request to the KDC service transaction API
type KdcServiceTransactionPost struct {
	Command     string `json:"command"`      // "start", "add-component", "remove-component", "view", "commit", "rollback", "list", "get", "status", "cleanup"
	ServiceID   string `json:"service_id,omitempty"`
	ServiceName string `json:"service_name,omitempty"` // For CLI convenience
	TxID        string `json:"tx_id,omitempty"`       // Transaction ID
	ComponentID string `json:"component_id,omitempty"`
	ComponentName string `json:"component_name,omitempty"` // For CLI convenience
	CreatedBy   string `json:"created_by,omitempty"`
	Comment     string `json:"comment,omitempty"`
	DryRun      bool   `json:"dry_run,omitempty"`     // For commit command: if true, don't apply changes
	StateFilter string `json:"state_filter,omitempty"` // For list command: filter by state
}

// KdcServiceTransactionResponse represents a response from the KDC service transaction API
type KdcServiceTransactionResponse struct {
	Time        time.Time              `json:"time"`
	Error       bool                   `json:"error,omitempty"`
	ErrorMsg    string                 `json:"error_msg,omitempty"`
	Msg         string                 `json:"msg,omitempty"`
	TxID        string                 `json:"tx_id,omitempty"`
	Transaction *ServiceTransaction    `json:"transaction,omitempty"`
	Transactions []*ServiceTransaction  `json:"transactions,omitempty"`
	DeltaReport *DeltaReport           `json:"delta_report,omitempty"`
}

// KdcNodeComponentPost represents a request for node-component assignment
type KdcNodeComponentPost struct {
	Command        string `json:"command"` // "add", "delete", "list"
	NodeID         string `json:"node_id,omitempty"`
	NodeName       string `json:"node_name,omitempty"` // For CLI convenience
	ComponentID    string `json:"component_id,omitempty"`
	ComponentName  string `json:"component_name,omitempty"` // For CLI convenience
}

// KdcNodeComponentResponse represents a response for node-component assignment
type KdcNodeComponentResponse struct {
	Time      time.Time   `json:"time"`
	Error     bool        `json:"error,omitempty"`
	ErrorMsg  string      `json:"error_msg,omitempty"`
	Msg       string      `json:"msg,omitempty"`
	Assignments []*NodeComponentAssignment `json:"assignments,omitempty"`
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
			if req.Zone.Name == "" {
				sendJSONError(w, http.StatusBadRequest, "zone name is required")
				return
			}
			if err := kdcDB.AddZone(req.Zone); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s added successfully", req.Zone.Name)
			}

		case "list":
			zones, err := kdcDB.GetAllZones()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Zones = zones
				// Enrich zones with service name and components
				resp.ZoneEnrichments = make(map[string]*ZoneEnrichment)
				for _, zone := range zones {
					enrichment := &ZoneEnrichment{}
					
					// Get service name
					if zone.ServiceID != "" {
						service, err := kdcDB.GetService(zone.ServiceID)
						if err == nil {
							enrichment.ServiceName = service.Name
						} else {
							enrichment.ServiceName = zone.ServiceID // Fallback to ID
						}
					}
					
					// Get components for this zone via its service (not direct assignments)
					// Zones are related to services, and components are derived from the service
					if zone.ServiceID != "" {
						componentIDs, err := kdcDB.GetComponentsForService(zone.ServiceID)
						if err == nil {
							// Separate signing components (sign_*) from non-signing components
							var signingComponentID string
							var nonSigningComponents []string
							
							// First pass: find sign_kdc if it exists
							for _, compID := range componentIDs {
								if compID == "sign_kdc" {
									signingComponentID = compID
									break
								}
							}
							
							// Second pass: if no sign_kdc, find first sign_* component
							if signingComponentID == "" {
								for _, compID := range componentIDs {
									if strings.HasPrefix(compID, "sign_") {
										signingComponentID = compID
										break
									}
								}
							}
							
							// Third pass: collect all non-signing components
							for _, compID := range componentIDs {
								if !strings.HasPrefix(compID, "sign_") {
									nonSigningComponents = append(nonSigningComponents, compID)
								}
							}
							
							// If no sign_* component found, default to sign_kdc
							if signingComponentID == "" {
								signingComponentID = "sign_kdc"
							}
							
							enrichment.SigningComponentID = signingComponentID
							enrichment.ComponentIDs = nonSigningComponents
							enrichment.ComponentNames = nonSigningComponents
							
							// Get nodes for components (for verbose mode - we'll include them always)
							nodeSet := make(map[string]bool)
							for _, compID := range componentIDs {
								nodes, err := kdcDB.GetNodesForComponent(compID)
								if err == nil {
									for _, nodeID := range nodes {
										nodeSet[nodeID] = true
									}
								}
							}
							for nodeID := range nodeSet {
								enrichment.NodeIDs = append(enrichment.NodeIDs, nodeID)
							}
						}
					}
					
					resp.ZoneEnrichments[zone.Name] = enrichment
				}
			}

		case "get":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for get command")
				return
			}
			zone, err := kdcDB.GetZone(req.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Zone = zone
			}

		case "get-keys":
			var keys []*DNSSECKey
			var err error
			if req.ZoneName == "" {
				// List all keys for all zones
				keys, err = kdcDB.GetAllDNSSECKeys()
			} else {
				// List keys for a specific zone
				keys, err = kdcDB.GetDNSSECKeysForZone(req.ZoneName)
			}
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Keys = keys
			}

		case "encrypt-key":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for encrypt-key command")
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
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneName, keyID)
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
					encryptedKey, ephemeralPubKey, distributionID, err := kdcDB.EncryptKeyForNode(key, node, kdcConf)
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
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for generate-key command")
				return
			}
			// Verify zone exists
			_, err := kdcDB.GetZone(req.ZoneName)
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
				key, err := kdcDB.GenerateDNSSECKey(req.ZoneName, keyType, algorithm, req.Comment)
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
			if req.Zone == nil || req.Zone.Name == "" {
				sendJSONError(w, http.StatusBadRequest, "zone with name is required for update command")
				return
			}
			if err := kdcDB.UpdateZone(req.Zone); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s updated successfully", req.Zone.Name)
			}

		case "set-service":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for set-service command")
				return
			}
			// Get service ID from name if provided
			serviceID := req.ServiceID
			if serviceID == "" && req.ServiceName != "" {
				// Look up service by name
				services, err := kdcDB.GetAllServices()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Failed to get services: %v", err)
				} else {
					found := false
					for _, s := range services {
						if s.Name == req.ServiceName {
							serviceID = s.ID
							found = true
							break
						}
					}
					if !found {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Service not found: %s", req.ServiceName)
					}
				}
			}
			if serviceID == "" {
				sendJSONError(w, http.StatusBadRequest, "service_id or service_name is required for set-service command")
				return
			}
			// Get zone
			zone, err := kdcDB.GetZone(req.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone not found: %v", err)
			} else {
				// Update zone service
				zone.ServiceID = serviceID
				if err := kdcDB.UpdateZone(zone); err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// Get signing mode from service components (zones derive components from service)
					newSigningMode, err := kdcDB.GetZoneSigningMode(req.ZoneName)
					if err != nil {
						log.Printf("KDC: Warning: Failed to get signing mode for zone %s: %v", req.ZoneName, err)
						newSigningMode = ZoneSigningModeCentral // Default
					}
					
					// Get components from the service for display
					serviceComponents, err := kdcDB.GetComponentsForService(serviceID)
					if err != nil {
						log.Printf("KDC: Warning: Failed to get components for service %s: %v", serviceID, err)
					}
					
					componentNames := make([]string, 0, len(serviceComponents))
					for _, compID := range serviceComponents {
						comp, err := kdcDB.GetComponent(compID)
						if err == nil {
							componentNames = append(componentNames, comp.Name)
						} else {
							componentNames = append(componentNames, compID)
						}
					}
					
					componentsStr := strings.Join(componentNames, ", ")
					if componentsStr == "" {
						componentsStr = "(none)"
					}
					
					resp.Msg = fmt.Sprintf("Zone %s assigned to service %s (signing mode: %s, components: %s)", req.ZoneName, serviceID, newSigningMode, componentsStr)
					resp.Zone = zone
				}
			}

		case "delete":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for delete command")
				return
			}
			if err := kdcDB.DeleteZone(req.ZoneName); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s deleted successfully", req.ZoneName)
			}

		case "distrib-single":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for distrib-single command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for distrib-single command")
				return
			}
			// Get the key and verify it's a ZSK in standby state
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
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
				// Check if zone uses sign_edge_full and get active KSK
				signingMode, _ := kdcDB.GetZoneSigningMode(req.ZoneName)
				var activeKSK *DNSSECKey
				if signingMode == ZoneSigningModeEdgesignFull {
					keys, _ := kdcDB.GetDNSSECKeysForZone(req.ZoneName)
					for _, k := range keys {
						if k.KeyType == KeyTypeKSK && k.State == KeyStateActive {
							activeKSK = k
							break
						}
					}
				}
				// Get distributionID for this key (before transitioning state)
				distributionID, err := kdcDB.GetOrCreateDistributionID(req.ZoneName, key)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Failed to get/create distribution ID: %v", err)
				} else {
					// Transition to distributed state
					if err := kdcDB.UpdateKeyState(req.ZoneName, req.KeyID, KeyStateDistributed); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						// Check zone signing mode - only distribute keys for edgesigned zones
						_, err := kdcDB.GetZone(req.ZoneName)
						if err != nil {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("Failed to get zone: %v", err)
						} else {
							signingMode, err := kdcDB.GetZoneSigningMode(req.ZoneName)
							if err != nil {
								resp.Error = true
								resp.ErrorMsg = fmt.Sprintf("Failed to get signing mode: %v", err)
							} else if signingMode != ZoneSigningModeEdgesignDyn && signingMode != ZoneSigningModeEdgesignZsk && signingMode != ZoneSigningModeEdgesignFull {
								resp.Error = true
								resp.ErrorMsg = fmt.Sprintf("Zone %s has signing_mode=%s, keys are not distributed to nodes (only edgesign_* modes support key distribution)", req.ZoneName, signingMode)
							} else {
								// Get nodes that serve this zone (via components)
								nodes, err := kdcDB.GetActiveNodesForZone(req.ZoneName)
								if err != nil {
									log.Printf("KDC: Warning: Failed to get nodes for zone: %v", err)
								} else if len(nodes) == 0 {
									log.Printf("KDC: Warning: No active nodes serve zone %s", req.ZoneName)
								} else {
									encryptedCount := 0
									for _, node := range nodes {
										if node.NotifyAddress == "" {
											log.Printf("KDC: Skipping node %s (no notify_address configured)", node.ID)
											continue
										}
										// Encrypt key for this node (creates distribution record)
										_, _, _, err := kdcDB.EncryptKeyForNode(key, node, kdcConf)
										if err != nil {
											log.Printf("KDC: Warning: Failed to encrypt key for node %s: %v", node.ID, err)
											continue
										}
										encryptedCount++
										log.Printf("KDC: Encrypted key %s for node %s (distribution ID: %s)", req.KeyID, node.ID, distributionID)
									}
									log.Printf("KDC: Encrypted key for %d/%d nodes serving zone %s", encryptedCount, len(nodes), req.ZoneName)
								}

								// Distribute active KSK for edgesign_full zones
								if activeKSK != nil {
									kskDistributionID, err := kdcDB.GetOrCreateDistributionID(req.ZoneName, activeKSK)
									if err != nil {
										log.Printf("KDC: Warning: Failed to get/create distribution ID for KSK %s: %v", activeKSK.ID, err)
									} else {
										// Transition to active_dist state
										if err := kdcDB.UpdateKeyState(req.ZoneName, activeKSK.ID, KeyStateActiveDist); err != nil {
											log.Printf("KDC: Warning: Failed to update KSK state: %v", err)
										} else {
											// Encrypt KSK for all nodes
											kskEncryptedCount := 0
											for _, node := range nodes {
												if node.NotifyAddress == "" {
													continue
												}
												_, _, _, err := kdcDB.EncryptKeyForNode(activeKSK, node, kdcConf)
												if err != nil {
													log.Printf("KDC: Warning: Failed to encrypt KSK for node %s: %v", node.ID, err)
													continue
												}
												kskEncryptedCount++
											}
											log.Printf("KDC: Encrypted KSK %s for %d/%d nodes serving zone %s (distribution ID: %s)", activeKSK.ID, kskEncryptedCount, len(nodes), req.ZoneName, kskDistributionID)
										}
									}
								}
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
							key, _ = kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
							resp.Key = key
						}
					}
				}
			}

		case "transition":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for transition command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for transition command")
				return
			}
			
			// Get key and determine next state based on current state
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
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
				
				if err := kdcDB.UpdateKeyState(req.ZoneName, req.KeyID, toState); err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Key %s transitioned from %s to %s", req.KeyID, key.State, toState)
					key, _ = kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
					resp.Key = key
				}
			}

		case "delete-key":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for delete-key command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for delete-key command")
				return
			}
			if err := kdcDB.DeleteDNSSECKey(req.ZoneName, req.KeyID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Key %s deleted successfully", req.KeyID)
			}

		case "purge-keys":
			// Purge keys in "removed" state
			// zone_name is optional - if provided, only purge keys for that zone
			deletedCount, err := kdcDB.DeleteKeysByState(KeyStateRemoved, req.ZoneName)
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

		case "setstate":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for setstate command")
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
				if err := kdcDB.UpdateKeyState(req.ZoneName, req.KeyID, newState); err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Key %s state set to %s", req.KeyID, newState)
					key, _ := kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
					resp.Key = key
				}
			}

		case "hash":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for hash command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for hash command")
				return
			}
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
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
			
			for _, zoneName := range req.Zones {
				result := DistributionResult{
					ZoneName: zoneName,
					Status:   "error",
				}
				
				// Find a standby ZSK for this zone
				keys, err := kdcDB.GetDNSSECKeysForZone(zoneName)
				if err != nil {
					result.Msg = fmt.Sprintf("Failed to get keys: %v", err)
					results = append(results, result)
					errorCount++
					continue
				}
				
				// Get nodes for this zone (needed to check confirmations for distributed ZSKs)
				nodes, err := kdcDB.GetActiveNodesForZone(zoneName)
				if err != nil {
					result.Msg = fmt.Sprintf("Failed to get nodes for zone: %v", err)
					results = append(results, result)
					errorCount++
					continue
				}
				
				// Find ZSK to distribute (prefer 'distributed' that needs retry, then 'standby')
				var standbyZSK *DNSSECKey
				var distributedZSK *DNSSECKey
				var distributedZSKNeedsRetry *DNSSECKey
				var zskStates []string
				for _, key := range keys {
					if key.KeyType == KeyTypeZSK {
						zskStates = append(zskStates, string(key.State))
						if key.State == KeyStateStandby && standbyZSK == nil {
							// Keep track of first standby ZSK as fallback
							standbyZSK = key
						} else if key.State == KeyStateDistributed {
							// Check if this distributed ZSK needs retry
							distID, err := kdcDB.GetOrCreateDistributionID(zoneName, key)
							if err == nil && len(nodes) > 0 {
								confirmedNodeIDs, err := kdcDB.GetDistributionConfirmations(distID)
								if err == nil {
									// Build map of confirmed nodes
									confirmedMap := make(map[string]bool)
									for _, nodeID := range confirmedNodeIDs {
										confirmedMap[nodeID] = true
									}
									// Check if any nodes haven't confirmed
									needsRetry := false
									for _, node := range nodes {
										if node.NotifyAddress != "" && !confirmedMap[node.ID] {
											needsRetry = true
											break
										}
									}
									if needsRetry {
										// This distributed ZSK needs retry - prefer it
										distributedZSKNeedsRetry = key
										log.Printf("KDC: Zone %s: Found ZSK %s in state distributed that needs retry", zoneName, key.ID)
										break // Found one that needs retry, use it
									}
								}
							}
							// Keep track of first distributed ZSK as fallback (even if all confirmed)
							if distributedZSK == nil {
								distributedZSK = key
								log.Printf("KDC: Zone %s: Found ZSK %s in state distributed", zoneName, key.ID)
							}
						}
					}
				}
				// Prefer distributed ZSK that needs retry, then standby, then any distributed
				if distributedZSKNeedsRetry != nil {
					standbyZSK = distributedZSKNeedsRetry
					log.Printf("KDC: Zone %s: Will retry distribution for ZSK %s in state distributed", zoneName, standbyZSK.ID)
				} else if standbyZSK == nil && distributedZSK != nil {
					// All distributed ZSKs are fully confirmed, but we'll check again later
					standbyZSK = distributedZSK
					log.Printf("KDC: Zone %s: Will check if ZSK %s in state distributed needs retry", zoneName, standbyZSK.ID)
				}
				
				// Check zone signing mode FIRST - only distribute keys for edgesigned zones
				_, err = kdcDB.GetZone(zoneName)
				if err != nil {
					result.Msg = fmt.Sprintf("Failed to get zone: %v", err)
					results = append(results, result)
					errorCount++
					continue
				}
				signingMode, err := kdcDB.GetZoneSigningMode(zoneName)
				if err != nil {
					result.Msg = fmt.Sprintf("Failed to get signing mode: %v", err)
					results = append(results, result)
					errorCount++
					continue
				}
				if signingMode != ZoneSigningModeEdgesignDyn && signingMode != ZoneSigningModeEdgesignZsk && signingMode != ZoneSigningModeEdgesignFull {
					result.Msg = fmt.Sprintf("Zone has signing_mode=%s, keys are not distributed to nodes (only edgesign_* modes support key distribution)", signingMode)
					results = append(results, result)
					errorCount++
					continue
				}

				// For edgesign_full zones, find KSK to distribute (prefer 'active', but also handle 'active_dist' for retries)
				var activeKSK *DNSSECKey
				var activeDistKSK *DNSSECKey
				if signingMode == ZoneSigningModeEdgesignFull {
					log.Printf("KDC: Zone %s uses sign_edge_full, searching for KSK to distribute (checked %d keys)", zoneName, len(keys))
					for _, key := range keys {
						if key.KeyType == KeyTypeKSK {
							log.Printf("KDC: Zone %s: Found KSK %s in state %s", zoneName, key.ID, key.State)
							if key.State == KeyStateActive {
								activeKSK = key
								log.Printf("KDC: Zone %s: Selected KSK %s for distribution (state: %s)", zoneName, key.ID, key.State)
								break // Prefer active over active_dist
							} else if key.State == KeyStateActiveDist && activeDistKSK == nil {
								// Keep track of active_dist KSK for retry if no active KSK found
								activeDistKSK = key
								log.Printf("KDC: Zone %s: Found KSK %s in state %s (candidate for retry)", zoneName, key.ID, key.State)
							}
						}
					}
					// If no active KSK found, use active_dist KSK for retry
					if activeKSK == nil && activeDistKSK != nil {
						activeKSK = activeDistKSK
						log.Printf("KDC: Zone %s: Will retry distribution for KSK %s in state active_dist", zoneName, activeKSK.ID)
					}
					if activeKSK == nil {
						log.Printf("KDC: Zone %s uses sign_edge_full but no active or active_dist KSK found (checked %d keys)", zoneName, len(keys))
						// Log all KSK states for debugging
						for _, key := range keys {
							if key.KeyType == KeyTypeKSK {
								log.Printf("KDC: Zone %s has KSK %s in state %s", zoneName, key.ID, key.State)
							}
						}
					}
				}

				if standbyZSK == nil && activeKSK == nil {
					if len(zskStates) == 0 {
						result.Msg = "No ZSK keys found for zone"
					} else {
						result.Msg = fmt.Sprintf("No standby or distributed ZSK found for zone (available ZSK states: %s)", strings.Join(zskStates, ", "))
					}
					results = append(results, result)
					errorCount++
					continue
				}

				// Check if we have any nodes (already retrieved above)
				if len(nodes) == 0 {
					result.Msg = fmt.Sprintf("No active nodes serve zone %s (zone may not be assigned to any components, or no nodes are assigned to those components)", zoneName)
					results = append(results, result)
					errorCount++
					continue
				}

				// Check if any nodes have notify_address configured
				nodesWithNotify := 0
				for _, node := range nodes {
					if node.NotifyAddress != "" {
						nodesWithNotify++
					}
				}
				if nodesWithNotify == 0 {
					result.Msg = fmt.Sprintf("No nodes with notify_address configured for zone %s (%d nodes found but none have notify_address)", zoneName, len(nodes))
					results = append(results, result)
					errorCount++
					continue
				}

				// Distribute ZSK (if available)
				var distributionID string
				var kskDistributionID string
				var encryptedCount int
				var zskNodeCount int // Track number of nodes that received ZSK
				var kskNodeCount int // Track number of nodes that received KSK
				if standbyZSK != nil {
					distributionID, err = kdcDB.GetOrCreateDistributionID(zoneName, standbyZSK)
					if err != nil {
						result.Msg = fmt.Sprintf("Failed to get/create distribution ID: %v", err)
						results = append(results, result)
						errorCount++
						continue
					}
					
					// Determine which nodes need distribution
					var nodesToDistribute []*Node
					if standbyZSK.State == KeyStateStandby {
						// First-time distribution: distribute to all nodes
						log.Printf("KDC: Distributing ZSK %s for zone %s (first-time distribution)", standbyZSK.ID, zoneName)
						nodesToDistribute = nodes
						// Transition to distributed state
						if err := kdcDB.UpdateKeyState(zoneName, standbyZSK.ID, KeyStateDistributed); err != nil {
							result.Msg = fmt.Sprintf("Failed to update key state: %v", err)
							results = append(results, result)
							errorCount++
							continue
						}
					} else if standbyZSK.State == KeyStateDistributed {
						// Retry distribution: only distribute to nodes that haven't confirmed
						log.Printf("KDC: Retrying distribution for ZSK %s in state distributed (zone: %s)", standbyZSK.ID, zoneName)
						
						// Get list of nodes that have already confirmed
						confirmedNodeIDs, err := kdcDB.GetDistributionConfirmations(distributionID)
						if err != nil {
							log.Printf("KDC: Warning: Failed to get confirmations for distribution %s: %v", distributionID, err)
							// If we can't get confirmations, distribute to all nodes (safe fallback)
							nodesToDistribute = nodes
						} else {
							// Build map of confirmed nodes for quick lookup
							confirmedMap := make(map[string]bool)
							for _, nodeID := range confirmedNodeIDs {
								confirmedMap[nodeID] = true
							}
							
							// Filter to only nodes that haven't confirmed
							for _, node := range nodes {
								if node.NotifyAddress == "" {
									continue
								}
								if !confirmedMap[node.ID] {
									nodesToDistribute = append(nodesToDistribute, node)
								} else {
									log.Printf("KDC: Skipping node %s (already confirmed distribution %s)", node.ID, distributionID)
								}
							}
							
							if len(nodesToDistribute) == 0 {
								log.Printf("KDC: All nodes have already confirmed distribution %s for ZSK %s, no retry needed", distributionID, standbyZSK.ID)
								// Don't create new distributions, but don't fail either
								// Clear standbyZSK so we don't try to encrypt it, but continue to KSK distribution if needed
								standbyZSK = nil
							} else {
								log.Printf("KDC: Retrying distribution for ZSK %s to %d node(s) that haven't confirmed", standbyZSK.ID, len(nodesToDistribute))
							}
						}
					} else {
						log.Printf("KDC: ZSK %s is in unexpected state %s, skipping distribution", standbyZSK.ID, standbyZSK.State)
						// If no KSK to distribute either, fail
						if activeKSK == nil {
							result.Msg = fmt.Sprintf("ZSK %s is in unexpected state %s", standbyZSK.ID, standbyZSK.State)
							results = append(results, result)
							errorCount++
							continue
						}
						// Otherwise, continue to KSK distribution
						standbyZSK = nil
					}

					// Encrypt ZSK for nodes that need distribution
					if standbyZSK != nil && len(nodesToDistribute) > 0 {
						for _, node := range nodesToDistribute {
							if node.NotifyAddress == "" {
								log.Printf("KDC: Skipping node %s (no notify_address configured)", node.ID)
								continue
							}
							_, _, _, err := kdcDB.EncryptKeyForNode(standbyZSK, node, kdcConf)
							if err != nil {
								log.Printf("KDC: Warning: Failed to encrypt ZSK for node %s: %v", node.ID, err)
								continue
							}
							encryptedCount++
							zskNodeCount++
						}
						log.Printf("KDC: Encrypted ZSK %s for %d/%d target node(s) serving zone %s", standbyZSK.ID, zskNodeCount, len(nodesToDistribute), zoneName)
					}
				}

				// Distribute active KSK for edgesign_full zones
				if activeKSK != nil {
					kskDistributionID, err = kdcDB.GetOrCreateDistributionID(zoneName, activeKSK)
					if err != nil {
						log.Printf("KDC: Error: Failed to get/create distribution ID for KSK %s: %v", activeKSK.ID, err)
					} else {
						log.Printf("KDC: KSK %s distribution ID: %s", activeKSK.ID, kskDistributionID)
						// Use KSK distribution ID if ZSK wasn't distributed
						if distributionID == "" {
							distributionID = kskDistributionID
						}
						
						// Determine which nodes need distribution
						var nodesToDistribute []*Node
						if activeKSK.State == KeyStateActive {
							// First-time distribution: distribute to all nodes
							log.Printf("KDC: Distributing KSK %s for zone %s (sign_edge_full, first-time distribution)", activeKSK.ID, zoneName)
							nodesToDistribute = nodes
							// Transition to active_dist state
							if err := kdcDB.UpdateKeyState(zoneName, activeKSK.ID, KeyStateActiveDist); err != nil {
								log.Printf("KDC: Error: Failed to update KSK state to active_dist: %v", err)
								continue
							}
							log.Printf("KDC: Successfully updated KSK %s state to active_dist", activeKSK.ID)
						} else if activeKSK.State == KeyStateActiveDist {
							// Retry distribution: only distribute to nodes that haven't confirmed
							log.Printf("KDC: Retrying distribution for KSK %s in state active_dist (zone: %s)", activeKSK.ID, zoneName)
							
							// Get list of nodes that have already confirmed
							confirmedNodeIDs, err := kdcDB.GetDistributionConfirmations(kskDistributionID)
							if err != nil {
								log.Printf("KDC: Warning: Failed to get confirmations for distribution %s: %v", kskDistributionID, err)
								// If we can't get confirmations, distribute to all nodes (safe fallback)
								nodesToDistribute = nodes
							} else {
								// Build map of confirmed nodes for quick lookup
								confirmedMap := make(map[string]bool)
								for _, nodeID := range confirmedNodeIDs {
									confirmedMap[nodeID] = true
								}
								
								// Filter to only nodes that haven't confirmed
								for _, node := range nodes {
									if node.NotifyAddress == "" {
										continue
									}
									if !confirmedMap[node.ID] {
										nodesToDistribute = append(nodesToDistribute, node)
									} else {
										log.Printf("KDC: Skipping node %s (already confirmed distribution %s)", node.ID, kskDistributionID)
									}
								}
								
								if len(nodesToDistribute) == 0 {
									log.Printf("KDC: All nodes have already confirmed distribution %s for KSK %s, no retry needed", kskDistributionID, activeKSK.ID)
									// Don't create new distributions, but don't fail either
									continue
								}
								log.Printf("KDC: Retrying distribution for KSK %s to %d node(s) that haven't confirmed", activeKSK.ID, len(nodesToDistribute))
							}
						} else {
							log.Printf("KDC: KSK %s is in unexpected state %s, skipping distribution", activeKSK.ID, activeKSK.State)
							continue
						}
						
						// Encrypt KSK for nodes that need distribution
						kskEncryptedCount := 0
						for _, node := range nodesToDistribute {
							if node.NotifyAddress == "" {
								log.Printf("KDC: Skipping node %s (no notify_address) for KSK distribution", node.ID)
								continue
							}
							log.Printf("KDC: Encrypting KSK %s for node %s", activeKSK.ID, node.ID)
							_, _, _, err := kdcDB.EncryptKeyForNode(activeKSK, node, kdcConf)
							if err != nil {
								log.Printf("KDC: Error: Failed to encrypt KSK for node %s: %v", node.ID, err)
								continue
							}
							kskEncryptedCount++
							kskNodeCount++
							log.Printf("KDC: Successfully encrypted KSK %s for node %s", activeKSK.ID, node.ID)
						}
						log.Printf("KDC: Encrypted KSK %s for %d/%d target node(s) serving zone %s", activeKSK.ID, kskEncryptedCount, len(nodesToDistribute), zoneName)
						encryptedCount += kskEncryptedCount
					}
				} else {
					log.Printf("KDC: No active or active_dist KSK to distribute for zone %s (sign_edge_full)", zoneName)
				}
				
				// Check if we have any keys to distribute (ZSK or KSK)
				if standbyZSK == nil && activeKSK == nil {
					// No keys to distribute - this could mean all distributions are already confirmed
					result.Msg = "No keys to distribute (all distributions already confirmed or no keys available)"
					results = append(results, result)
					errorCount++
					continue
				}
				
				if encryptedCount == 0 {
					result.Msg = fmt.Sprintf("Failed to encrypt key for any node (tried %d nodes)", len(nodes))
					results = append(results, result)
					errorCount++
					continue
				}
				
				// Send NOTIFY to all active nodes for ZSK distribution (if ZSK was distributed)
				if kdcConf != nil && kdcConf.ControlZone != "" && distributionID != "" && standbyZSK != nil {
					if err := kdcDB.SendNotifyWithDistributionID(distributionID, kdcConf.ControlZone); err != nil {
						log.Printf("KDC: Warning: Failed to send NOTIFYs for ZSK distribution: %v", err)
					} else {
						log.Printf("KDC: Successfully sent NOTIFY for ZSK distribution %s", distributionID)
					}
				}
				
				// Send NOTIFY to all active nodes for KSK distribution (if KSK was distributed)
				if kdcConf != nil && kdcConf.ControlZone != "" && activeKSK != nil && kskDistributionID != "" {
					if err := kdcDB.SendNotifyWithDistributionID(kskDistributionID, kdcConf.ControlZone); err != nil {
						log.Printf("KDC: Warning: Failed to send NOTIFYs for KSK distribution: %v", err)
					} else {
						log.Printf("KDC: Successfully sent NOTIFY for KSK distribution %s", kskDistributionID)
					}
				}
				
				result.Status = "success"
				if standbyZSK != nil {
					result.KeyID = standbyZSK.ID
				} else if activeKSK != nil {
					result.KeyID = activeKSK.ID
				}
				
				// Count keys and nodes for the message
				keyCount := 0
				if standbyZSK != nil {
					keyCount++
				}
				if activeKSK != nil {
					keyCount++
				}
				
				// Determine node count: use ZSK node count if available, otherwise KSK node count
				// Both keys are distributed to the same set of nodes, so use whichever is available
				nodeCount := zskNodeCount
				if nodeCount == 0 && activeKSK != nil {
					// If no ZSK was distributed, use KSK node count
					// Note: kskNodeCount is set in the KSK distribution loop above
					nodeCount = kskNodeCount
				}
				
				var keyPlural, nodePlural string
				if keyCount == 1 {
					keyPlural = "key"
				} else {
					keyPlural = "keys"
				}
				if nodeCount == 1 {
					nodePlural = "node"
				} else {
					nodePlural = "nodes"
				}
				
				result.Msg = fmt.Sprintf("%d %s distributed (distribution ID: %s) to %d %s", keyCount, keyPlural, distributionID, nodeCount, nodePlural)
				results = append(results, result)
				successCount++
			}
			
			resp.Results = results
			if errorCount == 0 {
				resp.Msg = fmt.Sprintf("Successfully distributed keys for %d zone(s)", successCount)
			} else if successCount == 0 {
				// Check if all failures are due to signing mode
				allSigningModeErrors := true
				for _, result := range results {
					if result.Status == "error" && !strings.Contains(result.Msg, "signing_mode") {
						allSigningModeErrors = false
						break
					}
				}
				if allSigningModeErrors {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Request denied: all %d zone(s) have signing_mode=central (keys are not distributed for central mode; use edgesign_* modes for key distribution)", errorCount)
				} else {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Failed to distribute keys for all %d zone(s)", errorCount)
				}
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
	Command        string `json:"command"`         // "list", "state", "completed", "purge", "purge-force"
	DistributionID string `json:"distribution_id,omitempty"` // For state and completed commands
	Force          bool   `json:"force,omitempty"` // For purge command: if true, delete all distributions
}

// DistributionStateInfo represents detailed information about a distribution
type DistributionStateInfo struct {
	DistributionID string   `json:"distribution_id"`
	ZoneName       string   `json:"zone_name"`
	KeyID          string   `json:"key_id"`
	KeyState       string   `json:"key_state"`
	CreatedAt      string   `json:"created_at"`
	TargetNodes   []string `json:"target_nodes"`   // All nodes that should receive this distribution
	ConfirmedNodes []string `json:"confirmed_nodes"` // Nodes that have confirmed
	PendingNodes   []string `json:"pending_nodes"`   // Nodes that haven't confirmed yet
	AllConfirmed   bool     `json:"all_confirmed"`
	CompletedAt    *string  `json:"completed_at,omitempty"` // When distribution was completed
}


// KdcDistribResponse represents a response from the KDC distrib API
type KdcDistribResponse struct {
	Time          time.Time                `json:"time"`
	Error         bool                     `json:"error,omitempty"`
	ErrorMsg      string                   `json:"error_msg,omitempty"`
	Msg           string                   `json:"msg,omitempty"`
	Distributions []string                 `json:"distributions,omitempty"` // For list command (simple format)
	Summaries     []DistributionSummaryInfo `json:"summaries,omitempty"`     // For list command (detailed format)
	State         *DistributionStateInfo    `json:"state,omitempty"`          // For state command
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
			// Get detailed distribution summaries
			summaries, err := kdcDB.GetDistributionSummaries()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Summaries = summaries
				// Also include simple list for backward compatibility
				distIDs := make([]string, len(summaries))
				for i, s := range summaries {
					distIDs[i] = s.DistributionID
				}
				resp.Distributions = distIDs
				resp.Msg = fmt.Sprintf("Found %d distribution(s)", len(summaries))
			}

		case "purge":
			// Delete all completed distributions (or all if force=true)
			var deleted int
			var err error
			if req.Force {
				deleted, err = kdcDB.PurgeAllDistributions()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Purged %d distribution(s) (force mode)", deleted)
				}
			} else {
				deleted, err = kdcDB.PurgeCompletedDistributions()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Purged %d completed distribution(s)", deleted)
				}
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
				key, err := kdcDB.GetDNSSECKeyByID(record.ZoneName, record.KeyID)
				keyState := "unknown"
				if err == nil {
					keyState = string(key.State)
				}
				
				// Get target nodes (nodes that serve this zone via components)
				zoneNodes, _ := kdcDB.GetActiveNodesForZone(record.ZoneName)
				var targetNodes []string
				for _, node := range zoneNodes {
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
					ZoneName:       record.ZoneName,
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
				if err := kdcDB.UpdateKeyState(record.ZoneName, record.KeyID, KeyStateEdgeSigner); err != nil {
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
// APIKdcService handles service management endpoints
func APIKdcService(kdcDB *KdcDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KdcServicePost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcServiceResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "add":
			if req.Service == nil {
				sendJSONError(w, http.StatusBadRequest, "service is required for add command")
				return
			}
			if req.Service.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "service.id is required")
				return
			}
			if err := kdcDB.AddService(req.Service); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Service %s added successfully", req.Service.ID)
			}

		case "list":
			services, err := kdcDB.GetAllServices()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Services = services
			}

		case "get":
			serviceID := req.ServiceID
			if serviceID == "" && req.ServiceName != "" {
				// Look up by name
				services, err := kdcDB.GetAllServices()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					found := false
					for _, s := range services {
						if s.Name == req.ServiceName {
							serviceID = s.ID
							found = true
							break
						}
					}
					if !found {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Service not found: %s", req.ServiceName)
					}
				}
			}
			if serviceID == "" {
				sendJSONError(w, http.StatusBadRequest, "service_id or service_name is required for get command")
				return
			}
			service, err := kdcDB.GetService(serviceID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Service = service
			}

		case "update":
			if req.Service == nil || req.Service.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "service with ID is required for update command")
				return
			}
			if err := kdcDB.UpdateService(req.Service); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Service %s updated successfully", req.Service.ID)
			}

		case "delete":
			serviceID := req.ServiceID
			if serviceID == "" && req.ServiceName != "" {
				// Look up by name
				services, err := kdcDB.GetAllServices()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					found := false
					for _, s := range services {
						if s.Name == req.ServiceName {
							serviceID = s.ID
							found = true
							break
						}
					}
					if !found {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Service not found: %s", req.ServiceName)
					}
				}
			}
			if serviceID == "" {
				sendJSONError(w, http.StatusBadRequest, "service_id or service_name is required for delete command")
				return
			}
			if err := kdcDB.DeleteService(serviceID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Service %s deleted successfully", serviceID)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKdcComponent handles component management endpoints
func APIKdcComponent(kdcDB *KdcDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KdcComponentPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcComponentResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "add":
			if req.Component == nil {
				sendJSONError(w, http.StatusBadRequest, "component is required for add command")
				return
			}
			if req.Component.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "component.id is required")
				return
			}
			if err := kdcDB.AddComponent(req.Component); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Component %s added successfully", req.Component.ID)
			}

		case "list":
			components, err := kdcDB.GetAllComponents()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Components = components
			}

		case "get":
			componentID := req.ComponentID
			if componentID == "" && req.ComponentName != "" {
				// Look up by name
				components, err := kdcDB.GetAllComponents()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					found := false
					for _, c := range components {
						if c.Name == req.ComponentName {
							componentID = c.ID
							found = true
							break
						}
					}
					if !found {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Component not found: %s", req.ComponentName)
					}
				}
			}
			if componentID == "" {
				sendJSONError(w, http.StatusBadRequest, "component_id or component_name is required for get command")
				return
			}
			component, err := kdcDB.GetComponent(componentID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Component = component
			}

		case "update":
			if req.Component == nil || req.Component.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "component with ID is required for update command")
				return
			}
			if err := kdcDB.UpdateComponent(req.Component); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Component %s updated successfully", req.Component.ID)
			}

		case "delete":
			componentID := req.ComponentID
			if componentID == "" && req.ComponentName != "" {
				// Look up by name
				components, err := kdcDB.GetAllComponents()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					found := false
					for _, c := range components {
						if c.Name == req.ComponentName {
							componentID = c.ID
							found = true
							break
						}
					}
					if !found {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Component not found: %s", req.ComponentName)
					}
				}
			}
			if componentID == "" {
				sendJSONError(w, http.StatusBadRequest, "component_id or component_name is required for delete command")
				return
			}
			if err := kdcDB.DeleteComponent(componentID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Component %s deleted successfully", componentID)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKdcServiceComponent handles service-component assignment endpoints
func APIKdcServiceComponent(kdcDB *KdcDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KdcServiceComponentPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcServiceComponentResponse{
			Time: time.Now(),
		}

		// Helper to resolve service ID from name or ID
		resolveServiceID := func() (string, error) {
			if req.ServiceID != "" {
				// Check if it's a valid service ID
				_, err := kdcDB.GetService(req.ServiceID)
				if err != nil {
					return "", fmt.Errorf("service not found: %s", req.ServiceID)
				}
				return req.ServiceID, nil
			}
			if req.ServiceName != "" {
				// First, try to find by ID (in case user passed ID as name)
				_, err := kdcDB.GetService(req.ServiceName)
				if err == nil {
					return req.ServiceName, nil
				}
				// If not found by ID, try to find by name
				services, err := kdcDB.GetAllServices()
				if err != nil {
					return "", err
				}
				for _, s := range services {
					if s.Name == req.ServiceName {
						return s.ID, nil
					}
				}
				return "", fmt.Errorf("service not found: %s", req.ServiceName)
			}
			return "", fmt.Errorf("service_id or service_name is required")
		}

		// Helper to resolve component ID from name or ID
		resolveComponentID := func() (string, error) {
			if req.ComponentID != "" {
				// Check if it's a valid component ID
				_, err := kdcDB.GetComponent(req.ComponentID)
				if err != nil {
					return "", fmt.Errorf("component not found: %s", req.ComponentID)
				}
				return req.ComponentID, nil
			}
			if req.ComponentName != "" {
				// First, try to find by ID (in case user passed ID as name)
				_, err := kdcDB.GetComponent(req.ComponentName)
				if err == nil {
					return req.ComponentName, nil
				}
				// If not found by ID, try to find by name
				components, err := kdcDB.GetAllComponents()
				if err != nil {
					return "", err
				}
				for _, c := range components {
					if c.Name == req.ComponentName {
						return c.ID, nil
					}
				}
				return "", fmt.Errorf("component not found: %s", req.ComponentName)
			}
			return "", fmt.Errorf("component_id or component_name is required")
		}

		switch req.Command {
		case "add":
			serviceID, err := resolveServiceID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				componentID, err := resolveComponentID()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if err := kdcDB.AddServiceComponentAssignment(serviceID, componentID); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Component %s assigned to service %s", componentID, serviceID)
					}
				}
			}

		case "replace":
			serviceID, err := resolveServiceID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				// Resolve old component ID
				oldComponentID := req.OldComponentID
				if oldComponentID == "" && req.OldComponentName != "" {
					// First try by ID
					_, err := kdcDB.GetComponent(req.OldComponentName)
					if err == nil {
						oldComponentID = req.OldComponentName
					} else {
						// Try by name
						components, err := kdcDB.GetAllComponents()
						if err != nil {
							resp.Error = true
							resp.ErrorMsg = err.Error()
						} else {
							found := false
							for _, c := range components {
								if c.Name == req.OldComponentName {
									oldComponentID = c.ID
									found = true
									break
								}
							}
							if !found {
								resp.Error = true
								resp.ErrorMsg = fmt.Sprintf("Old component not found: %s", req.OldComponentName)
							}
						}
					}
				}
				if oldComponentID == "" {
					resp.Error = true
					resp.ErrorMsg = "old_component_id or old_component_name is required for replace command"
				} else {
					// Resolve new component ID
					newComponentID := req.NewComponentID
					if newComponentID == "" && req.NewComponentName != "" {
						// First try by ID
						_, err := kdcDB.GetComponent(req.NewComponentName)
						if err == nil {
							newComponentID = req.NewComponentName
						} else {
							// Try by name
							components, err := kdcDB.GetAllComponents()
							if err != nil {
								resp.Error = true
								resp.ErrorMsg = err.Error()
							} else {
								found := false
								for _, c := range components {
									if c.Name == req.NewComponentName {
										newComponentID = c.ID
										found = true
										break
									}
								}
								if !found {
									resp.Error = true
									resp.ErrorMsg = fmt.Sprintf("New component not found: %s", req.NewComponentName)
								}
							}
						}
					}
					if newComponentID == "" {
						resp.Error = true
						resp.ErrorMsg = "new_component_id or new_component_name is required for replace command"
					} else {
						if err := kdcDB.ReplaceServiceComponentAssignment(serviceID, oldComponentID, newComponentID); err != nil {
							resp.Error = true
							resp.ErrorMsg = err.Error()
						} else {
							resp.Msg = fmt.Sprintf("Component %s replaced with %s in service %s", oldComponentID, newComponentID, serviceID)
						}
					}
				}
			}

		case "delete":
			serviceID, err := resolveServiceID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				componentID, err := resolveComponentID()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if err := kdcDB.RemoveServiceComponentAssignment(serviceID, componentID); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Component %s removed from service %s", componentID, serviceID)
					}
				}
			}

		case "list":
			serviceID, err := resolveServiceID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				componentIDs, err := kdcDB.GetComponentsForService(serviceID)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// Convert to ServiceComponentAssignment structs
					assignments := make([]*ServiceComponentAssignment, 0, len(componentIDs))
					for _, compID := range componentIDs {
						assignments = append(assignments, &ServiceComponentAssignment{
							ServiceID:   serviceID,
							ComponentID: compID,
							Active:      true,
						})
					}
					resp.Assignments = assignments
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

// APIKdcNodeComponent handles node-component assignment endpoints
func APIKdcNodeComponent(kdcDB *KdcDB, kdcConf *KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KdcNodeComponentPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcNodeComponentResponse{
			Time: time.Now(),
		}

		// Helper to resolve node ID from name or ID
		resolveNodeID := func() (string, error) {
			if req.NodeID != "" {
				// Check if it's a valid node ID
				_, err := kdcDB.GetNode(req.NodeID)
				if err != nil {
					return "", fmt.Errorf("node not found: %s", req.NodeID)
				}
				return req.NodeID, nil
			}
			if req.NodeName != "" {
				// First, try to find by ID (in case user passed ID as name)
				_, err := kdcDB.GetNode(req.NodeName)
				if err == nil {
					return req.NodeName, nil
				}
				// If not found by ID, try to find by name
				nodes, err := kdcDB.GetAllNodes()
				if err != nil {
					return "", err
				}
				for _, n := range nodes {
					if n.Name == req.NodeName {
						return n.ID, nil
					}
				}
				return "", fmt.Errorf("node not found: %s", req.NodeName)
			}
			return "", fmt.Errorf("node_id or node_name is required")
		}

		// Helper to resolve component ID from name or ID
		resolveComponentID := func() (string, error) {
			if req.ComponentID != "" {
				// Check if it's a valid component ID
				_, err := kdcDB.GetComponent(req.ComponentID)
				if err != nil {
					return "", fmt.Errorf("component not found: %s", req.ComponentID)
				}
				return req.ComponentID, nil
			}
			if req.ComponentName != "" {
				// First, try to find by ID (in case user passed ID as name)
				_, err := kdcDB.GetComponent(req.ComponentName)
				if err == nil {
					return req.ComponentName, nil
				}
				// If not found by ID, try to find by name
				components, err := kdcDB.GetAllComponents()
				if err != nil {
					return "", err
				}
				for _, c := range components {
					if c.Name == req.ComponentName {
						return c.ID, nil
					}
				}
				return "", fmt.Errorf("component not found: %s", req.ComponentName)
			}
			return "", fmt.Errorf("component_id or component_name is required")
		}

		switch req.Command {
		case "add":
			nodeID, err := resolveNodeID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				componentID, err := resolveComponentID()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if err := kdcDB.AddNodeComponentAssignment(nodeID, componentID, kdcConf); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Component %s assigned to node %s", componentID, nodeID)
					}
				}
			}

		case "delete":
			nodeID, err := resolveNodeID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				componentID, err := resolveComponentID()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if err := kdcDB.RemoveNodeComponentAssignment(nodeID, componentID, kdcConf); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Component %s removed from node %s", componentID, nodeID)
					}
				}
			}

		case "list":
			// If node_id or node_name is provided, list components for that node
			// Otherwise, list all node-component assignments
			if req.NodeID != "" || req.NodeName != "" {
				nodeID, err := resolveNodeID()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					componentIDs, err := kdcDB.GetComponentsForNode(nodeID)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						// Convert to NodeComponentAssignment structs
						assignments := make([]*NodeComponentAssignment, 0, len(componentIDs))
						for _, compID := range componentIDs {
							assignments = append(assignments, &NodeComponentAssignment{
								NodeID:      nodeID,
								ComponentID: compID,
								Active:      true,
							})
						}
						resp.Assignments = assignments
					}
				}
			} else {
				// List all node-component assignments
				assignments, err := kdcDB.GetAllNodeComponentAssignments()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Assignments = assignments
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

// APIKdcServiceTransaction handles service transaction endpoints
func APIKdcServiceTransaction(kdcDB *KdcDB, kdcConf *KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KdcServiceTransactionPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcServiceTransactionResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "start":
			serviceID := req.ServiceID
			if serviceID == "" {
				if req.ServiceName == "" {
					sendJSONError(w, http.StatusBadRequest, "service_id or service_name is required for start command")
					return
				}
				// Look up by name
				services, err := kdcDB.GetAllServices()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(resp)
					return
				}
				found := false
				for _, s := range services {
					if s.Name == req.ServiceName {
						serviceID = s.ID
						found = true
						break
					}
				}
				if !found {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Service not found: %s", req.ServiceName)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(resp)
					return
				}
			}
			txID, err := kdcDB.StartServiceTransaction(serviceID, req.CreatedBy, req.Comment)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.TxID = txID
				resp.Msg = fmt.Sprintf("Transaction %s started for service %s", txID, serviceID)
			}

		case "add-component", "remove-component":
			if req.TxID == "" {
				sendJSONError(w, http.StatusBadRequest, "tx_id is required for component commands")
				return
			}
			componentID := req.ComponentID
			if componentID == "" {
				sendJSONError(w, http.StatusBadRequest, "component_id is required")
				return
			}
			var err error
			if req.Command == "add-component" {
				err = kdcDB.AddComponentToTransaction(req.TxID, componentID)
				if err == nil {
					resp.Msg = fmt.Sprintf("Component %s added to transaction %s", componentID, req.TxID)
				}
			} else {
				err = kdcDB.RemoveComponentFromTransaction(req.TxID, componentID)
				if err == nil {
					resp.Msg = fmt.Sprintf("Component %s removed from transaction %s", componentID, req.TxID)
				}
			}
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "view":
			if req.TxID == "" {
				sendJSONError(w, http.StatusBadRequest, "tx_id is required for view command")
				return
			}
			report, err := kdcDB.ViewServiceTransaction(req.TxID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.DeltaReport = report
				resp.Msg = fmt.Sprintf("Delta report computed for transaction %s", req.TxID)
			}

		case "commit":
			if req.TxID == "" {
				sendJSONError(w, http.StatusBadRequest, "tx_id is required for commit command")
				return
			}
			report, err := kdcDB.CommitServiceTransaction(req.TxID, kdcConf, req.DryRun)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.DeltaReport = report
				if req.DryRun {
					resp.Msg = fmt.Sprintf("Dry-run completed for transaction %s (no changes applied)", req.TxID)
				} else {
					resp.Msg = fmt.Sprintf("Transaction %s committed successfully", req.TxID)
				}
			}

		case "rollback":
			if req.TxID == "" {
				sendJSONError(w, http.StatusBadRequest, "tx_id is required for rollback command")
				return
			}
			if err := kdcDB.RollbackServiceTransaction(req.TxID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Transaction %s rolled back", req.TxID)
			}

		case "get", "status":
			if req.TxID == "" {
				sendJSONError(w, http.StatusBadRequest, "tx_id is required for get/status command")
				return
			}
			tx, err := kdcDB.GetServiceTransaction(req.TxID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Transaction = tx
				resp.Msg = fmt.Sprintf("Transaction %s retrieved", req.TxID)
			}

		case "list":
			transactions, err := kdcDB.ListServiceTransactions(req.StateFilter)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Transactions = transactions
				resp.Msg = fmt.Sprintf("Found %d transaction(s)", len(transactions))
			}

		case "cleanup":
			// Cleanup expired transactions
			transactions, err := kdcDB.ListServiceTransactions("open")
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				cleaned := 0
				now := time.Now()
				for _, tx := range transactions {
					if tx.ExpiresAt.Before(now) {
						// Mark as rolled_back
						if err := kdcDB.RollbackServiceTransaction(tx.ID); err == nil {
							cleaned++
						}
					}
				}
				resp.Msg = fmt.Sprintf("Cleaned up %d expired transaction(s)", cleaned)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

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
	sr.HandleFunc("/kdc/service", APIKdcService(kdcDB)).Methods("POST")
	sr.HandleFunc("/kdc/component", APIKdcComponent(kdcDB)).Methods("POST")
	sr.HandleFunc("/kdc/service-component", APIKdcServiceComponent(kdcDB)).Methods("POST")
	sr.HandleFunc("/kdc/node-component", APIKdcNodeComponent(kdcDB, kdcConf)).Methods("POST")
	if kdcConf != nil {
		sr.HandleFunc("/kdc/service-transaction", APIKdcServiceTransaction(kdcDB, kdcConf)).Methods("POST")
		sr.HandleFunc("/kdc/config", APIKdcConfig(kdcConf, conf)).Methods("POST")
		sr.HandleFunc("/kdc/debug", APIKdcDebug(kdcDB, kdcConf)).Methods("POST")
	}
	
	log.Printf("KDC API routes registered: /api/v1/ping, /api/v1/kdc/zone, /api/v1/kdc/node, /api/v1/kdc/distrib, /api/v1/kdc/service, /api/v1/kdc/component, /api/v1/kdc/service-component, /api/v1/kdc/node-component, /api/v1/kdc/service-transaction, /api/v1/kdc/config, /api/v1/kdc/debug")
}

