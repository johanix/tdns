/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Blast zone calculation for node compromise scenarios
 */

package kdc

import (
	"fmt"
	"log"
)

// BlastZoneResult represents the result of calculating the blast zone for a compromised node
type BlastZoneResult struct {
	NodeID           string   `json:"node_id"`
	AffectedZones    []string `json:"affected_zones"`    // All zones in components served by this node
	EdgesignedZones []string `json:"edgesigned_zones"`  // Zones that need immediate ZSK rollover
	Components       []string `json:"components"`        // Components served by this node
}

// CalculateBlastZone calculates which zones are affected when a node is compromised
// Returns zones that need immediate ZSK rollover (only edgesigned zones)
func (kdc *KdcDB) CalculateBlastZone(nodeID string) (*BlastZoneResult, error) {
	result := &BlastZoneResult{
		NodeID:           nodeID,
		AffectedZones:    []string{},
		EdgesignedZones: []string{},
		Components:       []string{},
	}

	// Step 1: Find all components served by this node
	components, err := kdc.GetComponentsForNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get components for node %s: %v", nodeID, err)
	}
	result.Components = components

	if len(components) == 0 {
		log.Printf("KDC: Node %s serves no components, no blast zone", nodeID)
		return result, nil
	}

	// Step 2: For each component, find all zones served via services
	// Zones are assigned to services, and components belong to services
	// So we need to find all services that have these components, then all zones in those services
	zoneSet := make(map[string]bool)
	
	// Get all services that have any of these components
	serviceSet := make(map[string]bool)
	for _, componentID := range components {
		// Query for services that have this component
		rows, err := kdc.DB.Query(
			"SELECT DISTINCT service_id FROM service_component_assignments WHERE component_id = ? AND active = 1",
			componentID,
		)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get services for component %s: %v", componentID, err)
			continue
		}
		for rows.Next() {
			var serviceID string
			if err := rows.Scan(&serviceID); err == nil {
				serviceSet[serviceID] = true
			}
		}
		rows.Close()
	}
	
	// Get all zones from these services
	for serviceID := range serviceSet {
		rows, err := kdc.DB.Query(
			"SELECT name FROM zones WHERE service_id = ? AND active = 1",
			serviceID,
		)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get zones for service %s: %v", serviceID, err)
			continue
		}
		for rows.Next() {
			var zoneName string
			if err := rows.Scan(&zoneName); err == nil {
				zoneSet[zoneName] = true
			}
		}
		rows.Close()
	}

	// Convert set to slice
	for zoneName := range zoneSet {
		result.AffectedZones = append(result.AffectedZones, zoneName)
	}

	// Step 3: Filter to only edgesign_* zones (these need immediate rollover)
	// Note: edgesign_full also requires KSK rollover, but we track all edgesign_* zones here
	for _, zoneName := range result.AffectedZones {
		signingMode, err := kdc.GetZoneSigningMode(zoneName)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get signing mode for zone %s: %v", zoneName, err)
			continue
		}
		if signingMode == ZoneSigningModeEdgesignDyn || signingMode == ZoneSigningModeEdgesignZsk || signingMode == ZoneSigningModeEdgesignFull {
			result.EdgesignedZones = append(result.EdgesignedZones, zoneName)
		}
	}

	log.Printf("KDC: Blast zone for node %s: %d total zones, %d edgesign_* zones requiring rollover",
		nodeID, len(result.AffectedZones), len(result.EdgesignedZones))

	return result, nil
}

// GetComponentsForNode returns all component IDs served by a node
func (kdc *KdcDB) GetComponentsForNode(nodeID string) ([]string, error) {
	rows, err := kdc.DB.Query(
		`SELECT component_id FROM node_component_assignments 
		 WHERE node_id = ? AND active = 1`,
		nodeID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query node components: %v", err)
	}
	defer rows.Close()

	var components []string
	for rows.Next() {
		var componentID string
		if err := rows.Scan(&componentID); err != nil {
			return nil, fmt.Errorf("failed to scan component ID: %v", err)
		}
		components = append(components, componentID)
	}

	return components, rows.Err()
}

// GetZonesForComponent returns all zone names served by a component
// Zones are related to services, and components are derived from services
func (kdc *KdcDB) GetZonesForComponent(componentID string) ([]string, error) {
	rows, err := kdc.DB.Query(
		`SELECT DISTINCT z.name
		 FROM zones z
		 JOIN service_component_assignments sc ON sc.service_id = z.service_id
		 WHERE sc.component_id = ?
		   AND sc.active = 1
		   AND z.active = 1
		   AND z.service_id IS NOT NULL`,
		componentID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query component zones: %v", err)
	}
	defer rows.Close()

	var zones []string
	for rows.Next() {
		var zoneName string
		if err := rows.Scan(&zoneName); err != nil {
			return nil, fmt.Errorf("failed to scan zone name: %v", err)
		}
		zones = append(zones, zoneName)
	}

	return zones, rows.Err()
}

// GetNodesForComponent returns all node IDs that serve a component
func (kdc *KdcDB) GetNodesForComponent(componentID string) ([]string, error) {
	rows, err := kdc.DB.Query(
		`SELECT node_id FROM node_component_assignments 
		 WHERE component_id = ? AND active = 1`,
		componentID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query component nodes: %v", err)
	}
	defer rows.Close()

	var nodes []string
	for rows.Next() {
		var nodeID string
		if err := rows.Scan(&nodeID); err != nil {
			return nil, fmt.Errorf("failed to scan node ID: %v", err)
		}
		nodes = append(nodes, nodeID)
	}

	return nodes, rows.Err()
}

// GetNodesForZone returns all node IDs that serve a zone (via service → components → nodes)
// Zones are related to services, and components are derived from the service
// This replaces the old "all nodes serve all zones" model
func (kdc *KdcDB) GetNodesForZone(zoneName string) ([]string, error) {
	// Step 1: Get the zone's service
	zone, err := kdc.GetZone(zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone: %v", err)
	}
	
	if zone.ServiceID == "" {
		// Zone has no service assignment, return empty list
		return []string{}, nil
	}
	
	// Step 2: Get all components for the service
	componentIDs, err := kdc.GetComponentsForService(zone.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get components for service: %v", err)
	}
	
	if len(componentIDs) == 0 {
		// Service has no components, return empty list
		return []string{}, nil
	}
	
	// Step 3: For each component, find all nodes that serve it
	nodeSet := make(map[string]bool)
	for _, componentID := range componentIDs {
		nodes, err := kdc.GetNodesForComponent(componentID)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get nodes for component %s: %v", componentID, err)
			continue
		}
		for _, nodeID := range nodes {
			nodeSet[nodeID] = true
		}
	}
	
	// Convert set to slice
	var nodes []string
	for nodeID := range nodeSet {
		nodes = append(nodes, nodeID)
	}
	
	return nodes, nil
}

// GetActiveNodesForZone returns all active node objects that serve a zone (via components)
// This replaces the old "all nodes serve all zones" model
func (kdc *KdcDB) GetActiveNodesForZone(zoneName string) ([]*Node, error) {
	// Get node IDs for this zone
	nodeIDs, err := kdc.GetNodesForZone(zoneName)
	if err != nil {
		return nil, err
	}

	if len(nodeIDs) == 0 {
		return []*Node{}, nil
	}

	// Get full node objects and filter to only active ones
	var nodes []*Node
	for _, nodeID := range nodeIDs {
		node, err := kdc.GetNode(nodeID)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get node %s: %v", nodeID, err)
			continue
		}
		// Only include online nodes
		if node.State == NodeStateOnline {
			nodes = append(nodes, node)
		}
	}

	return nodes, nil
}

