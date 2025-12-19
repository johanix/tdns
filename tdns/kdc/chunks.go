/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Chunk preparation and retrieval for JSONMANIFEST and JSONCHUNK queries
 */

package kdc

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns/tdns/core"
	"github.com/johanix/tdns/tdns/hpke"
)

// chunkCache stores prepared chunks in memory (keyed by nodeID+distributionID)
type chunkCache struct {
	mu    sync.RWMutex
	cache map[string]*preparedChunks
}

type preparedChunks struct {
	manifest  *core.JSONMANIFEST
	chunks    []*core.JSONCHUNK
	checksum  string
	timestamp int64
}

var globalChunkCache = &chunkCache{
	cache: make(map[string]*preparedChunks),
}

// prepareChunksForNode prepares chunks for a node's distribution event
// This is called on-demand when MANIFEST is queried
func (kdc *KdcDB) prepareChunksForNode(nodeID, distributionID string, conf *KdcConf) (*preparedChunks, error) {
	cacheKey := fmt.Sprintf("%s:%s", nodeID, distributionID)

	// Check cache first
	globalChunkCache.mu.RLock()
	if cached, ok := globalChunkCache.cache[cacheKey]; ok {
		globalChunkCache.mu.RUnlock()
		log.Printf("KDC: Using cached chunks for node %s, distribution %s", nodeID, distributionID)
		return cached, nil
	}
	globalChunkCache.mu.RUnlock()

	// Not in cache, prepare chunks
	log.Printf("KDC: Preparing chunks for node %s, distribution %s", nodeID, distributionID)

	// Get all distribution records for this distributionID
	records, err := kdc.GetDistributionRecordsForDistributionID(distributionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get distribution records: %v", err)
	}

	// Filter to records for this node (or all nodes if nodeID is empty)
	var nodeRecords []*DistributionRecord
	for _, record := range records {
		if record.NodeID == nodeID || record.NodeID == "" {
			nodeRecords = append(nodeRecords, record)
		}
	}

	if len(nodeRecords) == 0 {
		return nil, fmt.Errorf("no distribution records found for node %s, distribution %s", nodeID, distributionID)
	}

	// For now, use "zones" mode (simpler)
	// Collect zone names from distribution records
	zoneSet := make(map[string]bool)
	for _, record := range nodeRecords {
		zoneSet[record.ZoneID] = true
	}

	zones := make([]string, 0, len(zoneSet))
	for zone := range zoneSet {
		zones = append(zones, zone)
	}

	// Prepare JSON data: zone list
	zoneListJSON, err := json.Marshal(zones)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal zone list: %v", err)
	}

	// Base64 encode
	base64Data := base64.StdEncoding.EncodeToString(zoneListJSON)

	// Calculate checksum
	hash := sha256.Sum256([]byte(base64Data))
	checksum := fmt.Sprintf("sha256:%x", hash)

	// Split into chunks
	chunkSize := conf.GetJsonchunkMaxSize()
	chunks := splitIntoChunks([]byte(base64Data), chunkSize)

	// Create manifest
	manifest := &core.JSONMANIFEST{
		ChunkCount: uint16(len(chunks)),
		ChunkSize:  uint16(chunkSize),
		Checksum:   checksum,
		Metadata: map[string]interface{}{
			"content":         "zonelist",
			"distribution_id": distributionID,
			"node_id":         nodeID,
			"zone_count":      len(zones),
		},
	}

	prepared := &preparedChunks{
		manifest:  manifest,
		chunks:    chunks,
		checksum:  checksum,
		timestamp: 0, // TODO: add timestamp
	}

	// Cache it
	globalChunkCache.mu.Lock()
	globalChunkCache.cache[cacheKey] = prepared
	globalChunkCache.mu.Unlock()

	log.Printf("KDC: Prepared %d chunks for node %s, distribution %s", len(chunks), nodeID, distributionID)
	return prepared, nil
}

// splitIntoChunks splits data into chunks of specified size
func splitIntoChunks(data []byte, chunkSize int) []*core.JSONCHUNK {
	if chunkSize <= 0 {
		chunkSize = 60000 // Default
	}

	var chunks []*core.JSONCHUNK
	total := len(data)
	numChunks := (total + chunkSize - 1) / chunkSize // Ceiling division

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > total {
			end = total
		}

		chunkData := make([]byte, end-start)
		copy(chunkData, data[start:end])

		chunk := &core.JSONCHUNK{
			Sequence: uint16(i),
			Total:    uint16(numChunks),
			Data:     chunkData,
		}
		chunks = append(chunks, chunk)
	}

	return chunks
}

// GetManifestForNode retrieves or prepares manifest for a node's distribution event
func (kdc *KdcDB) GetManifestForNode(nodeID, distributionID string, conf *KdcConf) (*core.JSONMANIFEST, error) {
	prepared, err := kdc.prepareChunksForNode(nodeID, distributionID, conf)
	if err != nil {
		return nil, err
	}
	return prepared.manifest, nil
}

// GetChunkForNode retrieves a specific chunk for a node's distribution event
func (kdc *KdcDB) GetChunkForNode(nodeID, distributionID string, chunkID uint16, conf *KdcConf) (*core.JSONCHUNK, error) {
	prepared, err := kdc.prepareChunksForNode(nodeID, distributionID, conf)
	if err != nil {
		return nil, err
	}

	if int(chunkID) >= len(prepared.chunks) {
		return nil, fmt.Errorf("chunk ID %d out of range (max %d)", chunkID, len(prepared.chunks)-1)
	}

	return prepared.chunks[chunkID], nil
}

// GetDistributionRecordsForDistributionID gets all distribution records for a distribution ID
func (kdc *KdcDB) GetDistributionRecordsForDistributionID(distributionID string) ([]*DistributionRecord, error) {
	rows, err := kdc.DB.Query(
		`SELECT id, zone_id, key_id, node_id, encrypted_key, ephemeral_pub_key, 
			created_at, expires_at, status, distribution_id
			FROM distribution_records 
			WHERE distribution_id = ? 
			ORDER BY created_at DESC`,
		distributionID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution records: %v", err)
	}
	defer rows.Close()

	var records []*DistributionRecord
	for rows.Next() {
		record := &DistributionRecord{}
		var nodeID sql.NullString
		var expiresAt sql.NullTime
		var statusStr string
		if err := rows.Scan(
			&record.ID, &record.ZoneID, &record.KeyID, &nodeID,
			&record.EncryptedKey, &record.EphemeralPubKey, &record.CreatedAt,
			&expiresAt, &statusStr, &record.DistributionID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan distribution record: %v", err)
		}
		if nodeID.Valid {
			record.NodeID = nodeID.String
		}
		if expiresAt.Valid {
			record.ExpiresAt = &expiresAt.Time
		}
		record.Status = hpke.DistributionStatus(statusStr)
		records = append(records, record)
	}
	return records, rows.Err()
}

// DistributionInfo contains distribution ID and the nodes it applies to
type DistributionInfo struct {
	DistributionID string   `json:"distribution_id"`
	Nodes          []string `json:"nodes"`
}

// GetAllDistributionIDs returns all unique distribution IDs from distribution_records and cache
func (kdc *KdcDB) GetAllDistributionIDs() ([]string, error) {
	infos, err := kdc.GetAllDistributionInfos()
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(infos))
	for i, info := range infos {
		ids[i] = info.DistributionID
	}
	return ids, nil
}

// GetAllDistributionInfos returns all distribution IDs with their associated nodes
func (kdc *KdcDB) GetAllDistributionInfos() ([]DistributionInfo, error) {
	// Get distribution IDs and nodes from database
	rows, err := kdc.DB.Query(
		`SELECT DISTINCT distribution_id, node_id FROM distribution_records ORDER BY distribution_id, node_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution IDs: %v", err)
	}
	defer rows.Close()

	distributionMap := make(map[string]map[string]bool) // distID -> set of nodeIDs
	for rows.Next() {
		var distID string
		var nodeID sql.NullString
		if err := rows.Scan(&distID, &nodeID); err != nil {
			return nil, fmt.Errorf("failed to scan distribution ID: %v", err)
		}
		if distributionMap[distID] == nil {
			distributionMap[distID] = make(map[string]bool)
		}
		if nodeID.Valid && nodeID.String != "" {
			distributionMap[distID][nodeID.String] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Also get distribution IDs from cache (for test distributions)
	globalChunkCache.mu.RLock()
	for cacheKey := range globalChunkCache.cache {
		// Cache key format: "nodeID:distributionID"
		parts := strings.Split(cacheKey, ":")
		if len(parts) == 2 {
			nodeID := parts[0]
			distID := parts[1]
			// Skip if distribution ID is empty
			if distID == "" {
				log.Printf("KDC: Warning: found cache entry with empty distribution ID: %s", cacheKey)
				continue
			}
			if distributionMap[distID] == nil {
				distributionMap[distID] = make(map[string]bool)
			}
			distributionMap[distID][nodeID] = true
		} else {
			log.Printf("KDC: Warning: invalid cache key format (expected 'nodeID:distributionID'): %s", cacheKey)
		}
	}
	globalChunkCache.mu.RUnlock()

	// Convert map to sorted slice
	distributionIDs := make([]string, 0, len(distributionMap))
	for distID := range distributionMap {
		distributionIDs = append(distributionIDs, distID)
	}
	sort.Strings(distributionIDs)

	infos := make([]DistributionInfo, 0, len(distributionIDs))
	for _, distID := range distributionIDs {
		// Skip empty distribution IDs
		if distID == "" {
			log.Printf("KDC: Warning: skipping empty distribution ID")
			continue
		}
		nodeSet := distributionMap[distID]
		nodes := make([]string, 0, len(nodeSet))
		for nodeID := range nodeSet {
			nodes = append(nodes, nodeID)
		}
		sort.Strings(nodes)
		infos = append(infos, DistributionInfo{
			DistributionID: distID,
			Nodes:          nodes,
		})
	}
	return infos, nil
}

// DeleteDistribution deletes all distribution records for a given distribution ID
func (kdc *KdcDB) DeleteDistribution(distributionID string) error {
	_, err := kdc.DB.Exec(
		`DELETE FROM distribution_records WHERE distribution_id = ?`,
		distributionID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete distribution records: %v", err)
	}
	return nil
}

// ClearDistributionCache clears the chunk cache for a distribution
func ClearDistributionCache(distributionID string) {
	globalChunkCache.mu.Lock()
	defer globalChunkCache.mu.Unlock()
	
	// Remove all cache entries matching this distribution ID
	for key := range globalChunkCache.cache {
		if strings.HasSuffix(key, ":"+distributionID) {
			delete(globalChunkCache.cache, key)
		}
	}
}

// PrepareTestTextChunks prepares chunks for a test_text distribution
// This creates a persistent distribution record that can be queried by KRS
func (kdc *KdcDB) PrepareTestTextChunks(nodeID, distributionID, testText string, conf *KdcConf) (*preparedChunks, error) {
	cacheKey := fmt.Sprintf("%s:%s", nodeID, distributionID)

	// Check cache first
	globalChunkCache.mu.RLock()
	if cached, ok := globalChunkCache.cache[cacheKey]; ok {
		globalChunkCache.mu.RUnlock()
		log.Printf("KDC: Using cached test_text chunks for node %s, distribution %s", nodeID, distributionID)
		return cached, nil
	}
	globalChunkCache.mu.RUnlock()

	// Not in cache, prepare chunks
	log.Printf("KDC: Preparing test_text chunks for node %s, distribution %s", nodeID, distributionID)

	// Base64 encode the test text
	base64Data := base64.StdEncoding.EncodeToString([]byte(testText))

	// Calculate checksum
	hash := sha256.Sum256([]byte(base64Data))
	checksum := fmt.Sprintf("sha256:%x", hash)

	// Split into chunks
	chunkSize := conf.GetJsonchunkMaxSize()
	chunks := splitIntoChunks([]byte(base64Data), chunkSize)

	// Create manifest
	manifest := &core.JSONMANIFEST{
		ChunkCount: uint16(len(chunks)),
		ChunkSize:  uint16(chunkSize),
		Checksum:   checksum,
		Metadata: map[string]interface{}{
			"content":         "test_text",
			"distribution_id": distributionID,
			"node_id":         nodeID,
			"text_length":     len(testText),
		},
	}

	prepared := &preparedChunks{
		manifest:  manifest,
		chunks:    chunks,
		checksum:  checksum,
		timestamp: 0,
	}

	// Cache it
	globalChunkCache.mu.Lock()
	globalChunkCache.cache[cacheKey] = prepared
	globalChunkCache.mu.Unlock()

	// Create a dummy distribution record in the database so it shows up in listings
	// Use special placeholder values for test distributions
	distRecordID := make([]byte, 16)
	if _, err := rand.Read(distRecordID); err != nil {
		log.Printf("KDC: Warning: Failed to generate distribution record ID: %v", err)
	} else {
		distRecordIDHex := hex.EncodeToString(distRecordID)
		// Create a dummy distribution record with placeholder values
		// We use "test" as zone_id and key_id, but these don't need to exist due to
		// the way we query (we also check cache)
		distRecord := &DistributionRecord{
			ID:             distRecordIDHex,
			ZoneID:         "test", // Placeholder zone for test distributions
			KeyID:          "test", // Placeholder key for test distributions
			NodeID:         nodeID,
			EncryptedKey:   []byte("test"), // Dummy data
			EphemeralPubKey: []byte("test"), // Dummy data
			CreatedAt:      time.Now(),
			ExpiresAt:      nil,
			Status:         hpke.DistributionStatusPending,
			DistributionID: distributionID,
		}

		// Try to insert, but don't fail if it doesn't work (e.g., foreign key constraints)
		if err := kdc.AddDistributionRecord(distRecord); err != nil {
			log.Printf("KDC: Warning: Failed to store test distribution record in database (this is OK for test distributions): %v", err)
			// Continue anyway - the distribution is cached and will work
		}
	}

	log.Printf("KDC: Prepared %d test_text chunks for node %s, distribution %s", len(chunks), nodeID, distributionID)
	return prepared, nil
}

