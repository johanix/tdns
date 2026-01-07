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

	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/johanix/tdns/v0.x/tdns/hpke"
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

	// Determine content type: use "encrypted_keys" if we have keys, otherwise "zonelist"
	// For now, we'll use "encrypted_keys" mode which sends the encrypted keys directly
	contentType := "encrypted_keys"
	
	var base64Data []byte
	var zoneCount int
	var keyCount int

	if contentType == "encrypted_keys" {
		// Prepare JSON structure with encrypted keys
		// Format: array of objects, each containing zone_name, key_id, encrypted_key, ephemeral_pub_key
		type EncryptedKeyEntry struct {
			ZoneName       string `json:"zone_name"`
			KeyID          string `json:"key_id"`
			KeyType        string `json:"key_type,omitempty"`
			Algorithm      uint8  `json:"algorithm,omitempty"`
			Flags          uint16 `json:"flags,omitempty"`
			PublicKey      string `json:"public_key,omitempty"`
			EncryptedKey   string `json:"encrypted_key"`   // base64-encoded
			EphemeralPubKey string `json:"ephemeral_pub_key"` // base64-encoded (duplicate, for verification)
		}

		entries := make([]EncryptedKeyEntry, 0, len(nodeRecords))
		zoneSet := make(map[string]bool)
		
		for _, record := range nodeRecords {
			// Get the key details to include key_id
			key, err := kdc.GetDNSSECKeyByID(record.ZoneName, record.KeyID)
			if err != nil {
				log.Printf("KDC: Warning: Failed to get key %s for zone %s: %v", record.KeyID, record.ZoneName, err)
				continue
			}

			entry := EncryptedKeyEntry{
				ZoneName:       record.ZoneName,
				KeyID:          record.KeyID,
				KeyType:        string(key.KeyType),
				Algorithm:      key.Algorithm,
				Flags:          key.Flags,
				PublicKey:      key.PublicKey,
				EncryptedKey:   base64.StdEncoding.EncodeToString(record.EncryptedKey),
				EphemeralPubKey: base64.StdEncoding.EncodeToString(record.EphemeralPubKey),
			}
			entries = append(entries, entry)
			zoneSet[record.ZoneName] = true
		}

		keyCount = len(entries)
		zoneCount = len(zoneSet)

		if keyCount == 0 {
			return nil, fmt.Errorf("no valid keys found for node %s, distribution %s", nodeID, distributionID)
		}

		// Marshal to JSON
		keysJSON, err := json.Marshal(entries)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal encrypted keys JSON: %v", err)
		}

		// Base64 encode the JSON
		base64Data = []byte(base64.StdEncoding.EncodeToString(keysJSON))
		log.Printf("KDC: Prepared encrypted_keys: %d keys for %d zones, JSON size: %d bytes, base64 size: %d bytes", 
			keyCount, zoneCount, len(keysJSON), len(base64Data))
	} else {
		// "zonelist" mode (fallback)
		// Collect zone names from distribution records
		zoneSet := make(map[string]bool)
		for _, record := range nodeRecords {
			zoneSet[record.ZoneName] = true
		}

		zones := make([]string, 0, len(zoneSet))
		for zone := range zoneSet {
			zones = append(zones, zone)
		}

		zoneCount = len(zones)

		// Prepare JSON data: zone list
		zoneListJSON, err := json.Marshal(zones)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal zone list: %v", err)
		}

		// Base64 encode
		base64Data = []byte(base64.StdEncoding.EncodeToString(zoneListJSON))
	}

	// Calculate checksum
	hash := sha256.Sum256([]byte(base64Data))
	checksum := fmt.Sprintf("sha256:%x", hash)

	// Create manifest
	now := time.Now()
	metadata := map[string]interface{}{
		"content":         contentType,
		"distribution_id": distributionID,
		"node_id":         nodeID,
		"zone_count":      zoneCount,
		"timestamp":       now.Unix(), // Unix timestamp for replay protection (validated by KRS)
	}
	if contentType == "encrypted_keys" {
		metadata["key_count"] = keyCount
	}
	// Add retire_time from config if available
	if conf != nil && conf.RetireTime > 0 {
		metadata["retire_time"] = conf.RetireTime.String() // Convert duration to string (e.g., "168h0m0s")
	}
	// Add distribution_ttl from config if available (for KRS validation)
	if conf != nil && conf.GetDistributionTTL() > 0 {
		metadata["distribution_ttl"] = conf.GetDistributionTTL().String() // Convert duration to string (e.g., "5m0s")
	}

	// Determine if payload should be included inline
	// DNS UDP message limit is ~1232 bytes with EDNS0, but we need to account for:
	// - DNS headers (~12 bytes)
	// - QNAME length (variable, ~50-100 bytes typical)
	// - JSONMANIFEST structure overhead (~200-300 bytes for metadata, field names, etc.)
	// - JSON encoding overhead (base64 string encoding adds ~33% overhead)
	// So we use a conservative threshold of ~500 bytes for base64Data to ensure it fits
	const inlinePayloadThreshold = 500
	payloadSize := len(base64Data)
	
	// Create a test manifest to check actual size
	testManifest := &core.JSONMANIFEST{
		ChunkCount: 0,
		ChunkSize:  0,
		Checksum:   checksum,
		Metadata:   metadata,
		Payload:    base64Data, // Test with actual payload
	}
	testSize := testManifest.Len()
	
	// Check if the manifest fits in DNS message (accounting for headers and QNAME)
	// Estimate: DNS headers (~12) + QNAME (~100) + RR header (~10) + manifest data
	const estimatedDNSOverhead = 150
	estimatedTotalSize := estimatedDNSOverhead + testSize
	includeInline := payloadSize <= inlinePayloadThreshold && estimatedTotalSize < 1200

	var chunks []*core.JSONCHUNK
	var chunkSize uint16
	var chunkCount uint16

	if includeInline {
		// Payload fits inline, include it directly in manifest
		chunkCount = 0
		chunkSize = 0
		log.Printf("KDC: Payload size %d bytes (base64), manifest size %d bytes, estimated total %d bytes - including inline in JSONMANIFEST", 
			payloadSize, testSize, estimatedTotalSize)
	} else {
		// Payload is too large, split into chunks
		chunkSizeInt := conf.GetJsonchunkMaxSize()
		chunks = splitIntoChunks([]byte(base64Data), chunkSizeInt)
		chunkCount = uint16(len(chunks))
		chunkSize = uint16(chunkSizeInt)
		log.Printf("KDC: Payload size %d bytes (base64), manifest size %d bytes, estimated total %d bytes - exceeds inline threshold, splitting into %d chunks", 
			payloadSize, testSize, estimatedTotalSize, chunkCount)
	}

	manifest := &core.JSONMANIFEST{
		ChunkCount: chunkCount,
		ChunkSize:  chunkSize,
		Checksum:   checksum,
		Metadata:   metadata,
	}

	// Include payload inline if it fits
	if includeInline {
		manifest.Payload = make([]byte, len(base64Data))
		copy(manifest.Payload, base64Data)
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
		`SELECT id, zone_name, key_id, node_id, encrypted_key, ephemeral_pub_key, 
			created_at, expires_at, status, distribution_id, completed_at
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
		var completedAt sql.NullTime
		var statusStr string
		if err := rows.Scan(
			&record.ID, &record.ZoneName, &record.KeyID, &nodeID,
			&record.EncryptedKey, &record.EphemeralPubKey, &record.CreatedAt,
			&expiresAt, &statusStr, &record.DistributionID, &completedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan distribution record: %v", err)
		}
		if nodeID.Valid {
			record.NodeID = nodeID.String
		}
		if expiresAt.Valid {
			record.ExpiresAt = &expiresAt.Time
		}
		if completedAt.Valid {
			record.CompletedAt = &completedAt.Time
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

// PrepareTextChunks prepares chunks for a text distribution (clear_text or encrypted_text)
// This creates a persistent distribution record that can be queried by KRS
// contentType should be "clear_text" or "encrypted_text"
func (kdc *KdcDB) PrepareTextChunks(nodeID, distributionID, text string, contentType string, conf *KdcConf) (*preparedChunks, error) {
	cacheKey := fmt.Sprintf("%s:%s", nodeID, distributionID)

	// Check cache first
	globalChunkCache.mu.RLock()
	if cached, ok := globalChunkCache.cache[cacheKey]; ok {
		globalChunkCache.mu.RUnlock()
		log.Printf("KDC: Using cached %s chunks for node %s, distribution %s", contentType, nodeID, distributionID)
		return cached, nil
	}
	globalChunkCache.mu.RUnlock()

	// Not in cache, prepare chunks
	log.Printf("KDC: Preparing %s chunks for node %s, distribution %s", contentType, nodeID, distributionID)

	var dataToChunk []byte
	// var err error

	if contentType == "encrypted_text" {
		// Get node's public key
		node, err := kdc.GetNode(nodeID)
		if err != nil {
			return nil, fmt.Errorf("failed to get node %s: %v", nodeID, err)
		}
		if len(node.LongTermPubKey) != 32 {
			return nil, fmt.Errorf("node %s has invalid public key length: %d (expected 32)", nodeID, len(node.LongTermPubKey))
		}

		// Encrypt the text using HPKE
		ciphertext, ephemeralPub, err := hpke.Encrypt(node.LongTermPubKey, nil, []byte(text))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt text: %v", err)
		}

		// Combine ephemeral public key and ciphertext for transport
		// Format: <ephemeral_pub_key (32 bytes)><ciphertext>
		encryptedData := append(ephemeralPub, ciphertext...)

		// Base64 encode the encrypted data
		dataToChunk = []byte(base64.StdEncoding.EncodeToString(encryptedData))
		log.Printf("KDC: Encrypted text (%d bytes) -> encrypted data (%d bytes) -> base64 (%d bytes)", len(text), len(encryptedData), len(dataToChunk))
	} else {
		// clear_text: just base64 encode the text
		dataToChunk = []byte(base64.StdEncoding.EncodeToString([]byte(text)))
	}

	// Calculate checksum
	hash := sha256.Sum256(dataToChunk)
	checksum := fmt.Sprintf("sha256:%x", hash)

	// Determine if payload should be included inline
	const inlinePayloadThreshold = 500
	payloadSize := len(dataToChunk)
	
	// Create a test manifest to check actual size
	testManifest := &core.JSONMANIFEST{
		ChunkCount: 0,
		ChunkSize:  0,
		Checksum:   checksum,
		Metadata: map[string]interface{}{
			"content":         contentType,
			"distribution_id": distributionID,
			"node_id":         nodeID,
			"text_length":     len(text),
		},
		Payload: dataToChunk, // Test with actual payload
	}
	testSize := testManifest.Len()
	
	// Check if the manifest fits in DNS message
	const estimatedDNSOverhead = 150
	estimatedTotalSize := estimatedDNSOverhead + testSize
	includeInline := payloadSize <= inlinePayloadThreshold && estimatedTotalSize < 1200

	var chunks []*core.JSONCHUNK
	var chunkSize uint16
	var chunkCount uint16

	if includeInline {
		// Payload fits inline, include it directly in manifest
		chunkCount = 0
		chunkSize = 0
		log.Printf("KDC: Test text payload size %d bytes, manifest size %d bytes, estimated total %d bytes - including inline in JSONMANIFEST", 
			payloadSize, testSize, estimatedTotalSize)
	} else {
		// Payload is too large, split into chunks
		chunkSizeInt := conf.GetJsonchunkMaxSize()
		chunks = splitIntoChunks(dataToChunk, chunkSizeInt)
		chunkCount = uint16(len(chunks))
		chunkSize = uint16(chunkSizeInt)
		log.Printf("KDC: Test text payload size %d bytes, manifest size %d bytes, estimated total %d bytes - exceeds inline threshold, splitting into %d chunks", 
			payloadSize, testSize, estimatedTotalSize, chunkCount)
	}

	// Create manifest
	manifest := &core.JSONMANIFEST{
		ChunkCount: chunkCount,
		ChunkSize:  chunkSize,
		Checksum:   checksum,
		Metadata: map[string]interface{}{
			"content":         contentType,
			"distribution_id": distributionID,
			"node_id":         nodeID,
			"text_length":     len(text),
		},
	}

	// Include payload inline if it fits
	if includeInline {
		manifest.Payload = make([]byte, len(dataToChunk))
		copy(manifest.Payload, dataToChunk)
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
			ZoneName:       "test", // Placeholder zone for test distributions
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

	log.Printf("KDC: Prepared %d %s chunks for node %s, distribution %s", len(chunks), contentType, nodeID, distributionID)
	return prepared, nil
}

// PrepareTestTextChunks is a convenience wrapper for backward compatibility
// It calls PrepareTextChunks with contentType="clear_text"
func (kdc *KdcDB) PrepareTestTextChunks(nodeID, distributionID, testText string, conf *KdcConf) (*preparedChunks, error) {
	return kdc.PrepareTextChunks(nodeID, distributionID, testText, "clear_text", conf)
}

