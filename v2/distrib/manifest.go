/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Manifest operations for CHUNK-based distribution framework.
 * Provides helpers for creating, estimating, and splitting distribution payloads.
 *
 * Note: Core CHUNK operations (CreateCHUNKManifest, ExtractManifestData,
 * CalculateCHUNKHMAC, VerifyCHUNKHMAC) are in tdns/v2/core/chunk_utilities.go.
 * This package provides distribution-specific helpers that build on core functions.
 */

package distrib

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/johanix/tdns/v2/core"
)

// ManifestData is re-exported from core for convenience.
// This is the JSON structure stored in a CHUNK manifest's Data field.
type ManifestData = core.ManifestData

// CreateCHUNKManifest is re-exported from core for convenience.
// Creates a CHUNK manifest record from manifest data.
func CreateCHUNKManifest(manifestData *ManifestData, format uint8) (*core.CHUNK, error) {
	return core.CreateCHUNKManifest(manifestData, format)
}

// ExtractManifestData is re-exported from core for convenience.
// Extracts ManifestData from a CHUNK manifest record.
func ExtractManifestData(chunk *core.CHUNK) (*ManifestData, error) {
	return core.ExtractManifestData(chunk)
}

// CalculateCHUNKHMAC is re-exported from core for convenience.
// Calculates HMAC-SHA256 for a CHUNK manifest record.
func CalculateCHUNKHMAC(chunk *core.CHUNK, hmacKey []byte) error {
	return core.CalculateCHUNKHMAC(chunk, hmacKey)
}

// VerifyCHUNKHMAC is re-exported from core for convenience.
// Verifies the HMAC-SHA256 for a CHUNK manifest record.
func VerifyCHUNKHMAC(chunk *core.CHUNK, hmacKey []byte) (bool, error) {
	return core.VerifyCHUNKHMAC(chunk, hmacKey)
}

// IsJWTManifest is re-exported from core for convenience.
// Checks if a CHUNK manifest uses JWT format.
func IsJWTManifest(chunk *core.CHUNK) bool {
	return core.IsJWTManifest(chunk)
}

// IsJSONManifest is re-exported from core for convenience.
// Checks if a CHUNK manifest uses JSON format.
func IsJSONManifest(chunk *core.CHUNK) bool {
	return core.IsJSONManifest(chunk)
}

// Format constants re-exported from core for convenience.
const (
	FormatJSON = core.FormatJSON
	FormatJWT  = core.FormatJWT
)

// CreateManifestMetadata creates base metadata for a distribution manifest.
// This is used to populate the Metadata field of ManifestData.
//
// Parameters:
//   - contentType: Type of content (e.g., "key_operations", "node_operations")
//   - distributionID: Unique identifier for this distribution
//   - receiverID: Identifier of the intended recipient (e.g., node ID)
//   - extraFields: Additional metadata fields to include
//
// Returns:
//   - A map containing the manifest metadata with timestamp for replay protection
func CreateManifestMetadata(contentType, distributionID, receiverID string, extraFields map[string]interface{}) map[string]interface{} {
	metadata := map[string]interface{}{
		"content":         contentType,
		"distribution_id": distributionID,
		"receiver_id":     receiverID,
		"timestamp":       time.Now().Unix(), // Unix timestamp for replay protection
	}

	// Add any extra fields
	for k, v := range extraFields {
		metadata[k] = v
	}

	return metadata
}

// ShouldIncludePayloadInline determines if a payload should be included inline in the manifest.
// DEPRECATED: This function uses hardcoded UDP-era thresholds (500/1200 bytes).
// For TCP transport, use ShouldIncludePayloadInlineWithLimit instead.
//
// Parameters:
//   - payloadSize: Size of the payload in bytes
//   - estimatedTotalSize: Estimated total manifest size including payload
//
// Returns:
//   - true if payload should be included inline, false if it should be chunked
func ShouldIncludePayloadInline(payloadSize, estimatedTotalSize int) bool {
	const inlinePayloadThreshold = 500 // Max payload size for inline (legacy UDP limit)
	const maxTotalSize = 1200          // Max total manifest size (legacy UDP limit)

	return payloadSize <= inlinePayloadThreshold && estimatedTotalSize < maxTotalSize
}

// ShouldIncludePayloadInlineWithLimit determines if a payload should be included inline in the manifest.
// Returns true if the estimated manifest size (including payload) fits within the maxSize limit.
//
// For TCP transport (which TDNS uses), maxSize can be up to 64KB.
// The maxSize should come from configuration (e.g., KdcConf.GetChunkMaxSize()).
//
// Parameters:
//   - estimatedTotalSize: Estimated total manifest size including payload
//   - maxSize: Maximum allowed manifest size (from config, typically up to 64KB for TCP)
//
// Returns:
//   - true if payload should be included inline, false if it should be chunked
func ShouldIncludePayloadInlineWithLimit(estimatedTotalSize, maxSize int) bool {
	return estimatedTotalSize <= maxSize
}

// EstimateManifestSize estimates the size of a CHUNK manifest with given metadata and payload.
// Uses a placeholder HMAC for size estimation.
//
// The size calculation accounts for:
//   - Format: 1 byte
//   - HMACLen: 2 bytes
//   - HMAC: 32 bytes (SHA-256)
//   - Sequence: 2 bytes
//   - Total: 2 bytes
//   - DataLength: 2 bytes
//   - Data: len(manifestJSON) bytes
//
// Parameters:
//   - metadata: The manifest metadata map
//   - payload: The optional inline payload
//
// Returns:
//   - Estimated size in bytes
func EstimateManifestSize(metadata map[string]interface{}, payload []byte) int {
	// Create test manifest data
	testManifestData := &ManifestData{
		ChunkCount: 0,
		ChunkSize:  0,
		Metadata:   metadata,
		Payload:    payload,
	}

	// Marshal to JSON to get size
	manifestJSON, err := json.Marshal(testManifestData)
	if err != nil {
		// Fallback estimate if marshaling fails
		return 500
	}

	// CHUNK manifest size = Format (1) + HMACLen (2) + HMAC (32) + Sequence (2) + Total (2) + DataLength (2) + Data
	return 1 + 2 + 32 + 2 + 2 + 2 + len(manifestJSON)
}

// SplitIntoCHUNKs splits data into CHUNK records of specified size.
// Returns CHUNK records with 1-based sequence numbers (1, 2, 3, ..., total).
//
// Parameters:
//   - data: The data to split into chunks
//   - chunkSize: Maximum size of each chunk (default 60000 if <= 0)
//   - format: The CHUNK format byte (typically core.FormatJSON)
//
// Returns:
//   - Slice of CHUNK records, or nil if:
//     - Data would result in more than 65535 chunks
//     - Any chunk would exceed 65535 bytes
func SplitIntoCHUNKs(data []byte, chunkSize int, format uint8) []*core.CHUNK {
	if chunkSize <= 0 {
		chunkSize = 60000 // Default
	}

	var chunks []*core.CHUNK
	total := len(data)
	numChunks := (total + chunkSize - 1) / chunkSize // Ceiling division

	// Check for integer overflow before converting to uint16
	if numChunks > math.MaxUint16 {
		return nil // Return nil if overflow would occur
	}
	numChunksUint16 := uint16(numChunks)

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > total {
			end = total
		}

		chunkData := make([]byte, end-start)
		copy(chunkData, data[start:end])

		// Check for chunk data length overflow before converting to uint16
		if len(chunkData) > math.MaxUint16 {
			return nil // Return nil if overflow would occur
		}

		chunk := &core.CHUNK{
			Format:     format,
			HMACLen:    0, // No HMAC for data chunks
			HMAC:       nil,
			Sequence:   uint16(i + 1), // 1-based: 1, 2, 3, ..., N
			Total:      numChunksUint16,
			DataLength: uint16(len(chunkData)),
			Data:       chunkData,
		}
		chunks = append(chunks, chunk)
	}

	return chunks
}

// ReassembleCHUNKs reassembles CHUNK chunks into complete data.
// Note: CHUNK uses 1-based sequence numbers (1, 2, 3, ..., total).
//
// Parameters:
//   - chunks: Slice of CHUNK records to reassemble (must have same Total value)
//
// Returns:
//   - The reassembled data bytes, or error if:
//     - No chunks provided
//     - Total is 0 or exceeds 65535
//     - Chunk count doesn't match Total
//     - Missing sequence numbers
//     - Sequence numbers out of range
func ReassembleCHUNKs(chunks []*core.CHUNK) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks to reassemble")
	}

	// Get total from first chunk (all chunks should have same Total)
	total := int(chunks[0].Total)
	if total == 0 {
		return nil, fmt.Errorf("invalid chunk total: 0 (expected > 0 for data chunks)")
	}

	// Check for integer overflow before converting to uint16
	if total > math.MaxUint16 {
		return nil, fmt.Errorf("chunk total too large: %d (max: %d)", total, math.MaxUint16)
	}
	totalUint16 := uint16(total)

	if len(chunks) != total {
		return nil, fmt.Errorf("chunk count mismatch: expected %d, got %d", total, len(chunks))
	}

	// Sort chunks by sequence number
	// Note: CHUNK uses 1-based sequence numbers (1, 2, 3, ..., total)
	chunkMap := make(map[uint16]*core.CHUNK)
	for _, chunk := range chunks {
		// Validate sequence is in range [1, total] (1-based)
		if chunk.Sequence < 1 || int(chunk.Sequence) > total {
			return nil, fmt.Errorf("chunk sequence %d out of range (expected 1-%d)", chunk.Sequence, total)
		}
		if chunk.Total != totalUint16 {
			return nil, fmt.Errorf("chunk total mismatch: expected %d, got %d", total, chunk.Total)
		}
		chunkMap[chunk.Sequence] = chunk
	}

	// Reassemble in order (1-based: 1, 2, 3, ..., total)
	reassembled := make([]byte, 0)
	for i := uint16(1); i <= totalUint16; i++ {
		chunk, ok := chunkMap[i]
		if !ok {
			return nil, fmt.Errorf("missing chunk with sequence %d", i)
		}
		reassembled = append(reassembled, chunk.Data...)
	}

	return reassembled, nil
}

// PrepareDistributionChunks prepares a complete set of CHUNK records for a distribution.
// This is a convenience function that combines manifest creation and data chunking.
//
// Parameters:
//   - payload: The data to distribute (will be split if too large for inline)
//   - contentType: Type of content for metadata
//   - distributionID: Unique distribution identifier
//   - receiverID: Intended recipient identifier
//   - hmacKey: Key for HMAC calculation (32 bytes)
//   - chunkSize: Maximum chunk size (0 for default)
//   - extraMetadata: Additional metadata fields
//
// Returns:
//   - Slice of CHUNK records (manifest at index 0, data chunks follow if needed)
//   - Error if preparation fails
func PrepareDistributionChunks(payload []byte, contentType, distributionID, receiverID string, hmacKey []byte, chunkSize int, extraMetadata map[string]interface{}) ([]*core.CHUNK, error) {
	// Create metadata
	metadata := CreateManifestMetadata(contentType, distributionID, receiverID, extraMetadata)

	// Use default chunk size if not specified
	if chunkSize <= 0 {
		chunkSize = 60000 // Default for TCP transport
	}

	// Estimate manifest size to determine if payload should be inline
	testSize := EstimateManifestSize(metadata, payload)
	includeInline := ShouldIncludePayloadInlineWithLimit(testSize, chunkSize)

	var dataChunks []*core.CHUNK
	var chunkCount uint16
	var manifestChunkSize uint16

	if includeInline {
		// Payload fits inline
		chunkCount = 0
		manifestChunkSize = 0
	} else {
		// Split payload into chunks
		if chunkSize <= 0 {
			chunkSize = 60000 // Default
		}
		dataChunks = SplitIntoCHUNKs(payload, chunkSize, core.FormatJSON)
		if dataChunks == nil && len(payload) > 0 {
			return nil, fmt.Errorf("failed to split payload into chunks: overflow detected")
		}
		if len(dataChunks) > math.MaxUint16 {
			return nil, fmt.Errorf("too many chunks: %d (max: %d)", len(dataChunks), math.MaxUint16)
		}
		chunkCount = uint16(len(dataChunks))
		if chunkSize > math.MaxUint16 {
			return nil, fmt.Errorf("chunk size too large: %d (max: %d)", chunkSize, math.MaxUint16)
		}
		manifestChunkSize = uint16(chunkSize)
	}

	// Create manifest data
	manifestData := &ManifestData{
		ChunkCount: chunkCount,
		ChunkSize:  manifestChunkSize,
		Metadata:   metadata,
	}

	// Include payload inline if it fits
	if includeInline {
		manifestData.Payload = make([]byte, len(payload))
		copy(manifestData.Payload, payload)
	}

	// Create manifest CHUNK
	manifestCHUNK, err := CreateCHUNKManifest(manifestData, core.FormatJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create CHUNK manifest: %w", err)
	}

	// Calculate HMAC if key is provided
	if len(hmacKey) == 32 {
		if err := CalculateCHUNKHMAC(manifestCHUNK, hmacKey); err != nil {
			return nil, fmt.Errorf("failed to calculate HMAC: %w", err)
		}
	}

	// Combine manifest and data chunks
	allChunks := make([]*core.CHUNK, 0, 1+len(dataChunks))
	allChunks = append(allChunks, manifestCHUNK)
	allChunks = append(allChunks, dataChunks...)

	return allChunks, nil
}
