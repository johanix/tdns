/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Generic CHUNK format utilities for manifest creation and HMAC integrity
 * Extracted from tdns-nm/tnm for shared use by KDC, KRS, and agents
 */

package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// ManifestData represents the JSON structure stored in a CHUNK manifest's Data field.
// This is a generic structure used by KDC (key distributions), agents (sync operations),
// and any other component that uses CHUNK-based data distribution.
type ManifestData struct {
	ChunkCount uint16                 `json:"chunk_count"`          // Number of data chunks (0 = inline payload)
	ChunkSize  uint16                 `json:"chunk_size,omitempty"` // Expected chunk size in bytes
	Metadata   map[string]interface{} `json:"metadata,omitempty"`   // Application-specific metadata
	Payload    []byte                 `json:"payload,omitempty"`    // Optional inline payload (for small data)
}

// CreateCHUNKManifest creates a CHUNK manifest record from manifest data.
//
// Manifest chunks are identified by Sequence=0. The Total field contains the number
// of data chunks. The Data field stores raw JSON bytes (not base64-encoded).
//
// Parameters:
//   - manifestData: The manifest structure containing chunk count, metadata, and optional payload
//   - format: The serialization format (typically FormatJSON=1)
//
// Returns:
//   - A CHUNK record with Sequence=0, or an error if JSON marshaling fails
func CreateCHUNKManifest(manifestData *ManifestData, format uint8) (*CHUNK, error) {
	manifestJSON, err := json.Marshal(manifestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest JSON: %v", err)
	}

	// Validate that the marshaled output is well-formed JSON
	if !json.Valid(manifestJSON) {
		return nil, fmt.Errorf("manifest JSON is not valid JSON")
	}

	chunk := &CHUNK{
		Format:     format,
		HMACLen:    0, // Will be set after HMAC calculation
		HMAC:       nil,
		Sequence:   0,                       // Sequence=0 indicates manifest chunk
		Total:      manifestData.ChunkCount, // Total contains the number of data chunks
		DataLength: uint16(len(manifestJSON)),
		Data:       manifestJSON, // Store raw JSON bytes (not base64-encoded)
	}

	return chunk, nil
}

// ExtractManifestData extracts ManifestData from a CHUNK manifest record.
//
// This function parses the JSON data from a manifest chunk (Sequence=0) and returns
// the structured ManifestData. Only FormatJSON is supported by this function.
// For FormatJWT manifests, use distrib.ExtractJWTManifestData instead.
//
// Parameters:
//   - chunk: The CHUNK record to extract from (must have Sequence=0)
//
// Returns:
//   - The parsed ManifestData structure, or an error if:
//   - Chunk is not a manifest (Sequence != 0)
//   - Format is not FormatJSON (use distrib.ExtractJWTManifestData for FormatJWT)
//   - JSON parsing fails
func ExtractManifestData(chunk *CHUNK) (*ManifestData, error) {
	if chunk.Sequence != 0 {
		return nil, fmt.Errorf("ExtractManifestData can only be called for manifest chunks (Sequence=0), got Sequence=%d", chunk.Sequence)
	}

	if chunk.Format == FormatJWT {
		return nil, fmt.Errorf("FormatJWT manifests require signature verification; use distrib.ExtractJWTManifestData instead")
	}

	if chunk.Format != FormatJSON {
		return nil, fmt.Errorf("unsupported CHUNK format: %d (expected FormatJSON=%d or FormatJWT=%d)", chunk.Format, FormatJSON, FormatJWT)
	}

	var manifestData ManifestData
	if err := json.Unmarshal(chunk.Data, &manifestData); err != nil {
		return nil, fmt.Errorf("failed to parse CHUNK manifest JSON: %v", err)
	}

	return &manifestData, nil
}

// IsJWTManifest checks if a CHUNK manifest uses JWT format.
// This can be used for format auto-detection before choosing the appropriate extraction method.
func IsJWTManifest(chunk *CHUNK) bool {
	return chunk.Sequence == 0 && chunk.Format == FormatJWT
}

// IsJSONManifest checks if a CHUNK manifest uses JSON format.
func IsJSONManifest(chunk *CHUNK) bool {
	return chunk.Sequence == 0 && chunk.Format == FormatJSON
}

// CalculateCHUNKHMAC calculates HMAC-SHA256 for a CHUNK manifest record.
//
// The HMAC is calculated over: Format (1 byte) + JSON data
// This provides integrity protection for the manifest. Only manifest chunks
// (Sequence=0) can have HMAC protection.
//
// The HMAC key is typically derived from the recipient's long-term public key,
// ensuring that only the intended recipient can verify the manifest integrity.
//
// Parameters:
//   - chunk: The CHUNK manifest to calculate HMAC for (must have Sequence=0)
//   - hmacKey: The 32-byte HMAC key (SHA-256)
//
// Returns:
//   - Error if the chunk is not a manifest, key is wrong size, or calculation fails
//   - On success, sets chunk.HMAC and chunk.HMACLen
func CalculateCHUNKHMAC(chunk *CHUNK, hmacKey []byte) error {
	if chunk.Sequence != 0 {
		return fmt.Errorf("HMAC can only be calculated for manifest chunks (Sequence=0), got Sequence=%d", chunk.Sequence)
	}

	if len(hmacKey) != 32 {
		return fmt.Errorf("HMAC key must be 32 bytes (SHA-256), got %d bytes", len(hmacKey))
	}

	// HMAC data is: Format (1 byte) + JSON data
	hmacData := make([]byte, 0, 1+len(chunk.Data))
	hmacData = append(hmacData, chunk.Format)
	hmacData = append(hmacData, chunk.Data...)

	// Calculate HMAC-SHA256
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(hmacData)
	hmacResult := mac.Sum(nil)

	// Set HMAC in CHUNK
	chunk.HMAC = hmacResult
	chunk.HMACLen = uint16(len(hmacResult))

	return nil
}

// VerifyCHUNKHMAC verifies the HMAC-SHA256 for a CHUNK manifest record.
//
// This function recalculates the HMAC using the provided key and compares it
// with the HMAC stored in the chunk using constant-time comparison to prevent
// timing attacks.
//
// Parameters:
//   - chunk: The CHUNK manifest to verify (must have Sequence=0)
//   - hmacKey: The 32-byte HMAC key (SHA-256)
//
// Returns:
//   - true if HMAC verification succeeds
//   - false with error if:
//   - Chunk is not a manifest (Sequence != 0)
//   - HMAC key is wrong size
//   - HMAC is not set in the chunk
//   - HMAC verification fails (false, nil)
func VerifyCHUNKHMAC(chunk *CHUNK, hmacKey []byte) (bool, error) {
	if chunk.Sequence != 0 {
		return false, fmt.Errorf("HMAC can only be verified for manifest chunks (Sequence=0), got Sequence=%d", chunk.Sequence)
	}

	if len(hmacKey) != 32 {
		return false, fmt.Errorf("HMAC key must be 32 bytes (SHA-256), got %d bytes", len(hmacKey))
	}

	if chunk.HMACLen == 0 || len(chunk.HMAC) == 0 {
		return false, fmt.Errorf("CHUNK HMAC is not set")
	}

	// HMAC data is: Format (1 byte) + JSON data
	hmacData := make([]byte, 0, 1+len(chunk.Data))
	hmacData = append(hmacData, chunk.Format)
	hmacData = append(hmacData, chunk.Data...)

	// Calculate expected HMAC
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(hmacData)
	expectedHMAC := mac.Sum(nil)

	// Compare HMACs (constant-time comparison)
	return hmac.Equal(chunk.HMAC, expectedHMAC), nil
}
