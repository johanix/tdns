/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 */

package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func init() {
	RegisterMANIFESTRR()
}

// MANIFEST - Distribution Manifest (generalized from JSONMANIFEST)
// Small metadata about a distribution event for a specific node
// Format: Format byte + HMAC + format-specific data structure
// Size limit: <500 bytes (never chunked)
//
// RDATA structure:
//   - Format (uint8): Format identifier (FormatJSON = 1, etc.)
//   - HMAC length (uint16): Length of HMAC checksum
//   - HMAC ([]byte): HMAC-SHA256 checksum of the manifest (excluding HMAC field)
//   - Format-specific data: For FormatJSON, this is a JSON structure
//
// For FormatJSON, the JSON structure contains:
//   - chunk_count: Number of CHUNK records (0 if payload is inline)
//   - chunk_size: Maximum size of each chunk in bytes (optional)
//   - metadata: Additional metadata (must include "content" field)
//   - payload: Inline payload (base64-encoded in JSON, optional)
//
// The Metadata map should contain a "content" field indicating the type:
//   - "zonelist": List of zone names (JSON array of strings)
//   - "encrypted_keys": HPKE-encrypted key material
//   - "clear_text": Clear text payload (base64 encoded)
//   - "encrypted_text": HPKE-encrypted text payload (base64 encoded)
//
// When payload fits inline (typically < 1000 bytes), it can be included directly
// in the Payload field, eliminating the need for separate CHUNK queries.
// In this case, ChunkCount should be 0 (or Payload is used instead of chunks).
//
// Presentation format (space-separated values):
//   <format> <hmac> <json-data>
//   Example:
//   node.distid.control. IN MANIFEST 1 a889a20e0722d903fe0772226ddd21bce465056f94785ea3dbba74069c897092 {"chunk_count":1,"chunk_size":60000,"metadata":{"content":"encrypted_keys","distribution_id":"3a29c33a",...}, "payload":"<base64-encoded-payload>"}"
type MANIFEST struct {
	Format     uint8                  // Format identifier (FormatJSON = 1, etc.) - REQUIRED
	HMAC       []byte                 // HMAC-SHA256 checksum - REQUIRED (replaces old Checksum field)
	ChunkCount uint16                 `json:"chunk_count"`        // Number of CHUNK records (0 if payload is inline)
	ChunkSize  uint16                 `json:"chunk_size,omitempty"` // Maximum size of each chunk in bytes (optional)
	Metadata   map[string]interface{} `json:"metadata,omitempty"` // Additional metadata (must include "content")
	Payload    []byte                 `json:"payload,omitempty"`  // Inline payload (base64-encoded in JSON, optional)
}

func NewMANIFEST() dns.PrivateRdata { return new(MANIFEST) }

func (rd MANIFEST) String() string {
	// Format field
	formatStr := FormatToString[rd.Format]
	if formatStr == "" {
		formatStr = fmt.Sprintf("FORMAT%d", rd.Format)
	}
	
	// HMAC field
	hmacStr := fmt.Sprintf("%x", rd.HMAC)
	
	// Data field: marshal JSON fields
	jsonFields := struct {
		ChunkCount uint16                 `json:"chunk_count"`
		ChunkSize  uint16                 `json:"chunk_size,omitempty"`
		Metadata   map[string]interface{} `json:"metadata,omitempty"`
		Payload    []byte                 `json:"payload,omitempty"`
	}{
		ChunkCount: rd.ChunkCount,
		ChunkSize:  rd.ChunkSize,
		Metadata:   rd.Metadata,
		Payload:    rd.Payload,
	}
	jsonBytes, err := json.Marshal(jsonFields)
	if err != nil {
		return fmt.Sprintf("%s %s marshal_error=%v", formatStr, hmacStr, err)
	}
	
	// Order: Format HMAC Data (MANIFEST has no Sequence/Total fields)
	return fmt.Sprintf("%s %s %s", formatStr, hmacStr, string(jsonBytes))
}

func (rd *MANIFEST) Parse(txt []string) error {
	// MANIFEST String() format: "Format HMAC JSON-data"
	// Format: "JSON" or "FORMAT<n>"
	// HMAC: hex string
	// JSON-data: the JSON structure
	
	if len(txt) < 3 {
		// Fallback: try to parse as single JSON string (backward compatibility)
		if len(txt) == 1 {
			if err := json.Unmarshal([]byte(txt[0]), rd); err != nil {
				return fmt.Errorf("invalid MANIFEST JSON: %v", err)
			}
			// Validate Format is present and valid
			if rd.Format == 0 {
				return errors.New("MANIFEST format field is required")
			}
			if rd.Format != FormatJSON {
				return fmt.Errorf("MANIFEST format %d not supported (only FormatJSON=1 is currently supported)", rd.Format)
			}
			// HMAC validation
			if rd.HMAC != nil && len(rd.HMAC) != 32 {
				return fmt.Errorf("MANIFEST HMAC must be 32 bytes (SHA-256), got %d bytes", len(rd.HMAC))
			}
			return nil
		}
		return errors.New("MANIFEST requires 3 fields: Format HMAC JSON-data")
	}

	// Parse Format (string -> enum)
	formatStr := txt[0]
	if format, ok := StringToFormat[formatStr]; ok {
		rd.Format = format
	} else if strings.HasPrefix(formatStr, "FORMAT") {
		// Format like "FORMAT1" (fallback for unknown formats)
		formatNum, err := strconv.ParseUint(strings.TrimPrefix(formatStr, "FORMAT"), 10, 8)
		if err != nil {
			return fmt.Errorf("invalid MANIFEST format: %s", formatStr)
		}
		rd.Format = uint8(formatNum)
	} else {
		return fmt.Errorf("invalid MANIFEST format: %s", formatStr)
	}

	// Parse HMAC (hex string)
	hmacStr := txt[1]
	hmac, err := hex.DecodeString(hmacStr)
	if err != nil {
		return fmt.Errorf("invalid MANIFEST HMAC (hex): %s", hmacStr)
	}
	if len(hmac) != 32 {
		return fmt.Errorf("MANIFEST HMAC must be 32 bytes (SHA-256), got %d bytes", len(hmac))
	}
	rd.HMAC = hmac

	// Parse JSON data (may contain spaces, so join remaining tokens)
	jsonStr := strings.Join(txt[2:], " ")
	var jsonFields struct {
		ChunkCount uint16                 `json:"chunk_count"`
		ChunkSize  uint16                 `json:"chunk_size,omitempty"`
		Metadata   map[string]interface{} `json:"metadata,omitempty"`
		Payload    []byte                 `json:"payload,omitempty"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &jsonFields); err != nil {
		return fmt.Errorf("invalid MANIFEST JSON: %v", err)
	}
	rd.ChunkCount = jsonFields.ChunkCount
	rd.ChunkSize = jsonFields.ChunkSize
	rd.Metadata = jsonFields.Metadata
	rd.Payload = jsonFields.Payload

	return nil
}

func (rd *MANIFEST) Pack(buf []byte) (int, error) {
	// Validate Format is set
	if rd.Format == 0 {
		return 0, errors.New("MANIFEST format field is required")
	}

	// Pack Format (uint8) - first byte
	off := 0
	if len(buf) < off+1 {
		return off, errors.New("buffer too small for MANIFEST format")
	}
	buf[off] = rd.Format
	off += 1

	// Pack HMAC length (uint16) + HMAC data
	if rd.HMAC == nil {
		return 0, errors.New("MANIFEST HMAC is required")
	}
	hmacLen := len(rd.HMAC)
	if hmacLen > 65535 {
		return 0, fmt.Errorf("MANIFEST HMAC too long (max 65535 bytes, got %d)", hmacLen)
	}
	if len(buf) < off+2 {
		return off, errors.New("buffer too small for MANIFEST HMAC length")
	}
	buf[off] = byte(hmacLen >> 8)
	buf[off+1] = byte(hmacLen)
	off += 2

	if len(buf) < off+hmacLen {
		return off, errors.New("buffer too small for MANIFEST HMAC")
	}
	copy(buf[off:], rd.HMAC)
	off += hmacLen

	// Pack format-specific data (for FormatJSON, this is JSON)
	// Marshal only the JSON fields (not Format or HMAC)
	jsonFields := struct {
		ChunkCount uint16                 `json:"chunk_count"`
		ChunkSize  uint16                 `json:"chunk_size,omitempty"`
		Metadata   map[string]interface{} `json:"metadata,omitempty"`
		Payload    []byte                 `json:"payload,omitempty"`
	}{
		ChunkCount: rd.ChunkCount,
		ChunkSize:  rd.ChunkSize,
		Metadata:   rd.Metadata,
		Payload:    rd.Payload,
	}
	jsonBytes, err := json.Marshal(jsonFields)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal MANIFEST JSON: %v", err)
	}

	if len(jsonBytes) > 65535 {
		return 0, errors.New("MANIFEST JSON data too large (max 65535 bytes)")
	}

	// Pack JSON data length (uint16) + JSON data
	if len(buf) < off+2 {
		return off, errors.New("buffer too small for MANIFEST JSON length")
	}
	buf[off] = byte(len(jsonBytes) >> 8)
	buf[off+1] = byte(len(jsonBytes))
	off += 2

	if len(buf) < off+len(jsonBytes) {
		return off, errors.New("buffer too small for MANIFEST JSON data")
	}
	copy(buf[off:], jsonBytes)
	off += len(jsonBytes)

	return off, nil
}

func (rd *MANIFEST) Unpack(buf []byte) (int, error) {
	off := 0

	// Unpack Format (uint8)
	if len(buf) < off+1 {
		return off, errors.New("buffer too short for MANIFEST format")
	}
	rd.Format = buf[off]
	off += 1

	// Validate Format
	if rd.Format == 0 {
		return off, errors.New("MANIFEST format field is required (cannot be 0)")
	}
	if rd.Format != FormatJSON {
		return off, fmt.Errorf("MANIFEST format %d not supported (only FormatJSON=1 is currently supported)", rd.Format)
	}

	// Unpack HMAC length (uint16) + HMAC data
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for MANIFEST HMAC length")
	}
	hmacLen := int(buf[off])<<8 | int(buf[off+1])
	off += 2

	if hmacLen == 0 {
		return off, errors.New("MANIFEST HMAC is required (length cannot be 0)")
	}
	if len(buf) < off+hmacLen {
		return off, errors.New("buffer too short for MANIFEST HMAC")
	}
	rd.HMAC = make([]byte, hmacLen)
	copy(rd.HMAC, buf[off:off+hmacLen])
	off += hmacLen

	// Unpack JSON data length (uint16) + JSON data
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for MANIFEST JSON length")
	}
	jsonLen := int(buf[off])<<8 | int(buf[off+1])
	off += 2

	if len(buf) < off+jsonLen {
		return off, errors.New("buffer too short for MANIFEST JSON data")
	}

	// Unmarshal JSON fields (not Format or HMAC)
	var jsonFields struct {
		ChunkCount uint16                 `json:"chunk_count"`
		ChunkSize  uint16                 `json:"chunk_size,omitempty"`
		Metadata   map[string]interface{} `json:"metadata,omitempty"`
		Payload    []byte                 `json:"payload,omitempty"`
	}
	if err := json.Unmarshal(buf[off:off+jsonLen], &jsonFields); err != nil {
		return off, fmt.Errorf("failed to unmarshal MANIFEST JSON: %v", err)
	}

	// Copy JSON fields to struct
	rd.ChunkCount = jsonFields.ChunkCount
	rd.ChunkSize = jsonFields.ChunkSize
	rd.Metadata = jsonFields.Metadata
	rd.Payload = jsonFields.Payload

	off += jsonLen
	return off, nil
}

func (rd *MANIFEST) Copy(dest dns.PrivateRdata) error {
	d := dest.(*MANIFEST)
	d.Format = rd.Format
	if rd.HMAC != nil {
		d.HMAC = make([]byte, len(rd.HMAC))
		copy(d.HMAC, rd.HMAC)
	}
	d.ChunkCount = rd.ChunkCount
	d.ChunkSize = rd.ChunkSize
	if rd.Metadata != nil {
		d.Metadata = make(map[string]interface{})
		for k, v := range rd.Metadata {
			d.Metadata[k] = v
		}
	}
	if rd.Payload != nil {
		d.Payload = make([]byte, len(rd.Payload))
		copy(d.Payload, rd.Payload)
	}
	return nil
}

func (rd *MANIFEST) Len() int {
	// Format (1 byte) + HMAC length (2 bytes) + HMAC (variable) + JSON length (2 bytes) + JSON (variable)
	jsonFields := struct {
		ChunkCount uint16                 `json:"chunk_count"`
		ChunkSize  uint16                 `json:"chunk_size,omitempty"`
		Metadata   map[string]interface{} `json:"metadata,omitempty"`
		Payload    []byte                 `json:"payload,omitempty"`
	}{
		ChunkCount: rd.ChunkCount,
		ChunkSize:  rd.ChunkSize,
		Metadata:   rd.Metadata,
		Payload:    rd.Payload,
	}
	jsonBytes, _ := json.Marshal(jsonFields)
	hmacLen := 0
	if rd.HMAC != nil {
		hmacLen = len(rd.HMAC)
	}
	return 1 + // Format
		2 + // HMAC length
		hmacLen + // HMAC
		2 + // JSON length
		len(jsonBytes) // JSON data
}

func RegisterMANIFESTRR() error {
	dns.PrivateHandle("MANIFEST", TypeMANIFEST, NewMANIFEST)
	// Explicitly set TypeToString to use "MANIFEST" for printing
	dns.TypeToString[TypeMANIFEST] = "MANIFEST"
	return nil
}

// GetHMACData returns the data that should be HMAC'd for this manifest.
// This includes Format + JSON fields (but NOT the HMAC field itself).
// The caller should calculate HMAC-SHA256 over this data using the long-term HPKE key.
func (rd *MANIFEST) GetHMACData() ([]byte, error) {
	// Pack Format (1 byte)
	buf := make([]byte, 1)
	buf[0] = rd.Format

	// Marshal JSON fields (not Format or HMAC)
	jsonFields := struct {
		ChunkCount uint16                 `json:"chunk_count"`
		ChunkSize  uint16                 `json:"chunk_size,omitempty"`
		Metadata   map[string]interface{} `json:"metadata,omitempty"`
		Payload    []byte                 `json:"payload,omitempty"`
	}{
		ChunkCount: rd.ChunkCount,
		ChunkSize:  rd.ChunkSize,
		Metadata:   rd.Metadata,
		Payload:    rd.Payload,
	}
	jsonBytes, err := json.Marshal(jsonFields)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MANIFEST JSON for HMAC: %v", err)
	}

	// Append JSON data (will be length-prefixed in actual Pack, but for HMAC we include it directly)
	// Actually, for HMAC we should include the same structure as Pack (Format + JSON length + JSON data)
	jsonLenBytes := make([]byte, 2)
	jsonLenBytes[0] = byte(len(jsonBytes) >> 8)
	jsonLenBytes[1] = byte(len(jsonBytes))

	// Return Format + JSON length + JSON data
	result := append(buf, jsonLenBytes...)
	result = append(result, jsonBytes...)
	return result, nil
}

// CalculateHMAC calculates and sets the HMAC field for this manifest.
// The HMAC key should be derived from the long-term HPKE key.
// This should be called before Pack().
func (rd *MANIFEST) CalculateHMAC(hmacKey []byte) error {
	if len(hmacKey) == 0 {
		return errors.New("HMAC key cannot be empty")
	}

	hmacData, err := rd.GetHMACData()
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(hmacData)
	rd.HMAC = mac.Sum(nil)

	return nil
}

// VerifyHMAC verifies the HMAC field for this manifest.
// The HMAC key should be derived from the long-term HPKE key.
// Returns true if HMAC is valid, false otherwise.
func (rd *MANIFEST) VerifyHMAC(hmacKey []byte) (bool, error) {
	if rd.HMAC == nil {
		return false, errors.New("MANIFEST HMAC is not set")
	}
	if len(hmacKey) == 0 {
		return false, errors.New("HMAC key cannot be empty")
	}

	hmacData, err := rd.GetHMACData()
	if err != nil {
		return false, err
	}

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(hmacData)
	expectedHMAC := mac.Sum(nil)

	// Use constant-time comparison to prevent timing attacks
	return hmac.Equal(rd.HMAC, expectedHMAC), nil
}

