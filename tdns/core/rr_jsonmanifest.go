/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 */

package core

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

func init() {
	RegisterJSONMANIFESTRR()
}

// JSONMANIFEST - JSON Distribution Manifest
// Small metadata about a distribution event for a specific node
// Format: JSON structure with chunk_count, checksum, metadata
// Size limit: <500 bytes (never chunked)
// The Metadata map should contain a "content" field indicating the type:
//   - "zonelist": List of zone names (JSON array of strings)
//   - "encrypted_keys": HPKE-encrypted key material
//   - "test_text": Test/debug text payload
type JSONMANIFEST struct {
	ChunkCount uint16                 `json:"chunk_count"`        // Number of JSONCHUNK records
	ChunkSize  uint16                 `json:"chunk_size,omitempty"` // Maximum size of each chunk in bytes (optional)
	Checksum   string                 `json:"checksum,omitempty"`  // SHA-256 checksum (optional)
	Metadata   map[string]interface{} `json:"metadata,omitempty"` // Additional metadata (must include "content")
}

func NewJSONMANIFEST() dns.PrivateRdata { return new(JSONMANIFEST) }

func (rd JSONMANIFEST) String() string {
	jsonBytes, err := json.Marshal(rd)
	if err != nil {
		return fmt.Sprintf("JSONMANIFEST(marshal error: %v)", err)
	}
	return string(jsonBytes)
}

func (rd *JSONMANIFEST) Parse(txt []string) error {
	if len(txt) != 1 {
		return errors.New("JSONMANIFEST requires single JSON string")
	}

	if err := json.Unmarshal([]byte(txt[0]), rd); err != nil {
		return fmt.Errorf("invalid JSONMANIFEST JSON: %v", err)
	}

	return nil
}

func (rd *JSONMANIFEST) Pack(buf []byte) (int, error) {
	jsonBytes, err := json.Marshal(rd)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal JSONMANIFEST: %v", err)
	}

	if len(jsonBytes) > 65535 {
		return 0, errors.New("JSONMANIFEST too large (max 65535 bytes)")
	}

	// Pack as length-prefixed JSON
	off := 0
	buf[off] = byte(len(jsonBytes) >> 8)
	buf[off+1] = byte(len(jsonBytes))
	off += 2

	if len(buf) < off+len(jsonBytes) {
		return off, errors.New("buffer too small for JSONMANIFEST")
	}

	copy(buf[off:], jsonBytes)
	off += len(jsonBytes)

	return off, nil
}

func (rd *JSONMANIFEST) Unpack(buf []byte) (int, error) {
	if len(buf) < 2 {
		return 0, errors.New("buffer too short for JSONMANIFEST length")
	}

	jsonLen := int(buf[0])<<8 | int(buf[1])
	off := 2

	if len(buf) < off+jsonLen {
		return off, errors.New("buffer too short for JSONMANIFEST data")
	}

	if err := json.Unmarshal(buf[off:off+jsonLen], rd); err != nil {
		return off, fmt.Errorf("failed to unmarshal JSONMANIFEST: %v", err)
	}

	off += jsonLen
	return off, nil
}

func (rd *JSONMANIFEST) Copy(dest dns.PrivateRdata) error {
	d := dest.(*JSONMANIFEST)
	d.ChunkCount = rd.ChunkCount
	d.Checksum = rd.Checksum
	if rd.Metadata != nil {
		d.Metadata = make(map[string]interface{})
		for k, v := range rd.Metadata {
			d.Metadata[k] = v
		}
	}
	return nil
}

func (rd *JSONMANIFEST) Len() int {
	jsonBytes, _ := json.Marshal(rd)
	return 2 + len(jsonBytes) // 2 bytes for length prefix
}

func RegisterJSONMANIFESTRR() error {
	dns.PrivateHandle("JSONMANIFEST", TypeJSONMANIFEST, NewJSONMANIFEST)
	return nil
}

