/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 */

package core

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func init() {
	RegisterCHUNKRR()
}

// CHUNK - Unified Chunk/Manifest RR type
// Fixed RDATA structure with all fields always present (some unused depending on context)
//
// RDATA structure (fixed field order):
//   - Format (uint8): Format identifier (used when Total=0, stored from manifest when Total>0)
//   - HMAC length (uint16): Length of HMAC (0 for data chunks, >0 for manifest)
//   - HMAC ([]byte): HMAC-SHA256 checksum (only present if HMAC length > 0)
//   - Sequence (uint16): Chunk sequence number (unused when Total=0, used when Total>0)
//   - Total (uint16): Total chunks or 0 for manifest (0 = manifest, >0 = data chunk)
//   - Data length (uint16): Length of data
//   - Data ([]byte): Format-specific data (JSON manifest or chunk payload)
//
// Semantics:
//   - When Total=0: This is a manifest chunk
//     * Format: Set (e.g., FormatJSON=1)
//     * HMAC length: >0 (typically 32 for SHA-256)
//     * HMAC: Present (length from HMAC length field)
//     * Sequence: Unused (can be 0)
//     * Total: 0 (indicates manifest)
//     * Data: JSON data (ChunkCount, ChunkSize, Metadata, Payload)
//
//   - When Total>0: This is a data chunk
//     * Format: Stored from CHUNK manifest (e.g., FormatJSON=1)
//     * HMAC length: 0
//     * HMAC: Not present (HMACLen=0)
//     * Sequence: Chunk sequence number (0-based)
//     * Total: Total number of chunks
//     * Data: Chunk payload data
//
// Presentation format (space-separated values):
//   - Manifest chunk: <sequence> <total> <format> <hmac> <json-data>
//     Example:
//     node.distid.control. IN CHUNK 0 0 JSON a889a20e0722d903fe0772226ddd21bce465056f94785ea3dbba74069c897092
//                                    {"chunk_count":1,"chunk_size":60000,"metadata":{"content":"encrypted_keys","distribution_id":"3a29c33a"},"payload":"<base64-encoded-payload>"}"
//   - Data chunk: <sequence> <total> <format> <hmac> <base64-data>
//     Example:
//     node.distid.control. IN CHUNK 1 2 JSON "" bWhBdGRTlac0hX2p0eGZzSW9kcHJKZ2d...QY1c3b05uYTd3aWpORXlLUDMrWG10T3c9PQ==

type CHUNK struct {
	Format     uint8  // Format identifier (used for manifest, unused for data chunks)
	HMACLen    uint16 // HMAC length (0 for data chunks, >0 for manifest)
	HMAC       []byte // HMAC-SHA256 checksum (only present if HMACLen > 0)
	Sequence   uint16 // Chunk sequence number (unused when Total=0)
	Total      uint16 // Total chunks or 0 for manifest (0 = manifest, >0 = data chunk)
	DataLength uint16 // Length of data
	Data       []byte // Format-specific data (JSON manifest or chunk payload)
}

func NewCHUNK() dns.PrivateRdata { return new(CHUNK) }

func (rd CHUNK) String() string {
	// Format field (always present)
	formatStr := FormatToString[rd.Format]
	if formatStr == "" {
		formatStr = fmt.Sprintf("FORMAT%d", rd.Format)
	}
	
	// HMAC field (always present)
	var hmacStr string
	if rd.HMACLen > 0 && rd.HMAC != nil {
		hmacStr = fmt.Sprintf("%x", rd.HMAC)
	} else {
		hmacStr = `""` // Empty string for data chunks
	}
	
	// Data field: try to parse as JSON for manifest chunks, otherwise base64
	var dataStr string
	if rd.Total == 0 {
		// Manifest chunk: try to parse JSON for better display
		var manifestData struct {
			ChunkCount uint16                 `json:"chunk_count"`
			ChunkSize  uint16                 `json:"chunk_size,omitempty"`
			Metadata   map[string]interface{} `json:"metadata,omitempty"`
			Payload    []byte                 `json:"payload,omitempty"`
		}
		if err := json.Unmarshal(rd.Data, &manifestData); err == nil {
			jsonBytes, _ := json.Marshal(manifestData)
			dataStr = string(jsonBytes)
		} else {
			// Fallback if JSON parsing fails
			dataStr = base64.StdEncoding.EncodeToString(rd.Data)
		}
	} else {
		// Data chunk: base64 encode
		dataStr = base64.StdEncoding.EncodeToString(rd.Data)
	}
	
	// Order: Sequence Total Format HMAC Data
	return fmt.Sprintf("%d %d %s %s %s", rd.Sequence, rd.Total, formatStr, hmacStr, dataStr)
}

func (rd *CHUNK) Parse(txt []string) error {
	// CHUNK String() format: "Sequence Total Format HMAC Data"
	// Format: "JSON" or "FORMAT<n>"
	// HMAC: hex string or "" for data chunks
	// Data: JSON (for manifest) or base64 (for data chunks)
	
	if len(txt) < 5 {
		return errors.New("CHUNK requires 5 fields: Sequence Total Format HMAC Data")
	}

	// Parse Sequence (uint16)
	seq, err := strconv.ParseUint(txt[0], 10, 16)
	if err != nil {
		return fmt.Errorf("invalid CHUNK sequence: %s", txt[0])
	}
	rd.Sequence = uint16(seq)

	// Parse Total (uint16)
	total, err := strconv.ParseUint(txt[1], 10, 16)
	if err != nil {
		return fmt.Errorf("invalid CHUNK total: %s", txt[1])
	}
	rd.Total = uint16(total)

	// Parse Format (string -> enum)
	formatStr := txt[2]
	if format, ok := StringToFormat[formatStr]; ok {
		rd.Format = format
	} else if strings.HasPrefix(formatStr, "FORMAT") {
		// Format like "FORMAT1" (fallback for unknown formats)
		formatNum, err := strconv.ParseUint(strings.TrimPrefix(formatStr, "FORMAT"), 10, 8)
		if err != nil {
			return fmt.Errorf("invalid CHUNK format: %s", formatStr)
		}
		rd.Format = uint8(formatNum)
	} else {
		return fmt.Errorf("invalid CHUNK format: %s", formatStr)
	}

	// Parse HMAC (hex string or "")
	hmacStr := txt[3]
	if hmacStr == `""` || hmacStr == "" {
		rd.HMACLen = 0
		rd.HMAC = nil
	} else {
		hmac, err := hex.DecodeString(hmacStr)
		if err != nil {
			return fmt.Errorf("invalid CHUNK HMAC (hex): %s", hmacStr)
		}
		rd.HMACLen = uint16(len(hmac))
		rd.HMAC = hmac
	}

	// Parse Data (JSON for manifest, base64 for data chunk)
	dataStr := txt[4]
	if rd.Total == 0 {
		// Manifest: data is JSON
		rd.Data = []byte(dataStr)
		rd.DataLength = uint16(len(rd.Data))
	} else {
		// Data chunk: data is base64
		data, err := base64.StdEncoding.DecodeString(dataStr)
		if err != nil {
			return fmt.Errorf("invalid CHUNK base64 data: %v", err)
		}
		rd.Data = data
		rd.DataLength = uint16(len(data))
	}

	return nil
}

func (rd *CHUNK) Pack(buf []byte) (int, error) {
	off := 0

	// Pack Format (uint8)
	if len(buf) < off+1 {
		return off, errors.New("buffer too small for CHUNK format")
	}
	buf[off] = rd.Format
	off += 1

	// Pack HMAC length (uint16)
	if len(buf) < off+2 {
		return off, errors.New("buffer too small for CHUNK HMAC length")
	}
	buf[off] = byte(rd.HMACLen >> 8)
	buf[off+1] = byte(rd.HMACLen)
	off += 2

	// Pack HMAC (only if HMACLen > 0)
	if rd.HMACLen > 0 {
		if len(buf) < off+int(rd.HMACLen) {
			return off, errors.New("buffer too small for CHUNK HMAC")
		}
		if len(rd.HMAC) != int(rd.HMACLen) {
			return off, fmt.Errorf("CHUNK HMAC length mismatch: expected %d, got %d", rd.HMACLen, len(rd.HMAC))
		}
		copy(buf[off:], rd.HMAC)
		off += int(rd.HMACLen)
	}

	// Pack Sequence (uint16)
	if len(buf) < off+2 {
		return off, errors.New("buffer too small for CHUNK sequence")
	}
	buf[off] = byte(rd.Sequence >> 8)
	buf[off+1] = byte(rd.Sequence)
	off += 2

	// Pack Total (uint16)
	if len(buf) < off+2 {
		return off, errors.New("buffer too small for CHUNK total")
	}
	buf[off] = byte(rd.Total >> 8)
	buf[off+1] = byte(rd.Total)
	off += 2

	// Pack Data length (uint16)
	if len(buf) < off+2 {
		return off, errors.New("buffer too small for CHUNK data length")
	}
	dataLen := len(rd.Data)
	if dataLen > 65535 {
		return off, errors.New("CHUNK data too long")
	}
	buf[off] = byte(dataLen >> 8)
	buf[off+1] = byte(dataLen)
	off += 2

	// Pack Data
	if len(buf) < off+dataLen {
		return off, errors.New("buffer too small for CHUNK data")
	}
	copy(buf[off:], rd.Data)
	off += dataLen

	return off, nil
}

func (rd *CHUNK) Unpack(buf []byte) (int, error) {
	off := 0

	// Unpack Format (uint8)
	if len(buf) < off+1 {
		return off, errors.New("buffer too short for CHUNK format")
	}
	rd.Format = buf[off]
	off += 1

	// Unpack HMAC length (uint16)
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for CHUNK HMAC length")
	}
	rd.HMACLen = binary.BigEndian.Uint16(buf[off:])
	off += 2

	// Unpack HMAC (only if HMACLen > 0)
	if rd.HMACLen > 0 {
		if len(buf) < off+int(rd.HMACLen) {
			return off, errors.New("buffer too short for CHUNK HMAC")
		}
		rd.HMAC = make([]byte, rd.HMACLen)
		copy(rd.HMAC, buf[off:off+int(rd.HMACLen)])
		off += int(rd.HMACLen)
	} else {
		rd.HMAC = nil
	}

	// Unpack Sequence (uint16)
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for CHUNK sequence")
	}
	rd.Sequence = binary.BigEndian.Uint16(buf[off:])
	off += 2

	// Unpack Total (uint16)
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for CHUNK total")
	}
	rd.Total = binary.BigEndian.Uint16(buf[off:])
	off += 2

	// Unpack Data length (uint16)
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for CHUNK data length")
	}
	rd.DataLength = binary.BigEndian.Uint16(buf[off:])
	off += 2

	// Unpack Data
	if len(buf) < off+int(rd.DataLength) {
		return off, errors.New("buffer too short for CHUNK data")
	}
	rd.Data = make([]byte, rd.DataLength)
	copy(rd.Data, buf[off:off+int(rd.DataLength)])
	off += int(rd.DataLength)

	return off, nil
}

func (rd *CHUNK) Copy(dest dns.PrivateRdata) error {
	d := dest.(*CHUNK)
	d.Format = rd.Format
	d.HMACLen = rd.HMACLen
	if rd.HMAC != nil {
		d.HMAC = make([]byte, len(rd.HMAC))
		copy(d.HMAC, rd.HMAC)
	} else {
		d.HMAC = nil
	}
	d.Sequence = rd.Sequence
	d.Total = rd.Total
	d.DataLength = rd.DataLength
	if rd.Data != nil {
		d.Data = make([]byte, len(rd.Data))
		copy(d.Data, rd.Data)
	}
	return nil
}

func (rd *CHUNK) Len() int {
	return 1 + // format
		2 + // hmac length
		int(rd.HMACLen) + // hmac (variable)
		2 + // sequence
		2 + // total
		2 + // data length
		len(rd.Data) // data
}

func RegisterCHUNKRR() error {
	dns.PrivateHandle("CHUNK", TypeCHUNK, NewCHUNK)
	// Explicitly set TypeToString to use "CHUNK" for printing
	dns.TypeToString[TypeCHUNK] = "CHUNK"
	return nil
}

