/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 */

package core

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/miekg/dns"
)

func init() {
	RegisterOLDCHUNKRR()
}

// OLDCHUNK - Chunked Data Transport (generalized from JSONCHUNK)
// Transports large format-specific data (zone lists or encrypted blobs) in chunks
// The format is determined by the associated MANIFEST, not by OLDCHUNK itself.
// DEPRECATED: This RR type is deprecated in favor of CHUNK (formerly CHUNK2).
//
// RDATA structure:
//   - Sequence (uint16): Chunk sequence number (0-based)
//   - Total (uint16): Total number of chunks
//   - Data length (uint16): Length of format-specific data
//   - Data ([]byte): Format-specific data
//
// For FormatJSON (as specified in MANIFEST), the data is base64-encoded JSON data (raw bytes, not base64 string)
//
// Presentation format (space-separated values):
//   - Single chunk: <base64-data>
//     Example: "<base64-encoded-chunk-data>"
//   - Multiple chunks: <base64-data> <sequence> <total>
//     Example: "<base64-encoded-chunk-data> 1 2"
type OLDCHUNK struct {
	Sequence uint16 `json:"sequence"` // Chunk sequence number (0-based)
	Total    uint16 `json:"total"`    // Total number of chunks
	Data     []byte `json:"data"`     // Format-specific data (format determined by associated MANIFEST)
}

func NewOLDCHUNK() dns.PrivateRdata { return new(OLDCHUNK) }

func (rd OLDCHUNK) String() string {
	dataStr := base64.StdEncoding.EncodeToString(rd.Data)
	if rd.Total > 1 {
		return fmt.Sprintf("%s %d %d", dataStr, rd.Sequence, rd.Total)
	}
	return dataStr
}

func (rd *OLDCHUNK) Parse(txt []string) error {
	if len(txt) < 1 || len(txt) > 3 {
		return errors.New("OLDCHUNK requires base64 data and optionally sequence/total")
	}

	// Decode base64-encoded data
	data, err := base64.StdEncoding.DecodeString(txt[0])
	if err != nil {
		return fmt.Errorf("invalid OLDCHUNK base64 data: %v", err)
	}

	rd.Data = data
	rd.Sequence = 0
	rd.Total = 1

	// Parse sequence and total if present
	if len(txt) >= 3 {
		seq, err := strconv.ParseUint(txt[1], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid OLDCHUNK sequence: %s", txt[1])
		}
		total, err := strconv.ParseUint(txt[2], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid OLDCHUNK total: %s", txt[2])
		}
		rd.Sequence = uint16(seq)
		rd.Total = uint16(total)
	}

	return nil
}

func (rd *OLDCHUNK) Pack(buf []byte) (int, error) {
	off := 0

	// Pack sequence and total (uint16 each)
	if len(buf) < off+4 {
		return off, errors.New("buffer too small for OLDCHUNK sequence/total")
	}
	buf[off] = byte(rd.Sequence >> 8)
	buf[off+1] = byte(rd.Sequence)
	off += 2
	buf[off] = byte(rd.Total >> 8)
	buf[off+1] = byte(rd.Total)
	off += 2

	// Pack data length (uint16)
	dataLen := len(rd.Data)
	if dataLen > 65535 {
		return off, errors.New("OLDCHUNK data too long")
	}
	if len(buf) < off+2 {
		return off, errors.New("buffer too small for OLDCHUNK data length")
	}
	buf[off] = byte(dataLen >> 8)
	buf[off+1] = byte(dataLen)
	off += 2

	// Pack data
	if len(buf) < off+dataLen {
		return off, errors.New("buffer too small for OLDCHUNK data")
	}
	copy(buf[off:], rd.Data)
	off += dataLen

	return off, nil
}

func (rd *OLDCHUNK) Unpack(buf []byte) (int, error) {
	off := 0

	// Unpack sequence
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for OLDCHUNK sequence")
	}
	rd.Sequence = binary.BigEndian.Uint16(buf[off:])
	off += 2

	// Unpack total
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for OLDCHUNK total")
	}
	rd.Total = binary.BigEndian.Uint16(buf[off:])
	off += 2

	// Unpack data length
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for OLDCHUNK data length")
	}
	dataLen := int(binary.BigEndian.Uint16(buf[off:]))
	off += 2

	// Unpack data
	if len(buf) < off+dataLen {
		return off, errors.New("buffer too short for OLDCHUNK data")
	}
	rd.Data = make([]byte, dataLen)
	copy(rd.Data, buf[off:off+dataLen])
	off += dataLen

	return off, nil
}

func (rd *OLDCHUNK) Copy(dest dns.PrivateRdata) error {
	d := dest.(*OLDCHUNK)
	d.Sequence = rd.Sequence
	d.Total = rd.Total
	if rd.Data != nil {
		d.Data = make([]byte, len(rd.Data))
		copy(d.Data, rd.Data)
	}
	return nil
}

func (rd *OLDCHUNK) Len() int {
	return 2 + // sequence
		2 + // total
		2 + // data length
		len(rd.Data) // data
}

func RegisterOLDCHUNKRR() error {
	dns.PrivateHandle("OLDCHUNK", TypeOLDCHUNK, NewOLDCHUNK)
	// Explicitly set TypeToString to use "OLDCHUNK" for printing
	dns.TypeToString[TypeOLDCHUNK] = "OLDCHUNK"
	return nil
}

