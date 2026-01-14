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
	RegisterJSONCHUNKRR()
}

// JSONCHUNK - Chunked JSON Data Transport
// Transports large JSON-structured data (zone lists or encrypted blobs) in chunks
// Format: Base64-encoded JSON data with sequence/total metadata
type JSONCHUNK struct {
	Sequence uint16 `json:"sequence"` // Chunk sequence number (0-based)
	Total    uint16 `json:"total"`    // Total number of chunks
	Data     []byte `json:"data"`     // Base64-encoded JSON data (raw bytes, not base64 string)
}

func NewJSONCHUNK() dns.PrivateRdata { return new(JSONCHUNK) }

func (rd JSONCHUNK) String() string {
	dataStr := base64.StdEncoding.EncodeToString(rd.Data)
	if rd.Total > 1 {
		return fmt.Sprintf("%s %d %d", dataStr, rd.Sequence, rd.Total)
	}
	return dataStr
}

func (rd *JSONCHUNK) Parse(txt []string) error {
	if len(txt) < 1 || len(txt) > 3 {
		return errors.New("JSONCHUNK requires base64 data and optionally sequence/total")
	}

	// Decode base64-encoded data
	data, err := base64.StdEncoding.DecodeString(txt[0])
	if err != nil {
		return fmt.Errorf("invalid JSONCHUNK base64 data: %v", err)
	}

	rd.Data = data
	rd.Sequence = 0
	rd.Total = 1

	// Parse sequence and total if present
	if len(txt) >= 3 {
		seq, err := strconv.ParseUint(txt[1], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid JSONCHUNK sequence: %s", txt[1])
		}
		total, err := strconv.ParseUint(txt[2], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid JSONCHUNK total: %s", txt[2])
		}
		rd.Sequence = uint16(seq)
		rd.Total = uint16(total)
	}

	return nil
}

func (rd *JSONCHUNK) Pack(buf []byte) (int, error) {
	off := 0

	// Pack sequence and total (uint16 each)
	buf[off] = byte(rd.Sequence >> 8)
	buf[off+1] = byte(rd.Sequence)
	off += 2
	buf[off] = byte(rd.Total >> 8)
	buf[off+1] = byte(rd.Total)
	off += 2

	// Pack data length (uint16)
	dataLen := len(rd.Data)
	if dataLen > 65535 {
		return off, errors.New("JSONCHUNK data too long")
	}
	buf[off] = byte(dataLen >> 8)
	buf[off+1] = byte(dataLen)
	off += 2

	// Pack data
	if len(buf) < off+dataLen {
		return off, errors.New("buffer too small for JSONCHUNK data")
	}
	copy(buf[off:], rd.Data)
	off += dataLen

	return off, nil
}

func (rd *JSONCHUNK) Unpack(buf []byte) (int, error) {
	off := 0

	// Unpack sequence
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for JSONCHUNK sequence")
	}
	rd.Sequence = binary.BigEndian.Uint16(buf[off:])
	off += 2

	// Unpack total
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for JSONCHUNK total")
	}
	rd.Total = binary.BigEndian.Uint16(buf[off:])
	off += 2

	// Unpack data length
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for JSONCHUNK data length")
	}
	dataLen := int(binary.BigEndian.Uint16(buf[off:]))
	off += 2

	// Unpack data
	if len(buf) < off+dataLen {
		return off, errors.New("buffer too short for JSONCHUNK data")
	}
	rd.Data = make([]byte, dataLen)
	copy(rd.Data, buf[off:off+dataLen])
	off += dataLen

	return off, nil
}

func (rd *JSONCHUNK) Copy(dest dns.PrivateRdata) error {
	d := dest.(*JSONCHUNK)
	d.Data = make([]byte, len(rd.Data))
	copy(d.Data, rd.Data)
	d.Sequence = rd.Sequence
	d.Total = rd.Total
	return nil
}

func (rd *JSONCHUNK) Len() int {
	return 2 + // sequence
		2 + // total
		2 + // data length
		len(rd.Data) // data
}

func RegisterJSONCHUNKRR() error {
	dns.PrivateHandle("JSONCHUNK", TypeJSONCHUNK, NewJSONCHUNK)
	return nil
}

