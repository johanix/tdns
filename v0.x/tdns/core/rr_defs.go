/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package core

import (
	"encoding/binary"
	"errors"
)

const TypeDSYNC = 0x0042 // 66 is the official IANA code
// const TypeDSYNC = 0x0F9B

const (
	TypeNOTIFY  = 0x0F9A
	TypeMSIGNER = 0x0F9C
	TypeHSYNC   = 0x0F9D
	TypeHSYNC2  = 0x0F9E
	TypeTSYNC   = 0x0F9F
	TypeMANIFEST = 65013 // 0xFDF5 - Distribution Manifest
	TypeOLDCHUNK = 65014 // 0xFDF6 - Chunked Data Transport (deprecated, use CHUNK)
	TypeCHUNK    = 65015 // 0xFDF7 - Unified Chunk/Manifest
)

// Format constants for MANIFEST and OLDCHUNK RR types
const (
	FormatJSON = 1 // JSON format (original format)
	// Future formats can be added as needed:
	// FormatJSONv2 = 9  // Example: if JSON v2 is needed in the future
	// FormatBinary = 2  // Example: binary format
	// FormatProtobuf = 3 // Example: protobuf format
)

// FormatToString maps format constants to their string representations
var FormatToString = map[uint8]string{
	FormatJSON: "JSON",
	// Future formats:
	// FormatJSONv2: "JSONv2",
	// FormatBinary: "BINARY",
	// FormatProtobuf: "PROTOBUF",
}

// StringToFormat maps string representations to format constants (reverse of FormatToString)
// NOTE: This map must be kept in sync with FormatToString - when adding a new format to FormatToString,
// also add the corresponding entry here.
var StringToFormat = map[string]uint8{
	"JSON": FormatJSON,
	// Future formats will be added here when FormatToString is updated:
	// "JSONv2": FormatJSONv2,
	// "BINARY": FormatBinary,
	// "PROTOBUF": FormatProtobuf,
}

func unpackUint8(msg []byte, off int) (i uint8, off1 int, err error) {
	if off+1 > len(msg) {
		return 0, len(msg), errors.New("overflow unpacking uint8")
	}
	return msg[off], off + 1, nil
}

func packUint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if off+1 > len(msg) {
		return len(msg), errors.New("overflow packing uint8")
	}
	msg[off] = i
	return off + 1, nil
}

func unpackUint16(msg []byte, off int) (i uint16, off1 int, err error) {
	if off+2 > len(msg) {
		return 0, len(msg), errors.New("overflow unpacking uint16")
	}
	return binary.BigEndian.Uint16(msg[off:]), off + 2, nil
}

func packUint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), errors.New("overflow packing uint16")
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}
