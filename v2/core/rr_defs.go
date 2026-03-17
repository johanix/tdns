/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package core

import (
	"encoding/binary"
	"errors"
)

const TypeDSYNC = 0x0042 // 66 is the official IANA code

// All experimental types use the private use range (65280-65534).
const (
	TypeNOTIFY       = 65280 // OBE, replaced by DSYNC (RFC 9859)
	TypeMSIGNER      = 65281 // OBE, replaced by HSYNC
	TypeHSYNC        = 65282 // Legacy provider enrollment
	TypeHSYNC2       = 65283 // Legacy provider enrollment (string flags)
	TypeTSYNC        = 65284 // Transfer sync
	TypeHSYNC3       = 65285 // Per-provider enrollment
	TypeHSYNCPARAM   = 65286 // Zone-wide multi-provider policy
	TypeCHUNK        = 65288 // Unified Chunk/Manifest
	TypeJSONMANIFEST = 65289 // Older version of CHUNK
	TypeJSONCHUNK    = 65289 // Older version of CHUNK
)

// Format constants for CHUNK RR type
const (
	FormatJSON = 1 // JSON format (original format)
	FormatJWT  = 2 // JWT format (signed manifest with flattened claims)
	// Future formats can be added as needed:
	// FormatBinary = 3  // Example: binary format
	// FormatProtobuf = 4 // Example: protobuf format
)

// FormatToString maps format constants to their string representations
var FormatToString = map[uint8]string{
	FormatJSON: "JSON",
	FormatJWT:  "JWT",
	// Future formats:
	// FormatBinary: "BINARY",
	// FormatProtobuf: "PROTOBUF",
}

// StringToFormat maps string representations to format constants (reverse of FormatToString)
// NOTE: This map must be kept in sync with FormatToString - when adding a new format to FormatToString,
// also add the corresponding entry here.
var StringToFormat = map[string]uint8{
	"JSON": FormatJSON,
	"JWT":  FormatJWT,
	// Future formats will be added here when FormatToString is updated:
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
