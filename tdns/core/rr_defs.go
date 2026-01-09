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
	TypeJSONMANIFEST = 65013 // 0xFDF5 - JSON Distribution Manifest
	TypeJSONCHUNK   = 65014 // 0xFDF6 - Chunked JSON Data Transport
)

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
