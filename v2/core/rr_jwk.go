/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * JWK DNS Resource Record implementation for miekg/dns library.
 * Provides a generic facility for publishing JSON Web Keys (RFC 7517) in DNS.
 */

package core

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// TypeJWK is the DNS type code for JWK records.
// Using private use range for testing. IANA allocation should be requested for production.
const TypeJWK = 0xFF2C // 65324 in decimal (private use range 65280-65534)

func init() {
	RegisterJWKRR()
}

// JWK represents the RDATA for a JWK DNS record.
// The RDATA contains a base64url-encoded JSON Web Key per RFC 7517.
//
// Zone file format:
//
//	owner TTL IN TYPE65324 \# length hexdata
//	OR (if registered):
//	owner TTL IN JWK "base64url-encoded-jwk-json"
type JWK struct {
	JWKData string // base64url-encoded JWK JSON
}

// NewJWK creates a new JWK PrivateRdata
func NewJWK() dns.PrivateRdata {
	return new(JWK)
}

// String returns the string representation for zone files
func (rd *JWK) String() string {
	if rd.JWKData == "" {
		return ""
	}
	// Return quoted base64url string
	return fmt.Sprintf(`"%s"`, rd.JWKData)
}

// Parse parses the JWK RDATA from zone file format
// Expected format: "base64url-encoded-jwk-json"
func (rd *JWK) Parse(txt []string) error {
	if len(txt) != 1 {
		return errors.New("JWK requires exactly one argument (quoted base64url-encoded JWK)")
	}

	// Remove quotes if present
	data := txt[0]
	if len(data) >= 2 && data[0] == '"' && data[len(data)-1] == '"' {
		data = data[1 : len(data)-1]
	}

	// Validate that it's valid base64url
	_, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return fmt.Errorf("JWK parse: invalid base64url data: %v", err)
	}

	rd.JWKData = data
	return nil
}

// Pack packs the JWK RDATA into wire format
func (rd *JWK) Pack(buf []byte) (int, error) {
	// Pack as a length-prefixed string (uint16 length)
	// Use existing packString function from rr_tsync.go
	return packString(rd.JWKData, buf, 0)
}

// Unpack unpacks the JWK RDATA from wire format
func (rd *JWK) Unpack(buf []byte) (int, error) {
	// Unpack length-prefixed string (uint16 length)
	// Use existing unpackString function from rr_tsync.go
	data, n, err := unpackString(buf, 0)
	if err != nil {
		return 0, err
	}
	rd.JWKData = data
	return n, nil
}

// Copy returns a copy of the JWK RDATA
func (rd *JWK) Copy(dest dns.PrivateRdata) error {
	d, ok := dest.(*JWK)
	if !ok {
		return errors.New("dest is not *JWK")
	}
	d.JWKData = rd.JWKData
	return nil
}

// Len returns the wire format length
func (rd *JWK) Len() int {
	// Length of uint16 length prefix + string data
	return 2 + len(rd.JWKData)
}

// RegisterJWKRR registers the JWK type with miekg/dns
func RegisterJWKRR() {
	dns.PrivateHandle("JWK", TypeJWK, NewJWK)
}
