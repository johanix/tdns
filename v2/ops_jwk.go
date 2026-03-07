/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Operations for publishing JWK (JSON Web Key) records.
 * Provides helper functions for adding JWK RRs to zones.
 */

package tdns

import (
	"crypto"
	"fmt"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// PublishJWKRR publishes a JWK record for the specified owner and public key.
// The public key is encoded to RFC 7517 JWK format and published as a JWK RR.
//
// Parameters:
//   - owner: The DNS name for the JWK record (typically the agent identity)
//   - publicKey: The crypto.PublicKey to encode and publish
//   - use: The intended use ("" to omit, "sig" for signing, "enc" for encryption)
//
// Returns error if encoding fails or zone update fails.
func (zd *ZoneData) PublishJWKRR(owner string, publicKey crypto.PublicKey, use string) error {
	if publicKey == nil {
		return fmt.Errorf("PublishJWKRR: public key is nil")
	}

	// Encode public key to JWK format with optional "use" field
	jwkData, algorithm, err := core.EncodePublicKeyToJWK(publicKey, use)
	if err != nil {
		return fmt.Errorf("PublishJWKRR: failed to encode public key to JWK: %w", err)
	}

	useInfo := "dual-use"
	if use != "" {
		useInfo = fmt.Sprintf("use=%s", use)
	}

	lgHandler.Info("PublishJWKRR: encoded public key to JWK",
		"owner", owner, "algorithm", algorithm, "use", useInfo, "size", len(jwkData))

	// Validate the encoded JWK before publishing
	if err := core.ValidateJWK(jwkData); err != nil {
		return fmt.Errorf("PublishJWKRR: encoded JWK is invalid: %w", err)
	}

	// Create JWK RR with generator function for proper copying
	jwkRR := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(owner),
			Rrtype: core.TypeJWK,
			Class:  dns.ClassINET,
			Ttl:    3600, // 1 hour TTL for public keys
		},
		Data: &core.JWK{
			JWKData: jwkData,
		},
	}
	// Set the generator function - required for dns.Copy() to work
	// This is normally set by PrivateHandle during parsing, but must be set manually
	// when creating PrivateRR programmatically
	jwkRR = &dns.PrivateRR{
		Hdr:  jwkRR.Hdr,
		Data: jwkRR.Data,
	}
	// Access the internal generator through reflection or use the registered one
	// Actually, we need to use the TypeToRR function to get a properly initialized RR
	tempRR := dns.TypeToRR[core.TypeJWK]()
	var ok bool
	jwkRR, ok = tempRR.(*dns.PrivateRR)
	if !ok {
		return fmt.Errorf("PublishJWKRR: TypeToRR returned unexpected type %T (expected *dns.PrivateRR)", tempRR)
	}
	jwkRR.Hdr = dns.RR_Header{
		Name:   dns.Fqdn(owner),
		Rrtype: core.TypeJWK,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	jwkInner, ok := jwkRR.Data.(*core.JWK)
	if !ok {
		return fmt.Errorf("PublishJWKRR: PrivateRR.Data has unexpected type %T (expected *core.JWK)", jwkRR.Data)
	}
	jwkInner.JWKData = jwkData

	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("PublishJWKRR: KeyDB.UpdateQ is nil")
	}

	// Send update request to zone
	updateRequest := UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{jwkRR},
		InternalUpdate: true, // Internal update, bypass external validation
	}

	select {
	case zd.KeyDB.UpdateQ <- updateRequest:
		lgHandler.Info("PublishJWKRR: successfully queued JWK record", "owner", owner, "algorithm", algorithm, "use", useInfo)
		return nil
	default:
		return fmt.Errorf("PublishJWKRR: failed to send update request (channel full)")
	}
}

// PublishJWKFromKeyRR publishes a JWK record by extracting the public key from a KEY RR.
// This is useful for migrating existing KEY records to JWK format.
//
// Parameters:
//   - owner: The DNS name for the JWK record
//   - keyRR: The existing KEY record containing the public key
//
// Returns error if key extraction or encoding fails.
func (zd *ZoneData) PublishJWKFromKeyRR(owner string, keyRR *dns.KEY) error {
	if keyRR == nil {
		return fmt.Errorf("PublishJWKFromKeyRR: KEY RR is nil")
	}

	// Extract public key from KEY RR
	// Note: This requires converting the KEY wire format back to crypto.PublicKey
	// The miekg/dns library stores the key in keyRR.PublicKey as a base64 string
	// We need to decode and reconstruct the actual key

	// For now, return an error indicating this needs implementation
	// TODO: Implement KEY to crypto.PublicKey conversion based on algorithm
	return fmt.Errorf("PublishJWKFromKeyRR: KEY to JWK migration not yet implemented (algorithm %d)", keyRR.Algorithm)
}
