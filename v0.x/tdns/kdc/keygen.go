/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * DNSSEC key generation for tdns-kdc
 */

package kdc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
)

// GenerateDNSSECKey generates a DNSSEC key (KSK, ZSK, or CSK) for a zone
// Returns the generated DNSSECKey struct ready for database storage
func (kdc *KdcDB) GenerateDNSSECKey(zoneName string, keyType KeyType, algorithm uint8, comment string) (*DNSSECKey, error) {
	// Validate algorithm
	if _, exist := dns.AlgorithmToString[algorithm]; !exist {
		return nil, fmt.Errorf("unknown algorithm: %d", algorithm)
	}

	// Validate key type
	if keyType != KeyTypeKSK && keyType != KeyTypeZSK && keyType != KeyTypeCSK {
		return nil, fmt.Errorf("unknown key type: %s (must be KSK, ZSK, or CSK)", keyType)
	}

	// Determine key size based on algorithm
	var bits int
	switch algorithm {
	case dns.ECDSAP256SHA256, dns.ED25519:
		bits = 256
	case dns.ECDSAP384SHA384:
		bits = 384
	case dns.RSASHA256, dns.RSASHA512:
		bits = 2048
	default:
		return nil, fmt.Errorf("unsupported algorithm for key generation: %d", algorithm)
	}

	// Create DNSKEY record
	dnskey := new(dns.DNSKEY)
	dnskey.Algorithm = algorithm
	dnskey.Protocol = 3
	dnskey.Flags = 256 // Default to ZSK
	if keyType == KeyTypeKSK || keyType == KeyTypeCSK {
		dnskey.Flags = 257 // KSK flag
	}

	dnskey.Header().Name = dns.Fqdn(zoneName)
	dnskey.Header().Rrtype = dns.TypeDNSKEY
	dnskey.Header().Class = dns.ClassINET
	dnskey.Header().Ttl = 3600

	// Generate the keypair
	privkey, err := dnskey.Generate(bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %v", err)
	}

	// Convert private key to PEM format for storage
	var pk crypto.PrivateKey
	switch privkey := privkey.(type) {
	case *rsa.PrivateKey:
		pk = privkey
	case ed25519.PrivateKey:
		pk = privkey
	case *ecdsa.PrivateKey:
		pk = privkey
	default:
		return nil, fmt.Errorf("unknown private key type: %T", privkey)
	}

	// Convert to PEM format
	privkeyPEM, err := privateKeyToPEM(pk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key to PEM: %v", err)
	}

	// Get key ID (KeyTag)
	keyID := dnskey.KeyTag()

	// Create key ID string for database (just the keytag)
	keyIDStr := fmt.Sprintf("%d", keyID)

	// Create DNSSECKey struct
	key := &DNSSECKey{
		ID:        keyIDStr,
		ZoneName:  zoneName,
		KeyType:   keyType,
		KeyID:     keyID,
		Algorithm: algorithm,
		Flags:     dnskey.Flags,
		PublicKey: dnskey.String(),        // DNSKEY RR string
		PrivateKey: []byte(privkeyPEM),     // PEM-encoded private key
		State:     KeyStateCreated,
		CreatedAt: time.Now(),
		Comment:   comment,
	}

	log.Printf("Generated %s key for zone %s: KeyID=%d, Algorithm=%d, Flags=%d",
		keyType, zoneName, keyID, algorithm, dnskey.Flags)

	return key, nil
}

// privateKeyToPEM converts a crypto.PrivateKey to PKCS#8 PEM format.
// This is a duplicate of tdns.PrivateKeyToPEM to avoid import cycles.
func privateKeyToPEM(privkey crypto.PrivateKey) (string, error) {
	if privkey == nil {
		return "", fmt.Errorf("private key is nil")
	}

	// Marshal the private key to PKCS#8 DER format
	derBytes, err := x509.MarshalPKCS8PrivateKey(privkey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key to PKCS#8: %v", err)
	}

	// Encode to PEM format
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes), nil
}

