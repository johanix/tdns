/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"crypto"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

// TestMLDSA44PKCS8RoundTrip generates an ML-DSA-44 key, encodes it to
// PKCS#8 PEM via PrivateKeyToPEM, parses it back via PEMToPrivateKey,
// and confirms the round-tripped key signs and verifies a SIG(0).
func TestMLDSA44PKCS8RoundTrip(t *testing.T) {
	keyrr := &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "sig0-mldsa44.example.",
			Rrtype: dns.TypeKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.MLDSA44,
	}}
	priv, err := keyrr.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sk, ok := priv.(*mldsa44.PrivateKey)
	if !ok {
		t.Fatalf("Generate returned %T, want *mldsa44.PrivateKey", priv)
	}

	pemStr, err := PrivateKeyToPEM(sk)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM: %v", err)
	}
	if !IsPEMFormat(pemStr) {
		t.Fatalf("IsPEMFormat returned false for round-tripped PEM")
	}

	parsed, err := PEMToPrivateKey(pemStr)
	if err != nil {
		t.Fatalf("PEMToPrivateKey: %v", err)
	}
	sk2, ok := parsed.(*mldsa44.PrivateKey)
	if !ok {
		t.Fatalf("PEMToPrivateKey returned %T, want *mldsa44.PrivateKey", parsed)
	}
	if !sk.Equal(sk2) {
		t.Errorf("round-tripped key does not equal original")
	}

	// End-to-end: sign a SIG(0) with the round-tripped key, verify.
	m := new(dns.Msg)
	m.SetUpdate("example.")
	now := uint32(time.Now().Unix())
	sigrr := &dns.SIG{RRSIG: dns.RRSIG{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY},
		Algorithm:  dns.MLDSA44,
		Expiration: now + 300,
		Inception:  now - 300,
		KeyTag:     keyrr.KeyTag(),
		SignerName: keyrr.Hdr.Name,
	}}
	mb, err := sigrr.Sign(sk2, m)
	if err != nil {
		t.Fatalf("sign with round-tripped key: %v", err)
	}
	if err := sigrr.Verify(keyrr, mb); err != nil {
		t.Errorf("verify with round-tripped key: %v", err)
	}

	// Sanity: a classical ECDSA key still round-trips through the
	// unchanged x509 path.
	ec := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "ecdsa.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	ecPriv, err := ec.Generate(256)
	if err != nil {
		t.Fatalf("ECDSA Generate: %v", err)
	}
	ecPEM, err := PrivateKeyToPEM(ecPriv.(crypto.PrivateKey))
	if err != nil {
		t.Fatalf("ECDSA PrivateKeyToPEM: %v", err)
	}
	if _, err := PEMToPrivateKey(ecPEM); err != nil {
		t.Errorf("ECDSA round-trip broken: %v", err)
	}
}
