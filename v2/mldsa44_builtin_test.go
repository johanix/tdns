/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * ML-DSA-44 is built into tdns (v2/algorithms/mldsa44). Keys minted, and
 * data signed, by the dnssec-algorithms package it came from keep working.
 */
package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func mldsa44Fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "mldsa44-before-move", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The fixture was made by github.com/johanix/dnssec-algorithms/mldsa44 (see
// its README). In this test binary nothing registers ML-DSA-44 but
// v2/algorithms, so every step below goes through the built-in.
func TestMLDSA44KeyMintedBeforeTheMove(t *testing.T) {
	dnskeyStr := strings.TrimSpace(mldsa44Fixture(t, "dnskey.txt"))
	rr, err := dns.NewRR(dnskeyStr)
	if err != nil {
		t.Fatalf("fixture DNSKEY does not parse: %v", err)
	}
	key := rr.(*dns.DNSKEY)
	if key.Algorithm != 18 {
		t.Fatalf("fixture DNSKEY algorithm = %d, want 18", key.Algorithm)
	}

	lines := strings.Split(strings.TrimSpace(mldsa44Fixture(t, "signed.txt")), "\n")
	if len(lines) != 2 {
		t.Fatalf("signed.txt has %d lines, want a TXT and its RRSIG", len(lines))
	}
	txt, err := dns.NewRR(lines[0])
	if err != nil {
		t.Fatalf("fixture TXT: %v", err)
	}
	sigRR, err := dns.NewRR(lines[1])
	if err != nil {
		t.Fatalf("fixture RRSIG: %v", err)
	}

	// A signature made before the move verifies.
	if err := sigRR.(*dns.RRSIG).Verify(key, []dns.RR{txt}); err != nil {
		t.Fatalf("RRSIG made by the old package does not verify: %v", err)
	}

	// The stored key loads through the keystore's read path, both as the
	// PKCS#8 PEM the keystore writes and as a legacy bare-base64 row, and
	// signs; the signature verifies against the old DNSKEY.
	var legacy string
	for _, l := range strings.Split(mldsa44Fixture(t, "private.bind"), "\n") {
		if v, ok := strings.CutPrefix(l, "PrivateKey: "); ok {
			legacy = strings.TrimSpace(v)
		}
	}
	if legacy == "" {
		t.Fatal("private.bind has no PrivateKey line")
	}
	for _, tc := range []struct {
		name   string
		stored string
	}{
		{"PKCS#8 PEM", mldsa44Fixture(t, "private.pem")},
		{"legacy base64", legacy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkc, alg, err := PrivateKeyCacheFromDB(tc.stored, "MLDSA44", dnskeyStr)
			if err != nil {
				t.Fatalf("PrivateKeyCacheFromDB: %v", err)
			}
			if alg != 18 || pkc.Algorithm != 18 {
				t.Errorf("algorithm = %d (cache %d), want 18", alg, pkc.Algorithm)
			}
			if pkc.CS == nil {
				t.Fatal("no crypto.Signer in the key cache")
			}
			now := uint32(time.Now().Unix())
			sig := &dns.RRSIG{
				Hdr:        dns.RR_Header{Name: key.Hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
				Algorithm:  18,
				KeyTag:     key.KeyTag(),
				SignerName: key.Hdr.Name,
				Inception:  now - 300,
				Expiration: now + 300,
			}
			if err := sig.Sign(pkc.CS, []dns.RR{txt}); err != nil {
				t.Fatalf("sign with the stored key: %v", err)
			}
			if err := sig.Verify(key, []dns.RR{txt}); err != nil {
				t.Fatalf("new signature does not verify against the old DNSKEY: %v", err)
			}
		})
	}
}
