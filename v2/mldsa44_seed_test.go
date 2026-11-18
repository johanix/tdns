/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * ML-DSA-44 keys stored in RFC 9881's PKCS#8 forms load through the
 * keystore's read path.
 */
package tdns

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/johanix/dnssec-algorithms/mldsakey"
	"github.com/miekg/dns"
)

// mldsa44Testdata reads a file from v2/algorithms/mldsa44/testdata: RFC
// 9881's ML-DSA-44 example keys (seed 000102...1e1f) and the DNSKEY of
// draft-schlyter-dnssec-jwk Appendix A.4, which is the same key.
func mldsa44Testdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("algorithms", "mldsa44", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestMLDSA44RFC9881KeysLoad: each RFC 9881 form of the example key
// loads from a keystore row and signs for the A.4 DNSKEY (algorithm 18,
// key tag 59828).
func TestMLDSA44RFC9881KeysLoad(t *testing.T) {
	dnskeyStr := mldsa44Testdata(t, "jwk-a4-dnskey.txt")
	rr, err := dns.NewRR(dnskeyStr)
	if err != nil {
		t.Fatalf("A.4 DNSKEY does not parse: %v", err)
	}
	key := rr.(*dns.DNSKEY)
	if key.KeyTag() != 59828 {
		t.Fatalf("A.4 DNSKEY key tag %d, want 59828", key.KeyTag())
	}
	txt, err := dns.NewRR("example.com. 3600 IN TXT \"hello\"")
	if err != nil {
		t.Fatal(err)
	}
	rfcSeed := make([]byte, mldsakey.SeedSize)
	for i := range rfcSeed {
		rfcSeed[i] = byte(i)
	}

	for _, form := range []string{"seed", "expanded", "both"} {
		t.Run(form, func(t *testing.T) {
			stored := mldsa44Testdata(t, "rfc9881-mldsa44-"+form+".pem")
			pkc, alg, err := PrivateKeyCacheFromDB(stored, "MLDSA44", dnskeyStr)
			if err != nil {
				t.Fatalf("PrivateKeyCacheFromDB: %v", err)
			}
			if alg != 18 || pkc.CS == nil {
				t.Fatalf("algorithm %d, signer %v; want 18 and a signer", alg, pkc.CS)
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
				t.Fatalf("sign: %v", err)
			}
			if err := sig.Verify(key, []dns.RR{txt}); err != nil {
				t.Fatalf("signature does not verify against the A.4 DNSKEY: %v", err)
			}

			// The read path re-encodes the key (PrepareKeyCache). A key
			// that came with its seed must still have it.
			block, _ := pem.Decode([]byte(pkc.PrivateKeyPEM))
			if block == nil {
				t.Fatal("key cache has no PEM")
			}
			seed, ok, err := mldsakey.Seed(block.Bytes)
			if err != nil {
				t.Fatalf("mldsakey.Seed on the re-encoded key: %v", err)
			}
			if wantSeed := form != "expanded"; ok != wantSeed {
				t.Errorf("re-encoded key has a seed: %v, want %v", ok, wantSeed)
			}
			if ok && !bytes.Equal(seed, rfcSeed) {
				t.Errorf("re-encoded key has seed %x, want %x", seed, rfcSeed)
			}
		})
	}

	// RFC 9881 Appendix C.4's first key: both form, halves disagree.
	if _, _, err := PrivateKeyCacheFromDB(mldsa44Testdata(t, "rfc9881-mldsa44-inconsistent-1.pem"), "MLDSA44", dnskeyStr); err == nil {
		t.Error("a both-form key whose seed and expanded key disagree was loaded")
	}
}

// TestMLDSA44KeystoreGenerateKeepsSeed: a key tdns generates into its
// keystore is stored with its seed, so it can later be exported in a
// seed-only format such as JWK.
func TestMLDSA44KeystoreGenerateKeepsSeed(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "mldsa44.example."
	if _, _, err := kdb.GenerateKeypair(zone, "test", DnskeyStateActive, dns.TypeDNSKEY, 18, "KSK", nil); err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	dak, err := kdb.GetDnssecKeys(zone, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeys: %v", err)
	}
	if len(dak.KSKs) != 1 {
		t.Fatalf("got %d KSKs, want 1", len(dak.KSKs))
	}
	block, _ := pem.Decode([]byte(dak.KSKs[0].PrivateKeyPEM))
	if block == nil {
		t.Fatal("stored key is not PEM")
	}
	k, err := mldsakey.Parse(block.Bytes)
	if err != nil {
		t.Fatalf("mldsakey.Parse: %v", err)
	}
	if k.Form != mldsakey.FormSeed {
		t.Errorf("generated key is stored in %s form, want seed", k.Form)
	}
}
