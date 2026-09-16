/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Ed448 (RFC 8080) through tdns's own key paths: the registration in
 * v2/algorithms, key generation into the keystore, PKCS#8 PEM storage, the
 * signing-key load, and bind-format conversion of a key another signer wrote.
 */

package tdns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/johanix/tdns/v2/algorithms"
)

// domainEd448Pub and domainEd448Priv are Ktest.+016+07379 from NLnet Labs' domain crate
// (test-data/dnssec-keys, BSD-3-Clause): an Ed448 key pair written by the
// library Cascade and dnst use, in their Private-key-format v1.2.
const (
	domainEd448Pub  = "test.	IN	DNSKEY	257 3 16 9tIYxOhfSE0dS7m9mVxjgMeWJ5arrusV9VSvxYrbJVhucOm6I35HpHi4Eau5P06vpHaMdbp3aFOA ;{id = 7379 (ksk), size = 456b}\n"
	domainEd448Priv = "Private-key-format: v1.2\nAlgorithm: 16 (ED448)\nPrivateKey: /hmHKRERsvW761FDTmGlCBJNmy1H8pbsU2LeV1NP2wb0xM286RFIyUMAwRmkFqPVZwwfQluIBXqe\n"
)

// Ed448 is registered for real in every binary: listed, and wired into
// miekg/dns so it can generate, sign and verify.
func TestEd448RegisteredForReal(t *testing.T) {
	caps, ok := algorithms.CapsReal(dns.ED448)
	if !ok {
		t.Fatal("ED448 is not registered as a real algorithm")
	}
	if !caps.ForDNSSEC || !caps.ForKSK || !caps.ForZSK || !caps.ForSIG0 {
		t.Errorf("ED448 capabilities = %+v, want every role", caps)
	}
	if name := dns.AlgorithmToString[dns.ED448]; name != "ED448" {
		t.Errorf("AlgorithmToString[16] = %q, want ED448", name)
	}
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 256, Protocol: 3, Algorithm: dns.ED448}
	if _, err := k.Generate(0); err != nil {
		t.Fatalf("miekg/dns cannot generate an ED448 key, so it is listed but not wired in: %v", err)
	}
}

// A key tdns generates into its keystore is stored as PEM, loads back as a
// signing key, and signs RRsets that verify.
func TestEd448KeystoreGenerateLoadSign(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "ed448.example."
	if _, _, err := kdb.GenerateKeypair(zone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED448, "KSK", nil); err != nil {
		t.Fatalf("GenerateKeypair KSK: %v", err)
	}
	if _, _, err := kdb.GenerateKeypair(zone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED448, "ZSK", nil); err != nil {
		t.Fatalf("GenerateKeypair ZSK: %v", err)
	}

	dak, err := kdb.GetDnssecKeys(zone, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeys: %v", err)
	}
	if len(dak.KSKs) != 1 || len(dak.ZSKs) != 1 {
		t.Fatalf("got %d KSKs and %d ZSKs, want 1 and 1", len(dak.KSKs), len(dak.ZSKs))
	}
	for _, pkc := range []*PrivateKeyCache{dak.KSKs[0], dak.ZSKs[0]} {
		if !IsPEMFormat(pkc.PrivateKeyPEM) {
			t.Errorf("keyid %d: private key is not stored as PEM", pkc.KeyId)
		}
		signAndVerifyEd448(t, pkc)
	}
}

// A bind-format Ed448 key written by domain (v1.2) becomes PKCS#8 PEM, and the
// PEM decodes back to a key that signs for the published DNSKEY.
func TestEd448DomainKeyToPEM(t *testing.T) {
	pkc, err := PrepareKeyCache(domainEd448Priv, domainEd448Pub)
	if err != nil {
		t.Fatalf("PrepareKeyCache: %v", err)
	}
	if pkc.KeyId != 7379 || pkc.Algorithm != dns.ED448 {
		t.Fatalf("keyid %d algorithm %d, want 7379 and 16", pkc.KeyId, pkc.Algorithm)
	}
	if err := VerifyKeyPairCorrespondence(pkc.CS, &pkc.DnskeyRR); err != nil {
		t.Fatalf("the private key does not belong to the DNSKEY: %v", err)
	}

	if _, err := PEMToPrivateKey(pkc.PrivateKeyPEM); err != nil {
		t.Fatalf("PEMToPrivateKey: %v", err)
	}
	fromPEM, err := PrepareKeyCache(pkc.PrivateKeyPEM, domainEd448Pub)
	if err != nil {
		t.Fatalf("PrepareKeyCache from PEM: %v", err)
	}
	if fromPEM.PrivateKeyPEM != pkc.PrivateKeyPEM {
		t.Error("PEM does not round-trip unchanged")
	}
	signAndVerifyEd448(t, fromPEM)
}

// bulk-convert takes a directory holding domain's Ed448 key to a pre-loadable
// export directory, and pre-load puts it in the keystore as a signing key.
func TestEd448BindConvertAndPreload(t *testing.T) {
	dir := t.TempDir()
	base := KeyFileBasename("test.", dns.ED448, 7379)
	if err := os.WriteFile(filepath.Join(dir, base+".key"), []byte(domainEd448Pub), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, base+".private"), []byte(domainEd448Priv), 0600); err != nil {
		t.Fatal(err)
	}

	ds, err := ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", DefaultState: DnskeyStateActive})
	if err != nil {
		t.Fatalf("ConvertBindKeyDir: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BindConvertConverted {
		t.Fatalf("dispositions = %+v, want one converted key", ds)
	}

	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Keystore.Preload.Dnssec = dir
	if err := conf.PreloadKeystore(context.Background()); err != nil {
		t.Fatalf("PreloadKeystore: %v", err)
	}
	dak, err := kdb.GetDnssecKeys("test.", DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeys: %v", err)
	}
	if len(dak.KSKs) != 1 || dak.KSKs[0].KeyId != 7379 {
		t.Fatalf("pre-loaded KSKs = %+v, want keyid 7379", dak.KSKs)
	}
	signAndVerifyEd448(t, dak.KSKs[0])
}

func signAndVerifyEd448(t *testing.T, pkc *PrivateKeyCache) {
	t.Helper()
	dnskey := &pkc.DnskeyRR
	rrset := []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: dnskey.Hdr.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"ed448"},
	}}
	now := time.Now()
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: dnskey.Hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ED448,
		Inception:  uint32(now.Add(-time.Hour).Unix()),
		Expiration: uint32(now.Add(time.Hour).Unix()),
		KeyTag:     dnskey.KeyTag(),
		SignerName: dnskey.Hdr.Name,
	}
	if err := sig.Sign(pkc.CS, rrset); err != nil {
		t.Fatalf("keyid %d: Sign: %v", pkc.KeyId, err)
	}
	if err := sig.Verify(dnskey, rrset); err != nil {
		t.Fatalf("keyid %d: Verify: %v", pkc.KeyId, err)
	}
}
