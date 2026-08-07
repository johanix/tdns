/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// genDnskey returns a real keypair plus its PKCS#8 PEM.
func genDnskey(t *testing.T, zone string, flags uint16, alg uint8) (*dns.DNSKEY, string) {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: alg,
	}
	bits := 256
	if alg == dns.RSASHA256 {
		bits = 2048
	}
	priv, err := k.Generate(bits)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pem, err := PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("to PEM: %v", err)
	}
	return k, pem
}

// The check must accept a matched pair and reject a swapped one. Rejecting the
// swap is the entire reason it exists: every other check in the import path is
// metadata, and metadata cannot tell that zone A's public key has been filed
// beside zone B's private key.
func TestVerifyKeyPairCorrespondence(t *testing.T) {
	for _, alg := range []uint8{dns.ED25519, dns.ECDSAP256SHA256, dns.RSASHA256} {
		name := dns.AlgorithmToString[alg]
		t.Run(name+"/matched pair is accepted", func(t *testing.T) {
			k, pem := genDnskey(t, "pq.dnslab.", 257, alg)
			ok, err := VerifyStoredKeyPair(pem, k)
			if !ok {
				t.Fatalf("%s should be loadable by this binary", name)
			}
			if err != nil {
				t.Fatalf("a matched pair must verify: %v", err)
			}
		})

		t.Run(name+"/swapped pair is rejected", func(t *testing.T) {
			kA, _ := genDnskey(t, "a.dnslab.", 257, alg)
			_, pemB := genDnskey(t, "b.dnslab.", 257, alg)
			ok, err := VerifyStoredKeyPair(pemB, kA)
			if !ok {
				t.Fatalf("%s should be loadable by this binary", name)
			}
			if err == nil {
				t.Fatal("zone A's public key filed with zone B's private key must be refused")
			}
		})
	}
}

// A SIG(0) KEY has flags 512 and therefore no ZONE bit. RRSIG.Verify refuses
// any key without it, so verifying against the KEY directly would fail for
// every SIG(0) key whether or not the halves correspond -- which would have
// made the check reject every SIG(0) import instead of only the broken ones.
func TestVerifyKeyPairCorrespondenceHandlesSig0Keys(t *testing.T) {
	mk := func(zone string) (*dns.KEY, string) {
		t.Helper()
		k := &dns.KEY{DNSKEY: dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     512, // no ZONE bit, which is the point
			Protocol:  3,
			Algorithm: dns.ED25519,
		}}
		priv, err := k.Generate(256)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		pem, err := PrivateKeyToPEM(priv)
		if err != nil {
			t.Fatalf("to PEM: %v", err)
		}
		return k, pem
	}

	// checked is asserted, not discarded. VerifyStoredKeyPair returns
	// (false, nil) for a key it cannot load, so ignoring it lets this test pass
	// green while verifying nothing at all -- which is precisely the failure it
	// exists to guard against, since the ZONE-flag bug made every SIG(0) key
	// fail and a test that never ran would not have noticed.
	kA, pemA := mk("agent.dnslab.")
	checked, err := VerifyStoredKeyPair(pemA, &kA.DNSKEY)
	if !checked {
		t.Fatal("the SIG(0) key must actually have been checked, not skipped as unloadable")
	}
	if err != nil {
		t.Fatalf("a matched SIG(0) pair must verify despite the missing ZONE flag: %v", err)
	}

	_, pemB := mk("other.dnslab.")
	checked, err = VerifyStoredKeyPair(pemB, &kA.DNSKEY)
	if !checked {
		t.Fatal("the swapped SIG(0) key must actually have been checked")
	}
	if err == nil {
		t.Fatal("a swapped SIG(0) pair must be refused")
	}
}

// checked=false means "this binary cannot load that algorithm", not "the key is
// fine". The import path relies on that distinction: a key whose algorithm is
// not linked must still restore, or pre-load stops being safe to run before any
// zone is bound.
func TestVerifyStoredKeyPairReportsWhenItCannotCheck(t *testing.T) {
	k, _ := genDnskey(t, "pq.dnslab.", 257, dns.ED25519)

	for _, tc := range []struct{ name, pem string }{
		{"empty", ""},
		{"not PEM at all", "Private-key-format: v1.3\nAlgorithm: 15 (ED25519)\n"},
		{"PEM armour, unusable contents", "-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checked, err := VerifyStoredKeyPair(tc.pem, k)
			if checked {
				t.Errorf("should report that it could not check, got checked=true")
			}
			if err != nil {
				t.Errorf("an uncheckable key must not be reported as WRONG: %v", err)
			}
		})
	}
}

// The swap has to be caught at the import boundary, not merely by the helper:
// bulk import is how key material actually reaches the keystore.
func TestBulkImportRefusesMismatchedKeyPair(t *testing.T) {
	kdb := newTestKeyDB(t)

	good := testDnssecKey(t, "pq.dnslab.", 257)
	other := testDnssecKey(t, "other.dnslab.", 257)

	// Zone pq's public key, zone other's private key. Every metadata check
	// passes: the owner, keytag, flags and algorithm all still describe the
	// public half correctly.
	swapped := good
	swapped.PrivateKey = other.PrivateKey

	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{swapped}, false); err == nil {
		t.Fatal("bulk import must refuse a private key that does not match its public key")
	}
	got, err := kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a refused key must not reach the keystore: %+v", got)
	}

	// The matched original still imports, so the check is not simply refusing
	// everything.
	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{good}, false); err != nil {
		t.Fatalf("a matched pair must still import: %v", err)
	}
}
