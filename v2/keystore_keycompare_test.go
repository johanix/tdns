/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/johanix/dnssec-algorithms/mldsakey"
	"github.com/miekg/dns"
)

// --- building other encodings of one key --------------------------------

func pemDERof(t *testing.T, s string) []byte {
	t.Helper()
	der := pemDER(s)
	if der == nil {
		t.Fatalf("not PEM: %q", s)
	}
	return der
}

// wrapPEM armours der with lines of width base64 characters (tdns and
// OpenSSL use 64; some tools use 76).
func wrapPEM(der []byte, width int) string {
	b64 := base64.StdEncoding.EncodeToString(der)
	var b strings.Builder
	b.WriteString("-----BEGIN PRIVATE KEY-----\n")
	for len(b64) > width {
		b.WriteString(b64[:width] + "\n")
		b64 = b64[width:]
	}
	b.WriteString(b64 + "\n-----END PRIVATE KEY-----\n")
	return b.String()
}

func derPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256        = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384        = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

// ecCompressedPEM writes an EC key as PKCS#8 whose inner SEC1 carries the
// public point in compressed form (and no curve, which the outer
// AlgorithmIdentifier names), as OpenSSL does with
// -pkeyopt ec_point_format:compressed.
func ecCompressedPEM(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	ek, err := priv.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	pub := ek.PublicKey().Bytes() // 0x04 || X || Y
	n := (len(pub) - 1) / 2
	compressed := append([]byte{0x02 | pub[len(pub)-1]&1}, pub[1:1+n]...)
	type sec1 struct {
		Version    int
		PrivateKey []byte
		PublicKey  asn1.BitString `asn1:"optional,explicit,tag:1"`
	}
	inner, err := asn1.Marshal(sec1{Version: 1, PrivateKey: ek.Bytes(),
		PublicKey: asn1.BitString{Bytes: compressed, BitLength: 8 * len(compressed)}})
	if err != nil {
		t.Fatal(err)
	}
	curve := oidP256
	if n == 48 {
		curve = oidP384
	}
	param, _ := asn1.Marshal(curve)
	der, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: oidECPublicKey, Parameters: asn1.RawValue{FullBytes: param}}, inner})
	if err != nil {
		t.Fatal(err)
	}
	return derPEM(der)
}

// mldsa44BothPEM and mldsa44ExpandedPEM are OpenSSL's default ("both":
// seed and expanded key) and priv-only ML-DSA encodings.
func mldsa44BothPEM(t *testing.T, sk *mldsa44.PrivateKey) string {
	t.Helper()
	der, err := mldsakey.MarshalBoth(mldsakey.MLDSA44, sk.Seed(), sk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return derPEM(der)
}

func mldsa44ExpandedPEM(t *testing.T, sk *mldsa44.PrivateKey) string {
	t.Helper()
	der, err := mldsakey.MarshalExpanded(mldsakey.MLDSA44, sk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return derPEM(der)
}

// pemVariant is one key whose stored PEM is not tdns's own text, as the
// live run found them.
type pemVariant struct {
	name string
	alg  uint8
	bits int
	text func(t *testing.T, k jwkTestKey) string
}

var pemVariants = []pemVariant{
	{"CRLF", dns.ECDSAP256SHA256, 256, func(t *testing.T, k jwkTestKey) string {
		return strings.ReplaceAll(k.privPEM, "\n", "\r\n")
	}},
	{"no-trailing-newline", dns.ED25519, 256, func(t *testing.T, k jwkTestKey) string {
		return strings.TrimRight(k.privPEM, "\n")
	}},
	{"text-before-BEGIN", dns.ED448, 0, func(t *testing.T, k jwkTestKey) string {
		return "ED448 Private-Key:\npriv:\n    00:01\n" + k.privPEM
	}},
	{"76-column", dns.RSASHA256, 2048, func(t *testing.T, k jwkTestKey) string {
		return wrapPEM(pemDERof(t, k.privPEM), 76)
	}},
	{"EC-compressed-point-P256", dns.ECDSAP256SHA256, 256, func(t *testing.T, k jwkTestKey) string {
		return ecCompressedPEM(t, k.priv.(*ecdsa.PrivateKey))
	}},
	{"EC-compressed-point-P384", dns.ECDSAP384SHA384, 384, func(t *testing.T, k jwkTestKey) string {
		return ecCompressedPEM(t, k.priv.(*ecdsa.PrivateKey))
	}},
	{"MLDSA44-both", 18, 0, func(t *testing.T, k jwkTestKey) string {
		return mldsa44BothPEM(t, k.priv.(*mldsa44.PrivateKey))
	}},
}

// collidingKeys returns two different Ed25519 keys for jwk.example. with
// the same keytag: the only way to offer "another key under the same
// keyid" that passes the private/public check.
func collidingKeys(t *testing.T, rrtype uint16) (jwkTestKey, jwkTestKey) {
	t.Helper()
	seen := map[uint16]jwkTestKey{}
	for i := 0; i < 20000; i++ {
		k := storedJWKTestKey(t, rrtype, dns.ED25519, 256)
		if prev, ok := seen[k.rr.KeyTag()]; ok {
			return prev, k
		}
		seen[k.rr.KeyTag()] = k
	}
	t.Fatal("no keytag collision found")
	return jwkTestKey{}, jwkTestKey{}
}

// --- the comparison itself ----------------------------------------------

func TestComparePrivateKeyPEMVariantsAreTheSameKey(t *testing.T) {
	for _, v := range pemVariants {
		t.Run(v.name, func(t *testing.T) {
			k := storedJWKTestKey(t, dns.TypeDNSKEY, v.alg, v.bits)
			other := v.text(t, k)
			if other == k.privPEM {
				t.Fatal("the variant is tdns's own text; the test proves nothing")
			}
			if c := comparePrivateKeyPEM(other, k.privPEM); c != keySame {
				t.Errorf("stored %s against tdns's PEM: %v, want the same key", v.name, c.detail())
			}
			if c := comparePrivateKeyPEM(k.privPEM, other); c != keySame {
				t.Errorf("tdns's PEM against offered %s: %v, want the same key", v.name, c.detail())
			}
		})
	}
}

func TestComparePrivateKeyPEMDifferentKeysDiffer(t *testing.T) {
	for _, f := range jwkFamilies {
		t.Run(f.name, func(t *testing.T) {
			a := storedJWKTestKey(t, dns.TypeDNSKEY, f.alg, f.bits)
			b := storedJWKTestKey(t, dns.TypeDNSKEY, f.alg, f.bits)
			if c := comparePrivateKeyPEM(a.privPEM, b.privPEM); c != keyDiffers {
				t.Errorf("two %s keys: %q, want privatekey", f.name, c.detail())
			}
		})
	}
	a := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	b := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ECDSAP256SHA256, 256)
	if c := comparePrivateKeyPEM(a.privPEM, b.privPEM); c != keyDiffers {
		t.Errorf("keys of two algorithms: %q", c.detail())
	}
}

// An ML-DSA key kept without its seed and the same key with one are the
// same key to sign with, but not the same row: the seed is what makes a
// JWK export possible, so the stored row is reported as lacking it. The
// other way round the stored row is the better one, and nothing differs.
func TestComparePrivateKeyPEMMLDSASeed(t *testing.T) {
	k := storedJWKTestKey(t, dns.TypeDNSKEY, 18, 0)
	sk := k.priv.(*mldsa44.PrivateKey)
	expanded := mldsa44ExpandedPEM(t, sk)
	both := mldsa44BothPEM(t, sk)

	if c := comparePrivateKeyPEM(expanded, k.privPEM); c != keyStoredWithoutSeed ||
		c.detail() != "privatekey (stored without seed)" {
		t.Errorf("stored expanded-only, offered seed: %q", c.detail())
	}
	if c := comparePrivateKeyPEM(expanded, both); c != keyStoredWithoutSeed {
		t.Errorf("stored expanded-only, offered both: %q", c.detail())
	}
	if c := comparePrivateKeyPEM(k.privPEM, expanded); c != keySame {
		t.Errorf("stored seed, offered expanded-only: %q", c.detail())
	}
	if c := comparePrivateKeyPEM(expanded, wrapPEM(pemDERof(t, expanded), 76)); c != keySame {
		t.Errorf("expanded-only against itself rewrapped: %q", c.detail())
	}
	other := storedJWKTestKey(t, dns.TypeDNSKEY, 18, 0)
	if c := comparePrivateKeyPEM(expanded, other.privPEM); c != keyDiffers {
		t.Errorf("stored expanded-only, another seeded key: %q, want privatekey", c.detail())
	}
}

// A PEM this binary cannot decode (an algorithm OID with no codec, a BIND
// blob) is compared as text, as before: equal text is the same, anything
// else differs.
func TestComparePrivateKeyPEMFallsBackToText(t *testing.T) {
	inner, _ := asn1.Marshal([]byte("not a key tdns knows"))
	der, _ := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}}, inner})
	unknown := derPEM(der)
	if _, err := PEMToPrivateKey(unknown); err == nil {
		t.Fatal("the unknown-OID key decodes; the test proves nothing")
	}
	if c := comparePrivateKeyPEM(unknown, unknown); c != keySame {
		t.Errorf("same undecodable text: %q", c.detail())
	}
	if c := comparePrivateKeyPEM(unknown, strings.ReplaceAll(unknown, "\n", "\r\n")); c != keyDiffers {
		t.Errorf("undecodable key in two texts: %q, want the text comparison's privatekey", c.detail())
	}
	k := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	if c := comparePrivateKeyPEM(unknown, k.privPEM); c != keyDiffers {
		t.Errorf("undecodable against decodable: %q", c.detail())
	}
	bind := "Private-key-format: v1.3\nAlgorithm: 15 (ED25519)\nPrivateKey: AAAA\n"
	if c := comparePrivateKeyPEM(bind, bind); c != keySame {
		t.Errorf("same BIND text: %q", c.detail())
	}
	if c := comparePrivateKeyPEM(bind, k.privPEM); c != keyDiffers {
		t.Errorf("BIND text against PEM: %q", c.detail())
	}
}

// --- bulk import ----------------------------------------------------------

// A key bulk-imported from a PEM in another encoding, then offered again as
// its JWK (which the daemon rebuilds in tdns's encoding), is unchanged, and
// the stored text stays as it was.
func TestBulkImportPEMThenJWKIsUnchanged(t *testing.T) {
	for _, v := range pemVariants {
		t.Run("DNSSEC/"+v.name, func(t *testing.T) {
			k := storedJWKTestKey(t, dns.TypeDNSKEY, v.alg, v.bits)
			text := v.text(t, k)
			kdb := newTestKeyDB(t)
			key := BulkDnssecKey{Zone: "jwk.example.", Keyid: k.rr.KeyTag(), Flags: k.rr.Flags,
				Algorithm: dns.AlgorithmToString[v.alg], State: DnskeyStateActive, Creator: "bulk",
				PrivateKey: text, KeyRR: k.keyRR}
			if ds, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, false); err != nil || ds[0].Status != BulkStatusImported {
				t.Fatalf("PEM import: %v %+v", err, ds)
			}
			j, err := JWKForExport(dns.TypeDNSKEY, k.keyRR, k.privPEM)
			if err != nil {
				t.Fatal(err)
			}
			key.PrivateKey, key.JWK, key.Creator = "", j, ""
			ds, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, false)
			if err != nil || ds[0].Status != BulkStatusUnchanged {
				t.Fatalf("JWK re-import: %v %+v", err, ds)
			}
			if got := readKeyStoreRow(t, kdb, "DnssecKeyStore", "jwk.example.", k.rr.KeyTag()); got.privkey != text {
				t.Error("an unchanged re-import rewrote the stored PEM")
			}
		})
		t.Run("SIG0/"+v.name, func(t *testing.T) {
			k := storedJWKTestKey(t, dns.TypeKEY, v.alg, v.bits)
			text := v.text(t, k)
			kdb := newTestKeyDB(t)
			key := BulkSig0Key{Zone: "jwk.example.", Keyid: k.rr.KeyTag(), Algorithm: dns.AlgorithmToString[v.alg],
				State: Sig0StateActive, Creator: "bulk", PrivateKey: text, KeyRR: k.keyRR}
			if ds, err := kdb.BulkImportSig0(nil, []BulkSig0Key{key}, false); err != nil || ds[0].Status != BulkStatusImported {
				t.Fatalf("PEM import: %v %+v", err, ds)
			}
			j, err := JWKForExport(dns.TypeKEY, k.keyRR, k.privPEM)
			if err != nil {
				t.Fatal(err)
			}
			key.PrivateKey, key.JWK, key.Creator = "", j, ""
			ds, err := kdb.BulkImportSig0(nil, []BulkSig0Key{key}, false)
			if err != nil || ds[0].Status != BulkStatusUnchanged {
				t.Fatalf("JWK re-import: %v %+v", err, ds)
			}
			if got := readKeyStoreRow(t, kdb, "Sig0KeyStore", "jwk.example.", k.rr.KeyTag()); got.privkey != text {
				t.Error("an unchanged re-import rewrote the stored PEM")
			}
		})
	}
}

func TestBulkImportDifferentKeySameKeyidConflicts(t *testing.T) {
	t.Run("DNSSEC", func(t *testing.T) {
		a, b := collidingKeys(t, dns.TypeDNSKEY)
		kdb := newTestKeyDB(t)
		mk := func(k jwkTestKey) BulkDnssecKey {
			return BulkDnssecKey{Zone: "jwk.example.", Keyid: k.rr.KeyTag(), Flags: k.rr.Flags, Algorithm: "ED25519",
				State: DnskeyStateActive, PrivateKey: k.privPEM, KeyRR: k.keyRR}
		}
		if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{mk(a)}, false); err != nil {
			t.Fatal(err)
		}
		ds, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{mk(b)}, false)
		if err != nil || ds[0].Status != BulkStatusConflict || ds[0].Detail != "privatekey, keyrr" {
			t.Fatalf("another key under keyid %d: %v %+v", a.rr.KeyTag(), err, ds)
		}
	})
	t.Run("SIG0", func(t *testing.T) {
		a, b := collidingKeys(t, dns.TypeKEY)
		kdb := newTestKeyDB(t)
		mk := func(k jwkTestKey) BulkSig0Key {
			return BulkSig0Key{Zone: "jwk.example.", Keyid: k.rr.KeyTag(), Algorithm: "ED25519",
				State: Sig0StateActive, PrivateKey: k.privPEM, KeyRR: k.keyRR}
		}
		if _, err := kdb.BulkImportSig0(nil, []BulkSig0Key{mk(a)}, false); err != nil {
			t.Fatal(err)
		}
		ds, err := kdb.BulkImportSig0(nil, []BulkSig0Key{mk(b)}, false)
		if err != nil || ds[0].Status != BulkStatusConflict || ds[0].Detail != "privatekey, keyrr" {
			t.Fatalf("another key under keyid %d: %v %+v", a.rr.KeyTag(), err, ds)
		}
	})
}

// A stored ML-DSA key without its seed is completed by a forced import of
// the same key with one, and not before.
func TestBulkImportMLDSAStoredWithoutSeed(t *testing.T) {
	k := storedJWKTestKey(t, dns.TypeDNSKEY, 18, 0)
	kdb := newTestKeyDB(t)
	key := BulkDnssecKey{Zone: "jwk.example.", Keyid: k.rr.KeyTag(), Flags: k.rr.Flags, Algorithm: "MLDSA44",
		State: DnskeyStateActive, PrivateKey: mldsa44ExpandedPEM(t, k.priv.(*mldsa44.PrivateKey)), KeyRR: k.keyRR}
	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, false); err != nil {
		t.Fatal(err)
	}
	key.PrivateKey = k.privPEM
	ds, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, false)
	if err != nil || ds[0].Status != BulkStatusConflict || ds[0].Detail != "privatekey (stored without seed)" {
		t.Fatalf("seeded key over a seedless row: %v %+v", err, ds)
	}
	ds, err = kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, true)
	if err != nil || ds[0].Status != BulkStatusReplaced {
		t.Fatalf("forced: %v %+v", err, ds)
	}
	if got := readKeyStoreRow(t, kdb, "DnssecKeyStore", "jwk.example.", k.rr.KeyTag()); got.privkey != k.privPEM {
		t.Error("the forced import did not store the seeded key")
	}
}

func storedCreator(t *testing.T, kdb *KeyDB, table string, keyid uint16) string {
	t.Helper()
	var c *string
	if err := kdb.DB.QueryRow("SELECT creator FROM "+table+" WHERE zonename='jwk.example.' AND keyid=?",
		int(keyid)).Scan(&c); err != nil {
		t.Fatal(err)
	}
	if c == nil {
		return ""
	}
	return *c
}

// creator is never a conflict; the stored creator wins, under force too,
// and also when it is empty.
func TestBulkImportCreatorIsNotAConflict(t *testing.T) {
	t.Run("DNSSEC", func(t *testing.T) {
		for _, first := range []string{"first", ""} {
			k := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
			kdb := newTestKeyDB(t)
			key := BulkDnssecKey{Zone: "jwk.example.", Keyid: k.rr.KeyTag(), Flags: k.rr.Flags, Algorithm: "ED25519",
				State: DnskeyStateActive, Creator: first, PrivateKey: k.privPEM, KeyRR: k.keyRR}
			if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, false); err != nil {
				t.Fatal(err)
			}
			key.Creator = "second"
			ds, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, false)
			if err != nil || ds[0].Status != BulkStatusUnchanged {
				t.Fatalf("creator %q -> %q: %v %+v", first, key.Creator, err, ds)
			}
			key.Comment = "changed"
			if ds, _ := kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, false); ds[0].Status != BulkStatusConflict || ds[0].Detail != "comment" {
				t.Errorf("comment and creator differ: %+v, want a conflict on comment alone", ds)
			}
			ds, err = kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, true)
			if err != nil || ds[0].Status != BulkStatusReplaced || ds[0].Detail != "comment" {
				t.Fatalf("forced: %v %+v", err, ds)
			}
			if got := storedCreator(t, kdb, "DnssecKeyStore", k.rr.KeyTag()); got != first {
				t.Errorf("creator after a forced replace: %q, want the stored %q", got, first)
			}
		}
	})
	t.Run("SIG0", func(t *testing.T) {
		for _, first := range []string{"first", ""} {
			k := storedJWKTestKey(t, dns.TypeKEY, dns.ED25519, 256)
			kdb := newTestKeyDB(t)
			key := BulkSig0Key{Zone: "jwk.example.", Keyid: k.rr.KeyTag(), Algorithm: "ED25519",
				State: Sig0StateActive, Creator: first, PrivateKey: k.privPEM, KeyRR: k.keyRR}
			if _, err := kdb.BulkImportSig0(nil, []BulkSig0Key{key}, false); err != nil {
				t.Fatal(err)
			}
			key.Creator = "second"
			ds, err := kdb.BulkImportSig0(nil, []BulkSig0Key{key}, false)
			if err != nil || ds[0].Status != BulkStatusUnchanged {
				t.Fatalf("creator %q -> %q: %v %+v", first, key.Creator, err, ds)
			}
			key.Comment = "changed"
			ds, err = kdb.BulkImportSig0(nil, []BulkSig0Key{key}, true)
			if err != nil || ds[0].Status != BulkStatusReplaced || ds[0].Detail != "comment" {
				t.Fatalf("forced: %v %+v", err, ds)
			}
			if got := storedCreator(t, kdb, "Sig0KeyStore", k.rr.KeyTag()); got != first {
				t.Errorf("creator after a forced replace: %q, want the stored %q", got, first)
			}
		}
	})
}

// --- single-key import ----------------------------------------------------

func setStoredState(t *testing.T, kdb *KeyDB, table string, keyid uint16, state string) {
	t.Helper()
	if _, err := kdb.DB.Exec("UPDATE "+table+" SET state=? WHERE zonename='jwk.example.' AND keyid=?",
		state, int(keyid)); err != nil {
		t.Fatal(err)
	}
}

func TestSingleKeyReimportDnssec(t *testing.T) {
	ctx := context.Background()
	a, b := collidingKeys(t, dns.TypeDNSKEY)
	keyid := a.rr.KeyTag()
	aj, _ := JWKForExport(dns.TypeDNSKEY, a.keyRR, a.privPEM)
	bj, _ := JWKForExport(dns.TypeDNSKEY, b.keyRR, b.privPEM)
	add := func(kdb *KeyDB, jwk string, force bool) (*KeystoreResponse, error) {
		return kdb.DnssecKeyMgmt(ctx, nil, KeystorePost{SubCommand: "add", Zone: "jwk.example.",
			JWK: jwk, State: DnskeyStateCreated, Force: force})
	}
	state := func(kdb *KeyDB) string {
		return readKeyStoreRow(t, kdb, "DnssecKeyStore", "jwk.example.", keyid).state
	}

	kdb := newTestKeyDB(t)
	if _, err := add(kdb, aj, false); err != nil {
		t.Fatalf("new key: %v", err)
	}
	setStoredState(t, kdb, "DnssecKeyStore", keyid, DnskeyStatePublished)

	// The same key again, as JWK and as PEM (another encoding of it): unchanged.
	resp, err := add(kdb, aj, false)
	if err != nil || !strings.Contains(resp.Msg, "Unchanged") || state(kdb) != DnskeyStatePublished {
		t.Fatalf("identical JWK re-import: %v %+v, state %s", err, resp, state(kdb))
	}
	pkc, err := PrepareKeyCache(strings.ReplaceAll(a.privPEM, "\n", "\r\n"), a.keyRR)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = kdb.DnssecKeyMgmt(ctx, nil, KeystorePost{SubCommand: "add", Zone: "jwk.example.",
		PrivateKeyCache: pkc, State: DnskeyStateCreated})
	if err != nil || !strings.Contains(resp.Msg, "Unchanged") || state(kdb) != DnskeyStatePublished {
		t.Fatalf("identical PEM re-import: %v %+v", err, resp)
	}

	// Another key under the same keyid: refused, naming the state.
	_, err = add(kdb, bj, false)
	if err == nil || !strings.Contains(err.Error(), "state published") ||
		!strings.Contains(err.Error(), "privatekey, keyrr") || !strings.Contains(err.Error(), "--force") ||
		!strings.Contains(err.Error(), "resets its state to created") {
		t.Fatalf("differing re-import: %v", err)
	}
	if got := readKeyStoreRow(t, kdb, "DnssecKeyStore", "jwk.example.", keyid); got.privkey != a.privPEM || got.state != DnskeyStatePublished {
		t.Fatal("a refused re-import changed the row")
	}
	// A different TTL in the RR is a difference too.
	ttl := strings.Replace(a.keyRR, "3600", "7200", 1)
	if _, err := kdb.DnssecKeyMgmt(ctx, nil, KeystorePost{SubCommand: "add", Zone: "jwk.example.",
		JWK: aj, KeyRR: ttl, State: DnskeyStateCreated}); err == nil || !strings.Contains(err.Error(), "(keyrr)") {
		t.Errorf("re-import with another TTL: %v", err)
	}

	// --force replaces and resets the state.
	resp, err = add(kdb, bj, true)
	if err != nil || !strings.Contains(resp.Msg, "Replaced") || state(kdb) != DnskeyStateCreated {
		t.Fatalf("forced re-import: %v %+v", err, resp)
	}
	if got := readKeyStoreRow(t, kdb, "DnssecKeyStore", "jwk.example.", keyid); got.privkey != b.privPEM {
		t.Error("the forced re-import did not store the new key")
	}
	// --force on the identical key is a deliberate reset.
	setStoredState(t, kdb, "DnssecKeyStore", keyid, DnskeyStatePublished)
	resp, err = add(kdb, bj, true)
	if err != nil || !strings.Contains(resp.Msg, "the same key") || state(kdb) != DnskeyStateCreated {
		t.Fatalf("forced identical re-import: %v %+v", err, resp)
	}
}

func TestSingleKeyReimportSig0(t *testing.T) {
	a, b := collidingKeys(t, dns.TypeKEY)
	keyid := a.rr.KeyTag()
	aj, _ := JWKForExport(dns.TypeKEY, a.keyRR, a.privPEM)
	bj, _ := JWKForExport(dns.TypeKEY, b.keyRR, b.privPEM)
	add := func(kdb *KeyDB, jwk string, force bool) (*KeystoreResponse, error) {
		return kdb.Sig0KeyMgmt(nil, KeystorePost{SubCommand: "add", Zone: "jwk.example.",
			JWK: jwk, State: Sig0StateCreated, Force: force})
	}
	state := func(kdb *KeyDB) string {
		return readKeyStoreRow(t, kdb, "Sig0KeyStore", "jwk.example.", keyid).state
	}

	kdb := newTestKeyDB(t)
	if _, err := add(kdb, aj, false); err != nil {
		t.Fatalf("new key: %v", err)
	}
	setStoredState(t, kdb, "Sig0KeyStore", keyid, Sig0StateActive)

	resp, err := add(kdb, aj, false)
	if err != nil || !strings.Contains(resp.Msg, "Unchanged") || state(kdb) != Sig0StateActive {
		t.Fatalf("identical re-import: %v %+v, state %s", err, resp, state(kdb))
	}
	_, err = add(kdb, bj, false)
	if err == nil || !strings.Contains(err.Error(), "state active") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("differing re-import: %v", err)
	}
	if state(kdb) != Sig0StateActive {
		t.Fatal("a refused re-import changed the state")
	}
	resp, err = add(kdb, bj, true)
	if err != nil || !strings.Contains(resp.Msg, "Replaced") || state(kdb) != Sig0StateCreated {
		t.Fatalf("forced re-import: %v %+v", err, resp)
	}
	if got := readKeyStoreRow(t, kdb, "Sig0KeyStore", "jwk.example.", keyid); got.privkey != b.privPEM {
		t.Error("the forced re-import did not store the new key")
	}
}

// --- JWK Set --------------------------------------------------------------

func TestJWKSetIsRefused(t *testing.T) {
	ctx := context.Background()
	k := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	j, _ := JWKForExport(dns.TypeDNSKEY, k.keyRR, k.privPEM)
	s := storedJWKTestKey(t, dns.TypeKEY, dns.ED25519, 256)
	sj, _ := JWKForExport(dns.TypeKEY, s.keyRR, s.privPEM)
	set := `{"keys":[` + j + `,` + j + `]}`
	sigSet := `{"keys":[` + sj + `]}`

	check := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrJWKSet) || !strings.Contains(err.Error(), "one key per file") {
			t.Errorf("%s: %v", what, err)
		}
	}
	_, err := ImportJWK(dns.TypeDNSKEY, set, "")
	check("ImportJWK", err)
	_, err = newTestKeyDB(t).DnssecKeyMgmt(ctx, nil, KeystorePost{SubCommand: "add", Zone: "jwk.example.",
		JWK: set, State: DnskeyStateCreated})
	check("DNSSEC add", err)
	_, err = newTestKeyDB(t).Sig0KeyMgmt(nil, KeystorePost{SubCommand: "add", Zone: "jwk.example.",
		JWK: sigSet, State: Sig0StateCreated})
	check("SIG(0) add", err)
	_, err = newTestKeyDB(t).BulkImportDnssec(nil, []BulkDnssecKey{{Zone: "jwk.example.", Keyid: k.rr.KeyTag(),
		Flags: k.rr.Flags, Algorithm: "ED25519", State: DnskeyStateActive, JWK: set}}, false)
	check("DNSSEC bulk-import", err)
	_, err = newTestKeyDB(t).BulkImportSig0(nil, []BulkSig0Key{{Zone: "jwk.example.", Keyid: s.rr.KeyTag(),
		Algorithm: "ED25519", State: Sig0StateActive, JWK: sigSet}}, false)
	check("SIG(0) bulk-import", err)
	r, err := newTestKeyDB(t).Sig0KeyMgmt(nil, KeystorePost{SubCommand: "bulk-import", BulkSig0Keys: []BulkSig0Key{{
		Zone: "jwk.example.", Keyid: s.rr.KeyTag(), Algorithm: "ED25519", State: Sig0StateActive, JWK: sigSet}}})
	if err == nil || r == nil || !strings.Contains(r.ErrorMsg, "JWK Set") {
		t.Errorf("SIG(0) bulk-import via Sig0KeyMgmt: %v %+v", err, r)
	}

	// Pre-load reads the set from a manifest's jwk_file and refuses it.
	dir := t.TempDir()
	base := "Kjwk.example.+015+00001"
	if err := os.WriteFile(filepath.Join(dir, base+".jwk"), []byte(set), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, base+".key"), []byte(k.keyRR+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := &KeystoreManifest{}
	m.UpsertDnssec(ManifestEntryForDnssec(BulkDnssecKey{Zone: "jwk.example.", Keyid: k.rr.KeyTag(),
		Flags: k.rr.Flags, Algorithm: "ED25519", State: DnskeyStateActive, JWK: set}, base))
	if err := m.Save(dir); err != nil {
		t.Fatal(err)
	}
	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Keystore.Preload.Dnssec = dir
	err = conf.PreloadKeystore(ctx)
	if err == nil || !strings.Contains(err.Error(), "JWK Set") || !strings.Contains(err.Error(), "one key per file") {
		t.Errorf("pre-load: %v", err)
	}
}
