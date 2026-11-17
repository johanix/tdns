/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	_ "github.com/johanix/dnssec-algorithms/mldsa65" // PKCS#8 codec only
	_ "github.com/johanix/dnssec-algorithms/mldsa87" // PKCS#8 codec only
	"github.com/miekg/dns"

	core "github.com/johanix/tdns/v2/core"
)

// jwkTestKey is a key as one of the two stores holds it.
type jwkTestKey struct {
	keyRR, privPEM string
	priv           crypto.PrivateKey
	rr             *dns.DNSKEY // the DNSKEY, or the DNSKEY inside the KEY
}

// storedJWKTestKey generates a key with the algorithm registry (every
// binary has the classical algorithms, ED448 and ML-DSA-44) and stores it
// the keystore's way: PKCS#8 PEM plus a DNSKEY (rrtype DNSKEY) or KEY RR.
func storedJWKTestKey(t *testing.T, rrtype uint16, alg uint8, bits int) jwkTestKey {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "jwk.example.", Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: alg,
	}
	if rrtype == dns.TypeKEY {
		k.Flags = 256
	}
	priv, err := k.Generate(bits)
	if err != nil {
		t.Fatalf("Generate(%s): %v", dns.AlgorithmToString[alg], err)
	}
	return storeJWKTestKey(t, rrtype, k, priv)
}

func storeJWKTestKey(t *testing.T, rrtype uint16, k *dns.DNSKEY, priv crypto.PrivateKey) jwkTestKey {
	t.Helper()
	privPEM, err := PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM: %v", err)
	}
	keyRR := k.String()
	if rrtype == dns.TypeKEY {
		keyRR = (&dns.KEY{DNSKEY: *k}).String()
	}
	return jwkTestKey{keyRR: keyRR, privPEM: privPEM, priv: priv, rr: k}
}

// mldsaTestKey builds an ML-DSA-65 or -87 key directly from CIRCL: those
// algorithms are not registered in this test binary, but their PKCS#8
// codecs are (blank imports above), which is all export needs.
func mldsaTestKey(t *testing.T, rrtype uint16, alg uint8) jwkTestKey {
	t.Helper()
	var pub []byte
	var priv crypto.PrivateKey
	switch alg {
	case 200:
		pk, sk, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, priv = pk.Bytes(), sk
	case 201:
		pk, sk, err := mldsa87.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, priv = pk.Bytes(), sk
	}
	k := &dns.DNSKEY{
		Hdr:      dns.RR_Header{Name: "jwk.example.", Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600},
		Flags:    257,
		Protocol: 3, Algorithm: alg,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	return storeJWKTestKey(t, rrtype, k, priv)
}

type jwkFamily struct {
	name string
	alg  uint8
	bits int
}

var jwkFamilies = []jwkFamily{
	{"RSASHA256", dns.RSASHA256, 2048},
	{"RSASHA512", dns.RSASHA512, 2048},
	{"ECDSAP256SHA256", dns.ECDSAP256SHA256, 256},
	{"ECDSAP384SHA384", dns.ECDSAP384SHA384, 384},
	{"ED25519", dns.ED25519, 256},
	{"ED448", dns.ED448, 0},
	{"MLDSA44", 18, 0},
}

// checkExportedJWK parses out as the import side would and checks the
// members the brief fixes: the kind's parameter and only it, kid and
// keytag always, alg only for AKP.
func checkExportedJWK(t *testing.T, out string, rrtype uint16, want *dns.DNSKEY) *core.DNSSECJWK {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatalf("output is not a JSON object: %v", err)
	}
	param, other := "dnskey", "sig0key"
	if rrtype == dns.TypeKEY {
		param, other = "sig0key", "dnskey"
	}
	if _, ok := top[param]; !ok {
		t.Errorf("no %q parameter", param)
	}
	if _, ok := top[other]; ok {
		t.Errorf("%q written on a %s key", other, dns.TypeToString[rrtype])
	}
	if _, ok := top["kid"]; !ok {
		t.Error("no kid")
	}
	d, rr, err := core.ParseKeyJWK([]byte(out))
	if err != nil {
		t.Fatalf("ParseKeyJWK: %v", err)
	}
	if (d.Key.Kty == core.JWKKtyAKP) != (d.Key.Alg != "") {
		t.Errorf("kty %s with alg %q: alg belongs on AKP keys only", d.Key.Kty, d.Key.Alg)
	}
	p := d.DNSKEY
	if rrtype == dns.TypeKEY {
		p = d.Sig0Key
	}
	if p.KeyTag == nil || *p.KeyTag != want.KeyTag() {
		t.Errorf("keytag %v, want %d", p.KeyTag, want.KeyTag())
	}
	kid, err := d.Key.Thumbprint()
	if err != nil || d.Key.Kid != kid {
		t.Errorf("kid %q, want the thumbprint %q (%v)", d.Key.Kid, kid, err)
	}
	var got *dns.DNSKEY
	switch r := rr.(type) {
	case *dns.DNSKEY:
		got = r
	case *dns.KEY:
		got = &r.DNSKEY
	}
	if got == nil || got.Header().Rrtype != rrtype || !sameKeyRR(got, want) {
		t.Errorf("JWK rebuilds %v, want %s", rr, want.String())
	}
	if !d.Key.IsPrivate() {
		t.Error("export wrote a public JWK; the keystore export is of the private key")
	}
	return d
}

func TestJWKExportEveryFamily(t *testing.T) {
	for _, rrtype := range []uint16{dns.TypeDNSKEY, dns.TypeKEY} {
		for _, f := range jwkFamilies {
			t.Run(dns.TypeToString[rrtype]+"/"+f.name, func(t *testing.T) {
				k := storedJWKTestKey(t, rrtype, f.alg, f.bits)
				out, err := JWKForExport(rrtype, k.keyRR, k.privPEM)
				if err != nil {
					t.Fatalf("JWKForExport: %v", err)
				}
				d := checkExportedJWK(t, out, rrtype, k.rr)
				if f.alg == 18 {
					sk := k.priv.(*mldsa44.PrivateKey)
					if string(d.Key.Priv) != string(sk.Seed()) {
						t.Error("ML-DSA-44 priv is not the stored seed")
					}
				}
				// Re-exporting is byte-identical, so a re-run into the
				// same directory is a no-op rather than a conflict.
				again, err := JWKForExport(rrtype, k.keyRR, k.privPEM)
				if err != nil || again != out {
					t.Errorf("second export differs (%v)", err)
				}
			})
		}
	}
}

func TestJWKExportMLDSA65And87(t *testing.T) {
	for _, alg := range []uint8{200, 201} {
		k := mldsaTestKey(t, dns.TypeDNSKEY, alg)
		out, err := JWKForExport(dns.TypeDNSKEY, k.keyRR, k.privPEM)
		if err != nil {
			t.Fatalf("algorithm %d: %v", alg, err)
		}
		d := checkExportedJWK(t, out, dns.TypeDNSKEY, k.rr)
		if len(d.Key.Priv) != 32 {
			t.Errorf("algorithm %d: priv is %d octets, want the 32-octet seed", alg, len(d.Key.Priv))
		}
	}
}

// expandedOnlyMLDSA44 is an ML-DSA-44 key the way releases before the
// seed form stored it: the expanded key alone.
func expandedOnlyMLDSA44(t *testing.T, rrtype uint16) jwkTestKey {
	t.Helper()
	k := storedJWKTestKey(t, rrtype, 18, 0)
	sk := new(mldsa44.PrivateKey)
	if err := sk.UnmarshalBinary(k.priv.(*mldsa44.PrivateKey).Bytes()); err != nil {
		t.Fatal(err)
	}
	if sk.Seed() != nil {
		t.Fatal("fixture: an unmarshalled expanded key still has a seed")
	}
	return storeJWKTestKey(t, rrtype, k.rr, sk)
}

func TestJWKExportRefusesMLDSAWithoutSeed(t *testing.T) {
	k := expandedOnlyMLDSA44(t, dns.TypeDNSKEY)
	if !strings.Contains(k.privPEM, "PRIVATE KEY") {
		t.Fatal("fixture is not PEM")
	}
	_, err := JWKForExport(dns.TypeDNSKEY, k.keyRR, k.privPEM)
	if !errors.Is(err, ErrJWKNoSeed) || !IsJWKUnsupported(err) {
		t.Fatalf("got %v, want ErrJWKNoSeed", err)
	}
	for _, want := range []string{"seed", "--format pem", "--format bind", "rollover"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should say why and what to do (%q): %v", want, err)
		}
	}
	// The refusal points at pem and bind; both must work for this key.
	for _, f := range []string{KeyFormatPEM, KeyFormatBind} {
		out, err := PrivateKeyForExport(f, k.keyRR, k.privPEM, "", "", "")
		if err != nil || out == "" {
			t.Errorf("--format %s of a seedless ML-DSA key: %q, %v", f, out, err)
		}
	}
}

func TestJWKExportRefusesAlgorithmWithoutJWKForm(t *testing.T) {
	keyRR := "jwk.example. 3600 IN DNSKEY 257 3 3 AQID"
	_, err := JWKForExport(dns.TypeDNSKEY, keyRR, "unused")
	if !errors.Is(err, core.ErrNoJWKRepresentation) || !IsJWKUnsupported(err) {
		t.Fatalf("got %v, want ErrNoJWKRepresentation", err)
	}
	if !strings.Contains(err.Error(), "DSA") {
		t.Errorf("the refusal should name the algorithm: %v", err)
	}
}

// A DNSSEC row exports with "dnskey" only, a SIG(0) row with "sig0key"
// only; a row whose RR type is not its store's is refused, not exported
// under the other parameter.
func TestJWKExportKindFollowsTheStore(t *testing.T) {
	dk := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	sk := storedJWKTestKey(t, dns.TypeKEY, dns.ED25519, 256)
	if _, err := JWKForExport(dns.TypeKEY, dk.keyRR, dk.privPEM); err == nil {
		t.Error("a DNSKEY row exported from the SIG(0) store")
	}
	if _, err := JWKForExport(dns.TypeDNSKEY, sk.keyRR, sk.privPEM); err == nil {
		t.Error("a KEY row exported from the DNSSEC store")
	}
}

func TestJWKExportRefusesMismatchedRow(t *testing.T) {
	a := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	b := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	_, err := JWKForExport(dns.TypeDNSKEY, a.keyRR, b.privPEM)
	if err == nil {
		t.Fatal("a private key that is not the RR's was exported")
	}
	if IsJWKUnsupported(err) {
		t.Errorf("a broken row must not be skippable as unsupported: %v", err)
	}
	c := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ECDSAP256SHA256, 256)
	if _, err := JWKForExport(dns.TypeDNSKEY, a.keyRR, c.privPEM); err == nil {
		t.Error("an ECDSA private key exported under an Ed25519 RR")
	}
}

func TestPrivateKeyForExportRefusesJWK(t *testing.T) {
	k := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	out, err := PrivateKeyForExport(KeyFormatJWK, k.keyRR, k.privPEM, "", "", "")
	if err == nil || out != "" {
		t.Errorf("PrivateKeyForExport(jwk) returned %q, %v; it must not fall through to PEM", out, err)
	}
	if err := ValidateKeyFormat(KeyFormatJWK); err != nil {
		t.Errorf("jwk rejected: %v", err)
	}
}

// --- manifest ----------------------------------------------------------

func TestManifestJWKFieldAndVersion(t *testing.T) {
	dir := t.TempDir()
	key := testDnssecKey(t, "pq.dnslab.", 257)

	pemEntry := ManifestEntryForDnssec(key, "Ka")
	if pemEntry.PrivateFile != "Ka.private" || pemEntry.JwkFile != "" {
		t.Errorf("PEM entry: %+v", pemEntry)
	}
	m := &KeystoreManifest{}
	m.UpsertDnssec(pemEntry)
	if err := m.Save(dir); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, KeystoreManifestFile))
	if !strings.Contains(string(raw), "version: 1\n") || strings.Contains(string(raw), "jwk_file") {
		t.Errorf("a PEM-only manifest must stay version 1:\n%s", raw)
	}

	jk := key
	jk.PrivateKey, jk.JWK = "", "{}"
	jwkEntry := ManifestEntryForDnssec(jk, "Ka")
	if jwkEntry.PrivateFile != "" || jwkEntry.JwkFile != "Ka.jwk" {
		t.Errorf("JWK entry: %+v", jwkEntry)
	}
	m.UpsertDnssec(jwkEntry)
	s0 := testBulkSig0Key(t, "pq.dnslab.")
	s0.PrivateKey, s0.JWK = "", "{}"
	if e := ManifestEntryForSig0(s0, "Kb"); e.JwkFile != "Kb.jwk" || e.PrivateFile != "" {
		t.Errorf("SIG(0) JWK entry: %+v", e)
	}
	if err := m.Save(dir); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, KeystoreManifestFile))
	if !strings.Contains(string(raw), "version: 2\n") || !strings.Contains(string(raw), "jwk_file: Ka.jwk") ||
		strings.Contains(string(raw), "private_file") {
		t.Errorf("a manifest with a JWK file must be version 2 with jwk_file and no private_file:\n%s", raw)
	}
	back, err := LoadKeystoreManifest(dir)
	if err != nil {
		t.Fatalf("a version 2 manifest must load: %v", err)
	}
	if back.Dnssec[0].JwkFile != "Ka.jwk" {
		t.Errorf("jwk_file lost on reload: %+v", back.Dnssec[0])
	}

	// Back to PEM: the version follows the content, so the directory is
	// readable by v1 binaries again.
	back.UpsertDnssec(pemEntry)
	if err := back.Save(dir); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, KeystoreManifestFile))
	if !strings.Contains(string(raw), "version: 1\n") {
		t.Errorf("re-exported as PEM, the manifest should drop back to version 1:\n%s", raw)
	}

	if err := os.WriteFile(filepath.Join(dir, KeystoreManifestFile), []byte("version: 3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeystoreManifest(dir); err == nil {
		t.Error("version 3 must be refused")
	}
}

// --- through the keystore ----------------------------------------------

func TestBulkExportJWKFailsOrSkipsUnsupported(t *testing.T) {
	kdb := newTestKeyDB(t)
	good := testDnssecKey(t, "good.dnslab.", 257)
	old := expandedOnlyMLDSA44(t, dns.TypeDNSKEY)
	oldKey := BulkDnssecKey{Zone: "jwk.example.", Keyid: old.rr.KeyTag(), Flags: 257,
		Algorithm: "MLDSA44", State: DnskeyStateActive, PrivateKey: old.privPEM, KeyRR: old.keyRR}
	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{good, oldKey}, false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ctx := context.Background()

	resp, err := kdb.DnssecKeyMgmt(ctx, nil, KeystorePost{SubCommand: "bulk-export", KeyFormat: KeyFormatJWK})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "seed") {
		t.Errorf("an unexportable key must fail the run by default: %+v", resp)
	}

	resp, err = kdb.DnssecKeyMgmt(ctx, nil, KeystorePost{SubCommand: "bulk-export", KeyFormat: KeyFormatJWK,
		SkipUnsupported: true})
	if err != nil || resp.Error {
		t.Fatalf("skip-unsupported: %v %s", err, resp.ErrorMsg)
	}
	if len(resp.BulkDnssecKeys) != 1 || resp.BulkDnssecKeys[0].Zone != good.Zone {
		t.Fatalf("exported %+v, want only %s", resp.BulkDnssecKeys, good.Zone)
	}
	exp := resp.BulkDnssecKeys[0]
	if exp.JWK == "" || exp.PrivateKey != "" {
		t.Errorf("a jwk export carries the JWK and no PEM: %+v", exp)
	}
	if len(resp.BulkSkipped) != 1 || resp.BulkSkipped[0].Zone != "jwk.example." || resp.BulkSkipped[0].Reason == "" {
		t.Errorf("skipped list: %+v", resp.BulkSkipped)
	}

	resp, _ = kdb.DnssecKeyMgmt(ctx, nil, KeystorePost{SubCommand: "bulk-export", KeyFormat: KeyFormatPEM,
		SkipUnsupported: true})
	if !resp.Error {
		t.Error("skip-unsupported with pem must be refused")
	}
}

func TestSig0ExportJWKUsesSig0Key(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := testBulkSig0Key(t, "sig0.dnslab.")
	if _, err := kdb.BulkImportSig0(nil, []BulkSig0Key{key}, false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := kdb.Sig0KeyMgmt(nil, KeystorePost{SubCommand: "bulk-export", KeyFormat: KeyFormatJWK})
	if err != nil || resp.Error || len(resp.BulkSig0Keys) != 1 {
		t.Fatalf("bulk-export: %v %+v", err, resp)
	}
	j := resp.BulkSig0Keys[0].JWK
	if !strings.Contains(j, `"sig0key"`) || strings.Contains(j, `"dnskey"`) {
		t.Errorf("a SIG(0) export must carry sig0key and never dnskey:\n%s", j)
	}

	resp, err = kdb.Sig0KeyMgmt(nil, KeystorePost{SubCommand: "export", KeyFormat: KeyFormatJWK,
		Zone: key.Zone, Keyid: key.Keyid})
	if err != nil || resp.Error {
		t.Fatalf("export: %v %+v", err, resp)
	}
	for _, v := range resp.Sig0keys {
		if !strings.Contains(v.JWK, `"sig0key"`) || v.PrivateKey != "" {
			t.Errorf("single-key SIG(0) export: %+v", v)
		}
	}
}
