/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"

	core "github.com/johanix/tdns/v2/core"
)

func readJWKVector(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("core", "testdata", "dnssec-jwk", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The draft's Appendix A private keys import, rebuild the DNSKEY next to
// them, and come out as PEM the keystore can load. ML-DSA-44 keeps its
// seed (00..1f) through the import.
func TestJWKImportAppendixA(t *testing.T) {
	for _, v := range []string{"rsasha256", "ecdsap256sha256", "ed25519", "mldsa44", "ed25519-escaped-owner"} {
		t.Run(v, func(t *testing.T) {
			imp, err := ImportJWK(dns.TypeDNSKEY, readJWKVector(t, v+".json"), "")
			if err != nil {
				t.Fatalf("ImportJWK: %v", err)
			}
			want, err := dns.NewRR(readJWKVector(t, v+".dnskey"))
			if err != nil {
				t.Fatal(err)
			}
			if !sameKeyRR(imp.RR, want.(*dns.DNSKEY)) {
				t.Errorf("rebuilt %s, want %s", imp.RR, want)
			}
			if imp.RR.Hdr.Ttl != jwkImportTTL {
				t.Errorf("TTL %d, want %d", imp.RR.Hdr.Ttl, jwkImportTTL)
			}
			if _, err := PrepareKeyCache(imp.PrivateKeyPEM, imp.KeyRR); err != nil {
				t.Errorf("the stored row does not load: %v", err)
			}
			if v == "mldsa44" {
				priv, err := PEMToPrivateKey(imp.PrivateKeyPEM)
				if err != nil {
					t.Fatal(err)
				}
				seed := priv.(*mldsa44.PrivateKey).Seed()
				for i, b := range seed {
					if b != byte(i) {
						t.Fatalf("seed not retained: %x", seed)
					}
				}
				if len(seed) != 32 {
					t.Fatalf("seed is %d octets", len(seed))
				}
			}
		})
	}
	if _, err := ImportJWK(dns.TypeDNSKEY, readJWKVector(t, "ecdsap256sha256-public.json"), ""); err == nil {
		t.Error("a public JWK was imported into the keystore")
	}
}

func TestJWKImportKindMismatch(t *testing.T) {
	dk := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	sk := storedJWKTestKey(t, dns.TypeKEY, dns.ED25519, 256)
	dj, err := JWKForExport(dns.TypeDNSKEY, dk.keyRR, dk.privPEM)
	if err != nil {
		t.Fatal(err)
	}
	sj, err := JWKForExport(dns.TypeKEY, sk.keyRR, sk.privPEM)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ImportJWK(dns.TypeKEY, dj, "")
	if !errors.Is(err, ErrJWKKindMismatch) || !strings.Contains(err.Error(), `"dnskey"`) {
		t.Errorf("DNSSEC JWK into the SIG(0) store: %v", err)
	}
	_, err = ImportJWK(dns.TypeDNSKEY, sj, "")
	if !errors.Is(err, ErrJWKKindMismatch) || !strings.Contains(err.Error(), `"sig0key"`) {
		t.Errorf("SIG(0) JWK into the DNSSEC store: %v", err)
	}
	both := strings.Replace(dj, `"dnskey"`, `"sig0key": {"name":"jwk.example.","flags":256,"protocol":3,"algorithm":15}, "dnskey"`, 1)
	if _, err := ImportJWK(dns.TypeDNSKEY, both, ""); !errors.Is(err, core.ErrBothKeyParams) {
		t.Errorf("both parameters: %v", err)
	}
	neither := strings.Replace(dj, `"dnskey"`, `"other"`, 1)
	if _, err := ImportJWK(dns.TypeDNSKEY, neither, ""); !errors.Is(err, core.ErrNoKeyParam) {
		t.Errorf("neither parameter: %v", err)
	}
}

func TestJWKImportRefusesMismatchedPrivateKey(t *testing.T) {
	a := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	b := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	aj, _ := JWKForExport(dns.TypeDNSKEY, a.keyRR, a.privPEM)
	bj, _ := JWKForExport(dns.TypeDNSKEY, b.keyRR, b.privPEM)
	da, _, err := core.ParseDNSSECJWK([]byte(aj))
	if err != nil {
		t.Fatal(err)
	}
	db, _, err := core.ParseDNSSECJWK([]byte(bj))
	if err != nil {
		t.Fatal(err)
	}
	mixed := strings.Replace(aj, b64urlString(da.Key.D), b64urlString(db.Key.D), 1)
	_, err = ImportJWK(dns.TypeDNSKEY, mixed, "")
	if !errors.Is(err, core.ErrDNSKEYPrivateMismatch) {
		t.Errorf("another key's private half: %v", err)
	}
	// A .key that is not the JWK's key is refused too.
	if _, err := ImportJWK(dns.TypeDNSKEY, aj, b.keyRR); err == nil {
		t.Error("a public RR that is not the JWK's key was accepted")
	}
}

func b64urlString(b []byte) string {
	k := core.JSONWebKey{Kty: core.JWKKtyOKP, Crv: core.JWKCrvEd25519, X: b}
	out, _ := k.MarshalJSON()
	s := string(out)
	i := strings.Index(s, `"x":"`) + 5
	return s[i : i+strings.Index(s[i:], `"`)]
}

func TestJWKImportRefusesUnlinkedAndUnknownAlgorithms(t *testing.T) {
	// ML-DSA-65 has a JWK form and a PKCS#8 codec in this test binary, but
	// no registered implementation: the daemon would store a key it can
	// neither check nor sign with.
	k := mldsaTestKey(t, dns.TypeDNSKEY, 200)
	j, err := JWKForExport(dns.TypeDNSKEY, k.keyRR, k.privPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportJWK(dns.TypeDNSKEY, j, ""); !errors.Is(err, ErrJWKAlgorithmNotLinked) {
		t.Errorf("unlinked ML-DSA-65: %v", err)
	}
	dsa := `{"kty":"OKP","crv":"Ed25519","x":"xX2gT6qJ76coFM3_pAUBxfBZYGnfSZqbNvbZFI428Ao",` +
		`"d":"Dz9KOncZ00D1WiPEJR_Ec_WXR7YuCbdhUO_H9AERYvw",` +
		`"dnskey":{"name":"example.com.","flags":256,"protocol":3,"algorithm":3}}`
	if _, err := ImportJWK(dns.TypeDNSKEY, dsa, ""); !errors.Is(err, core.ErrNoJWKRepresentation) {
		t.Errorf("algorithm with no JWK form: %v", err)
	}
	unassigned := strings.Replace(dsa, `"algorithm":3`, `"algorithm":99`, 1)
	if _, err := ImportJWK(dns.TypeDNSKEY, unassigned, ""); err == nil {
		t.Error("an unassigned algorithm was imported")
	}
}

// Export -> import, per family and for both stores: the key comes back
// into an empty keystore exactly as it was stored (PEM, RR text with its
// TTL), and re-importing into the source keystore is "unchanged".
func TestJWKExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()
	for _, f := range jwkFamilies {
		t.Run("DNSSEC/"+f.name, func(t *testing.T) {
			k := storedJWKTestKey(t, dns.TypeDNSKEY, f.alg, f.bits)
			src := newTestKeyDB(t)
			key := BulkDnssecKey{Zone: "jwk.example.", Keyid: k.rr.KeyTag(), Flags: k.rr.Flags,
				Algorithm: dns.AlgorithmToString[f.alg], State: DnskeyStateActive, Creator: "test",
				PublishedAt: "2026-01-02T03:04:05Z", PrivateKey: k.privPEM, KeyRR: k.keyRR}
			if _, err := src.BulkImportDnssec(nil, []BulkDnssecKey{key}, false); err != nil {
				t.Fatalf("seed: %v", err)
			}
			resp, err := src.DnssecKeyMgmt(ctx, nil, KeystorePost{SubCommand: "bulk-export", KeyFormat: KeyFormatJWK})
			if err != nil || resp.Error || len(resp.BulkDnssecKeys) != 1 {
				t.Fatalf("export: %v %+v", err, resp)
			}
			exported := resp.BulkDnssecKeys[0]

			dst := newTestKeyDB(t)
			ds, err := dst.BulkImportDnssec(nil, []BulkDnssecKey{exported}, false)
			if err != nil || ds[0].Status != BulkStatusImported {
				t.Fatalf("import: %v %+v", err, ds)
			}
			back, err := dst.BulkExportDnssec(nil, KeySelector{})
			if err != nil || len(back) != 1 {
				t.Fatalf("read back: %v", err)
			}
			orig, _ := src.BulkExportDnssec(nil, KeySelector{})
			if back[0].PrivateKey != orig[0].PrivateKey || back[0].KeyRR != orig[0].KeyRR ||
				back[0].State != orig[0].State || back[0].PublishedAt != orig[0].PublishedAt {
				t.Errorf("round trip changed the row:\n got %+v\nwant %+v", back[0], orig[0])
			}
			ds, err = src.BulkImportDnssec(nil, []BulkDnssecKey{exported}, false)
			if err != nil || ds[0].Status != BulkStatusUnchanged {
				t.Errorf("re-import into the source: %v %+v", err, ds)
			}
		})
		t.Run("SIG0/"+f.name, func(t *testing.T) {
			k := storedJWKTestKey(t, dns.TypeKEY, f.alg, f.bits)
			src := newTestKeyDB(t)
			key := BulkSig0Key{Zone: "jwk.example.", Keyid: k.rr.KeyTag(), Algorithm: dns.AlgorithmToString[f.alg],
				State: Sig0StateActive, PrivateKey: k.privPEM, KeyRR: k.keyRR}
			if _, err := src.BulkImportSig0(nil, []BulkSig0Key{key}, false); err != nil {
				t.Fatalf("seed: %v", err)
			}
			resp, err := src.Sig0KeyMgmt(nil, KeystorePost{SubCommand: "bulk-export", KeyFormat: KeyFormatJWK})
			if err != nil || resp.Error || len(resp.BulkSig0Keys) != 1 {
				t.Fatalf("export: %v %+v", err, resp)
			}
			exported := resp.BulkSig0Keys[0]
			exported.KeyRR = "" // a jwk_file entry without public_file

			dst := newTestKeyDB(t)
			r2, err := dst.Sig0KeyMgmt(nil, KeystorePost{SubCommand: "bulk-import", BulkSig0Keys: []BulkSig0Key{exported}})
			if err != nil || r2.Error || len(r2.BulkDispositions) != 1 || r2.BulkDispositions[0].Status != BulkStatusImported {
				t.Fatalf("import: %v %+v", err, r2)
			}
			back, _ := dst.BulkExportSig0(nil, KeySelector{})
			orig, _ := src.BulkExportSig0(nil, KeySelector{})
			if len(back) != 1 || back[0].PrivateKey != orig[0].PrivateKey || back[0].KeyRR != orig[0].KeyRR {
				t.Errorf("round trip changed the row:\n got %+v\nwant %+v", back, orig)
			}
			if _, ok := trustStoreEntry(t, dst, "jwk.example.", k.rr.KeyTag()); !ok {
				t.Error("a SIG(0) key imported from a JWK is missing from the TrustStore")
			}
		})
	}
}

// The bulk path reads jwk_file through the manifest, and pre-load uses it.
func TestPreloadReadsJWKFiles(t *testing.T) {
	k := storedJWKTestKey(t, dns.TypeDNSKEY, 18, 0)
	j, err := JWKForExport(dns.TypeDNSKEY, k.keyRR, k.privPEM)
	if err != nil {
		t.Fatal(err)
	}
	key := BulkDnssecKey{Zone: "jwk.example.", Keyid: k.rr.KeyTag(), Flags: k.rr.Flags, Algorithm: "MLDSA44",
		State: DnskeyStateActive, JWK: j, KeyRR: k.keyRR}
	dir := t.TempDir()
	base := "Kjwk.example.+018+00001"
	if err := os.WriteFile(filepath.Join(dir, base+".jwk"), []byte(j), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, base+".key"), []byte(k.keyRR+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := &KeystoreManifest{}
	m.UpsertDnssec(ManifestEntryForDnssec(key, base))
	if err := m.Save(dir); err != nil {
		t.Fatal(err)
	}

	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Keystore.Preload.Dnssec = dir
	if err := conf.PreloadKeystore(context.Background()); err != nil {
		t.Fatalf("PreloadKeystore: %v", err)
	}
	got, err := kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil || len(got) != 1 {
		t.Fatalf("pre-load did not restore the key: %v %+v", err, got)
	}
	if got[0].PrivateKey != k.privPEM {
		t.Error("the stored PEM is not the seed-form PEM the key was exported from")
	}

	// Both private_file and jwk_file is refused, not resolved by guessing.
	m.Dnssec[0].PrivateFile = base + ".private"
	if _, err := m.LoadDnssecKeys(dir); err == nil || !strings.Contains(err.Error(), "both") {
		t.Errorf("an entry with both files: %v", err)
	}
	// A JWK that fails the import rules fails the pre-load.
	if err := os.WriteFile(filepath.Join(dir, base+".jwk"),
		[]byte(strings.Replace(j, `"dnskey"`, `"sig0key"`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	m.Dnssec[0].PrivateFile = ""
	keys, err := m.LoadDnssecKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestKeyDB(t).BulkImportDnssec(nil, keys, false); !errors.Is(err, ErrJWKKindMismatch) {
		t.Errorf("a SIG(0) JWK in the DNSSEC section: %v", err)
	}
}

func TestSingleKeyAddFromJWK(t *testing.T) {
	ctx := context.Background()
	k := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ECDSAP256SHA256, 256)
	j, _ := JWKForExport(dns.TypeDNSKEY, k.keyRR, k.privPEM)

	kdb := newTestKeyDB(t)
	if _, err := kdb.DnssecKeyMgmt(ctx, nil, KeystorePost{SubCommand: "add", Zone: "other.example.",
		JWK: j, State: DnskeyStateCreated}); err == nil {
		t.Error("a key for jwk.example. was added to other.example.")
	}
	if _, err := kdb.DnssecKeyMgmt(ctx, nil, KeystorePost{SubCommand: "add", Zone: "jwk.example.",
		JWK: j, KeyRR: k.keyRR, State: DnskeyStateCreated}); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, _ := kdb.BulkExportDnssec(nil, KeySelector{})
	if len(got) != 1 || got[0].State != DnskeyStateCreated || got[0].KeyRR != k.rr.String() {
		t.Errorf("add stored %+v", got)
	}
	if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{SubCommand: "add", Zone: "jwk.example.",
		JWK: j, State: Sig0StateCreated}); !errors.Is(err, ErrJWKKindMismatch) {
		t.Errorf("a DNSSEC JWK added to the SIG(0) store: %v", err)
	}

	s := storedJWKTestKey(t, dns.TypeKEY, dns.ED448, 0)
	sj, _ := JWKForExport(dns.TypeKEY, s.keyRR, s.privPEM)
	if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{SubCommand: "add", Zone: "jwk.example.",
		JWK: sj, State: Sig0StateCreated}); err != nil {
		t.Fatalf("SIG(0) add: %v", err)
	}
	if _, ok := trustStoreEntry(t, kdb, "jwk.example.", s.rr.KeyTag()); !ok {
		t.Error("SIG(0) add from a JWK did not reach the TrustStore")
	}
}
