/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Regression cover for BIND .key comment headers reaching the keystore.
 *
 * dnssec-keygen writes four ";" comment lines above the record in a .key file.
 * dns.NewRR skips comments, so a .key file kept verbatim parsed fine and passed
 * every metadata check -- but the text that got STORED in the keyrr column was
 * the whole file, and "keystore dnssec list" showed the first comment line where
 * the DNSKEY should be.
 */
package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// bindCommentHeader is what dnssec-keygen puts above the record.
const bindCommentHeader = `; This is a key-signing key, keyid 59146, for dnslab.
; Created: 20240917174637 (Tue Sep 17 17:46:37 2024)
; Publish: 20240917174637 (Tue Sep 17 17:46:37 2024)
; Activate: 20240917174637 (Tue Sep 17 17:46:37 2024)
`

func TestCanonicalKeyRRStripsBindComments(t *testing.T) {
	dnskey := "dnslab.\t3600\tIN\tDNSKEY\t257 3 15 C4RKfg3IUwpjc+CnISaCuDX4OGpxsUIe7dqRVXj0KdU="
	keyrr := "dnslab.\t3600\tIN\tKEY\t512 3 15 C4RKfg3IUwpjc+CnISaCuDX4OGpxsUIe7dqRVXj0KdU="

	for _, tc := range []struct {
		name  string
		in    string
		want  string
		isErr bool
	}{
		{name: "DNSKEY with bind comments", in: bindCommentHeader + dnskey + "\n", want: dnskey},
		{name: "KEY with bind comments", in: bindCommentHeader + keyrr + "\n", want: keyrr},
		{name: "already clean DNSKEY", in: dnskey, want: dnskey},
		{name: "trailing newlines", in: dnskey + "\n\n", want: dnskey},
		{name: "comments only", in: bindCommentHeader, isErr: true},
		{name: "empty", in: "", isErr: true},
		{name: "wrong RR type", in: "dnslab. 3600 IN TXT \"nope\"", isErr: true},
		{name: "unparsable", in: "this is not a resource record", isErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalKeyRR(tc.in)
			if tc.isErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalKeyRR: %v", err)
			}
			if got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// writeBindStyleKeyFiles lays down a .key/.private pair the way an operator's
// BIND9 key directory has them, comment header included.
func writeBindStyleKeyFiles(t *testing.T, dir, zone string, sig0 bool) (base, wantRR, privPEM string) {
	t.Helper()

	rrtype, flags := dns.TypeDNSKEY, uint16(257)
	if sig0 {
		rrtype, flags = dns.TypeKEY, uint16(512)
	}
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	priv, err := dnskey.Generate(256)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	privPEM, err = PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("converting key to PEM: %v", err)
	}

	var rr dns.RR = dnskey
	if sig0 {
		rr = &dns.KEY{DNSKEY: *dnskey}
	}
	wantRR = rr.String()

	base = KeyFileBasename(dns.Fqdn(zone), dns.ED25519, dnskey.KeyTag())
	if err := os.WriteFile(filepath.Join(dir, base+".key"),
		[]byte(bindCommentHeader+wantRR+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, base+".private"), []byte(privPEM), 0600); err != nil {
		t.Fatal(err)
	}
	return base, wantRR, privPEM
}

// TestManifestLoadStripsBindComments is the bug as reported: BIND9 keys reached
// the keystore through a manifest, and the keyrr column ended up holding the
// comment header instead of the record.
func TestManifestLoadStripsBindComments(t *testing.T) {
	t.Run("DNSSEC", func(t *testing.T) {
		dir := t.TempDir()
		base, wantRR, _ := writeBindStyleKeyFiles(t, dir, "dnslab.", false)

		m := &KeystoreManifest{Dnssec: []ManifestDnssecKey{{
			Zone: "dnslab.", Keyid: 1, Flags: 257, Algorithm: "ED25519",
			State: DnskeyStateActive, PrivateFile: base + ".private", PublicFile: base + ".key",
		}}}

		keys, err := m.LoadDnssecKeys(dir)
		if err != nil {
			t.Fatalf("LoadDnssecKeys: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(keys))
		}
		if strings.Contains(keys[0].KeyRR, ";") {
			t.Errorf("comment header survived into KeyRR:\n%s", keys[0].KeyRR)
		}
		if keys[0].KeyRR != wantRR {
			t.Errorf("got  %q\nwant %q", keys[0].KeyRR, wantRR)
		}
	})

	t.Run("SIG0", func(t *testing.T) {
		dir := t.TempDir()
		base, wantRR, _ := writeBindStyleKeyFiles(t, dir, "dnslab.", true)

		m := &KeystoreManifest{Sig0: []ManifestSig0Key{{
			Zone: "dnslab.", Keyid: 1, Algorithm: "ED25519",
			State: Sig0StateActive, PrivateFile: base + ".private", PublicFile: base + ".key",
		}}}

		keys, err := m.LoadSig0Keys(dir)
		if err != nil {
			t.Fatalf("LoadSig0Keys: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(keys))
		}
		if strings.Contains(keys[0].KeyRR, ";") {
			t.Errorf("comment header survived into KeyRR:\n%s", keys[0].KeyRR)
		}
		if keys[0].KeyRR != wantRR {
			t.Errorf("got  %q\nwant %q", keys[0].KeyRR, wantRR)
		}
	})
}

// TestManifestLoadRejectsRecordlessKeyFile: a .key file with nothing but
// comments used to sail through here and fail much later, with an error about
// the wire key rather than about the file.
func TestManifestLoadRejectsRecordlessKeyFile(t *testing.T) {
	dir := t.TempDir()
	base, _, privPEM := writeBindStyleKeyFiles(t, dir, "dnslab.", false)
	if err := os.WriteFile(filepath.Join(dir, base+".key"), []byte(bindCommentHeader), 0644); err != nil {
		t.Fatal(err)
	}
	_ = privPEM

	m := &KeystoreManifest{Dnssec: []ManifestDnssecKey{{
		Zone: "dnslab.", Keyid: 1, Flags: 257, Algorithm: "ED25519",
		State: DnskeyStateActive, PrivateFile: base + ".private", PublicFile: base + ".key",
	}}}

	_, err := m.LoadDnssecKeys(dir)
	if err == nil {
		t.Fatal("a comment-only .key file was accepted")
	}
	if !strings.Contains(err.Error(), base+".key") {
		t.Errorf("error does not name the offending file: %v", err)
	}
}

// TestBulkValidateCanonicalisesKeyRR covers the backstop: a bulk payload that
// never went through a manifest -- hand-written, or produced by a tdns old
// enough to have copied .key files verbatim -- must still be canonicalised
// before it is stored.
func TestBulkValidateCanonicalisesKeyRR(t *testing.T) {
	t.Run("DNSSEC", func(t *testing.T) {
		k := testDnssecKey(t, "dnslab.", 257)
		want := k.KeyRR
		k.KeyRR = bindCommentHeader + k.KeyRR + "\n"

		got, err := validateDnssecKeyRR(k)
		if err != nil {
			t.Fatalf("validateDnssecKeyRR: %v", err)
		}
		if got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	})

	t.Run("SIG0", func(t *testing.T) {
		k := testBulkSig0Key(t, "dnslab.")
		want := k.KeyRR
		k.KeyRR = bindCommentHeader + k.KeyRR + "\n"

		got, err := validateSig0KeyRR(k)
		if err != nil {
			t.Fatalf("validateSig0KeyRR: %v", err)
		}
		if got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	})
}

// TestBulkImportStoresCanonicalKeyRR is the end-to-end shape of the bug: import
// a key whose RR text carries the comment header, then read the column back.
func TestBulkImportStoresCanonicalKeyRR(t *testing.T) {
	kdb := newTestKeyDB(t)

	k := testDnssecKey(t, "dnslab.", 257)
	want := k.KeyRR
	k.KeyRR = bindCommentHeader + k.KeyRR + "\n"

	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{k}, false); err != nil {
		t.Fatalf("BulkImportDnssec: %v", err)
	}

	var stored string
	row := kdb.DB.QueryRow(`SELECT keyrr FROM DnssecKeyStore WHERE zonename=? AND keyid=?`,
		"dnslab.", int(k.Keyid))
	if err := row.Scan(&stored); err != nil {
		t.Fatalf("reading back keyrr: %v", err)
	}
	if strings.Contains(stored, ";") {
		t.Errorf("comment header was stored in the keyrr column:\n%s", stored)
	}
	if stored != want {
		t.Errorf("got  %q\nwant %q", stored, want)
	}
}

// TestBulkImportCommentedRRIsNotAConflict: with the RR canonicalised before the
// diff, re-offering the same key from a still-commented .key file must read as
// "unchanged" rather than a keyrr conflict needing --force.
func TestBulkImportCommentedRRIsNotAConflict(t *testing.T) {
	kdb := newTestKeyDB(t)

	k := testDnssecKey(t, "dnslab.", 257)
	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{k}, false); err != nil {
		t.Fatalf("first import: %v", err)
	}

	commented := k
	commented.KeyRR = bindCommentHeader + k.KeyRR + "\n"

	disp, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{commented}, false)
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if len(disp) != 1 {
		t.Fatalf("got %d dispositions, want 1", len(disp))
	}
	if disp[0].Status != BulkStatusUnchanged {
		t.Errorf("status = %q (%s), want %q",
			disp[0].Status, disp[0].Detail, BulkStatusUnchanged)
	}
}

// TestTruststoreStoresCanonicalKeyRR: SIG(0) bulk-import mirrors each imported
// key into the truststore, and that mirror is fed from the CALLER's slice --
// canonicalising inside the import loop does not reach it. The truststore keeps
// RR text in a column of its own, so it canonicalises at its own boundary.
func TestTruststoreStoresCanonicalKeyRR(t *testing.T) {
	kdb := newTestKeyDB(t)

	k := testBulkSig0Key(t, "dnslab.")
	want := k.KeyRR
	k.KeyRR = bindCommentHeader + k.KeyRR + "\n"

	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "truststore", SubCommand: "add",
		Keyname: "dnslab.", Keyid: int(k.Keyid),
		Validated: true, Trusted: true, Src: "keystore",
		KeyRR: k.KeyRR,
	}); err != nil {
		t.Fatalf("Sig0TrustMgmt add: %v", err)
	}

	var stored string
	row := kdb.DB.QueryRow(`SELECT keyrr FROM Sig0TrustStore WHERE zonename=? AND keyid=?`,
		"dnslab.", int(k.Keyid))
	if err := row.Scan(&stored); err != nil {
		t.Fatalf("reading back keyrr: %v", err)
	}
	if strings.Contains(stored, ";") {
		t.Errorf("comment header was stored in the truststore keyrr column:\n%s", stored)
	}
	if stored != want {
		t.Errorf("got  %q\nwant %q", stored, want)
	}
}

// TestTruststoreRejectsRecordlessKeyRR: an "add" carrying text with no record in
// it used to be stored as-is. src=dns legitimately carries no key at all, which
// is why the canonicalisation is guarded on a non-empty KeyRR rather than
// required outright.
func TestTruststoreRejectsRecordlessKeyRR(t *testing.T) {
	kdb := newTestKeyDB(t)

	_, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "truststore", SubCommand: "add",
		Keyname: "dnslab.", Keyid: 1, Src: "file",
		KeyRR: bindCommentHeader,
	})
	if err == nil {
		t.Fatal("a comment-only KeyRR was accepted")
	}

	// src=dns supplies no key and must still be accepted.
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "truststore", SubCommand: "add",
		Keyname: "dnslab.", Keyid: 1, Src: "dns",
	}); err != nil {
		t.Errorf("src=dns with no KeyRR was rejected: %v", err)
	}
}

// TestTruststoreRejectsDnskey: the SIG(0) truststore must hold KEY records only.
// LoadSig0ChildKeys reads the table back through a *dns.KEY assertion and
// silently skips anything else, so a DNSKEY accepted here would be stored, then
// be absent from the runtime cache, with nothing logged at either end. Refusing
// it at the write boundary is the only place the operator finds out.
func TestTruststoreRejectsDnskey(t *testing.T) {
	kdb := newTestKeyDB(t)

	// Same key material, published as a DNSKEY rather than a KEY.
	dnssec := testDnssecKey(t, "dnslab.", 257)

	_, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "truststore", SubCommand: "add",
		Keyname: "dnslab.", Keyid: int(dnssec.Keyid),
		Validated: true, Trusted: true, Src: "keystore",
		KeyRR: dnssec.KeyRR,
	})
	if err == nil {
		t.Fatal("a DNSKEY was accepted into the SIG(0) truststore")
	}
	if !strings.Contains(err.Error(), "KEY") {
		t.Errorf("error does not say what was expected: %v", err)
	}

	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM Sig0TrustStore WHERE zonename=?`,
		"dnslab.").Scan(&n); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	if n != 0 {
		t.Errorf("the rejected DNSKEY was stored anyway: %d row(s)", n)
	}
}

// TestCanonicalSig0KeyRRRequiresKEY is the unit-level counterpart: KEY through,
// DNSKEY refused, comments stripped either way.
func TestCanonicalSig0KeyRRRequiresKEY(t *testing.T) {
	keyrr := "dnslab.\t3600\tIN\tKEY\t512 3 15 C4RKfg3IUwpjc+CnISaCuDX4OGpxsUIe7dqRVXj0KdU="
	dnskey := "dnslab.\t3600\tIN\tDNSKEY\t257 3 15 C4RKfg3IUwpjc+CnISaCuDX4OGpxsUIe7dqRVXj0KdU="

	got, err := canonicalSig0KeyRR(bindCommentHeader + keyrr + "\n")
	if err != nil {
		t.Fatalf("canonicalSig0KeyRR on a KEY: %v", err)
	}
	if got != keyrr {
		t.Errorf("got  %q\nwant %q", got, keyrr)
	}

	if _, err := canonicalSig0KeyRR(dnskey); err == nil {
		t.Error("a DNSKEY was accepted by canonicalSig0KeyRR")
	}
	if _, err := canonicalSig0KeyRR(bindCommentHeader); err == nil {
		t.Error("a comment-only input was accepted by canonicalSig0KeyRR")
	}
}
