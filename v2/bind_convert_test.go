/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// writeBindKeyTriple lays out a bind9 key the way dnssec-keygen does: a .key
// holding the public RR under two ';' comment lines, a .private in bind's own
// format, and (for a dnssec-policy zone) a .state.
//
// The key material is generated rather than pasted so the keytag in the RR, the
// keytag in the filename and the private key genuinely agree -- a fixture with a
// hand-copied keytag would pass while testing nothing.
func writeBindKeyTriple(t *testing.T, dir, zone string, flags uint16, state string) (base string, keyid uint16) {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keyid = k.KeyTag()
	base = KeyFileBasename(dns.Fqdn(zone), dns.ED25519, keyid)

	pub := "; This is a key-signing key, keyid " + strconv.Itoa(int(keyid)) + ", for " + dns.Fqdn(zone) + "\n" +
		"; Created: 20260715120000 (Wed Jul 15 14:00:00 2026)\n" + k.String() + "\n"
	if err := os.WriteFile(filepath.Join(dir, base+".key"), []byte(pub), 0644); err != nil {
		t.Fatalf("write .key: %v", err)
	}

	// k.PrivateKeyString produces exactly bind's Private-key-format text.
	privText := k.PrivateKeyString(priv) +
		"\nCreated: 20260715120000\nPublish: 20260715120000\nActivate: 20260716000000\n"
	if err := os.WriteFile(filepath.Join(dir, base+".private"), []byte(privText), 0600); err != nil {
		t.Fatalf("write .private: %v", err)
	}

	if state != "" {
		ksk, zsk := "no", "yes"
		if flags&0x0001 != 0 {
			ksk, zsk = "yes", "no"
		}
		st := "; This is the state of key " + strconv.Itoa(int(keyid)) + ", for " + dns.Fqdn(zone) + ".\n" +
			"Algorithm: 15\nLength: 256\nLifetime: 0\n" +
			"KSK: " + ksk + "\nZSK: " + zsk + "\n" +
			"Generated: 20260715120000\nPublished: 20260715120000\nActive: 20260716000000\n" + state
		if err := os.WriteFile(filepath.Join(dir, base+".state"), []byte(st), 0600); err != nil {
			t.Fatalf("write .state: %v", err)
		}
	}
	return base, keyid
}

// TestConvertBindKeyDirEndToEnd is the whole point of the command: a directory
// of bind9 output must come out loadable by PreloadKeystore, which is the thing
// that cannot be done today at all.
func TestConvertBindKeyDirEndToEnd(t *testing.T) {
	dir := t.TempDir()
	kskBase, kskID := writeBindKeyTriple(t, dir, "pq.dnslab.", 257,
		"DNSKEYState: omnipresent\nKRRSIGState: omnipresent\nDSState: omnipresent\nGoalState: omnipresent\n")
	zskBase, _ := writeBindKeyTriple(t, dir, "pq.dnslab.", 256,
		"DNSKEYState: rumoured\nZRRSIGState: hidden\nGoalState: omnipresent\n")

	ds, err := ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", Backup: true})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(ds) != 2 {
		t.Fatalf("expected 2 keys, got %+v", ds)
	}
	for _, d := range ds {
		if d.Status != BindConvertConverted {
			t.Fatalf("%s: got %q, want %q", d.Basename, d.Status, BindConvertConverted)
		}
	}

	// The private halves are PEM now, and the originals were kept.
	for _, base := range []string{kskBase, zskBase} {
		priv, err := os.ReadFile(filepath.Join(dir, base+".private"))
		if err != nil {
			t.Fatalf("read converted private: %v", err)
		}
		if !IsPEMFormat(string(priv)) {
			t.Fatalf("%s: private key was not converted to PEM", base)
		}
		orig, err := os.ReadFile(filepath.Join(dir, base+".private.orig"))
		if err != nil {
			t.Fatalf("%s: original was not preserved: %v", base, err)
		}
		if !strings.Contains(string(orig), "Private-key-format") {
			t.Errorf("%s: .private.orig does not hold the bind-format original", base)
		}
		// Still a private key, so still 0600.
		info, err := os.Stat(filepath.Join(dir, base+".private.orig"))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("%s: backup is mode %04o, want 0600", base, info.Mode().Perm())
		}
	}

	// The .key file must be untouched: it already held the final form.
	pub, err := os.ReadFile(filepath.Join(dir, kskBase+".key"))
	if err != nil {
		t.Fatalf("read .key: %v", err)
	}
	if !strings.Contains(string(pub), "; This is a key-signing key") {
		t.Error("the .key file was rewritten; it should not be touched at all")
	}

	// The states came from the .state files, per the agreed mapping.
	m, err := LoadKeystoreManifest(dir)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if len(m.Dnssec) != 2 {
		t.Fatalf("manifest should describe 2 keys, got %+v", m.Dnssec)
	}
	for _, e := range m.Dnssec {
		want := DnskeyStatePublished // the ZSK: DNSKEY out, not yet signing
		if e.Keyid == kskID {
			want = DnskeyStateActive // the KSK: fully rolled in
		}
		if e.State != want {
			t.Errorf("keyid %d: state %q, want %q", e.Keyid, e.State, want)
		}
		if e.ActiveAt != "2026-07-16T00:00:00Z" {
			t.Errorf("keyid %d: active_at %q, want the .state file's Active", e.Keyid, e.ActiveAt)
		}
		if e.Zone != "pq.dnslab." || e.Algorithm != "ED25519" {
			t.Errorf("keyid %d: wrong metadata: %+v", e.Keyid, e)
		}
	}

	// THE point: what comes out must pre-load.
	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Keystore.Preload.Dnssec = dir
	if err := conf.PreloadKeystore(context.Background()); err != nil {
		t.Fatalf("converted directory must be pre-loadable: %v", err)
	}
	got, err := kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("pre-load restored %d keys, want 2", len(got))
	}
}

// Re-running must be a no-op, not a second conversion of an already-PEM key
// (which would destroy it) and not a clobbered backup.
func TestConvertBindKeyDirIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	base, _ := writeBindKeyTriple(t, dir, "pq.dnslab.", 257,
		"DNSKEYState: omnipresent\nKRRSIGState: omnipresent\nDSState: omnipresent\n")

	if _, err := ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", Backup: true}); err != nil {
		t.Fatalf("first convert: %v", err)
	}
	firstPEM, err := os.ReadFile(filepath.Join(dir, base+".private"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	ds, err := ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", Backup: true})
	if err != nil {
		t.Fatalf("second convert: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BindConvertAlreadyPEM {
		t.Fatalf("got %+v, want one %q", ds, BindConvertAlreadyPEM)
	}
	againPEM, err := os.ReadFile(filepath.Join(dir, base+".private"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(firstPEM) != string(againPEM) {
		t.Error("a second run must not rewrite an already-converted key")
	}
}

// A key with no .state file cannot have its state guessed. Guessing wrong is
// how a retired key gets published again, so the run is refused unless the
// operator says which state to use.
func TestConvertBindKeyDirRefusesToGuessState(t *testing.T) {
	dir := t.TempDir()
	base, _ := writeBindKeyTriple(t, dir, "pq.dnslab.", 257, "") // no .state

	if _, err := ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", Backup: true}); err == nil {
		t.Fatal("a key with no .state and no --state must be refused")
	}
	// ...and nothing may have been written on the way to that refusal.
	priv, err := os.ReadFile(filepath.Join(dir, base+".private"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if IsPEMFormat(string(priv)) {
		t.Error("a refused run must not have converted anything")
	}
	if _, err := os.Stat(filepath.Join(dir, base+".private.orig")); err == nil {
		t.Error("a refused run must not have written a backup")
	}

	// With --state it goes through.
	ds, err := ConvertBindKeyDir(dir, BindConvertOptions{
		Class: "dnssec", DefaultState: DnskeyStateActive, Backup: true})
	if err != nil {
		t.Fatalf("convert with --state: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BindConvertConverted {
		t.Fatalf("got %+v, want one %q", ds, BindConvertConverted)
	}
	m, err := LoadKeystoreManifest(dir)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if len(m.Dnssec) != 1 || m.Dnssec[0].State != DnskeyStateActive {
		t.Fatalf("--state was not applied: %+v", m.Dnssec)
	}
}

// One bad key must take the whole run down BEFORE anything is written. A
// half-converted directory is the state an operator cannot diagnose by looking.
func TestConvertBindKeyDirIsAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	goodBase, _ := writeBindKeyTriple(t, dir, "aaa.dnslab.", 257,
		"DNSKEYState: omnipresent\nKRRSIGState: omnipresent\nDSState: omnipresent\n")
	badBase, _ := writeBindKeyTriple(t, dir, "zzz.dnslab.", 257,
		"DNSKEYState: sideways\n") // not a state bind can produce

	// aaa sorts before zzz, so the good key is planned first and would already
	// have been written under a one-pass implementation.
	if _, err := ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", Backup: true}); err == nil {
		t.Fatal("an unmappable state must fail the run")
	}
	for _, base := range []string{goodBase, badBase} {
		priv, err := os.ReadFile(filepath.Join(dir, base+".private"))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if IsPEMFormat(string(priv)) {
			t.Errorf("%s was converted despite another key failing", base)
		}
		if _, err := os.Stat(filepath.Join(dir, base+".private.orig")); err == nil {
			t.Errorf("%s: a backup was written despite the run failing", base)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, KeystoreManifestFile)); err == nil {
		t.Error("no manifest may be written by a failed run")
	}
}

// An unreadable private key is a VALIDATION failure, and must not be reported
// as a partial conversion: telling the operator the directory may be
// half-converted when it is untouched sends them hunting for damage that is not
// there -- the mirror image of the bug that motivated PartialConvertError.
//
// Scope, stated honestly: this exercises the phase-1 path. It does NOT prove
// the touched/untouched distinction inside phase 2, and an earlier version of
// this test claimed to and did not -- chmod 0000 makes phase 1's own read fail,
// so phase 2 is never reached, and the test passed with the distinction
// deliberately broken.
//
// That case is now closed by construction rather than by assertion: phase 2 no
// longer re-reads the private key (it carries the bytes from phase 1), so its
// first action on any key is a write. There is no read left in phase 2 to fail
// before something has been touched.
func TestConvertBindKeyDirValidationFailureIsNotReportedAsPartial(t *testing.T) {
	dir := t.TempDir()
	base, _ := writeBindKeyTriple(t, dir, "pq.dnslab.", 257,
		"DNSKEYState: omnipresent\nKRRSIGState: omnipresent\nDSState: omnipresent\n")

	priv := filepath.Join(dir, base+".private")
	if err := os.Chmod(priv, 0000); err != nil {
		t.Skipf("cannot make the private key unreadable: %v", err)
	}
	t.Cleanup(func() { os.Chmod(priv, 0600) })
	// chmod SUCCEEDS for root and then means nothing: root reads the file
	// regardless of the bits, the run converts the key, and the assertion below
	// fails for an environmental reason rather than a defect. Many CI images
	// run tests as root, so prove the premise before relying on it.
	if _, rerr := os.ReadFile(priv); rerr == nil {
		t.Skip("this process can read a mode-0000 file (running as root?); " +
			"the unreadable-key premise does not hold here")
	}

	_, err := ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", Backup: true})
	if err == nil {
		t.Fatal("an unreadable private key must fail the run")
	}
	var partial *PartialConvertError
	if errors.As(err, &partial) {
		t.Fatalf("a validation failure must NOT be reported as partial: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, base+".private.orig")); serr == nil {
		t.Error("no backup should exist after a validation failure")
	}
}

// A .state file that disagrees with the DNSKEY's SEP bit means the two files do
// not belong to the same key. Trusting either silently is how a ZSK ends up
// judged on the KSK's signing record.
func TestConvertBindKeyDirRefusesMismatchedStateFile(t *testing.T) {
	dir := t.TempDir()
	// flags 256 => ZSK, but the .state claims KSK.
	writeBindKeyTriple(t, dir, "pq.dnslab.", 256,
		"DNSKEYState: omnipresent\nZRRSIGState: omnipresent\n")
	base, _ := func() (string, uint16) {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".state") {
				return strings.TrimSuffix(e.Name(), ".state"), 0
			}
		}
		t.Fatal("no .state written")
		return "", 0
	}()
	st, err := os.ReadFile(filepath.Join(dir, base+".state"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	flipped := strings.Replace(string(st), "KSK: no\nZSK: yes", "KSK: yes\nZSK: no", 1)
	if err := os.WriteFile(filepath.Join(dir, base+".state"), []byte(flipped), 0600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	_, err = ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", Backup: true})
	if err == nil {
		t.Fatal("a .state file that disagrees with the DNSKEY flags must be refused")
	}
	if !strings.Contains(err.Error(), "does not match the key") {
		t.Errorf("the error should name the mismatch, got: %v", err)
	}
}

// Two distinct keys that collide on zone+keyid are one manifest entry, and
// Upsert* replaces rather than appends. Converting both would rewrite both
// .private files while describing only the second, leaving the first converted
// and unreferenced -- pre-load would never restore it, and nothing would say so.
func TestConvertBindKeyDirRefusesManifestIdentityCollision(t *testing.T) {
	dir := t.TempDir()
	base, keyid := writeBindKeyTriple(t, dir, "pq.dnslab.", 257,
		"DNSKEYState: omnipresent\nKRRSIGState: omnipresent\nDSState: omnipresent\n")

	// A second, genuinely different key forced onto the same keytag by copying
	// the first one's filename identity is not possible through the filename
	// alone -- the identity comes from the RR -- so build the collision the way
	// it would really arise: a second key whose RR carries the same owner and
	// keytag. Simplest faithful construction is to copy the triple under a new
	// basename, which yields two files describing one manifest identity.
	for _, ext := range []string{".key", ".private", ".state"} {
		data, err := os.ReadFile(filepath.Join(dir, base+ext))
		if err != nil {
			t.Fatalf("read %s: %v", ext, err)
		}
		if err := os.WriteFile(filepath.Join(dir, base+".copy"+ext), data, 0600); err != nil {
			t.Fatalf("write copy%s: %v", ext, err)
		}
	}

	_, err := ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", Backup: true})
	if err == nil {
		t.Fatal("two keys sharing one manifest identity must fail the run")
	}
	if !strings.Contains(err.Error(), "share zone") {
		t.Errorf("the error should name the collision, got: %v", err)
	}
	_ = keyid

	// All-or-nothing: neither copy may have been converted.
	for _, b := range []string{base, base + ".copy"} {
		priv, rerr := os.ReadFile(filepath.Join(dir, b+".private"))
		if rerr != nil {
			t.Fatalf("read %s: %v", b, rerr)
		}
		if IsPEMFormat(string(priv)) {
			t.Errorf("%s was converted despite the collision", b)
		}
	}
}

// The converted key is written atomically, so a reader never sees a truncated
// file and a crash mid-write cannot destroy the only copy of the key material.
func TestConvertBindKeyDirWritesTheKeyAtomically(t *testing.T) {
	dir := t.TempDir()
	base, _ := writeBindKeyTriple(t, dir, "pq.dnslab.", 257,
		"DNSKEYState: omnipresent\nKRRSIGState: omnipresent\nDSState: omnipresent\n")

	if _, err := ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", Backup: false}); err != nil {
		t.Fatalf("convert: %v", err)
	}

	priv := filepath.Join(dir, base+".private")
	data, err := os.ReadFile(priv)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !IsPEMFormat(string(data)) {
		t.Fatalf("not converted: %q", string(data[:min(40, len(data))]))
	}
	// The mode must arrive with the file, not be applied afterwards to
	// something that already holds the secret.
	info, err := os.Stat(priv)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("converted key is mode %04o, want 0600", info.Mode().Perm())
	}
	// No temp files left behind, whether or not the run succeeded.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") && strings.Contains(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// The same collision, but with the two owners differing only in CASE. DNS names
// are case-insensitive, yet the manifest's own matchers disagree about that --
// UpsertDnssec compares with ==, manifestHasKey uses EqualFold -- so an
// unnormalised collision key would let these through to be appended as two
// entries for what is one zone, and imported as two keystore rows.
func TestConvertBindKeyDirCollisionIsCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	base, _ := writeBindKeyTriple(t, dir, "pq.dnslab.", 257,
		"DNSKEYState: omnipresent\nKRRSIGState: omnipresent\nDSState: omnipresent\n")

	// Copy the triple, upper-casing the owner in the public RR so the parsed
	// name differs only by case.
	for _, ext := range []string{".key", ".private", ".state"} {
		data, err := os.ReadFile(filepath.Join(dir, base+ext))
		if err != nil {
			t.Fatalf("read %s: %v", ext, err)
		}
		out := string(data)
		if ext == ".key" {
			// The OWNER on the RR line, not the first match in the file: the
			// first "pq.dnslab." is inside dnssec-keygen's ';' comment header,
			// which stripZonefileComments discards before parsing. Rewriting
			// that changed nothing the parser ever saw, and the test quietly
			// became a second copy of the plain-collision case.
			var lines []string
			for _, ln := range strings.Split(out, "\n") {
				if !strings.HasPrefix(strings.TrimSpace(ln), ";") && strings.HasPrefix(ln, "pq.dnslab.") {
					ln = "PQ.DNSLAB." + strings.TrimPrefix(ln, "pq.dnslab.")
				}
				lines = append(lines, ln)
			}
			out = strings.Join(lines, "\n")
			if !strings.Contains(out, "PQ.DNSLAB.\t") && !strings.Contains(out, "PQ.DNSLAB. ") {
				t.Fatalf("fixture did not upper-case the RR owner:\n%s", out)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, base+".upper"+ext), []byte(out), 0600); err != nil {
			t.Fatalf("write upper%s: %v", ext, err)
		}
	}

	_, err := ConvertBindKeyDir(dir, BindConvertOptions{Class: "dnssec", Backup: true})
	if err == nil {
		t.Fatal("owners differing only by case are one zone and must collide")
	}
	if !strings.Contains(err.Error(), "share zone") {
		t.Errorf("the error should name the collision, got: %v", err)
	}
}
