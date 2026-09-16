/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// cxKey describes one key of a fixture keyset. st is the state as dnst would
// record it; a CSK takes kskRole and zskRole instead.
type cxKey struct {
	role    string // Ksk, Zsk, Csk, Include
	st      cascadeKeyState
	kskRole cascadeKeyState
	zskRole cascadeKeyState
	kmip    bool
}

// cxGenerated is what the fixture builder made for one key.
type cxGenerated struct {
	dnskey *dns.DNSKEY
	base   string
	pubURL string
}

// cxZone builds a Cascade keys-dir: key files in dnst's form and a state file
// in serde's JSON shape, with the fields the converter ignores present too.
type cxZone struct {
	t          *testing.T
	dir        string
	zone       string // as dnst writes it: no trailing dot
	keys       []cxGenerated
	state      map[string]any
	rollstates map[string]any
}

var (
	cxT0 = int64(1757000000)
	st   = func(available, old, signer, present, atParent bool) cascadeKeyState {
		return cascadeKeyState{Available: available, Old: old, Signer: signer, Present: present, AtParent: atParent}
	}
	// Steady states from dnst's roll sequences.
	activeKSK  = st(true, false, true, true, true)
	activeZSK  = st(true, false, true, true, false)
	incomingZ  = st(true, false, false, true, false)
	leavingZSK = st(true, true, true, true, false)
	retiredZSK = st(true, true, false, true, false)
	staleKey   = st(true, true, false, false, false)
	futureKey  = st(true, false, false, false, false)
)

func newCxZone(t *testing.T, zone string, keys ...cxKey) *cxZone {
	t.Helper()
	z := &cxZone{t: t, dir: t.TempDir(), zone: zone, rollstates: map[string]any{}}
	jsonKeys := map[string]any{}
	var apex, ds []string
	for i, k := range keys {
		flags := uint16(256)
		if k.role == "Ksk" || k.role == "Csk" {
			flags = 257
		}
		dnskey := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     flags,
			Protocol:  3,
			Algorithm: dns.ECDSAP256SHA256,
		}
		priv, err := dnskey.Generate(256)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		base := KeyFileBasename(dns.Fqdn(zone), dnskey.Algorithm, dnskey.KeyTag())
		// dnst names keys under Cascade's keys-dir on its own host; the
		// converter has to find them by base name in the copy.
		pubURL := "file:///var/lib/cascade/keys/" + base + ".key"
		privURL := "file:///var/lib/cascade/keys/" + base + ".private"
		if k.kmip {
			pubURL = "kmip://hsm1/keys/pub-" + base + "?algorithm=13&flags=257"
			privURL = "kmip://hsm1/keys/priv-" + base + "?algorithm=13&flags=257"
		}

		if k.role != "Include" {
			// domain writes the RR without a TTL and a trailing comment, and
			// the private key as Private-key-format v1.2.
			pub := dns.Fqdn(zone) + " IN DNSKEY " + strings.TrimPrefix(dnskey.String(), dnskey.Hdr.String()) + " ;{id = x}\n"
			if err := os.WriteFile(filepath.Join(z.dir, base+".key"), []byte(pub), 0644); err != nil {
				t.Fatal(err)
			}
			privText := strings.Replace(dnskey.PrivateKeyString(priv), "v1.3", "v1.2", 1)
			if err := os.WriteFile(filepath.Join(z.dir, base+".private"), []byte(privText), 0600); err != nil {
				t.Fatal(err)
			}
		}

		var keytype any
		var present, atParent bool
		switch k.role {
		case "Csk":
			keytype = map[string]any{"Csk": []cascadeKeyState{k.kskRole, k.zskRole}}
			present, atParent = k.kskRole.Present, k.kskRole.AtParent
		default:
			keytype = map[string]any{k.role: k.st}
			present, atParent = k.st.Present, k.st.AtParent
		}
		var privref any = privURL
		if k.role == "Include" {
			privref = nil
		}
		ts := func(off int64) map[string]any { return map[string]any{"secs": cxT0 + off, "nanos": 123456789} }
		jsonKeys[pubURL] = map[string]any{
			"privref":   privref,
			"decoupled": false,
			"keytype":   keytype,
			"algorithm": dnskey.Algorithm,
			"key_tag":   dnskey.KeyTag(),
			"timestamps": map[string]any{
				"creation": ts(int64(i)), "published": ts(100), "visible": ts(3700),
				"ds_visible": nil, "rrsig_visible": ts(7300), "withdrawn": nil,
			},
		}
		if present {
			apex = append(apex, dnskey.String())
		}
		if atParent {
			ds = append(ds, dnskey.ToDS(dns.SHA256).String())
		}
		z.keys = append(z.keys, cxGenerated{dnskey: dnskey, base: base, pubURL: pubURL})
	}
	apex = append(apex, dns.Fqdn(zone)+" 3600 IN RRSIG DNSKEY 13 2 3600 20360101000000 20260101000000 12345 "+dns.Fqdn(zone)+" AAAA")
	z.state = map[string]any{
		"keyset":                       map[string]any{"name": zone, "keys": jsonKeys, "rollstates": z.rollstates},
		"dnskey_rrset":                 apex,
		"ds_rrset":                     ds,
		"cds_rrset":                    []string{},
		"ns_rrset":                     []string{},
		"apex_remove":                  []string{"DNSKEY", "CDS", "CDNSKEY"},
		"apex_extra":                   apex,
		"cron_next":                    map[string]any{"secs": cxT0 + 86400, "nanos": 0},
		"kmip":                         map[string]any{"servers": map[string]any{}},
		"internal":                     map[string]any{},
		"a_field_from_a_later_release": true,
	}
	return z
}

func (z *cxZone) write() string {
	z.t.Helper()
	data, err := json.MarshalIndent(z.state, "", "  ")
	if err != nil {
		z.t.Fatal(err)
	}
	path := filepath.Join(z.dir, strings.ToLower(z.zone)+".state")
	if err := os.WriteFile(path, data, 0600); err != nil {
		z.t.Fatal(err)
	}
	return path
}

func (z *cxZone) convert(dest string, mod func(*CascadeConvertOptions)) ([]CascadeConvertDisposition, error) {
	z.t.Helper()
	opts := CascadeConvertOptions{StateFiles: []string{z.write()}, Dest: dest,
		Now: time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)}
	if mod != nil {
		mod(&opts)
	}
	return ConvertCascadeKeys(opts)
}

func manifestByKeyid(t *testing.T, dir string) map[uint16]ManifestDnssecKey {
	t.Helper()
	m, err := LoadKeystoreManifest(dir)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	out := map[uint16]ManifestDnssecKey{}
	for _, e := range m.Dnssec {
		out[e.Keyid] = e
	}
	return out
}

func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(data)
	}
	return out
}

// The default case: a KSK and a ZSK, no roll in progress. Both become active,
// the output pre-loads, and Cascade's keys-dir is left exactly as it was.
func TestCascadeConvertKskZsk(t *testing.T) {
	z := newCxZone(t, "example.com", cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK})
	stateFile := z.write()
	before := snapshotDir(t, z.dir)
	dest := filepath.Join(t.TempDir(), "export")

	ds, err := ConvertCascadeKeys(CascadeConvertOptions{StateFiles: []string{stateFile}, Dest: dest})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(ds) != 2 {
		t.Fatalf("dispositions = %+v, want 2", ds)
	}
	for _, d := range ds {
		if d.Status != CascadeConvertConverted || d.State != DnskeyStateActive || d.Zone != "example.com." {
			t.Errorf("disposition %+v, want converted, active, zone example.com.", d)
		}
	}

	if after := snapshotDir(t, z.dir); len(after) != len(before) {
		t.Errorf("Cascade's keys-dir changed: %d files before, %d after", len(before), len(after))
	} else {
		for name, content := range before {
			if after[name] != content {
				t.Errorf("Cascade's %s was modified", name)
			}
		}
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("dest is mode %04o, want 0700", info.Mode().Perm())
	}
	entries := manifestByKeyid(t, dest)
	for _, k := range z.keys {
		e, ok := entries[k.dnskey.KeyTag()]
		if !ok {
			t.Fatalf("keyid %d missing from the manifest", k.dnskey.KeyTag())
		}
		if e.Zone != "example.com." || e.Creator != "cascade" || e.State != DnskeyStateActive {
			t.Errorf("keyid %d: entry %+v", e.Keyid, e)
		}
		if e.PublishedAt != time.Unix(cxT0+100, 0).UTC().Format(time.RFC3339) {
			t.Errorf("keyid %d: published_at %q, want Cascade's published", e.Keyid, e.PublishedAt)
		}
		if e.ActiveAt != time.Unix(cxT0+7300, 0).UTC().Format(time.RFC3339) {
			t.Errorf("keyid %d: active_at %q, want Cascade's rrsig_visible", e.Keyid, e.ActiveAt)
		}
		if e.RetiredAt != "" {
			t.Errorf("keyid %d: retired_at %q on an active key", e.Keyid, e.RetiredAt)
		}
		if !strings.HasPrefix(e.Comment, "cascade: ") || !strings.Contains(e.Comment, "created ") {
			t.Errorf("keyid %d: comment %q lacks Cascade's label and creation time", e.Keyid, e.Comment)
		}
		priv, err := os.ReadFile(filepath.Join(dest, e.PrivateFile))
		if err != nil {
			t.Fatal(err)
		}
		if !IsPEMFormat(string(priv)) {
			t.Errorf("keyid %d: private key is not PEM", e.Keyid)
		}
		if pi, _ := os.Stat(filepath.Join(dest, e.PrivateFile)); pi.Mode().Perm() != 0600 {
			t.Errorf("keyid %d: private key is mode %04o, want 0600", e.Keyid, pi.Mode().Perm())
		}
	}

	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Keystore.Preload.Dnssec = dest
	if err := conf.PreloadKeystore(context.Background()); err != nil {
		t.Fatalf("pre-load: %v", err)
	}
	dak, err := kdb.GetDnssecKeys("example.com.", DnskeyStateActive)
	if err != nil {
		t.Fatal(err)
	}
	if len(dak.KSKs) != 1 || dak.KSKs[0].KeyId != z.keys[0].dnskey.KeyTag() {
		t.Errorf("active KSKs after pre-load = %d, want keyid %d", len(dak.KSKs), z.keys[0].dnskey.KeyTag())
	}
	var realZSK bool
	for _, k := range dak.ZSKs {
		if k.KeyId == z.keys[1].dnskey.KeyTag() && k.DnskeyRR.Flags == 256 {
			realZSK = true
		}
	}
	if !realZSK {
		t.Errorf("the ZSK is not an active ZSK after pre-load")
	}
}

func TestCascadeConvertCsk(t *testing.T) {
	z := newCxZone(t, "csk.example", cxKey{role: "Csk", kskRole: activeKSK, zskRole: activeZSK})
	dest := t.TempDir()
	if _, err := z.convert(dest, nil); err != nil {
		t.Fatalf("convert: %v", err)
	}
	e := manifestByKeyid(t, dest)[z.keys[0].dnskey.KeyTag()]
	if e.State != DnskeyStateActive || e.Flags != 257 {
		t.Errorf("CSK entry %+v, want active with flags 257", e)
	}
}

// A roll in progress is refused unless allowed; allowed, the roll's keys map
// to neighbouring states and nothing tdns does not keep.
func TestCascadeConvertRollInProgress(t *testing.T) {
	// A ZSK roll just after its start: the new ZSK is published, the old one
	// still signs.
	z := newCxZone(t, "roll.example",
		cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: leavingZSK}, cxKey{role: "Zsk", st: incomingZ})
	z.rollstates["ZskRoll"] = "Propagation1"

	if _, err := z.convert(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "roll in progress") {
		t.Fatalf("a roll in progress was not refused: %v", err)
	}

	dest := t.TempDir()
	if _, err := z.convert(dest, func(o *CascadeConvertOptions) { o.AllowRollInProgress = true }); err != nil {
		t.Fatalf("convert with --allow-roll-in-progress: %v", err)
	}
	entries := manifestByKeyid(t, dest)
	if got := entries[z.keys[1].dnskey.KeyTag()].State; got != DnskeyStateActive {
		t.Errorf("the leaving ZSK is %q, want active (it still signs)", got)
	}
	if got := entries[z.keys[2].dnskey.KeyTag()].State; got != DnskeyStatePublished {
		t.Errorf("the incoming ZSK is %q, want published", got)
	}

	// Later in the roll: the old ZSK no longer signs but is still published.
	z2 := newCxZone(t, "roll2.example",
		cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK}, cxKey{role: "Zsk", st: retiredZSK})
	z2.rollstates["ZskRoll"] = map[string]any{"CacheExpire1": 3600}
	dest2 := t.TempDir()
	if _, err := z2.convert(dest2, func(o *CascadeConvertOptions) { o.AllowRollInProgress = true }); err != nil {
		t.Fatalf("convert: %v", err)
	}
	e := manifestByKeyid(t, dest2)[z2.keys[2].dnskey.KeyTag()]
	if e.State != DnskeyStateRetired {
		t.Errorf("the retired ZSK is %q, want retired", e.State)
	}
	if e.RetiredAt != "2026-09-16T12:00:00Z" {
		t.Errorf("retired_at %q, want the conversion time: the key state worker never removes a retired key without it", e.RetiredAt)
	}
}

// Another signer's key is never converted. In the DNSKEY RRset it is refused
// unless the target is tdns-mpsigner (--multi-signer), and it still counts in
// the cross-check.
func TestCascadeConvertOtherSignersKeys(t *testing.T) {
	z := newCxZone(t, "ms.example",
		cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK}, cxKey{role: "Include", st: activeZSK})
	other := z.keys[2].dnskey.KeyTag()

	if _, err := z.convert(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "--multi-signer") {
		t.Fatalf("another signer's present key was not refused: %v", err)
	}

	dest := t.TempDir()
	ds, err := z.convert(dest, func(o *CascadeConvertOptions) { o.MultiSigner = true })
	if err != nil {
		t.Fatalf("convert with --multi-signer: %v", err)
	}
	var reported bool
	for _, d := range ds {
		if d.Keyid == other {
			reported = d.Status == CascadeConvertSkipped && d.Role == "Include"
		}
	}
	if !reported {
		t.Errorf("another signer's key %d is not reported as skipped: %+v", other, ds)
	}
	if _, ok := manifestByKeyid(t, dest)[other]; ok {
		t.Errorf("another signer's key %d was written to the export directory", other)
	}
}

func TestCascadeConvertRefusesHSMKeys(t *testing.T) {
	z := newCxZone(t, "hsm.example", cxKey{role: "Ksk", st: activeKSK, kmip: true}, cxKey{role: "Zsk", st: activeZSK})
	if _, err := z.convert(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "HSM") {
		t.Fatalf("a KMIP key was not refused: %v", err)
	}
}

func TestCascadeConvertRefusesSignerNotPresent(t *testing.T) {
	z := newCxZone(t, "odd.example", cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: st(true, false, true, false, false)})
	if _, err := z.convert(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "signs but is not in the DNSKEY RRset") {
		t.Fatalf("a signing key that is not published was not refused: %v", err)
	}
}

func TestCascadeConvertSkipsStaleAndFuture(t *testing.T) {
	z := newCxZone(t, "old.example",
		cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK},
		cxKey{role: "Zsk", st: staleKey}, cxKey{role: "Ksk", st: futureKey})
	dest := t.TempDir()
	ds, err := z.convert(dest, nil)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	entries := manifestByKeyid(t, dest)
	for _, k := range z.keys[2:] {
		if _, ok := entries[k.dnskey.KeyTag()]; ok {
			t.Errorf("keyid %d (stale or future) was converted", k.dnskey.KeyTag())
		}
	}
	skipped := 0
	for _, d := range ds {
		if d.Status == CascadeConvertSkipped {
			skipped++
		}
	}
	if skipped != 2 {
		t.Errorf("%d keys reported skipped, want 2: %+v", skipped, ds)
	}
}

// The mapping is proved against what Cascade serves; a state file that
// disagrees with itself is refused.
func TestCascadeConvertCrossChecks(t *testing.T) {
	t.Run("DNSKEY RRset", func(t *testing.T) {
		z := newCxZone(t, "x1.example", cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK})
		apex := z.state["apex_extra"].([]string)
		z.state["apex_extra"] = []string{apex[0], apex[2]} // the ZSK is gone
		z.state["dnskey_rrset"] = z.state["apex_extra"]
		if _, err := z.convert(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "does not reproduce the DNSKEY RRset") {
			t.Fatalf("a DNSKEY RRset without the active ZSK was not refused: %v", err)
		}
	})
	t.Run("DS set from the flags", func(t *testing.T) {
		notAtParent := activeKSK
		notAtParent.AtParent = false
		z := newCxZone(t, "x2.example", cxKey{role: "Ksk", st: notAtParent}, cxKey{role: "Zsk", st: activeZSK})
		if _, err := z.convert(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "at the parent") {
			t.Fatalf("an active KSK without a DS was not refused: %v", err)
		}
	})
	t.Run("ds_rrset", func(t *testing.T) {
		z := newCxZone(t, "x3.example", cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK})
		z.state["ds_rrset"] = []string{z.keys[1].dnskey.ToDS(dns.SHA256).String()} // names the ZSK
		if _, err := z.convert(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "ds_rrset") {
			t.Fatalf("a ds_rrset naming the wrong key was not refused: %v", err)
		}
	})
	t.Run("key file disagrees with the state file", func(t *testing.T) {
		z := newCxZone(t, "x4.example", cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK})
		keys := z.state["keyset"].(map[string]any)["keys"].(map[string]any)
		keys[z.keys[1].pubURL].(map[string]any)["key_tag"] = z.keys[1].dnskey.KeyTag() + 1
		if _, err := z.convert(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "the state file says") {
			t.Fatalf("a key tag mismatch was not refused: %v", err)
		}
	})
	t.Run("role disagrees with the flags", func(t *testing.T) {
		z := newCxZone(t, "x5.example", cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK})
		keys := z.state["keyset"].(map[string]any)["keys"].(map[string]any)
		keys[z.keys[0].pubURL].(map[string]any)["keytype"] = map[string]any{"Zsk": activeKSK}
		if _, err := z.convert(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "does not fit its role") {
			t.Fatalf("a KSK file recorded as a ZSK was not refused: %v", err)
		}
	})
}

func TestCascadeConvertNeverWritesWhereItReads(t *testing.T) {
	z := newCxZone(t, "same.example", cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK})
	before := snapshotDir(t, z.dir)
	if _, err := z.convert(z.dir, nil); err == nil || !strings.Contains(err.Error(), "reads from") {
		t.Fatalf("--dest equal to the keys-dir was not refused: %v", err)
	}
	after := snapshotDir(t, z.dir)
	for name := range after {
		if _, ok := before[name]; !ok && !strings.HasSuffix(name, ".state") {
			t.Errorf("%s appeared in the keys-dir", name)
		}
	}
}

func TestCascadeConvertIsIdempotent(t *testing.T) {
	z := newCxZone(t, "again.example", cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK})
	dest := t.TempDir()
	if _, err := z.convert(dest, nil); err != nil {
		t.Fatalf("first run: %v", err)
	}
	first := snapshotDir(t, dest)
	if _, err := z.convert(dest, nil); err != nil {
		t.Fatalf("second run: %v", err)
	}
	second := snapshotDir(t, dest)
	if len(first) != len(second) {
		t.Fatalf("second run changed the file set: %d then %d", len(first), len(second))
	}
	for name, content := range first {
		if second[name] != content {
			t.Errorf("%s changed on the second run", name)
		}
	}

	// A destination file holding something else is refused before writing.
	for name := range first {
		if strings.HasSuffix(name, ".key") {
			if err := os.WriteFile(filepath.Join(dest, name), []byte("something else\n"), 0644); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	_, err := z.convert(dest, nil)
	var partial *PartialConvertError
	if err == nil || errors.As(err, &partial) || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("a conflicting destination file was not refused up front: %v", err)
	}
}

// The state file names keys by absolute paths on the Cascade host; the keys
// are found by base name, in --keys-dir when the state file lives elsewhere.
func TestCascadeConvertKeysDir(t *testing.T) {
	z := newCxZone(t, "split.example", cxKey{role: "Ksk", st: activeKSK}, cxKey{role: "Zsk", st: activeZSK})
	stateDir := t.TempDir()
	data, err := json.Marshal(z.state)
	if err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(stateDir, "split.example.state")
	if err := os.WriteFile(stateFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := ConvertCascadeKeys(CascadeConvertOptions{StateFiles: []string{stateFile}, Dest: t.TempDir()}); err == nil {
		t.Fatal("keys missing beside the state file were not reported")
	}
	if _, err := ConvertCascadeKeys(CascadeConvertOptions{StateFiles: []string{stateFile}, KeysDir: z.dir, Dest: t.TempDir()}); err != nil {
		t.Fatalf("convert with --keys-dir: %v", err)
	}
}
