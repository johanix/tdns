/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Converting the keys of zones signed by NLnet Labs' Cascade into an export
 * directory tdns can pre-load, so a zone moves to tdns with the SAME keys and
 * the parent's DS stays as it is. Design: docs/2026-09-16-cascade-key-migration.md.
 *
 * Cascade leaves key management to `dnst keyset`, which keeps one JSON state
 * file per zone (<keys-dir>/<zone>.state) and, for file-backed keys, a
 * bind-format .key/.private pair per key (Private-key-format v1.2). The state
 * file is the source of truth for which keys sign, which are published and
 * which have a DS; the key files carry the material.
 *
 * Unlike bind conversion this never writes where it reads: Cascade's signer
 * reads the bind-format files, so the output goes to a separate directory.
 */

package tdns

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Outcomes of one Cascade key.
const (
	CascadeConvertConverted = "converted"
	CascadeConvertSkipped   = "skipped"
)

// CascadeConvertOptions controls one conversion run.
type CascadeConvertOptions struct {
	// StateFiles are dnst keyset state files, one per zone.
	StateFiles []string

	// KeysDir is where the key files are looked up, by the base name of the
	// URL the state file records. Empty means each state file's own directory,
	// which is Cascade's layout (keys-dir holds both).
	KeysDir string

	// Dest is the export directory to write. It must not be a directory the
	// run reads from.
	Dest string

	// AllowRollInProgress converts a zone whose keyset has a roll in progress,
	// with the approximate mapping. tdns does not continue Cascade's roll.
	AllowRollInProgress bool

	// MultiSigner accepts another signer's key (no private key) that is
	// present in the DNSKEY RRset: the target is tdns-mpsigner, which takes
	// the other signers' keys from its incoming zone. Without it such a key is
	// refused, because tdns-auth and tdns-signer would drop it from the zone.
	MultiSigner bool

	// Now stamps retired_at on retired keys. Zero means time.Now().
	Now time.Time
}

// CascadeConvertDisposition is one key's outcome.
type CascadeConvertDisposition struct {
	StateFile string
	Zone      string
	Keyid     uint16
	Algorithm string
	Role      string // KSK, ZSK, CSK, or Include for another signer's key
	Cascade   string // Cascade's own label for the key, e.g. "Active, at parent"
	State     string // the tdns state, for a converted key
	Status    string
	Detail    string
}

// --- the state file ------------------------------------------------------
//
// The shape is serde's derived JSON of dnst's KeySetState and domain's KeySet
// (identical in dnst 0.2.0-alpha3 and main). Only the fields the conversion
// needs are declared; everything else is ignored, because the format is a
// pre-1.0 serialization that grows fields with serde defaults.

type cascadeStateFile struct {
	Keyset      cascadeKeySet `json:"keyset"`
	DnskeyRRset []string      `json:"dnskey_rrset"`
	DsRRset     []string      `json:"ds_rrset"`
	ApexExtra   []string      `json:"apex_extra"`
}

type cascadeKeySet struct {
	Name       string                     `json:"name"`
	Keys       map[string]cascadeKey      `json:"keys"`
	Rollstates map[string]json.RawMessage `json:"rollstates"`
}

type cascadeKey struct {
	Privref    *string           `json:"privref"`
	Keytype    json.RawMessage   `json:"keytype"`
	Algorithm  *uint8            `json:"algorithm"`
	KeyTag     *uint16           `json:"key_tag"`
	Timestamps cascadeTimestamps `json:"timestamps"`
}

type cascadeKeyState struct {
	Available bool `json:"available"`
	Old       bool `json:"old"`
	Signer    bool `json:"signer"`
	Present   bool `json:"present"`
	AtParent  bool `json:"at_parent"`
}

type cascadeTimestamps struct {
	Creation     *cascadeUnixTime `json:"creation"`
	Published    *cascadeUnixTime `json:"published"`
	Visible      *cascadeUnixTime `json:"visible"`
	DsVisible    *cascadeUnixTime `json:"ds_visible"`
	RrsigVisible *cascadeUnixTime `json:"rrsig_visible"`
	Withdrawn    *cascadeUnixTime `json:"withdrawn"`
}

// cascadeUnixTime is serde's form of a Rust Duration since the epoch.
type cascadeUnixTime struct {
	Secs  int64 `json:"secs"`
	Nanos int64 `json:"nanos"`
}

func (u *cascadeUnixTime) rfc3339() string {
	if u == nil {
		return ""
	}
	return time.Unix(u.Secs, 0).UTC().Format(time.RFC3339)
}

// cascadeRole is a key's role and its effective state. A CSK has a state per
// role; it signs if either role does, and its KSK role decides DNSKEY
// membership and the DS (Q5).
type cascadeRole struct {
	name string // KSK, ZSK, CSK, Include
	st   cascadeKeyState
}

func parseCascadeKeytype(raw json.RawMessage) (cascadeRole, error) {
	var tagged map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tagged); err != nil || len(tagged) != 1 {
		return cascadeRole{}, fmt.Errorf("keytype is not one of Ksk, Zsk, Csk or Include: %s", string(raw))
	}
	for variant, body := range tagged {
		switch variant {
		case "Ksk", "Zsk", "Include":
			var st cascadeKeyState
			if err := json.Unmarshal(body, &st); err != nil {
				return cascadeRole{}, fmt.Errorf("keytype %s: %v", variant, err)
			}
			return cascadeRole{name: map[string]string{"Ksk": "KSK", "Zsk": "ZSK", "Include": "Include"}[variant], st: st}, nil
		case "Csk":
			var both []cascadeKeyState
			if err := json.Unmarshal(body, &both); err != nil || len(both) != 2 {
				return cascadeRole{}, fmt.Errorf("keytype Csk: want [ksk-role, zsk-role], got %s", string(body))
			}
			st := both[0]
			st.Signer = both[0].Signer || both[1].Signer
			return cascadeRole{name: "CSK", st: st}, nil
		default:
			return cascadeRole{}, fmt.Errorf("unknown keytype %q", variant)
		}
	}
	return cascadeRole{}, fmt.Errorf("empty keytype")
}

// cascadeLabel reproduces Cascade's own naming of a key state, for reports.
func cascadeLabel(st cascadeKeyState) string {
	var label string
	switch {
	case !st.Old && !st.Signer && !st.Present:
		label = "Future"
	case !st.Old && !st.Signer && st.Present:
		label = "Incoming"
	case !st.Old && st.Signer:
		label = "Active"
	case st.Old && st.Signer:
		label = "Leaving"
	case st.Old && !st.Signer && st.Present:
		label = "Retired"
	default:
		label = "Stale"
	}
	if st.AtParent {
		label += ", at parent"
	}
	return label
}

// cascadeTdnsState maps a key's effective state to a tdns state (design §5.4).
// convert is false for a key tdns has no use for: Future and Stale.
func cascadeTdnsState(role string, st cascadeKeyState) (state string, convert bool, err error) {
	sep := role == "KSK" || role == "CSK"
	switch {
	case st.Signer && !st.Present:
		return "", false, fmt.Errorf("the key signs but is not in the DNSKEY RRset; tdns requires a signing key to be published")
	case st.Signer:
		return DnskeyStateActive, true, nil // Active and Leaving (Q4)
	case !st.Old && st.Present && st.AtParent && sep:
		return DnskeyStateStandby, true, nil
	case !st.Old && st.Present:
		return DnskeyStatePublished, true, nil
	case st.Old && st.Present:
		return DnskeyStateRetired, true, nil
	case !st.Old && st.AtParent:
		return DnskeyStateDsPublished, true, nil
	default:
		return "", false, nil // Future, Stale
	}
}

// --- planning -------------------------------------------------------------

type cascadePlan struct {
	base    string
	privPEM string
	keyRR   string
	entry   ManifestDnssecKey
}

// cascadeZone is everything read and checked for one state file.
type cascadeZone struct {
	stateFile    string
	zone         string
	plans        []cascadePlan
	dispositions []CascadeConvertDisposition
	readDirs     []string
}

// ConvertCascadeKeys converts the keys named by Cascade state files into an
// export directory. Every state file and key is read and checked before
// anything is written; a phase-2 failure is reported as *PartialConvertError.
func ConvertCascadeKeys(opts CascadeConvertOptions) ([]CascadeConvertDisposition, error) {
	if len(opts.StateFiles) == 0 {
		return nil, fmt.Errorf("no state file given")
	}
	if opts.Dest == "" {
		return nil, fmt.Errorf("no destination directory given")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	// --- phase 1: read and check everything, write nothing --------------
	var zones []*cascadeZone
	var dispositions []CascadeConvertDisposition
	var readDirs []string
	identity := map[string]string{}
	for _, sf := range opts.StateFiles {
		z, err := planCascadeZone(sf, opts, now)
		if z != nil {
			dispositions = append(dispositions, z.dispositions...)
		}
		if err != nil {
			return dispositions, fmt.Errorf("%s: %v", sf, err)
		}
		for _, p := range z.plans {
			id := fmt.Sprintf("%s::%d", p.entry.Zone, p.entry.Keyid)
			if prev, clash := identity[id]; clash {
				return dispositions, fmt.Errorf("%s and %s both describe zone %s keyid %d, which is one manifest entry",
					prev, sf, p.entry.Zone, p.entry.Keyid)
			}
			identity[id] = sf
		}
		readDirs = append(readDirs, z.readDirs...)
		zones = append(zones, z)
	}

	if err := refuseDestAmongSources(opts.Dest, readDirs); err != nil {
		return dispositions, err
	}

	manifest, err := LoadOrNewKeystoreManifest(opts.Dest)
	if err != nil {
		return dispositions, err
	}
	// A destination file that already holds something else is refused now,
	// not halfway through writing.
	for _, z := range zones {
		for _, p := range z.plans {
			for _, f := range []struct{ name, content string }{
				{p.base + ".private", p.privPEM}, {p.base + ".key", p.keyRR},
			} {
				existing, err := os.ReadFile(filepath.Join(opts.Dest, f.name))
				switch {
				case err == nil && string(existing) != f.content:
					return dispositions, fmt.Errorf("%s already exists in %s with different content; move it aside if you mean to replace it", f.name, opts.Dest)
				case err != nil && !os.IsNotExist(err):
					return dispositions, fmt.Errorf("reading %s: %v", filepath.Join(opts.Dest, f.name), err)
				}
			}
		}
	}

	// --- phase 2: write ---------------------------------------------------
	touched := false
	fail := func(err error) ([]CascadeConvertDisposition, error) {
		if touched {
			return dispositions, &PartialConvertError{err}
		}
		return dispositions, err
	}

	planned := 0
	for _, z := range zones {
		planned += len(z.plans)
	}
	if planned == 0 {
		return dispositions, nil
	}

	if err := os.MkdirAll(opts.Dest, 0700); err != nil {
		return fail(fmt.Errorf("creating %s: %v", opts.Dest, err))
	}
	for _, z := range zones {
		for _, p := range z.plans {
			for _, f := range []struct {
				name, content string
				perm          os.FileMode
			}{
				{p.base + ".private", p.privPEM, 0600}, {p.base + ".key", p.keyRR, 0644},
			} {
				path := filepath.Join(opts.Dest, f.name)
				if existing, err := os.ReadFile(path); err == nil && string(existing) == f.content {
					continue // an earlier run wrote exactly this
				}
				touched = true
				if err := writeFileAtomic(path, []byte(f.content), f.perm); err != nil {
					return fail(err)
				}
			}
			manifest.UpsertDnssec(p.entry)
		}
	}
	touched = true
	if err := manifest.Save(opts.Dest); err != nil {
		return fail(fmt.Errorf("writing the manifest: %v", err))
	}
	return dispositions, nil
}

func planCascadeZone(stateFile string, opts CascadeConvertOptions, now time.Time) (*cascadeZone, error) {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, err
	}
	var sf cascadeStateFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("not a dnst keyset state file: %v", err)
	}
	if sf.Keyset.Name == "" {
		return nil, fmt.Errorf("not a dnst keyset state file: keyset.name is missing")
	}
	if sf.Keyset.Keys == nil {
		return nil, fmt.Errorf("not a dnst keyset state file: keyset.keys is missing")
	}

	keysDir := opts.KeysDir
	if keysDir == "" {
		keysDir = filepath.Dir(stateFile)
	}
	// The state file writes the zone without a trailing dot; the manifest and
	// the keystore key on the fully qualified, canonical name.
	zone := core.CanonicalizeName(dns.Fqdn(sf.Keyset.Name))
	z := &cascadeZone{stateFile: stateFile, zone: zone, readDirs: []string{filepath.Dir(stateFile), keysDir}}

	rollInProgress := len(sf.Keyset.Rollstates) > 0
	if rollInProgress && !opts.AllowRollInProgress {
		var rolls []string
		for r := range sf.Keyset.Rollstates {
			rolls = append(rolls, r)
		}
		sort.Strings(rolls)
		return z, fmt.Errorf("zone %s has a key roll in progress (%s); wait until it is done, or pass --allow-roll-in-progress",
			zone, strings.Join(rolls, ", "))
	}

	// Sorted by URL so a run is reproducible and its report diffable.
	var urls []string
	for u := range sf.Keyset.Keys {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	publishedRDATA := map[string]string{}         // RDATA -> key, for keys mapped to pub=1
	var includePresent []cascadeKeyIdent          // other signers' keys in the DNSKEY RRset
	activeSEP := map[cascadeKeyIdent]bool{}       // A in the DS check
	includeAtParent := map[cascadeKeyIdent]bool{} // also A
	atParent := map[cascadeKeyIdent]bool{}        // B

	for _, pubURL := range urls {
		k := sf.Keyset.Keys[pubURL]
		if k.Algorithm == nil || k.KeyTag == nil {
			return z, fmt.Errorf("key %s: algorithm or key_tag missing", pubURL)
		}
		ident := cascadeKeyIdent{tag: *k.KeyTag, alg: *k.Algorithm}
		role, err := parseCascadeKeytype(k.Keytype)
		if err != nil {
			return z, fmt.Errorf("key %s: %v", pubURL, err)
		}
		disp := CascadeConvertDisposition{
			StateFile: stateFile, Zone: zone, Keyid: ident.tag,
			Algorithm: algorithmLabel(ident.alg), Role: role.name, Cascade: cascadeLabel(role.st),
		}
		if role.st.AtParent {
			atParent[ident] = true
		}

		// Another signer's key: never converted (Q6).
		if k.Privref == nil || role.name == "Include" {
			disp.Status = CascadeConvertSkipped
			disp.Detail = "another signer's key (no private key); not converted"
			if role.st.AtParent {
				includeAtParent[ident] = true
			}
			if role.st.Present {
				if !opts.MultiSigner {
					z.dispositions = append(z.dispositions, disp)
					return z, fmt.Errorf("key %d is another signer's key in the DNSKEY RRset. tdns-auth and tdns-signer publish only their own keys and would drop it; pass --multi-signer if the target is tdns-mpsigner, which takes it from the incoming zone", ident.tag)
				}
				disp.Detail += "; tdns-mpsigner takes it from the incoming zone"
				includePresent = append(includePresent, ident)
			}
			z.dispositions = append(z.dispositions, disp)
			continue
		}

		state, convert, err := cascadeTdnsState(role.name, role.st)
		if err != nil {
			z.dispositions = append(z.dispositions, disp)
			return z, fmt.Errorf("key %d: %v", ident.tag, err)
		}
		if !convert {
			disp.Status = CascadeConvertSkipped
			disp.Detail = "not in use (" + cascadeLabel(role.st) + "); not converted"
			z.dispositions = append(z.dispositions, disp)
			continue
		}

		pubPath, err := cascadeKeyFilePath(pubURL, keysDir)
		if err != nil {
			z.dispositions = append(z.dispositions, disp)
			return z, fmt.Errorf("key %d: %v", ident.tag, err)
		}
		privPath, err := cascadeKeyFilePath(*k.Privref, keysDir)
		if err != nil {
			z.dispositions = append(z.dispositions, disp)
			return z, fmt.Errorf("key %d: %v", ident.tag, err)
		}

		plan, dnskey, err := planCascadeKey(zone, role.name, ident.tag, ident.alg, pubPath, privPath)
		if err != nil {
			z.dispositions = append(z.dispositions, disp)
			return z, fmt.Errorf("key %d: %v", ident.tag, err)
		}

		plan.entry.State = state
		if state != DnskeyStateDsPublished {
			plan.entry.PublishedAt = k.Timestamps.Published.rfc3339()
		}
		if state == DnskeyStateActive || state == DnskeyStateRetired {
			plan.entry.ActiveAt = k.Timestamps.RrsigVisible.rfc3339()
			if plan.entry.ActiveAt == "" {
				plan.entry.ActiveAt = k.Timestamps.Published.rfc3339()
			}
		}
		if state == DnskeyStateRetired {
			// Cascade records no "stopped signing" time, and the key state
			// worker never removes a retired key without one.
			plan.entry.RetiredAt = now.UTC().Format(time.RFC3339)
		}
		plan.entry.Comment = cascadeComment(role.name, role.st, k.Timestamps)

		switch state {
		case DnskeyStatePublished, DnskeyStateStandby, DnskeyStateActive, DnskeyStateRetired:
			publishedRDATA[dnskeyRDATA(dnskey)] = fmt.Sprintf("%d", ident.tag)
		}
		if state == DnskeyStateActive && dnskey.Flags&dns.SEP != 0 {
			activeSEP[ident] = true
		}

		disp.State = state
		disp.Status = CascadeConvertConverted
		z.plans = append(z.plans, plan)
		z.dispositions = append(z.dispositions, disp)
	}

	// --- cross-check 1: the DNSKEY RRset Cascade serves ------------------
	served, err := cascadeServedDNSKEYs(sf, zone)
	if err != nil {
		return z, err
	}
	servedByIdent := map[cascadeKeyIdent]string{}
	for rdata, k := range served {
		servedByIdent[cascadeKeyIdent{tag: k.KeyTag(), alg: k.Algorithm}] = rdata
	}
	expected := map[string]string{}
	for rdata, tag := range publishedRDATA {
		expected[rdata] = tag
	}
	for _, id := range includePresent {
		rdata, ok := servedByIdent[id]
		if !ok {
			return z, fmt.Errorf("another signer's key %d is present in the keyset but not in the served DNSKEY RRset", id.tag)
		}
		expected[rdata] = fmt.Sprintf("%d", id.tag)
	}
	var missing, extra []string
	for rdata, k := range served {
		if _, ok := expected[rdata]; !ok {
			missing = append(missing, fmt.Sprintf("%d", k.KeyTag()))
		}
	}
	for rdata, tag := range expected {
		if _, ok := served[rdata]; !ok {
			extra = append(extra, tag)
		}
	}
	if len(missing) > 0 || len(extra) > 0 {
		sort.Strings(missing)
		sort.Strings(extra)
		return z, fmt.Errorf("the mapping does not reproduce the DNSKEY RRset in the state file: served but not published by the conversion: [%s]; published by the conversion but not served: [%s]",
			strings.Join(missing, " "), strings.Join(extra, " "))
	}

	// --- cross-check 2: the DS set, when no roll is in progress ----------
	if !rollInProgress {
		want := map[cascadeKeyIdent]bool{}
		for id := range activeSEP {
			want[id] = true
		}
		for id := range includeAtParent {
			want[id] = true
		}
		if !sameKeyIdents(want, atParent) {
			return z, fmt.Errorf("the active KSKs/CSKs (with other signers' keys at the parent) %s are not the keys Cascade has at the parent %s",
				formatKeyIdents(want), formatKeyIdents(atParent))
		}
		if len(sf.DsRRset) > 0 {
			dsKeys := map[cascadeKeyIdent]bool{}
			for _, s := range sf.DsRRset {
				rr, err := dns.NewRR(s)
				if err != nil {
					return z, fmt.Errorf("ds_rrset: unparsable record %q: %v", s, err)
				}
				if ds, ok := rr.(*dns.DS); ok {
					dsKeys[cascadeKeyIdent{tag: ds.KeyTag, alg: ds.Algorithm}] = true
				}
			}
			if !sameKeyIdents(dsKeys, atParent) {
				return z, fmt.Errorf("ds_rrset names %s, but the keys at the parent are %s",
					formatKeyIdents(dsKeys), formatKeyIdents(atParent))
			}
		}
	}

	return z, nil
}

// planCascadeKey reads one key pair, checks it against its state entry, proves
// the two halves belong together, and renders the export form.
func planCascadeKey(zone, role string, tag uint16, alg uint8, pubPath, privPath string) (cascadePlan, *dns.DNSKEY, error) {
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return cascadePlan{}, nil, fmt.Errorf("reading the public key: %v", err)
	}
	rr, err := dns.NewRR(stripZonefileComments(string(pubBytes)))
	if err != nil || rr == nil {
		return cascadePlan{}, nil, fmt.Errorf("%s: unparsable public key RR: %v", pubPath, err)
	}
	dnskey, ok := rr.(*dns.DNSKEY)
	if !ok {
		return cascadePlan{}, nil, fmt.Errorf("%s holds a %s record, not a DNSKEY", pubPath, dns.TypeToString[rr.Header().Rrtype])
	}
	if !core.EqualNames(dnskey.Hdr.Name, zone) {
		return cascadePlan{}, nil, fmt.Errorf("%s is for %s, not for zone %s", pubPath, dnskey.Hdr.Name, zone)
	}
	if dnskey.Algorithm != alg || dnskey.KeyTag() != tag {
		return cascadePlan{}, nil, fmt.Errorf("%s is algorithm %d keyid %d, but the state file says algorithm %d keyid %d",
			pubPath, dnskey.Algorithm, dnskey.KeyTag(), alg, tag)
	}
	sep := dnskey.Flags&dns.SEP != 0
	if (role == "ZSK") == sep {
		return cascadePlan{}, nil, fmt.Errorf("%s has flags %d, which does not fit its role %s", pubPath, dnskey.Flags, role)
	}
	dnskey.Hdr.Name = zone

	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		return cascadePlan{}, nil, fmt.Errorf("reading the private key: %v", err)
	}
	pkc, err := PrepareKeyCache(string(privBytes), dnskey.String())
	if err != nil {
		return cascadePlan{}, nil, fmt.Errorf("%s: converting the private key: %v", privPath, err)
	}
	if pkc.PrivateKeyPEM == "" {
		return cascadePlan{}, nil, fmt.Errorf("%s: converting the private key produced no PEM output", privPath)
	}
	if err := VerifyKeyPairCorrespondence(pkc.CS, dnskey); err != nil {
		return cascadePlan{}, nil, fmt.Errorf("%s and %s: %v", pubPath, privPath, err)
	}

	algName := dns.AlgorithmToString[alg]
	base := KeyFileBasename(zone, alg, tag)
	return cascadePlan{
		base:    base,
		privPEM: pkc.PrivateKeyPEM,
		keyRR:   dnskey.String() + "\n",
		entry: ManifestDnssecKey{
			Zone: zone, Keyid: tag, Flags: dnskey.Flags, Algorithm: algName,
			Creator: "cascade", PrivateFile: base + ".private", PublicFile: base + ".key",
		},
	}, dnskey, nil
}

// cascadeKeyFilePath resolves a key URL from the state file to a file in
// keysDir, by base name: the URL is an absolute path on the Cascade host, and
// the directory may have been copied elsewhere since.
func cascadeKeyFilePath(ref, keysDir string) (string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("unparsable key reference %q: %v", ref, err)
	}
	switch u.Scheme {
	case "file":
	case "kmip":
		return "", fmt.Errorf("the key is in an HSM (%s); only file-backed keys can be converted", ref)
	default:
		return "", fmt.Errorf("unsupported key reference %q", ref)
	}
	name := filepath.Base(u.Path)
	if name == "." || name == "/" || name == "" {
		return "", fmt.Errorf("key reference %q names no file", ref)
	}
	return filepath.Join(keysDir, name), nil
}

// cascadeServedDNSKEYs returns the DNSKEY records Cascade puts at the apex,
// keyed by RDATA: from apex_extra, or from the older dnskey_rrset when
// apex_extra carries none.
func cascadeServedDNSKEYs(sf cascadeStateFile, zone string) (map[string]*dns.DNSKEY, error) {
	collect := func(records []string) (map[string]*dns.DNSKEY, error) {
		out := map[string]*dns.DNSKEY{}
		for _, s := range records {
			rr, err := dns.NewRR(s)
			if err != nil {
				return nil, fmt.Errorf("unparsable apex record %q: %v", s, err)
			}
			k, ok := rr.(*dns.DNSKEY)
			if !ok {
				continue
			}
			if !core.EqualNames(k.Hdr.Name, zone) {
				return nil, fmt.Errorf("apex DNSKEY for %s in the state file of zone %s", k.Hdr.Name, zone)
			}
			out[dnskeyRDATA(k)] = k
		}
		return out, nil
	}
	served, err := collect(sf.ApexExtra)
	if err != nil {
		return nil, err
	}
	if len(served) == 0 {
		if served, err = collect(sf.DnskeyRRset); err != nil {
			return nil, err
		}
	}
	if len(served) == 0 {
		return nil, fmt.Errorf("the state file holds no DNSKEY RRset (neither apex_extra nor dnskey_rrset), so the conversion cannot be checked")
	}
	return served, nil
}

// dnskeyRDATA is a DNSKEY's RDATA in a form that compares equal however the
// base64 was wrapped.
func dnskeyRDATA(k *dns.DNSKEY) string {
	key := strings.Join(strings.Fields(k.PublicKey), "")
	if b, err := base64.StdEncoding.DecodeString(key); err == nil {
		key = base64.StdEncoding.EncodeToString(b)
	}
	return fmt.Sprintf("%d %d %d %s", k.Flags, k.Protocol, k.Algorithm, key)
}

func cascadeComment(role string, st cascadeKeyState, ts cascadeTimestamps) string {
	parts := []string{"cascade: " + role + " " + cascadeLabel(st)}
	for _, t := range []struct {
		name string
		v    *cascadeUnixTime
	}{
		{"created", ts.Creation}, {"visible", ts.Visible}, {"ds_visible", ts.DsVisible}, {"withdrawn", ts.Withdrawn},
	} {
		if s := t.v.rfc3339(); s != "" {
			parts = append(parts, t.name+" "+s)
		}
	}
	return strings.Join(parts, "; ")
}

func algorithmLabel(alg uint8) string {
	if name := dns.AlgorithmToString[alg]; name != "" {
		return name
	}
	return fmt.Sprintf("%d", alg)
}

// cascadeKeyIdent identifies a key within one zone the way the state file,
// the DS records and the DNSKEY RRset can all name it.
type cascadeKeyIdent struct {
	tag uint16
	alg uint8
}

func sameKeyIdents(a, b map[cascadeKeyIdent]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func formatKeyIdents(m map[cascadeKeyIdent]bool) string {
	var out []string
	for k := range m {
		out = append(out, fmt.Sprintf("%d/%s", k.tag, algorithmLabel(k.alg)))
	}
	sort.Strings(out)
	return "[" + strings.Join(out, " ") + "]"
}

// refuseDestAmongSources refuses a destination that is one of the directories
// the run reads from: Cascade's signer reads the bind-format files there.
func refuseDestAmongSources(dest string, readDirs []string) error {
	destAbs, err := resolvedDir(dest)
	if err != nil {
		return err
	}
	for _, d := range readDirs {
		abs, err := resolvedDir(d)
		if err != nil {
			return err
		}
		if abs == destAbs {
			return fmt.Errorf("--dest %s is a directory this run reads from (%s); the conversion never writes where Cascade's files are", dest, d)
		}
	}
	return nil
}

// resolvedDir is dir as an absolute path with symlinks resolved as far as the
// directory exists.
func resolvedDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r, nil
	}
	return filepath.Clean(abs), nil
}
