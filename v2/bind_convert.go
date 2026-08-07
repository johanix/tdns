/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Turning a directory of bind9-generated keys into one tdns can pre-load.
 *
 * Pre-load reads a DIRECTORY, and LoadKeystoreManifest fails outright when the
 * manifest is absent -- so raw dnssec-keygen output is unloadable even though
 * the key material itself is perfectly good. Two things are missing: the private
 * half is in bind's own format rather than PKCS#8 PEM, and there is no manifest
 * to say which keys are present or what state they are in.
 *
 * This fills both gaps offline, with no running daemon, which is the point: the
 * keys have to be committed to a config repo BEFORE the server that will serve
 * them exists. Going through the API instead would mean importing into a live
 * keystore and exporting straight back out again.
 *
 * What it does NOT touch is the .key file. tdns's own export format already
 * stores exactly what bind writes there -- the public RR as zone-file text -- so
 * the public half is already in its final form.
 */

package tdns

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Outcomes of a single key. Not the Bulk* statuses: those describe what
// happened to a keystore ROW, these describe what happened to a pair of files.
const (
	BindConvertConverted  = "converted"
	BindConvertAlreadyPEM = "already-pem"
	BindConvertSkipped    = "skipped"
)

// BindConvertOptions controls one conversion run.
type BindConvertOptions struct {
	// Class is "dnssec" or "sig0" and decides which RR type is accepted. A
	// directory holding both is normal, so the other class is skipped rather
	// than treated as an error.
	Class string

	// DefaultState is used for a key with no .state file. Empty means "refuse
	// such a key": guessing a state is how a retired key gets published again,
	// so the operator has to say it out loud.
	DefaultState string

	// Backup writes the original bind-format private key alongside as
	// <base>.private.orig before overwriting. On by default in the CLI; the
	// original is still a private key, so a caller keeping these directories in
	// version control may not want a second copy of every secret.
	Backup bool
}

// PartialConvertError marks a failure that happened AFTER writing began.
//
// The two-phase design means most failures leave the directory untouched, and
// the CLI says so -- which is worth saying, because it tells the operator to fix
// the cause and re-run rather than go looking for a mess. But phase 2 can fail
// too (a backup write, the PEM write, a chmod, the manifest save), and by then
// earlier keys have already been rewritten. Claiming "nothing was converted"
// there would be a confident lie about exactly the state that is hardest to
// diagnose by looking at the directory.
type PartialConvertError struct{ Err error }

func (e *PartialConvertError) Error() string { return e.Err.Error() }
func (e *PartialConvertError) Unwrap() error { return e.Err }

// BindConvertDisposition is one key's outcome, in the order the keys were found.
type BindConvertDisposition struct {
	Basename string
	Zone     string
	Keyid    uint16
	Status   string
	Detail   string
}

// convertPlan is one validated key, ready to write. Nothing is written until
// every key in the directory has produced one of these.
type convertPlan struct {
	base     string
	privPath string
	origPath string
	privPEM  string
	// origBytes is the bind-format original, read during phase 1. Kept rather
	// than re-read at backup time: a second read is a second chance to fail,
	// and it fails in the one place where "did anything change on disk?" is
	// hardest to answer. It is also a TOCTOU window -- the bytes backed up
	// would not necessarily be the bytes that were parsed and converted.
	origBytes []byte
	dnssec    *ManifestDnssecKey
	sig0      *ManifestSig0Key
	disp      BindConvertDisposition
}

// ConvertBindKeyDir converts every bind9 key in dir and writes the manifest.
//
// Two-phase on purpose: every key is read, parsed and mapped before ANY file is
// written. A directory half-converted because the nineteenth key was malformed
// is far worse than one that was refused whole -- the operator cannot tell by
// looking which halves are which, and the failure arrives when the server tries
// to start.
//
// Re-running is safe. A key whose private half is already PEM is left alone,
// and the manifest merges rather than replaces, so a directory can be built up
// over several runs.
func ConvertBindKeyDir(dir string, opts BindConvertOptions) ([]BindConvertDisposition, error) {
	if opts.Class != "dnssec" && opts.Class != "sig0" {
		return nil, fmt.Errorf("unknown key class %q", opts.Class)
	}
	if opts.DefaultState != "" {
		states := dnssecKeyStates
		if opts.Class == "sig0" {
			states = sig0KeyStates
		}
		if err := validKeyState(opts.DefaultState, states); err != nil {
			return nil, fmt.Errorf("--state: %v", err)
		}
	}

	manifest, err := LoadOrNewKeystoreManifest(dir)
	if err != nil {
		return nil, err
	}

	bases, err := discoverBindKeyBasenames(dir)
	if err != nil {
		return nil, err
	}
	if len(bases) == 0 {
		return nil, fmt.Errorf("no bind9 key files (*.key with a matching .private) found in %s", dir)
	}

	// --- phase 1: validate everything, write nothing ---------------------
	var plans []convertPlan
	var dispositions []BindConvertDisposition
	// A manifest entry is identified by zone plus keyid, and Upsert* REPLACES a
	// matching entry. Two distinct keys for one zone can collide on keytag --
	// uncommon, but nothing prevents it -- and the result would be quietly
	// lossy: both .private files rewritten, only the second described in the
	// manifest, the first converted and unreferenced so pre-load never restores
	// it. Caught here so the run refuses whole, per the all-or-nothing contract,
	// rather than half-succeeding without saying so.
	identity := map[string]string{}
	for _, base := range bases {
		plan, err := planBindKeyConversion(dir, base, manifest, opts)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", base, err)
		}
		dispositions = append(dispositions, plan.disp)
		if plan.disp.Status != BindConvertConverted {
			continue
		}
		id := fmt.Sprintf("%s::%d", plan.disp.Zone, plan.disp.Keyid)
		if prev, clash := identity[id]; clash {
			return nil, fmt.Errorf("%s and %s are different keys but share zone %s keyid %d, "+
				"which is one manifest entry: converting both would leave one of them "+
				"unreferenced and unrestorable. Move one aside and convert it separately",
				prev, base, plan.disp.Zone, plan.disp.Keyid)
		}
		identity[id] = base
		plans = append(plans, plan)
	}

	// --- phase 2: write --------------------------------------------------
	//
	// touched goes true the moment anything on disk COULD have changed, and
	// only failures after that point are reported as partial. Being in phase 2
	// is not itself evidence that a file was written: the first thing this loop
	// does is a plain read, and a failure there leaves the directory as intact
	// as any phase-1 refusal. Wrapping every phase-2 error would trade one
	// false certainty ("nothing was converted") for its mirror image.
	touched := false
	fail := func(err error) ([]BindConvertDisposition, error) {
		if touched {
			return dispositions, &PartialConvertError{err}
		}
		return dispositions, err
	}

	for _, p := range plans {
		if opts.Backup {
			// O_EXCL: never silently replace an existing backup. Phase 1 already
			// established that the path is free, so reaching this error means
			// something else is writing into the directory concurrently.
			//
			// Marked as touched BEFORE the attempt, not after: a write that
			// fails partway through has still created the file.
			touched = true
			if err := writeNewFileExcl(p.origPath, p.origBytes, 0600); err != nil {
				return fail(fmt.Errorf("%s: %v", p.base, err))
			}
		}
		// Atomic replace rather than truncate-in-place: the target is the
		// operator's private key, and a half-written one is unrecoverable when
		// --no-backup is in force. The temp file is created at 0600, so the
		// mode arrives with the rename instead of being applied to a file that
		// already holds the secret -- which is why there is no pre-chmod here
		// any more.
		touched = true
		if err := writeFileAtomic(p.privPath, []byte(p.privPEM), 0600); err != nil {
			return fail(fmt.Errorf("%s: writing the converted private key: %v", p.base, err))
		}
		if p.dnssec != nil {
			manifest.UpsertDnssec(*p.dnssec)
		}
		if p.sig0 != nil {
			manifest.UpsertSig0(*p.sig0)
		}
	}

	if len(plans) > 0 {
		if err := manifest.Save(dir); err != nil {
			return fail(fmt.Errorf("writing the manifest: %v", err))
		}
	}
	return dispositions, nil
}

// discoverBindKeyBasenames returns the sorted basenames of every .key file that
// has a matching .private. Sorted so a run is reproducible and its output
// diffable; .key-anchored so .private.orig files from an earlier run cannot be
// mistaken for input.
func discoverBindKeyBasenames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".key")
		if _, err := os.Stat(filepath.Join(dir, base+".private")); err != nil {
			continue // a public half with no private half is not ours to convert
		}
		out = append(out, base)
	}
	sort.Strings(out)
	return out, nil
}

func planBindKeyConversion(dir, base string, manifest *KeystoreManifest, opts BindConvertOptions) (convertPlan, error) {
	plan := convertPlan{
		base:     base,
		privPath: filepath.Join(dir, base+".private"),
		origPath: filepath.Join(dir, base+".private.orig"),
		disp:     BindConvertDisposition{Basename: base},
	}

	pubBytes, err := os.ReadFile(filepath.Join(dir, base+".key"))
	if err != nil {
		return plan, fmt.Errorf("reading the public key: %v", err)
	}
	pubkey := stripZonefileComments(string(pubBytes))
	rr, err := dns.NewRR(pubkey)
	if err != nil {
		return plan, fmt.Errorf("unparsable public key RR: %v", err)
	}

	// Wrong class for this run is a skip, not a failure: an operator may
	// reasonably keep DNSSEC and SIG(0) keys in one directory.
	dnskey, isDnskey := rr.(*dns.DNSKEY)
	keyrr, isKey := rr.(*dns.KEY)
	switch {
	case opts.Class == "dnssec" && !isDnskey:
		plan.disp.Status, plan.disp.Detail = BindConvertSkipped, "not a DNSKEY"
		return plan, nil
	case opts.Class == "sig0" && !isKey:
		plan.disp.Status, plan.disp.Detail = BindConvertSkipped, "not a KEY"
		return plan, nil
	}

	var owner, algName string
	var keyid, flags uint16
	if isDnskey {
		owner, keyid, flags = dnskey.Header().Name, dnskey.KeyTag(), dnskey.Flags
		algName = dns.AlgorithmToString[dnskey.Algorithm]
	} else {
		owner, keyid, flags = keyrr.Header().Name, keyrr.KeyTag(), keyrr.Flags
		algName = dns.AlgorithmToString[keyrr.Algorithm]
	}
	if algName == "" {
		return plan, fmt.Errorf("unknown DNSSEC algorithm in the public key RR")
	}
	// Canonicalised once, here, so the collision key below, the manifest entry
	// and the reported zone are all the same string.
	//
	// DNS names are case-insensitive but the RR carries whatever case the file
	// used, and the manifest's two matchers disagree about that:
	// UpsertDnssec/UpsertSig0 compare with ==, while manifestHasKey uses
	// EqualFold. So PQ.DNSLAB. and pq.dnslab. are one zone to one and two to
	// the other -- they would evade the collision check, be appended as two
	// manifest entries, and import as two keystore rows for a single zone.
	owner = dns.CanonicalName(owner)
	plan.disp.Zone, plan.disp.Keyid = owner, keyid

	privBytes, err := os.ReadFile(plan.privPath)
	if err != nil {
		return plan, fmt.Errorf("reading the private key: %v", err)
	}

	// Already converted. Left alone -- but only if the manifest knows about it,
	// because a PEM key with no manifest entry is what an interrupted earlier
	// run leaves behind, and reporting that as "nothing to do" would hide it.
	if IsPEMFormat(string(privBytes)) {
		if manifestHasKey(manifest, opts.Class, owner, keyid) {
			plan.disp.Status, plan.disp.Detail = BindConvertAlreadyPEM, "already converted"
			return plan, nil
		}
		return plan, fmt.Errorf("private key is already PKCS#8 PEM but the manifest has no entry for it; " +
			"an earlier run may have been interrupted -- restore the .private.orig or remove the key and re-export")
	}

	// Parses the whole bind private-key format, RSA's eight-field variant
	// included, and hands back PKCS#8 PEM. Note PrivateKeyPEM, never
	// PrivateKey: the latter is bind's single base64 field, which does not
	// exist for RSA.
	pkc, err := PrepareKeyCache(string(privBytes), pubkey)
	if err != nil {
		return plan, fmt.Errorf("converting the private key: %v", err)
	}
	if pkc.PrivateKeyPEM == "" {
		return plan, fmt.Errorf("converting the private key produced no PEM output")
	}

	// Prove the two halves belong together, by signing with the private key and
	// verifying with the published one.
	//
	// This replaces a check that compared pkc.KeyId to the keytag -- both of
	// which PrepareKeyCache derives from the SAME public RR, so it compared the
	// public key to itself and could never fire. Every other check in this
	// function is metadata-only for good reasons, which leaves a directory
	// pairing one zone's .key with another's .private converting and importing
	// clean, and the zone then publishing one key while signing with another.
	//
	// Cheap to do here because the private key has just been parsed anyway.
	verifyAgainst := dnskey
	if !isDnskey {
		verifyAgainst = &keyrr.DNSKEY // dns.KEY embeds it; the maths is identical
	}
	if err := VerifyKeyPairCorrespondence(pkc.CS, verifyAgainst); err != nil {
		return plan, err
	}
	plan.privPEM = pkc.PrivateKeyPEM
	plan.origBytes = privBytes

	if opts.Backup {
		if _, err := os.Stat(plan.origPath); err == nil {
			return plan, fmt.Errorf("%s already exists; move it aside if you mean to re-convert", plan.origPath)
		} else if !os.IsNotExist(err) {
			return plan, fmt.Errorf("checking for %s: %v", plan.origPath, err)
		}
	}

	times := ParseBindKeyTimes(privBytes)
	state, stateTimes, err := resolveBindKeyState(dir, base, flags, opts)
	if err != nil {
		return plan, err
	}
	if stateTimes != nil {
		times = *stateTimes
	}

	published, err := BindTimeToRFC3339(times.Publish)
	if err != nil {
		return plan, err
	}
	active, err := BindTimeToRFC3339(times.Activate)
	if err != nil {
		return plan, err
	}
	retired, err := BindTimeToRFC3339(times.Inactive)
	if err != nil {
		return plan, err
	}

	if isDnskey {
		plan.dnssec = &ManifestDnssecKey{
			Zone: owner, Keyid: keyid, Flags: flags, Algorithm: algName, State: state,
			Creator: "bind9", PublishedAt: published, ActiveAt: active, RetiredAt: retired,
			PrivateFile: base + ".private", PublicFile: base + ".key",
		}
	} else {
		plan.sig0 = &ManifestSig0Key{
			Zone: owner, Keyid: keyid, Algorithm: algName, State: state, Creator: "bind9",
			PrivateFile: base + ".private", PublicFile: base + ".key",
		}
	}
	plan.disp.Status = BindConvertConverted
	plan.disp.Detail = "state " + state
	return plan, nil
}

// resolveBindKeyState decides the key's tdns state, preferring the .state file
// and falling back to the operator's --state.
//
// When a .state file is present its timestamps are returned too: for a
// dnssec-policy zone those are what actually happened, where the .private
// file's are the schedule that was planned.
func resolveBindKeyState(dir, base string, flags uint16, opts BindConvertOptions) (string, *BindKeyTimes, error) {
	statePath := filepath.Join(dir, base+".state")
	data, err := os.ReadFile(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", nil, fmt.Errorf("reading %s: %v", statePath, err)
		}
		if opts.DefaultState == "" {
			return "", nil, fmt.Errorf("no .state file and no --state given; " +
				"a key's state cannot be guessed, and guessing wrong republishes a retired key")
		}
		return opts.DefaultState, nil, nil
	}

	// SIG(0) keys are not KASP-managed, so a .state file beside one is not
	// something to interpret.
	if opts.Class == "sig0" {
		if opts.DefaultState == "" {
			return "", nil, fmt.Errorf("SIG(0) keys carry no KASP state; --state is required")
		}
		return opts.DefaultState, nil, nil
	}

	st, err := ParseBindKeyState(data)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %v", base+".state", err)
	}

	// The SEP bit in the RR, not the .state file's KSK:/ZSK: booleans. They
	// should agree; if they do not, one of the two files does not belong to
	// this key, and silently trusting either is how a ZSK gets judged on the
	// KSK's signing record.
	isKSK := flags&0x0001 != 0
	if st.KSK != isKSK {
		return "", nil, fmt.Errorf("%s says KSK=%v but the DNSKEY flags (%d) say KSK=%v; "+
			"the .state file does not match the key", base+".state", st.KSK, flags, isKSK)
	}

	state, err := BindStateToDnssecState(st, isKSK)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %v", base+".state", err)
	}
	return state, &BindKeyTimes{
		Created:  st.Generated,
		Publish:  st.Published,
		Activate: st.Active,
		Inactive: st.Retired,
		Delete:   st.Removed,
	}, nil
}

func manifestHasKey(m *KeystoreManifest, class, zone string, keyid uint16) bool {
	if class == "sig0" {
		for _, k := range m.Sig0 {
			if strings.EqualFold(k.Zone, zone) && k.Keyid == keyid {
				return true
			}
		}
		return false
	}
	for _, k := range m.Dnssec {
		if strings.EqualFold(k.Zone, zone) && k.Keyid == keyid {
			return true
		}
	}
	return false
}

// stripZonefileComments removes the ";" comment lines dnssec-keygen writes above
// the RR in a .key file. tdns's own exports have none, so the zone parser has
// never had to cope with them here.
func stripZonefileComments(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), ";") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// writeNewFileExcl writes data to path, refusing to replace an existing file.
// O_CREATE|O_EXCL makes that refusal atomic rather than a check-then-write race,
// which matters because the file being protected is an unredacted private key.
// writeFileAtomic replaces path's contents via a temp file in the same
// directory: write, fsync, chmod, rename, then fsync the directory.
//
// The naive os.WriteFile truncates in place, and this file is an operator's
// private key. A crash, a full disk or a short write during that call leaves
// something that is neither the bind-format original nor valid PKCS#8 PEM --
// and with --no-backup there is then no copy of the key material anywhere.
// KeystoreManifest.Save already goes to this trouble for the manifest; the key
// itself deserves it at least as much.
//
// Creating the temp file at 0600 also removes the need to pre-chmod the target:
// the mode arrives with the rename rather than being applied to a file that
// already holds the secret.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("creating a temp file beside %s: %v", path, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("writing %s: %v", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("syncing %s: %v", tmpPath, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return fmt.Errorf("chmod %s: %v", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing %s: %v", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming into place as %s: %v", path, err)
	}
	// The rename is directory metadata; syncing the file above does not make
	// the NAME durable. Same reasoning as the manifest save.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening %s to make the rename durable: %v", dir, err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("syncing %s: %v", dir, err)
	}
	return d.Close()
}

func writeNewFileExcl(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("refusing to overwrite existing file %s", path)
		}
		return fmt.Errorf("open %s: %v", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %v", path, err)
	}
	return nil
}
