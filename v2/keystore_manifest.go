/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * On-disk representation of exported keystore material: BIND-convention key
 * files plus a sidecar manifest carrying everything the key files cannot
 * express.
 *
 * The manifest is what makes an export/import round trip lossless. A
 * K<name>+<alg>+<keyid>.{key,private} pair says nothing about whether the key
 * is published, standby, active or retired, and nothing about when it got
 * there — and a key restored into the wrong state either flattens a zone
 * mid-rollover or, for a published key with no published_at, restarts its
 * propagation clock (see KeyStateWorker's stamp-and-defer path).
 *
 * The manifest also records each key's FILE NAMES rather than deriving them.
 * That keeps the read side (bulk-import, and the keystore pre-load that runs
 * before any zone is parsed) free of algorithm-name-to-codepoint lookups: it
 * reads what the manifest says, so a key whose algorithm this binary does not
 * link still loads into the keystore instead of failing at boot.
 */

package tdns

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// KeystoreManifestVersion is the on-disk format version. The reader
	// refuses anything newer rather than silently ignoring fields it does
	// not understand — a half-understood key restore is worse than none.
	KeystoreManifestVersion = 1

	// KeystoreManifestFile is the manifest's fixed name inside an export
	// directory.
	KeystoreManifestFile = "manifest.yaml"
)

// KeystoreManifest describes the keystore material in one directory. It
// deliberately carries all three key classes: pointing keystore.preload.dnssec
// and keystore.preload.sig0 at the same directory is legal and works, each
// reading only its own section.
type KeystoreManifest struct {
	Version int                 `yaml:"version"`
	Dnssec  []ManifestDnssecKey `yaml:"dnssec,omitempty"`
	Sig0    []ManifestSig0Key   `yaml:"sig0,omitempty"`
	Tsig    []ManifestTsigKey   `yaml:"tsig,omitempty"`
}

// ManifestDnssecKey mirrors a DnssecKeyStore row minus the key material, which
// lives in PrivateFile/PublicFile. The *_at fields and ActiveSeq are the
// rollover bookkeeping that BIND-convention files have nowhere to put.
type ManifestDnssecKey struct {
	Zone        string `yaml:"zone"`
	Keyid       uint16 `yaml:"keyid"`
	Flags       uint16 `yaml:"flags"`
	Algorithm   string `yaml:"algorithm"`
	State       string `yaml:"state"`
	Creator     string `yaml:"creator,omitempty"`
	Comment     string `yaml:"comment,omitempty"`
	PublishedAt string `yaml:"published_at,omitempty"`
	ActiveAt    string `yaml:"active_at,omitempty"`
	RetiredAt   string `yaml:"retired_at,omitempty"`
	ActiveSeq   *int64 `yaml:"active_seq,omitempty"`
	PrivateFile string `yaml:"private_file"`
	PublicFile  string `yaml:"public_file"`
}

// ManifestSig0Key mirrors a Sig0KeyStore row minus the key material.
type ManifestSig0Key struct {
	Zone        string `yaml:"zone"`
	Keyid       uint16 `yaml:"keyid"`
	Algorithm   string `yaml:"algorithm"`
	State       string `yaml:"state"`
	Creator     string `yaml:"creator,omitempty"`
	Comment     string `yaml:"comment,omitempty"`
	ParentState uint8  `yaml:"parent_state,omitempty"`
	PrivateFile string `yaml:"private_file"`
	PublicFile  string `yaml:"public_file"`
}

// ManifestTsigKey carries a TSIG key whole: the secret IS the key material, so
// there is no separate file for it. That is not a new exposure — a directory
// holding .private files is already private-key material, and the directory's
// permissions are the trust boundary either way.
type ManifestTsigKey struct {
	Keyname   string `yaml:"keyname"`
	Algorithm string `yaml:"algorithm"`
	Secret    string `yaml:"secret"`
	Origin    string `yaml:"origin,omitempty"`
	Owner     string `yaml:"owner,omitempty"`
	Creator   string `yaml:"creator,omitempty"`
	CreatedAt string `yaml:"created_at,omitempty"`
	Comment   string `yaml:"comment,omitempty"`
}

// LoadKeystoreManifest reads dir's manifest. A missing manifest is an error:
// every caller that reads a directory needs one, and "no manifest" would
// otherwise silently mean "no keys" — the failure mode we are building this to
// avoid.
func LoadKeystoreManifest(dir string) (*KeystoreManifest, error) {
	path := filepath.Join(dir, KeystoreManifestFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading keystore manifest %s: %v", path, err)
	}
	// A blank or comment-only manifest is refused, not read as "no keys". It
	// unmarshals happily into a zero value, Version gets promoted below, and the
	// caller receives an accepted manifest describing nothing -- so pre-load
	// imports zero keys, returns nil, startup continues, and a signed zone mints
	// replacements the parent DS does not match. That is the exact failure the
	// doc comment above says a missing manifest must never cause; a truncated
	// one reaches it by another road.
	//
	// Deliberately a blank-data check and nothing more: a hand-written manifest
	// that omits `version` or lists only one class is still perfectly valid.
	if !manifestHasContent(data) {
		return nil, fmt.Errorf("keystore manifest %s is empty; refusing to read that as "+
			"\"this directory holds no keys\" (remove the directory from keystore.preload, "+
			"or re-export into it)", path)
	}
	var m KeystoreManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing keystore manifest %s: %v", path, err)
	}
	if m.Version > KeystoreManifestVersion {
		return nil, fmt.Errorf("keystore manifest %s is version %d, this binary understands up to %d",
			path, m.Version, KeystoreManifestVersion)
	}
	if m.Version == 0 {
		m.Version = KeystoreManifestVersion
	}
	return &m, nil
}

// LoadOrNewKeystoreManifest is the export-side variant: a directory with no
// manifest yet is the normal first-export case, not an error.
func LoadOrNewKeystoreManifest(dir string) (*KeystoreManifest, error) {
	path := filepath.Join(dir, KeystoreManifestFile)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return &KeystoreManifest{Version: KeystoreManifestVersion}, nil
		}
		return nil, fmt.Errorf("stat %s: %v", path, err)
	}
	return LoadKeystoreManifest(dir)
}

// Save writes the manifest to dir atomically (temp + rename). Mode is 0600:
// the TSIG section holds secrets.
//
// Entries are sorted first, so re-exporting an unchanged keystore produces a
// byte-identical file — these directories are meant to live in version
// control, where a reordered manifest is noise that hides the real change.
func (m *KeystoreManifest) Save(dir string) error {
	m.sort()
	if m.Version == 0 {
		m.Version = KeystoreManifestVersion
	}

	data, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshalling keystore manifest: %v", err)
	}
	header := fmt.Sprintf("# tdns keystore export manifest (v%d) -- generated, but safe to read.\n"+
		"# Restored by 'keystore <class> bulk-import' and by keystore.preload at startup.\n",
		m.Version)
	data = append([]byte(header), data...)

	path := filepath.Join(dir, KeystoreManifestFile)
	tmp, err := os.CreateTemp(dir, "."+KeystoreManifestFile+".tmp")
	if err != nil {
		return fmt.Errorf("creating temp manifest in %s: %v", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("writing temp manifest: %v", err)
	}
	// Fsync before rename: a crash here would otherwise be able to leave a
	// correctly-named but empty manifest, which the reader would take to mean
	// "this directory holds no keys".
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("syncing temp manifest: %v", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp manifest: %v", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing temp manifest: %v", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming temp manifest to %s: %v", path, err)
	}
	// Fsync the PARENT DIRECTORY as well. Syncing the temp file above makes its
	// contents durable; it says nothing about the directory entry that now
	// names them. A rename is a directory-metadata operation, so a crash in
	// this window can still leave the manifest missing or pointing at nothing —
	// exactly the outcome the temp+rename dance and the sync above exist to
	// prevent, reached by the one path they do not cover.
	//
	// A failure here is reported rather than swallowed: the manifest IS in
	// place at this point, but it is not known to have survived a power cut,
	// and the caller is writing an export it intends to rely on later.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening %s to make the manifest rename durable: %v", dir, err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("syncing %s after renaming the manifest into place: %v", dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("closing %s after syncing the manifest rename: %v", dir, err)
	}
	return nil
}

func (m *KeystoreManifest) sort() {
	sort.Slice(m.Dnssec, func(i, j int) bool {
		if m.Dnssec[i].Zone != m.Dnssec[j].Zone {
			return m.Dnssec[i].Zone < m.Dnssec[j].Zone
		}
		return m.Dnssec[i].Keyid < m.Dnssec[j].Keyid
	})
	sort.Slice(m.Sig0, func(i, j int) bool {
		if m.Sig0[i].Zone != m.Sig0[j].Zone {
			return m.Sig0[i].Zone < m.Sig0[j].Zone
		}
		return m.Sig0[i].Keyid < m.Sig0[j].Keyid
	})
	sort.Slice(m.Tsig, func(i, j int) bool { return m.Tsig[i].Keyname < m.Tsig[j].Keyname })
}

// UpsertDnssec replaces the entry for (zone, keyid) or appends it. Upsert
// rather than rebuild is what lets a directory accumulate several exports:
// `bulk-export --zones pq.dnslab` followed by `--zone dnslab.` leaves both in
// the manifest instead of the second erasing the first.
func (m *KeystoreManifest) UpsertDnssec(e ManifestDnssecKey) {
	for i := range m.Dnssec {
		if m.Dnssec[i].Zone == e.Zone && m.Dnssec[i].Keyid == e.Keyid {
			m.Dnssec[i] = e
			return
		}
	}
	m.Dnssec = append(m.Dnssec, e)
}

// UpsertSig0 replaces the entry for (zone, keyid) or appends it.
func (m *KeystoreManifest) UpsertSig0(e ManifestSig0Key) {
	for i := range m.Sig0 {
		if m.Sig0[i].Zone == e.Zone && m.Sig0[i].Keyid == e.Keyid {
			m.Sig0[i] = e
			return
		}
	}
	m.Sig0 = append(m.Sig0, e)
}

// UpsertTsig replaces the entry for keyname or appends it.
func (m *KeystoreManifest) UpsertTsig(e ManifestTsigKey) {
	for i := range m.Tsig {
		if m.Tsig[i].Keyname == e.Keyname {
			m.Tsig[i] = e
			return
		}
	}
	m.Tsig = append(m.Tsig, e)
}

// KeyFileBasename is the BIND filename convention shared by the export writer
// and anything that wants to predict a name: K<owner>+<alg>+<keyid>, with the
// owner in its trailing-dot form.
func KeyFileBasename(owner string, algNum uint8, keyid uint16) string {
	return fmt.Sprintf("K%s+%03d+%05d", owner, algNum, keyid)
}

// LoadDnssecKeys rehydrates the manifest's DNSSEC section into wire keys by
// reading each entry's key files out of dir.
func (m *KeystoreManifest) LoadDnssecKeys(dir string) ([]BulkDnssecKey, error) {
	out := make([]BulkDnssecKey, 0, len(m.Dnssec))
	for _, e := range m.Dnssec {
		priv, keyRR, err := readManifestKeyFiles(dir, e.PrivateFile, e.PublicFile)
		if err != nil {
			return nil, fmt.Errorf("DNSSEC key %s keyid %d: %v", e.Zone, e.Keyid, err)
		}
		out = append(out, BulkDnssecKey{
			Zone:        e.Zone,
			Keyid:       e.Keyid,
			Flags:       e.Flags,
			Algorithm:   e.Algorithm,
			State:       e.State,
			Creator:     e.Creator,
			Comment:     e.Comment,
			PublishedAt: e.PublishedAt,
			ActiveAt:    e.ActiveAt,
			RetiredAt:   e.RetiredAt,
			ActiveSeq:   e.ActiveSeq,
			PrivateKey:  priv,
			KeyRR:       keyRR,
		})
	}
	return out, nil
}

// LoadSig0Keys rehydrates the manifest's SIG(0) section into wire keys.
func (m *KeystoreManifest) LoadSig0Keys(dir string) ([]BulkSig0Key, error) {
	out := make([]BulkSig0Key, 0, len(m.Sig0))
	for _, e := range m.Sig0 {
		priv, keyRR, err := readManifestKeyFiles(dir, e.PrivateFile, e.PublicFile)
		if err != nil {
			return nil, fmt.Errorf("SIG(0) key %s keyid %d: %v", e.Zone, e.Keyid, err)
		}
		out = append(out, BulkSig0Key{
			Zone:        e.Zone,
			Keyid:       e.Keyid,
			Algorithm:   e.Algorithm,
			State:       e.State,
			Creator:     e.Creator,
			Comment:     e.Comment,
			ParentState: e.ParentState,
			PrivateKey:  priv,
			KeyRR:       keyRR,
		})
	}
	return out, nil
}

// TsigKeys projects the manifest's TSIG section into wire keys. Unlike the
// other two classes there is nothing to read from disk: the secret is already
// in the manifest. (Named TsigKeys, not LoadTsigKeys, to stay clear of
// Config.LoadTsigKeys, which is a different thing entirely.)
func (m *KeystoreManifest) TsigKeys() []BulkTsigKey {
	out := make([]BulkTsigKey, 0, len(m.Tsig))
	for _, e := range m.Tsig {
		out = append(out, BulkTsigKey{
			Keyname:   e.Keyname,
			Algorithm: e.Algorithm,
			Secret:    e.Secret,
			Origin:    e.Origin,
			Owner:     e.Owner,
			Creator:   e.Creator,
			CreatedAt: e.CreatedAt,
			Comment:   e.Comment,
		})
	}
	return out
}

// ManifestEntryForDnssec builds the manifest entry for an exported DNSSEC key,
// given the file basename the caller wrote it under.
func ManifestEntryForDnssec(k BulkDnssecKey, base string) ManifestDnssecKey {
	return ManifestDnssecKey{
		Zone:        k.Zone,
		Keyid:       k.Keyid,
		Flags:       k.Flags,
		Algorithm:   k.Algorithm,
		State:       k.State,
		Creator:     k.Creator,
		Comment:     k.Comment,
		PublishedAt: k.PublishedAt,
		ActiveAt:    k.ActiveAt,
		RetiredAt:   k.RetiredAt,
		ActiveSeq:   k.ActiveSeq,
		PrivateFile: base + ".private",
		PublicFile:  base + ".key",
	}
}

// ManifestEntryForSig0 builds the manifest entry for an exported SIG(0) key.
func ManifestEntryForSig0(k BulkSig0Key, base string) ManifestSig0Key {
	return ManifestSig0Key{
		Zone:        k.Zone,
		Keyid:       k.Keyid,
		Algorithm:   k.Algorithm,
		State:       k.State,
		Creator:     k.Creator,
		Comment:     k.Comment,
		ParentState: k.ParentState,
		PrivateFile: base + ".private",
		PublicFile:  base + ".key",
	}
}

// ManifestEntryForTsig builds the manifest entry for an exported TSIG key.
func ManifestEntryForTsig(k BulkTsigKey) ManifestTsigKey {
	return ManifestTsigKey{
		Keyname:   k.Keyname,
		Algorithm: k.Algorithm,
		Secret:    k.Secret,
		Origin:    k.Origin,
		Owner:     k.Owner,
		Creator:   k.Creator,
		CreatedAt: k.CreatedAt,
		Comment:   k.Comment,
	}
}

// readManifestKeyFiles loads the private (PEM) and public (RR text) halves of a
// manifest entry. Paths are resolved against dir and are refused if they try to
// escape it: a manifest is a data file, and an export directory pulled from
// somewhere else must not be able to make the reader open ../../etc/anything.
func readManifestKeyFiles(dir, privateFile, publicFile string) (privPEM, keyRR string, err error) {
	priv, err := readContainedFile(dir, privateFile)
	if err != nil {
		return "", "", err
	}
	pub, err := readContainedFile(dir, publicFile)
	if err != nil {
		return "", "", err
	}
	return priv, strings.TrimRight(pub, "\n"), nil
}

// readContainedFile reads one file named by the manifest, refusing an absolute
// path or one that climbs out of dir.
//
// LIMITATION: containment is checked on the PATH, not on what the path resolves
// to, so a symlink placed inside dir is followed wherever it points. Closing
// that would need an openat2/O_NOFOLLOW-style walk, and it buys little here:
// planting the symlink already requires write access to a directory that holds
// private keys, at which point the attacker can simply write the key file. The
// check exists to stop a manifest -- a data file that may have travelled from
// somewhere else -- from naming ../../etc/anything, and it does that.
func readContainedFile(dir, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("manifest entry has no file name")
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("manifest file name %q must be relative to the export directory", name)
	}
	clean := filepath.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("manifest file name %q escapes the export directory", name)
	}
	data, err := os.ReadFile(filepath.Join(dir, clean))
	if err != nil {
		return "", fmt.Errorf("reading %s: %v", clean, err)
	}
	return string(data), nil
}

// manifestHasContent reports whether data holds anything but blank lines and
// '#' comments. The generated manifest always carries a header comment, so
// "the file is not zero bytes" is not on its own evidence of content.
func manifestHasContent(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return true
		}
	}
	return false
}
