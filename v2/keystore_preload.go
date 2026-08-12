/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Keystore pre-load: restore exported key material into the keystore at
 * startup, before any zone is parsed.
 *
 * The ordering is the whole point. A signed zone that comes up with an empty
 * keystore mints its own keys (EnsureActiveDnssecKeys), and by the time an
 * operator could import the real ones the zone has already published a DNSKEY
 * set nobody's parent DS matches. Loading first means the zone finds its keys
 * already there and adopts them — the correct outcome by construction rather
 * than by racing the signer.
 *
 * Pre-load does not force BY DEFAULT: a key already in the keystore under
 * different material is the keystore winning, because a file on disk may be
 * arbitrarily stale (see keystore_bulk.go). keystore.preload.overwrite-existing-keys
 * reverses that for a host rebuilt from a repo, and is passed straight through
 * as the import's force argument -- so on such a host the on-disk copy DOES
 * overwrite, and every replacement is logged individually.
 */

package tdns

import (
	"context"
	"fmt"
	"os"
	"sort"
)

// PreloadKeystore loads each configured keystore.preload directory into the
// keystore. It runs after the KeyDB exists and before LoadTsigKeys/ParseZones.
//
// Failures that mean "the operator's intent could not be carried out" — a
// configured directory that is missing, an unreadable or self-inconsistent
// manifest — are returned as errors and abort startup. A pre-load that half
// worked is precisely the state this feature exists to prevent.
//
// Conflicts are NOT failures: a key already in the keystore under different
// material is the keystore winning, which is the designed behaviour. Those are
// logged at WARN, individually, because the operator needs to know their
// on-disk copy is not what is running.
func (conf *Config) PreloadKeystore(ctx context.Context) error {
	dirs := conf.Keystore.Preload.Dirs()
	if len(dirs) == 0 {
		return nil
	}
	if conf.Internal.KeyDB == nil {
		// An app with no keystore at all — tdns-imr, tdns-cli. This is normal
		// when one config file is shared via include:, so it must not be fatal:
		// refusing to start a daemon over a block it does not use would be a
		// much worse outcome than the operator not getting keys it never had.
		// Loud enough to notice if it IS a mistake.
		lgConfig.Warn("keystore.preload is configured but this app has no keystore; ignoring",
			"app", Globals.App.Name, "classes", len(dirs))
		return nil
	}

	// Deterministic order, and dnssec first: it is the class an operator is
	// most likely to be watching the log for.
	classes := make([]string, 0, len(dirs))
	for c := range dirs {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool { return classOrder(classes[i]) < classOrder(classes[j]) })

	overwrite := conf.Keystore.Preload.OverwriteExistingKeys
	if overwrite {
		// Announced unconditionally, before anything is touched, so the setting
		// is visible in the log of every boot -- not only the boots where it
		// happens to change something.
		lgConfig.Warn("keystore pre-load: overwrite-existing-keys is SET; on-disk keys will REPLACE differing keystore entries",
			"classes", classes,
			"hint", "intended for rebuilt-from-repo hosts; on a host whose keystore is authoritative this can revert a key rolled by hand")
	}

	// ONE transaction across every class. The doc comment above promises
	// all-or-nothing, and per-class commits did not deliver it: a dnssec class
	// that loaded followed by a sig0 class that failed left the daemon booting
	// with half the operator's key material in place and an error telling them
	// none of it was — the "pre-load that half worked" this feature exists to
	// prevent, produced by pre-load itself.
	kdb := conf.Internal.KeyDB
	tx, err := kdb.Begin("PreloadKeystore")
	if err != nil {
		return fmt.Errorf("keystore.preload: starting transaction: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	var sig0Invalidate []string
	for _, class := range classes {
		// Between classes, not inside one: a class is a single all-or-nothing
		// import and there is nothing useful to do half way through it. The
		// transaction rolls back via the defer either way.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("keystore.preload: aborted before class %s: %w", class, err)
		}
		inv, err := conf.preloadClass(tx, class, dirs[class], overwrite)
		if err != nil {
			return fmt.Errorf("keystore.preload.%s: %w", class, err)
		}
		sig0Invalidate = append(sig0Invalidate, inv...)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("keystore.preload: committing: %v", err)
	}
	committed = true

	// BulkImportSig0 delegates cache invalidation to whoever owns the
	// transaction, and that is now us. Expected to be a no-op in practice --
	// pre-load runs before anything reads a SIG(0) key, so the cache is still
	// nil and invalidateSig0Cache returns immediately. Done anyway: the
	// correctness of the delegation should not rest on startup ordering that
	// some later change is free to shuffle.
	for _, zone := range sig0Invalidate {
		kdb.invalidateSig0Cache(zone)
	}
	return nil
}

func classOrder(class string) int {
	switch class {
	case "dnssec":
		return 0
	case "sig0":
		return 1
	default:
		return 2
	}
}

// preloadClass loads one class into the caller's transaction. It never commits:
// PreloadKeystore owns the transaction so that the classes land together or not
// at all.
//
// The returned names are the zones whose SIG(0) cache entries the import
// invalidated. They travel back rather than being dropped here because the rows
// are not visible until the caller commits — see BulkSig0InvalidateZones.
func (conf *Config) preloadClass(tx *Tx, class, dir string, overwrite bool) ([]string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("directory %s does not exist", dir)
		}
		return nil, fmt.Errorf("cannot stat %s: %v", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	warnIfReadableBeyondOwner(dir, info)

	manifest, err := LoadKeystoreManifest(dir)
	if err != nil {
		return nil, err
	}

	kdb := conf.Internal.KeyDB
	var dispositions []BulkKeyDisposition
	var sig0Invalidate []string
	var offered int

	switch class {
	case "dnssec":
		keys, err := manifest.LoadDnssecKeys(dir)
		if err != nil {
			return nil, err
		}
		offered = len(keys)
		if offered == 0 {
			break
		}
		if dispositions, err = kdb.BulkImportDnssec(tx, keys, overwrite); err != nil {
			return nil, err
		}

	case "sig0":
		keys, err := manifest.LoadSig0Keys(dir)
		if err != nil {
			return nil, err
		}
		offered = len(keys)
		if offered == 0 {
			break
		}
		if dispositions, err = kdb.BulkImportSig0(tx, keys, overwrite); err != nil {
			return nil, err
		}
		sig0Invalidate = changedZones(dispositions)

	case "tsig":
		keys := manifest.TsigKeys()
		for i := range keys {
			// Restore as api-origin, ALWAYS — never as the config origin the
			// manifest may record.
			//
			// LoadTsigKeys runs immediately after pre-load and ends in
			// SyncConfigTsigKeys, which deletes every origin=config row that is
			// not in this host's keys.tsig: (no isReferenced withholding on the
			// startup path). A key restored as config-origin would therefore be
			// deleted seconds later, on every boot, right after pre-load logged
			// it as imported.
			//
			// api is also the only other origin insertTsigKeystore accepts.
			// The config file stays authoritative: if it declares this key,
			// SyncConfigTsigKeys reconciles against it as usual.
			keys[i].Origin = "api"
		}
		offered = len(keys)
		if offered == 0 {
			break
		}
		// Nil StillInConfig: at this point in startup the live TSIG store is
		// still empty (LoadTsigKeys runs next), so the predicate could only
		// answer "not in config" for every key and would be worse than no
		// answer. Safe here precisely because of the loop above -- every
		// restored key is forced to origin=api, so pre-load cannot create or
		// impersonate a config-managed row whatever the manifest claims.
		if dispositions, err = kdb.BulkImportTsig(tx, keys, overwrite, TsigBulkPolicy{}); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unknown key class %q", class)
	}

	if offered == 0 {
		lgConfig.Warn("keystore pre-load: manifest lists no keys for this class",
			"class", class, "dir", dir)
		return nil, nil
	}

	imported, unchanged, conflicts, replaced := 0, 0, 0, 0
	for _, d := range dispositions {
		switch d.Status {
		case BulkStatusImported:
			imported++
		case BulkStatusUnchanged:
			unchanged++
		case BulkStatusConflict:
			conflicts++
			lgConfig.Warn("keystore pre-load: key differs from the one already in the keystore; KEEPING the keystore's copy",
				"class", class, "name", d.Name, "keyid", d.Keyid, "differs", d.Detail,
				"hint", "the on-disk export is stale; re-export, or 'keystore "+class+" bulk-import --force' to overwrite")
		case BulkStatusReplaced:
			replaced++
			// One line per key actually overwritten. This is the destructive
			// path: if overwrite-existing-keys ever reverts a key that was
			// rolled by hand, this line is the only place that says so.
			lgConfig.Warn("keystore pre-load: OVERWROTE a differing key in the keystore (keystore.preload.overwrite-existing-keys is set)",
				"class", class, "name", d.Name, "keyid", d.Keyid, "differs", d.Detail)
		}
	}
	// "staged", not "complete": nothing is durable until PreloadKeystore
	// commits, and a later class can still take the whole pre-load down.
	lgConfig.Info("keystore pre-load staged", "class", class, "dir", dir,
		"imported", imported, "unchanged", unchanged, "conflicts", conflicts, "replaced", replaced)
	return sig0Invalidate, nil
}

// modeLeaksBeyondOwner is the single definition of "exposed" for a directory
// holding private key material: any permission bit granted to group or other.
func modeLeaksBeyondOwner(mode os.FileMode) bool {
	return mode.Perm()&0o077 != 0
}

// DirLeaksBeyondOwner stats dir and reports its permission bits together with
// whether they reach beyond the owner.
//
// Exported because the WRITE side needs the same check: `keystore <class>
// bulk-export` lives in v2/cli and creates these directories, while pre-load
// only ever reads them. Two independent notions of "exposed" — one on the
// producer, one on the consumer — would be worse than either check alone, so
// both go through this.
func DirLeaksBeyondOwner(dir string) (os.FileMode, bool, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return 0, false, err
	}
	mode := info.Mode().Perm()
	return mode, modeLeaksBeyondOwner(mode), nil
}

// warnIfReadableBeyondOwner flags an export directory that anyone else on the
// box can read. Named for what it checks: modeLeaksBeyondOwner tests the group
// bits as well as other, so mode 0750 trips it while not being world-readable
// at all. It is a warning, not a refusal: this is private-key material, but the
// operator may have deliberate reasons (a lab where the keys are public on
// purpose), and refusing to start over a permission bit is worse than saying so.
func warnIfReadableBeyondOwner(dir string, info os.FileInfo) {
	if mode := info.Mode().Perm(); modeLeaksBeyondOwner(mode) {
		lgConfig.Warn("keystore pre-load: directory is readable beyond its owner",
			"dir", dir, "mode", fmt.Sprintf("%04o", mode),
			"hint", "it holds private keys; chmod 700 unless the exposure is intended")
	}
}

// PreloadDirsForCheck exposes the configured directories for `config check`,
// which validates them without loading anything.
func (conf *Config) PreloadDirsForCheck() []string {
	// Dirs() already trims and cleans; re-doing it here is how the two paths
	// came to disagree in the first place.
	dirs := conf.Keystore.Preload.Dirs()
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
