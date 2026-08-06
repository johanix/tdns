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
 * Pre-load never forces. See keystore_bulk.go for why the running keystore
 * outranks a file on disk.
 */

package tdns

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
func (conf *Config) PreloadKeystore() error {
	dirs := conf.Keystore.Preload.Dirs()
	if len(dirs) == 0 {
		return nil
	}
	if conf.Internal.KeyDB == nil {
		// Reaching here means the operator configured pre-load for an app that
		// has no keystore at all. Silently ignoring it would leave them waiting
		// for keys that will never appear.
		return fmt.Errorf("keystore.preload is configured but this app (%s) has no keystore",
			Globals.App.Name)
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

	for _, class := range classes {
		if err := conf.preloadClass(class, dirs[class], overwrite); err != nil {
			return fmt.Errorf("keystore.preload.%s: %w", class, err)
		}
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

func (conf *Config) preloadClass(class, dir string, overwrite bool) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory %s does not exist", dir)
		}
		return fmt.Errorf("cannot stat %s: %v", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	warnIfWorldReadable(dir, info)

	manifest, err := LoadKeystoreManifest(dir)
	if err != nil {
		return err
	}

	kdb := conf.Internal.KeyDB
	var dispositions []BulkKeyDisposition
	var offered int

	switch class {
	case "dnssec":
		keys, err := manifest.LoadDnssecKeys(dir)
		if err != nil {
			return err
		}
		offered = len(keys)
		if offered == 0 {
			break
		}
		if dispositions, err = kdb.BulkImportDnssec(nil, keys, overwrite); err != nil {
			return err
		}

	case "sig0":
		keys, err := manifest.LoadSig0Keys(dir)
		if err != nil {
			return err
		}
		offered = len(keys)
		if offered == 0 {
			break
		}
		if dispositions, err = kdb.BulkImportSig0(nil, keys, overwrite); err != nil {
			return err
		}

	case "tsig":
		keys := manifest.TsigKeys()
		for i := range keys {
			if keys[i].Origin == "" {
				keys[i].Origin = "preload"
			}
		}
		offered = len(keys)
		if offered == 0 {
			break
		}
		if dispositions, err = kdb.BulkImportTsig(nil, keys, overwrite); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown key class %q", class)
	}

	if offered == 0 {
		lgConfig.Warn("keystore pre-load: manifest lists no keys for this class",
			"class", class, "dir", dir)
		return nil
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
	lgConfig.Info("keystore pre-load complete", "class", class, "dir", dir,
		"imported", imported, "unchanged", unchanged, "conflicts", conflicts, "replaced", replaced)
	return nil
}

// warnIfWorldReadable flags an export directory that anyone on the box can
// read. It is a warning, not a refusal: this is private-key material, but the
// operator may have deliberate reasons (a lab where the keys are public on
// purpose), and refusing to start over a permission bit is worse than saying so.
func warnIfWorldReadable(dir string, info os.FileInfo) {
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		lgConfig.Warn("keystore pre-load: directory is readable beyond its owner",
			"dir", dir, "mode", fmt.Sprintf("%04o", mode),
			"hint", "it holds private keys; chmod 700 unless the exposure is intended")
	}
}

// PreloadDirsForCheck exposes the configured directories for `config check`,
// which validates them without loading anything.
func (conf *Config) PreloadDirsForCheck() []string {
	dirs := conf.Keystore.Preload.Dirs()
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		out = append(out, filepath.Clean(strings.TrimSpace(d)))
	}
	sort.Strings(out)
	return out
}
