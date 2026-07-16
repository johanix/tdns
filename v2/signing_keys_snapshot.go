/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Per-zone copy-on-write signing-keys snapshot (G3). Replaces the global
 * KeystoreDnskeyCache map. See docs/2026-07-16-signing-keys-snapshot-design.md.
 */

package tdns

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// signingKeysSnapshot is an immutable, keystore-derived view of the keys a
// zone signs with. Published snapshots are never mutated in place; a key-set
// change builds a fresh one and swaps the pointer.
type signingKeysSnapshot struct {
	// built is true iff this snapshot was produced by a successful DB build
	// (eager republish or CAS-if-unbuilt lazy fill). false means unbuilt —
	// either the package sentinel or a post-failed-republish marker.
	// Keyless-but-loaded zones have built=true with empty Active slices.
	built  bool
	Active *DnssecKeys
}

// emptySigningKeys is returned when Load() is nil. built=false.
// NEVER Store this shared instance onto a zone (ABA with CAS-if-unbuilt).
var emptySigningKeys = &signingKeysSnapshot{built: false, Active: &DnssecKeys{}}

// SigningKeys returns the current keys snapshot. Never nil, lock-free.
func (zd *ZoneData) SigningKeys() *signingKeysSnapshot {
	if zd == nil {
		return emptySigningKeys
	}
	if s := zd.signingKeys.Load(); s != nil {
		return s
	}
	return emptySigningKeys
}

// ActiveDnssecKeys is the hot-path sugar: never nil *DnssecKeys (may be empty).
// Does not trigger a DB load; callers that need freshness after mutation use
// refreshActiveDnssecKeys / republishSigningKeys. For unbuilt snapshots the
// returned set is empty until eager republish or activeKeysCAS runs.
func (zd *ZoneData) ActiveDnssecKeys() *DnssecKeys {
	s := zd.SigningKeys()
	if s.Active == nil {
		return &DnssecKeys{}
	}
	return s.Active
}

// buildSigningKeysSnapshot loads active keys from the keystore DB and returns a
// fresh immutable snapshot with built=true (including keyless empty Active).
func buildSigningKeysSnapshot(kdb *KeyDB, zone string) (*signingKeysSnapshot, error) {
	dak, err := loadDnssecKeysFromDB(kdb, zone, DnskeyStateActive)
	if err != nil {
		return nil, err
	}
	return &signingKeysSnapshot{built: true, Active: dak}, nil
}

// republishSigningKeys builds from DB and atomically publishes onto zd.
// Call ONLY after the keystore transaction that changed this zone's keys has
// COMMITTED. On persistent build failure: loud Error, mark unbuilt with a
// fresh allocation (never the shared sentinel), return err (M3).
func (zd *ZoneData) republishSigningKeys(kdb *KeyDB) error {
	if zd == nil {
		return fmt.Errorf("republishSigningKeys: nil ZoneData")
	}
	snap, err := buildSigningKeysSnapshot(kdb, zd.ZoneName)
	if err != nil {
		lgSigner.Error("republishSigningKeys: build failed, retrying", "zone", zd.ZoneName, "err", err)
		snap, err = buildSigningKeysSnapshot(kdb, zd.ZoneName)
	}
	if err != nil {
		zd.signingKeys.Store(&signingKeysSnapshot{built: false, Active: &DnssecKeys{}})
		lgSigner.Error("republishSigningKeys: failed after retry; marked unbuilt",
			"zone", zd.ZoneName, "err", err)
		return err
	}
	zd.signingKeys.Store(snap)
	return nil
}

// republishSigningKeysForZone looks up the loaded ZoneData by FQDN and
// republishes. If the zone is not loaded, this is a no-op.
func republishSigningKeysForZone(kdb *KeyDB, zone string) error {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	if zone == "." {
		return nil
	}
	zd, ok := Zones.Get(zone)
	if !ok || zd == nil {
		return nil
	}
	return zd.republishSigningKeys(kdb)
}

// activeKeysCAS returns the active key set, building from DB with CAS-if-unbuilt
// when the snapshot is not yet built (M1). Never plain-Stores from the read path.
func (zd *ZoneData) activeKeysCAS(kdb *KeyDB) (*DnssecKeys, error) {
	loaded := zd.signingKeys.Load()
	if loaded != nil && loaded.built {
		if loaded.Active == nil {
			return &DnssecKeys{}, nil
		}
		return loaded.Active, nil
	}
	built, err := buildSigningKeysSnapshot(kdb, zd.ZoneName)
	if err != nil {
		return nil, err
	}
	if zd.signingKeys.CompareAndSwap(loaded, built) {
		return built.Active, nil
	}
	// Lost the race — a concurrent republish or another CAS won.
	winner := zd.signingKeys.Load()
	if winner == nil || winner.Active == nil {
		return &DnssecKeys{}, nil
	}
	return winner.Active, nil
}

// loadDnssecKeysFromDB loads DNSSEC keys for zone+state directly from the
// keystore (no snapshot, no cache). Used for cold states and as the build
// source for the active signing-keys snapshot.
func loadDnssecKeysFromDB(kdb *KeyDB, zonename, state string) (*DnssecKeys, error) {
	const fetchDnssecPrivKeySql = `
SELECT keyid, flags, algorithm, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND state=?`

	var dk DnssecKeys

	rows, err := kdb.Query(fetchDnssecPrivKeySql, zonename, state)
	if err != nil {
		lgSigner.Error("failed to query DNSSEC keys", "sql", fetchDnssecPrivKeySql, "zone", zonename, "err", err)
		return nil, err
	}
	defer rows.Close()

	var algorithm, privatekey, keyrrstr, logmsg string
	var flags, keyid int
	var keysfound bool

	for rows.Next() {
		err := rows.Scan(&keyid, &flags, &algorithm, &privatekey, &keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				lgSigner.Debug("no active DNSSEC key found", "zone", zonename)
				return &dk, nil
			}
			lgSigner.Error("rows.Scan failed", "err", err)
			return nil, err
		}

		keysfound = true

		_, alg, bindFormat, err := ParsePrivateKeyFromDB(privatekey, algorithm, keyrrstr)
		if err != nil {
			lgSigner.Error("ParsePrivateKeyFromDB failed", "err", err)
			return nil, err
		}

		pkc, err := PrepareKeyCache(bindFormat, keyrrstr)
		if err != nil {
			lgSigner.Error("PrepareKeyCache failed", "err", err)
			return nil, err
		}

		if pkc.Algorithm != alg {
			lgSigner.Warn("algorithm mismatch", "stored", alg, "parsed", pkc.Algorithm)
			return nil, fmt.Errorf("error: algorithm mismatch for key %s: stored=%d, parsed=%d", keyrrstr, alg, pkc.Algorithm)
		}

		if (flags & 0x0001) != 0 {
			dk.KSKs = append(dk.KSKs, pkc)
			logmsg += fmt.Sprintf("%d (KSK) ", keyid)
		} else {
			dk.ZSKs = append(dk.ZSKs, pkc)
			logmsg += fmt.Sprintf("%d (ZSK) ", keyid)
		}
	}

	if !keysfound {
		lgSigner.Debug("no DNSSEC keys found", "state", state, "zone", zonename)
		return &dk, nil
	}

	if len(dk.KSKs) == 0 {
		lgSigner.Warn("no DNSSEC KSK found", "state", state, "zone", zonename)
		return &dk, nil
	}

	if len(dk.ZSKs) == 0 {
		lgSigner.Info("no DNSSEC ZSK found, reusing KSK as CSK", "state", state, "zone", zonename)
		dk.ZSKs = append(dk.ZSKs, dk.KSKs[0])
	}

	lgSigner.Debug("loadDnssecKeysFromDB returned keys", "zone", zonename, "state", state, "keys", logmsg)
	return &dk, nil
}
