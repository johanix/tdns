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

// buildSigningKeysSnapshot loads the signing keys (sign=1) from the keystore
// and returns a fresh immutable snapshot with built=true (including keyless
// empty Active).
func buildSigningKeysSnapshot(kdb *KeyDB, zone string) (*signingKeysSnapshot, error) {
	dak, err := loadSigningKeysFromDB(kdb, zone)
	if err != nil {
		return nil, err
	}
	return &signingKeysSnapshot{built: true, Active: dak}, nil
}

// republishSigningKeys builds from DB and atomically publishes onto zd.
// Call ONLY after the keystore transaction that changed this zone's keys has
// COMMITTED. On persistent build failure: loud Error, mark unbuilt with a
// fresh allocation (never the shared sentinel), return err (M3).
//
// Overlapping republishes are generation-gated: each call takes a new
// signingKeysGen; Store (success or unbuilt marker) runs only if that
// generation is still current, so an older build cannot clobber a newer one.
func (zd *ZoneData) republishSigningKeys(kdb *KeyDB) error {
	if zd == nil {
		return fmt.Errorf("republishSigningKeys: nil ZoneData")
	}
	gen := zd.signingKeysGen.Add(1)
	snap, err := buildSigningKeysSnapshot(kdb, zd.ZoneName)
	if err != nil {
		lgSigner.Error("republishSigningKeys: build failed, retrying", "zone", zd.ZoneName, "err", err)
		snap, err = buildSigningKeysSnapshot(kdb, zd.ZoneName)
	}
	if err != nil {
		if zd.signingKeysGen.Load() == gen {
			zd.signingKeys.Store(&signingKeysSnapshot{built: false, Active: &DnssecKeys{}})
		}
		lgSigner.Error("republishSigningKeys: failed after retry; marked unbuilt",
			"zone", zd.ZoneName, "err", err)
		return err
	}
	if zd.signingKeysGen.Load() == gen {
		zd.signingKeys.Store(snap)
	}
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

// loadDnssecKeysFromDB loads the DNSSEC keys of a zone in one lifecycle
// state directly from the keystore (no snapshot, no cache). For the keys that
// sign, which is a question of the sign column and not of a state, see
// loadSigningKeysFromDB.
func loadDnssecKeysFromDB(kdb *KeyDB, zonename, state string) (*DnssecKeys, error) {
	return loadDnssecKeysWhere(kdb, zonename, `state=?`, state, state)
}

// loadSigningKeysFromDB loads the keys a zone signs with: the rows with
// sign=1 (design D3). It is the build source of the signing-keys snapshot.
// A row with sign set but no private key cannot sign and fails the load,
// as a missing key file always has.
func loadSigningKeysFromDB(kdb *KeyDB, zonename string) (*DnssecKeys, error) {
	return loadDnssecKeysWhere(kdb, zonename, `sign=1`, "signing")
}

// loadDnssecKeysWhere is the shared loader: the zone's rows matching where,
// their private keys parsed, split by the SEP bit into KSKs and ZSKs, with
// the KSK reused as CSK when there is no ZSK. label names the set in logs.
func loadDnssecKeysWhere(kdb *KeyDB, zonename, where, label string, args ...any) (*DnssecKeys, error) {
	fetchDnssecPrivKeySql := `SELECT keyid, flags, algorithm, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND ` + where
	state := label

	var dk DnssecKeys

	rows, err := kdb.Query(fetchDnssecPrivKeySql, append([]any{zonename}, args...)...)
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

		// PrivateKeyCacheFromDB, NOT ParsePrivateKeyFromDB + PrepareKeyCache: the
		// latter pair re-derives a BIND blob from an already-parsed PEM and
		// re-parses it via NewPrivateKey, which dispatches on the algorithm
		// codepoint and fails ("dns: bad private key") for any key stored under
		// a codepoint that has since been renumbered.
		pkc, alg, err := PrivateKeyCacheFromDB(privatekey, algorithm, keyrrstr)
		if err != nil {
			lgSigner.Error("PrivateKeyCacheFromDB failed", "err", err)
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

	if err := rows.Err(); err != nil {
		lgSigner.Error("iterate DNSSEC keys failed", "zone", zonename, "state", state, "err", err)
		return nil, fmt.Errorf("iterate DNSSEC keys for zone %s: %w", zonename, err)
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
