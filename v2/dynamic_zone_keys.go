/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The keys of a deleted dynamic zone (design 2026-11-23 API ownership, 4.10).
 */

package tdns

import (
	"fmt"
	"strings"
)

// What the KSK rollover engine last saw of a DS for a zone at its parent
// (ZoneRemoval.ParentDS).
const (
	ParentDSSeen = "seen"
	ParentDSNone = "none"
)

// zoneKeyStateTables hold state that describes a zone's DNSSEC keys, keyed
// by the zone (column "zone"). They go with the keys: a zone added later
// under the same name gets fresh keys, and would otherwise inherit a
// rollover phase, confirmed and published DS/CDS ranges and per-key
// timestamps that belong to the old keys (a new key whose tag collides with
// an old one would even take over its active_at), and a last-applied policy
// that the reload path holds the new zone to. ZonePolicyOverride goes whole:
// the override was set on the old zone, and a re-added zone starts from its
// own config.
//
// ZoneSigningState stays: max_observed_ttl measures the zone's content, not
// its keys, every full signing pass rewrites it, and the only reader is a
// KSK rollover's withdraw phase, which comes long after the first one.
var zoneKeyStateTables = []string{
	"RolloverKeyState",
	"RolloverZoneState",
	"ZskRolloverState",
	"RolloverCdsPublication",
	"ZonePolicyOverride",
}

// removeZoneKeys deletes a removed zone's SIG(0) and DNSSEC keys, or, when
// keepKeys is set, only counts them. RemoveDynamicZone calls it once the
// zone has left the dynamic config for good, so a failure here cannot put
// the zone back: it is reported in KeysError, and the zone stays deleted.
//
// TSIG keys are not touched: one key may serve many zones, and a key's
// reference count is computed from the zones served, so the removed zone's
// reference went with it from Zones.
func (conf *Config) removeZoneKeys(zone string, keepKeys bool) *ZoneRemoval {
	r := &ZoneRemoval{Zone: zone, KeepKeys: keepKeys}
	kdb := conf.Internal.KeyDB
	if kdb == nil {
		return r
	}

	// A rollover tick that is working on the zone writes the state deleted
	// here, and a SIG(0) rollover already past its check of zd.removed
	// commits a new key (generateRolloverSig0Key); either finishes first.
	// With keepKeys too: the rollover's new key is then one of the kept
	// ones, and counted here, and a rollover that checks after this finds
	// the zone removed and makes none. RemoveDynamicZone calls this under
	// templateApplyMu, with zd.mu released.
	lock := AcquireRolloverLock(zone)
	lock.Lock()
	defer lock.Unlock()
	// The same for the paths that make keys outside the rollover machinery:
	// a zone's first keys (EnsureActiveDnssecKeys), standby keys, a policy
	// reset's. Taken after the rollover lock (acquireZoneKeysLock).
	keysLock := acquireZoneKeysLock(zone)
	keysLock.Lock()
	defer keysLock.Unlock()

	if keepKeys {
		var err error
		if r.DnssecKeys, r.Sig0Keys, err = kdb.countZoneKeys(zone); err != nil {
			lg.Warn("zone delete: could not count the kept keys", "zone", zone, "error", err)
			r.KeysError = err.Error()
		}
		return r
	}

	// Read before the delete, which takes the row it is kept in.
	r.ParentDS, r.ParentDSAt = parentDSObservation(kdb, zone)
	dnssec, sig0, err := kdb.deleteZoneKeys(zone)
	if err != nil {
		lg.Error("zone delete: the zone is deleted, but its keys could not be", "zone", zone, "error", err)
		r.ParentDS, r.ParentDSAt = "", ""
		r.KeysError = err.Error()
		return r
	}
	r.DnssecKeys, r.Sig0Keys = dnssec, sig0
	lg.Info("zone delete: deleted the zone's keys", "zone", zone, "dnssec", dnssec, "sig0", sig0)
	return r
}

// parentDSObservation is what the KSK rollover engine saw of a DS for zone
// at the parent at its last poll, and when: ParentDSSeen, ParentDSNone, or
// "" when that tells nothing. Only zones the engine manages are polled. A
// parent that has held a DS for the zone before counts as unknown even if
// the last poll found none, since validators may still have it cached.
func parentDSObservation(kdb *KeyDB, zone string) (state, at string) {
	row, err := LoadRolloverZoneRow(kdb, zone)
	if err != nil {
		lg.Warn("zone delete: could not read the parent DS observation", "zone", zone, "error", err)
		return "", ""
	}
	if row == nil || !row.LastDsObservedAt.Valid || !row.LastDsObservedKeyids.Valid {
		return "", ""
	}
	at = strings.TrimSpace(row.LastDsObservedAt.String)
	switch {
	case strings.TrimSpace(row.LastDsObservedKeyids.String) != "":
		return ParentDSSeen, at
	case parentShowedNoDS(row) && !dsRangeEverConfirmed(row):
		return ParentDSNone, at
	}
	return "", ""
}

// countZoneKeys counts zone's DNSSEC and SIG(0) keys, in every state.
func (kdb *KeyDB) countZoneKeys(zone string) (dnssec, sig0 int, err error) {
	if err = kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=?`, zone).Scan(&dnssec); err != nil {
		return 0, 0, fmt.Errorf("count DNSSEC keys: %w", err)
	}
	if err = kdb.DB.QueryRow(`SELECT COUNT(*) FROM Sig0KeyStore WHERE zonename=?`, zone).Scan(&sig0); err != nil {
		return 0, 0, fmt.Errorf("count SIG(0) keys: %w", err)
	}
	return dnssec, sig0, nil
}

// deleteZoneKeys deletes every DNSSEC and SIG(0) key of zone, in every
// state, with the state in zoneKeyStateTables, in one transaction. It
// returns how many keys of each kind it deleted.
//
// The keystore's own SIG(0) delete takes the key's TrustStore copy along;
// so does this, but only the copies the keystore put there (source
// "keystore"). A truststore row from anywhere else under the zone's name is
// a child's key: someone else's authority, not this zone's key.
//
// There is no DNSSEC cache to drop: the signing-key snapshot lives on the
// ZoneData, which left Zones with the zone.
func (kdb *KeyDB) deleteZoneKeys(zone string) (dnssec, sig0 int, err error) {
	tx, err := kdb.Begin("deleteZoneKeys")
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	rows, err := tx.Query(`SELECT keyid FROM Sig0KeyStore WHERE zonename=?`, zone)
	if err != nil {
		return 0, 0, fmt.Errorf("list SIG(0) keys: %w", err)
	}
	var keyids []int
	for rows.Next() {
		var keyid int
		if err = rows.Scan(&keyid); err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("list SIG(0) keys: %w", err)
		}
		keyids = append(keyids, keyid)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("list SIG(0) keys: %w", err)
	}
	for _, keyid := range keyids {
		res, err := tx.Exec(`DELETE FROM Sig0TrustStore WHERE zonename=? AND keyid=? AND source='keystore'`, zone, keyid)
		if err != nil {
			return 0, 0, fmt.Errorf("delete the TrustStore copy of SIG(0) key %d: %w", keyid, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			kdb.dropSig0CacheEntry(tx, fmt.Sprintf("%s::%d", zone, keyid))
		}
	}

	res, err := tx.Exec(`DELETE FROM Sig0KeyStore WHERE zonename=?`, zone)
	if err != nil {
		return 0, 0, fmt.Errorf("delete SIG(0) keys: %w", err)
	}
	n, _ := res.RowsAffected()
	sig0 = int(n)
	if res, err = tx.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=?`, zone); err != nil {
		return 0, 0, fmt.Errorf("delete DNSSEC keys: %w", err)
	}
	n, _ = res.RowsAffected()
	dnssec = int(n)
	for _, table := range zoneKeyStateTables {
		if _, err = tx.Exec(`DELETE FROM `+table+` WHERE zone=?`, zone); err != nil {
			return 0, 0, fmt.Errorf("delete the zone's %s rows: %w", table, err)
		}
	}

	// After the commit, never before: a reader that refilled the cache from
	// the rows still there would otherwise keep the keys alive.
	tx.OnCommit(func() { kdb.invalidateSig0Cache(zone) })
	if err = tx.Commit(); err != nil {
		return 0, 0, err
	}
	return dnssec, sig0, nil
}

// Msg is the outcome of the delete, verdict first, one sentence per line.
func (r *ZoneRemoval) Msg() string {
	var lines []string
	nokeys := fmt.Sprintf("zone %s deleted; it had no DNSSEC or SIG(0) keys", r.Zone)
	counts := fmt.Sprintf("%d DNSSEC, %d SIG(0)", r.DnssecKeys, r.Sig0Keys)
	switch {
	case r.NotSynced != "":
		// Until the removal is on disk a crash can bring the zone back, and
		// it needs its keys. Nothing here can tell when it is; the next
		// rewrite of the dynamic config that is synced puts it there, as that
		// file does not name the zone either. That rewrite does not delete
		// the keys, so the commands come with the step they must wait for.
		lines = append(lines, fmt.Sprintf("zone %s deleted, but a crash could bring it back: %s", r.Zone, r.NotSynced))
		if r.KeepKeys {
			lines = append(lines, "its keys were kept, as asked; a re-add takes them back")
			break
		}
		lines = append(lines,
			"its keys were kept, and must stay until the removal is on disk: the next zone add, modify or delete that succeeds puts it there, but does not delete them",
			"after that, delete them; \"keystore sig0 list\" shows the SIG(0) key IDs:")
		lines = append(lines, r.keyDeleteCommands()...)

	case r.KeepKeys:
		switch {
		case r.KeysError != "":
			lines = append(lines, fmt.Sprintf("zone %s deleted; its keys were kept, but could not be counted: %s", r.Zone, r.KeysError))
		case r.DnssecKeys+r.Sig0Keys == 0:
			return nokeys
		default:
			lines = append(lines, fmt.Sprintf("zone %s deleted; its keys were kept: %s", r.Zone, counts))
		}
		lines = append(lines, "the kept keys belong to no zone now; a re-add takes them back")

	case r.KeysError != "":
		// The commands on lines of their own, indented, to copy.
		lines = append(lines,
			fmt.Sprintf("zone %s deleted, but its keys were not: %s", r.Zone, r.KeysError),
			"delete them by hand; \"keystore sig0 list\" shows the SIG(0) key IDs:")
		lines = append(lines, r.keyDeleteCommands()...)

	case r.DnssecKeys+r.Sig0Keys == 0:
		return nokeys

	default:
		lines = append(lines, fmt.Sprintf("zone %s deleted, with its keys: %s", r.Zone, counts))
		if r.DnssecKeys > 0 && r.ParentDS == ParentDSNone {
			lines = append(lines, fmt.Sprintf("the parent had no DS for %s at the last poll (%s)", r.Zone, r.ParentDSAt))
		}
	}
	return strings.Join(lines, "\n")
}

// keyDeleteCommands are the commands that delete the zone's keys by hand,
// indented, one per line, to copy whole.
func (r *ZoneRemoval) keyDeleteCommands() []string {
	return []string{
		fmt.Sprintf("  keystore dnssec clear --zone %s --force", r.Zone),
		fmt.Sprintf("  keystore sig0 delete --zone %s --keyid <keyid>", r.Zone),
	}
}

// Warnings says what the operator must not overlook. A DS at the parent
// matches only a key deleted here, so validators treat the zone as bogus
// until the DS goes (R12). Worded as a fact only when the rollover engine
// saw the DS; when it does not know, conditionally.
func (r *ZoneRemoval) Warnings() []string {
	if r.KeepKeys || r.KeysError != "" || r.NotSynced != "" || r.DnssecKeys == 0 {
		return nil
	}
	const consequence = "validating resolvers treat the zone as bogus until the DS is removed or replaced"
	switch r.ParentDS {
	case ParentDSSeen:
		return []string{fmt.Sprintf("the parent had a DS for %s at the last poll (%s); it matches no key here now: %s",
			r.Zone, r.ParentDSAt, consequence)}
	case ParentDSNone:
		return nil
	}
	return []string{fmt.Sprintf("if the parent has a DS for %s, it matches no key here now: %s", r.Zone, consequence)}
}
