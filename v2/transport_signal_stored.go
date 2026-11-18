/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// What the transport-signal start-up pass stored, per owner, so that a later
// run tells its own signal from records provisioned in the zone (design
// 2026-11-14 section 5; the maintainer's ruling on plan step S2,
// 2026-11-15). The pass leaves provisioned records alone, replaces its own
// signal with what the configuration gives now, and withdraws it from a name
// that is no longer an identity at home in the zone. Its own signal is zone
// content, and a journal replay or a persisted copy brings it back after a
// restart, so the record is kept in the KeyDB as well as in memory. Without
// a KeyDB the record lasts as long as the process. Matching what the
// configuration gives is never taken as the pass's own: an operator may
// write exactly that.
//
// The record keeps the digests of the signals the pass stored before the
// last one, too. The pass stores a signal into the working set; it reaches
// the zone file only when the zone is next written (WriteZoneToFile writes
// every RRset), which may be much later or never. A restart in between
// loads whatever signal the file holds, which is then an earlier one of the
// pass's, not the last. Known by the last digest alone, it would be taken
// for the operator's and kept for good. Up to signalStoredKeep digests are
// kept, newest first.

// signalStoredKeep is how many digests the record keeps per owner.
const signalStoredKeep = 8

// signalDigest is a digest of an RRset's records, TTL and order aside, and
// names compared without case, as dns.IsDuplicate compares them.
func signalDigest(rrs []dns.RR) string {
	lines := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		c := dns.Copy(rr)
		c.Header().Ttl = 0
		lines = append(lines, strings.ToLower(c.String()))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// signalRecordDB is the KeyDB the record is kept in, or nil when there is
// none behind the zone: the record then lasts as long as the process.
func (zd *ZoneData) signalRecordDB() *KeyDB {
	if zd.KeyDB == nil || zd.KeyDB.DB == nil {
		return nil
	}
	return zd.KeyDB
}

// noteSignalStored records that the signal pass stored rrs at owner, in
// memory and in the KeyDB, ahead of the digests of what it stored there
// before. The earlier digests are read first (signalStoredDigests), and the
// write is SetTransportSignalStored after a read and
// PrependTransportSignalStored after a failed one. With D the new digest and
// E the digests read (or, unread, those the record holds), the four outcomes:
//
//   - Read ok, write ok: memory [D E], the record [D E], signalUnrecorded
//     cleared. The next run reads memory: the signal is the pass's.
//   - Read ok, write fails: memory [D E], the record unchanged,
//     signalUnrecorded cleared (its digests are in E). The next run reads
//     memory: the signal is the pass's. After a restart the record lacks D,
//     so a zone that holds this signal reads as the operator's, which the
//     warning says.
//   - Read fails, prepend ok: memory unset, the record [D E]. The next run
//     reads the record: the signal is the pass's once the record reads, and
//     is left as it is while it does not. Memory holding [D] alone would be
//     what the next store reads, without the KeyDB, and writes back whole,
//     dropping E.
//   - Read fails, prepend fails, as with the earlier column missing: memory
//     unset, the record unchanged, D kept in signalUnrecorded. The next run
//     knows the signal for the pass's without a read (signalStoredByPass),
//     and its next store that reads the record writes [D E], clearing
//     signalUnrecorded. A restart forgets D, as in the second case.
//
// In every case the next store that reads the record writes the new digest
// ahead of every digest kept, never a shorter list.
func (zd *ZoneData) noteSignalStored(owner string, rrs []dns.RR) {
	owner = core.CanonicalizeName(owner)
	digest := signalDigest(rrs)
	digests := []string{digest}
	earlier, readErr := zd.signalStoredDigests(owner)
	if readErr != nil {
		lgDns.Warn("noteSignalStored: could not read the earlier digests; the new one is put ahead of what the KeyDB holds",
			"zone", zd.ZoneName, "owner", owner, "error", readErr)
	}
	digests = mergeSignalDigests(digests, earlier)
	if readErr == nil {
		// The digests read include those the KeyDB had not taken
		// (signalStoredDigests); the record in memory holds them now.
		zd.signalStoredMu.Lock()
		if zd.signalStored == nil {
			zd.signalStored = map[string][]string{}
		}
		zd.signalStored[owner] = digests
		delete(zd.signalUnrecorded, owner)
		zd.signalStoredMu.Unlock()
	}
	kdb := zd.signalRecordDB()
	if kdb == nil {
		return
	}
	write := func() error { return kdb.SetTransportSignalStored(zd.ZoneName, owner, digests) }
	if readErr != nil {
		write = func() error { return kdb.PrependTransportSignalStored(zd.ZoneName, owner, digest) }
	}
	if err := write(); err != nil {
		lgDns.Warn("noteSignalStored: could not record the stored signal; after a restart it may be taken for the operator's",
			"zone", zd.ZoneName, "owner", owner, "error", err)
		if readErr != nil {
			zd.noteSignalUnrecorded(owner, digest)
		}
	}
}

// noteSignalUnrecorded keeps digest, a signal the pass stored at owner that
// neither the in-memory record nor the KeyDB holds, ahead of the others it
// keeps there (signalUnrecorded).
func (zd *ZoneData) noteSignalUnrecorded(owner, digest string) {
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	if zd.signalUnrecorded == nil {
		zd.signalUnrecorded = map[string][]string{}
	}
	zd.signalUnrecorded[owner] = mergeSignalDigests([]string{digest}, zd.signalUnrecorded[owner])
}

// mergeSignalDigests is first followed by the digests of then that are not
// in it, at most signalStoredKeep in all.
func mergeSignalDigests(first, then []string) []string {
	out := make([]string, 0, len(first)+len(then))
	for _, d := range append(append([]string(nil), first...), then...) {
		if !slices.Contains(out, d) && len(out) < signalStoredKeep {
			out = append(out, d)
		}
	}
	return out
}

// forgetSignalStored ends the pass's claim on owner: the RRset there is the
// operator's now. The in-memory record becomes an explicit revocation first,
// an entry with no digest, so that nothing falls back to the KeyDB's record
// while it is being dropped. The entry goes once the KeyDB has dropped its
// record. A failed KeyDB delete is returned and the revocation stays: in
// this process the owner is not the pass's, signalStoredOwners still lists
// it, and the next forget tries the delete again. After a restart the
// KeyDB's record would count again, which is why the callers warn.
func (zd *ZoneData) forgetSignalStored(owner string) error {
	owner = core.CanonicalizeName(owner)
	zd.signalStoredMu.Lock()
	if zd.signalStored == nil {
		zd.signalStored = map[string][]string{}
	}
	zd.signalStored[owner] = nil
	delete(zd.signalUnrecorded, owner)
	zd.signalStoredMu.Unlock()
	if kdb := zd.signalRecordDB(); kdb != nil {
		if err := kdb.DeleteTransportSignalStoredOwner(zd.ZoneName, owner); err != nil {
			return fmt.Errorf("forgetSignalStored: zone %s owner %s: %w", zd.ZoneName, owner, err)
		}
	}
	zd.signalStoredMu.Lock()
	if d, ok := zd.signalStored[owner]; ok && d == nil {
		delete(zd.signalStored, owner)
	}
	zd.signalStoredMu.Unlock()
	return nil
}

// signalRevocationPending reports whether forgetSignalStored revoked owner
// in this process and the KeyDB has not yet dropped its record.
func (zd *ZoneData) signalRevocationPending(owner string) bool {
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	d, ok := zd.signalStored[core.CanonicalizeName(owner)]
	return ok && d == nil
}

// warnSignalForgetFailed is how the pass handles a failed forget: the
// revocation holds in this process, and the pass tries the delete again on
// its next run, but a restart before the KeyDB drops the record would make
// the pass take the records at the owner for its own again.
func (zd *ZoneData) warnSignalForgetFailed(owner string, err error) {
	lgDns.Warn("the KeyDB could not drop the stored-signal record: the records at the owner are not the pass's in this process and the pass tries again on its next run, but after a restart the KeyDB's record would count again",
		"zone", zd.ZoneName, "owner", owner, "error", err)
}

// signalStoredReadHook, when set, is asked before the KeyDB's record is read
// in signalStoredDigests, and an error it returns is the read's: tests set
// it to make the read fail while the writes still work.
var signalStoredReadHook func(zone, owner string) error

// signalStoredDigests returns the digests the pass recorded for owner, the
// last first: the in-memory record, or else the KeyDB's, which holds what
// an earlier process stored, behind the digests the KeyDB did not take
// (signalUnrecorded). nil when there is none, and nil for an owner revoked
// in this process (forgetSignalStored), whose KeyDB record is then not
// consulted.
//
// An error when the KeyDB's record cannot be read. "No record" and "a
// record that cannot be read" are not the same answer: the first makes the
// RRset at the owner the operator's, while the second leaves it unknown,
// and a caller that took it for the first would forget the pass's own
// signal for good (CodeRabbit on #1118).
func (zd *ZoneData) signalStoredDigests(owner string) ([]string, error) {
	zd.signalStoredMu.Lock()
	digests, ok := zd.signalStored[owner]
	unrecorded := append([]string(nil), zd.signalUnrecorded[owner]...)
	zd.signalStoredMu.Unlock()
	if ok {
		return digests, nil
	}
	kdb := zd.signalRecordDB()
	if kdb == nil {
		return unrecorded, nil
	}
	if signalStoredReadHook != nil {
		if err := signalStoredReadHook(zd.ZoneName, owner); err != nil {
			return nil, err
		}
	}
	digests, _, err := kdb.GetTransportSignalStored(zd.ZoneName, owner)
	if err != nil {
		return nil, err
	}
	if len(unrecorded) > 0 {
		return mergeSignalDigests(unrecorded, digests), nil
	}
	return digests, nil
}

// signalStoredByPass reports whether rrs at owner are exactly a signal the
// pass stored there: the last one, or one before it that a zone written in
// between may hold. An RRset the operator has since replaced, by an update
// or in the zone file, is not. An error when the record cannot be read
// (signalStoredDigests); the answer is then neither yes nor no.
//
// A digest the KeyDB did not take (signalUnrecorded) answers yes without a
// read: the pass stored that signal in this process.
func (zd *ZoneData) signalStoredByPass(owner string, rrs []dns.RR) (bool, error) {
	owner = core.CanonicalizeName(owner)
	digest := signalDigest(rrs)
	zd.signalStoredMu.Lock()
	unrecorded := slices.Contains(zd.signalUnrecorded[owner], digest)
	zd.signalStoredMu.Unlock()
	if unrecorded {
		return true, nil
	}
	digests, err := zd.signalStoredDigests(owner)
	if err != nil {
		return false, err
	}
	return slices.Contains(digests, digest), nil
}

// warnSignalRecordUnreadable is how the pass handles an owner whose record
// cannot be read: it does not know whether the RRset there is its own or the
// operator's, so it neither replaces nor withdraws it, and does not forget
// the record. The owner stays as it is until the pass next runs.
func (zd *ZoneData) warnSignalRecordUnreadable(owner string, err error) {
	lgDns.Warn("transport signal pass: could not read the record of what the pass stored at the owner; leaving the owner as it is until the pass next runs",
		"zone", zd.ZoneName, "owner", owner, "error", err)
}

// signalStoredOwners lists the owners the pass has a record of storing a
// signal at in this zone: in this process, and in the KeyDB from an earlier
// one. An owner whose revocation is pending is listed too, so that the pass
// tries the KeyDB delete again.
func (zd *ZoneData) signalStoredOwners() []string {
	seen := map[string]bool{}
	var out []string
	zd.signalStoredMu.Lock()
	for owner := range zd.signalStored {
		seen[owner] = true
		out = append(out, owner)
	}
	for owner := range zd.signalUnrecorded {
		if !seen[owner] {
			seen[owner] = true
			out = append(out, owner)
		}
	}
	zd.signalStoredMu.Unlock()
	if kdb := zd.signalRecordDB(); kdb != nil {
		owners, err := kdb.ListTransportSignalStored(zd.ZoneName)
		if err != nil {
			lgDns.Warn("signalStoredOwners: could not list the stored-signal records",
				"zone", zd.ZoneName, "error", err)
		}
		for _, owner := range owners {
			if !seen[owner] {
				seen[owner] = true
				out = append(out, owner)
			}
		}
	}
	sort.Strings(out)
	return out
}

// SetTransportSignalStored records the digests of the signals stored at
// owner, the last first: the last in digest, the earlier ones in earlier,
// separated by spaces.
func (kdb *KeyDB) SetTransportSignalStored(zone, owner string, digests []string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("SetTransportSignalStored: no database")
	}
	if len(digests) == 0 {
		return fmt.Errorf("SetTransportSignalStored: zone %s owner %s: no digest", zone, owner)
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	_, err := kdb.DB.Exec(`
INSERT OR REPLACE INTO TransportSignalStored (zone, owner, digest, earlier, updated_at)
VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		dns.Fqdn(zone), core.CanonicalizeName(owner), digests[0], strings.Join(digests[1:], " "))
	if err != nil {
		return fmt.Errorf("SetTransportSignalStored: zone %s owner %s: %v", zone, owner, err)
	}
	return nil
}

// PrependTransportSignalStored records digest as the last one for owner,
// ahead of the digests the record holds, in one statement: for a writer that
// could not read the record first (noteSignalStored). A digest that is the
// last one already changes nothing; one among the earlier digests moves to
// the front rather than appearing twice, where it would take one of the
// signalStoredKeep places from a distinct digest. The list is not trimmed
// here; the next SetTransportSignalStored trims it.
func (kdb *KeyDB) PrependTransportSignalStored(zone, owner, digest string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("PrependTransportSignalStored: no database")
	}
	if digest == "" {
		return fmt.Errorf("PrependTransportSignalStored: zone %s owner %s: no digest", zone, owner)
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	_, err := kdb.DB.Exec(`
INSERT INTO TransportSignalStored (zone, owner, digest, earlier, updated_at)
VALUES (?, ?, ?, '', CURRENT_TIMESTAMP)
ON CONFLICT(zone, owner) DO UPDATE SET
	earlier = CASE WHEN digest = excluded.digest THEN earlier
		ELSE TRIM(REPLACE(' ' || digest || ' ' || earlier || ' ', ' ' || excluded.digest || ' ', ' ')) END,
	digest = excluded.digest,
	updated_at = CURRENT_TIMESTAMP`,
		dns.Fqdn(zone), core.CanonicalizeName(owner), digest)
	if err != nil {
		return fmt.Errorf("PrependTransportSignalStored: zone %s owner %s: %v", zone, owner, err)
	}
	return nil
}

// GetTransportSignalStored returns the recorded digests for owner, the last
// first, and whether there is a record. No record is not an error.
func (kdb *KeyDB) GetTransportSignalStored(zone, owner string) ([]string, bool, error) {
	if kdb == nil || kdb.DB == nil {
		return nil, false, fmt.Errorf("GetTransportSignalStored: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	var digest, earlier string
	err := kdb.DB.QueryRow(`SELECT digest, earlier FROM TransportSignalStored WHERE zone=? AND owner=?`,
		dns.Fqdn(zone), core.CanonicalizeName(owner)).Scan(&digest, &earlier)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("GetTransportSignalStored: zone %s owner %s: %v", zone, owner, err)
	}
	return append([]string{digest}, strings.Fields(earlier)...), true, nil
}

// ListTransportSignalStored returns the owners with a record in zone.
func (kdb *KeyDB) ListTransportSignalStored(zone string) ([]string, error) {
	if kdb == nil || kdb.DB == nil {
		return nil, fmt.Errorf("ListTransportSignalStored: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	rows, err := kdb.DB.Query(`SELECT owner FROM TransportSignalStored WHERE zone=?`, dns.Fqdn(zone))
	if err != nil {
		return nil, fmt.Errorf("ListTransportSignalStored: zone %s: %v", zone, err)
	}
	defer rows.Close()
	var owners []string
	for rows.Next() {
		var owner string
		if err := rows.Scan(&owner); err != nil {
			return owners, fmt.Errorf("ListTransportSignalStored: zone %s: %v", zone, err)
		}
		owners = append(owners, owner)
	}
	if err := rows.Err(); err != nil {
		return owners, fmt.Errorf("ListTransportSignalStored: zone %s: %v", zone, err)
	}
	return owners, nil
}

// DeleteTransportSignalStoredOwner drops the record for one owner.
func (kdb *KeyDB) DeleteTransportSignalStoredOwner(zone, owner string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("DeleteTransportSignalStoredOwner: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	if _, err := kdb.DB.Exec(`DELETE FROM TransportSignalStored WHERE zone=? AND owner=?`,
		dns.Fqdn(zone), core.CanonicalizeName(owner)); err != nil {
		return fmt.Errorf("DeleteTransportSignalStoredOwner: %v", err)
	}
	return nil
}

// DeleteTransportSignalStored drops a zone's records, used when the zone is
// removed.
func (kdb *KeyDB) DeleteTransportSignalStored(zone string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("DeleteTransportSignalStored: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	if _, err := kdb.DB.Exec(`DELETE FROM TransportSignalStored WHERE zone=?`, dns.Fqdn(zone)); err != nil {
		return fmt.Errorf("DeleteTransportSignalStored: %v", err)
	}
	return nil
}

// refreshCarriesSignal reports whether a refresh carries the SVCB RRset rrs
// at owner over from the published zone (CollectDynamicRRs): when it is the
// pass's own, and when that cannot be told because the record cannot be
// read. A signal the pass synthesized is in no zone file or transfer, so
// not carrying it would take it out of the served zone for as long as the
// record stays unreadable. An operator's RRset is not carried because the
// fresh data holds their edit, and a carried copy never overrides that:
// records the fresh data holds at the owner win (repopulateWorkingSetLocked
// drops the carried copy). Only an RRset the operator removed from the file
// comes back, until a refresh after the record reads again.
func (zd *ZoneData) refreshCarriesSignal(owner string, rrs []dns.RR) bool {
	own, err := zd.signalStoredByPass(owner, rrs)
	if err != nil {
		lgDns.Warn("CollectDynamicRRs: could not read the record of what the pass stored at the owner; its SVCB RRset is carried over the refresh, as the pass's own would be",
			"zone", zd.ZoneName, "owner", owner, "error", err)
		return true
	}
	return own
}
