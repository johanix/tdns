/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
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
// memory and in the KeyDB. A failed write is logged and the in-memory record
// stands: the signal is then known as the pass's own until the next restart.
func (zd *ZoneData) noteSignalStored(owner string, rrs []dns.RR) {
	owner = core.CanonicalizeName(owner)
	digest := signalDigest(rrs)
	zd.signalStoredMu.Lock()
	if zd.signalStored == nil {
		zd.signalStored = map[string]string{}
	}
	zd.signalStored[owner] = digest
	zd.signalStoredMu.Unlock()
	kdb := zd.signalRecordDB()
	if kdb == nil {
		return
	}
	if err := kdb.SetTransportSignalStored(zd.ZoneName, owner, digest); err != nil {
		lgDns.Warn("noteSignalStored: could not record the stored signal; after a restart it may be taken for the operator's",
			"zone", zd.ZoneName, "owner", owner, "error", err)
	}
}

// forgetSignalStored drops the record for owner: the RRset there is the
// operator's now.
func (zd *ZoneData) forgetSignalStored(owner string) {
	owner = core.CanonicalizeName(owner)
	zd.signalStoredMu.Lock()
	delete(zd.signalStored, owner)
	zd.signalStoredMu.Unlock()
	kdb := zd.signalRecordDB()
	if kdb == nil {
		return
	}
	if err := kdb.DeleteTransportSignalStoredOwner(zd.ZoneName, owner); err != nil {
		lgDns.Warn("forgetSignalStored: could not drop the stored-signal record",
			"zone", zd.ZoneName, "owner", owner, "error", err)
	}
}

// signalStoredByPass reports whether rrs at owner are exactly what the signal
// pass last stored there. An RRset the operator has since replaced, by an
// update or in the zone file, is not. The in-memory record is asked first,
// then the KeyDB, which holds what an earlier process stored.
func (zd *ZoneData) signalStoredByPass(owner string, rrs []dns.RR) bool {
	owner = core.CanonicalizeName(owner)
	zd.signalStoredMu.Lock()
	digest, ok := zd.signalStored[owner]
	zd.signalStoredMu.Unlock()
	if kdb := zd.signalRecordDB(); !ok && kdb != nil {
		var err error
		digest, ok, err = kdb.GetTransportSignalStored(zd.ZoneName, owner)
		if err != nil {
			lgDns.Warn("signalStoredByPass: could not read the stored-signal record",
				"zone", zd.ZoneName, "owner", owner, "error", err)
			return false
		}
	}
	return ok && digest == signalDigest(rrs)
}

// signalStoredOwners lists the owners the pass has a record of storing a
// signal at in this zone: in this process, and in the KeyDB from an earlier
// one.
func (zd *ZoneData) signalStoredOwners() []string {
	seen := map[string]bool{}
	var out []string
	zd.signalStoredMu.Lock()
	for owner := range zd.signalStored {
		seen[owner] = true
		out = append(out, owner)
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

// SetTransportSignalStored records the digest of the signal stored at owner.
func (kdb *KeyDB) SetTransportSignalStored(zone, owner, digest string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("SetTransportSignalStored: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	_, err := kdb.DB.Exec(`
INSERT OR REPLACE INTO TransportSignalStored (zone, owner, digest, updated_at)
VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		dns.Fqdn(zone), core.CanonicalizeName(owner), digest)
	if err != nil {
		return fmt.Errorf("SetTransportSignalStored: zone %s owner %s: %v", zone, owner, err)
	}
	return nil
}

// GetTransportSignalStored returns the recorded digest for owner, and
// whether there is one. No record is not an error.
func (kdb *KeyDB) GetTransportSignalStored(zone, owner string) (string, bool, error) {
	if kdb == nil || kdb.DB == nil {
		return "", false, fmt.Errorf("GetTransportSignalStored: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	var digest string
	err := kdb.DB.QueryRow(`SELECT digest FROM TransportSignalStored WHERE zone=? AND owner=?`,
		dns.Fqdn(zone), core.CanonicalizeName(owner)).Scan(&digest)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("GetTransportSignalStored: zone %s owner %s: %v", zone, owner, err)
	}
	return digest, true, nil
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
