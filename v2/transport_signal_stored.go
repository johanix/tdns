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
// run tells its own signal from an operator's RRset (design 2026-11-14
// section 5). The pass leaves an operator's RRset alone and replaces its own
// with what the configuration gives now. Its own signal is zone content, and
// a journal replay or a persisted copy brings it back after a restart, so
// the record is kept in the KeyDB as well as in memory. Without a KeyDB the
// record lasts as long as the process.

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
	if zd.KeyDB == nil {
		return
	}
	if err := zd.KeyDB.SetTransportSignalStored(zd.ZoneName, owner, digest); err != nil {
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
	if zd.KeyDB == nil {
		return
	}
	if err := zd.KeyDB.DeleteTransportSignalStoredOwner(zd.ZoneName, owner); err != nil {
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
	if !ok && zd.KeyDB != nil {
		var err error
		digest, ok, err = zd.KeyDB.GetTransportSignalStored(zd.ZoneName, owner)
		if err != nil {
			lgDns.Warn("signalStoredByPass: could not read the stored-signal record",
				"zone", zd.ZoneName, "owner", owner, "error", err)
			return false
		}
	}
	return ok && digest == signalDigest(rrs)
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
