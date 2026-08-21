/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// ZoneFileState records the IDENTITY of the zone file as tdns last read it or
// last wrote it: its SOA serial, and a ZONEMD digest of its contents.
//
// The serial alone cannot answer "is this the same file?". A zone file can be
// regenerated with the same serial, restored from a backup that reuses one, or
// reformatted without changing it at all -- and the delta journal is anchored
// to the file, so getting that question wrong means either replaying changes
// onto a base they were not computed against, or refusing a journal that was
// perfectly good. The digest answers it exactly, and answers it in terms of
// zone CONTENT: reordering records, editing comments, reflowing whitespace and
// changing $TTL style all leave it unchanged, because none of them change the
// zone.
//
// Recorded at both ends -- every read from the file and every write to it --
// so the comparison is always file-against-file. Never file against the
// in-memory zone: a loaded zone re-signs, so its digest diverges from the
// file's by construction and a comparison across that boundary would report
// every signed zone as modified.

// ZoneFileIdentity is one recorded observation of a zone file.
type ZoneFileIdentity struct {
	Zone      string
	Serial    uint32
	Digest    string // lowercase hex
	Scheme    uint8
	Algorithm uint8
	UpdatedAt string
}

// zoneFileStateAlg is the digest algorithm used for the identity record.
// SHA-384 is ZONEMD's mandatory-to-implement algorithm and the one every
// published ZONEMD in the wild uses.
const zoneFileStateAlg = ZonemdAlgSHA384

// SetZoneFileState records what the zone file now holds.
func (kdb *KeyDB) SetZoneFileState(zone string, serial uint32, digest string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("SetZoneFileState: no database")
	}
	zone = dns.Fqdn(zone)

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	_, err := kdb.DB.Exec(`
INSERT OR REPLACE INTO ZoneFileState (zone, serial, digest, scheme, algorithm, updated_at)
VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		zone, serial, digest, ZonemdSchemeSimple, zoneFileStateAlg)
	if err != nil {
		return fmt.Errorf("SetZoneFileState: zone %s: %v", zone, err)
	}
	return nil
}

// GetZoneFileState returns the last recorded identity of the zone's file, and
// whether there is one at all.
//
// "No record" is not an error and not a mismatch. It is what every zone looks
// like the first time this code runs against an existing database, and the
// reconciliation path treats it as "no basis for comparison" rather than as
// evidence the file changed.
func (kdb *KeyDB) GetZoneFileState(zone string) (*ZoneFileIdentity, bool, error) {
	if kdb == nil || kdb.DB == nil {
		return nil, false, fmt.Errorf("GetZoneFileState: no database")
	}
	zone = dns.Fqdn(zone)

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var id ZoneFileIdentity
	id.Zone = zone
	err := kdb.DB.QueryRow(
		`SELECT serial, digest, scheme, algorithm, updated_at FROM ZoneFileState WHERE zone=?`,
		zone).Scan(&id.Serial, &id.Digest, &id.Scheme, &id.Algorithm, &id.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("GetZoneFileState: zone %s: %v", zone, err)
	}
	return &id, true, nil
}

// DeleteZoneFileState drops the recorded identity, used when a zone is removed.
func (kdb *KeyDB) DeleteZoneFileState(zone string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("DeleteZoneFileState: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	if _, err := kdb.DB.Exec(`DELETE FROM ZoneFileState WHERE zone=?`, dns.Fqdn(zone)); err != nil {
		return fmt.Errorf("DeleteZoneFileState: %v", err)
	}
	return nil
}

// zoneRRsFromSnapshot flattens a published snapshot into the RR list the digest
// is computed over.
//
// Deliberately mirrors what WriteZoneToFile serialises, RRSIGs included: the
// two must see the same records, or the digest recorded at write time would
// not match the digest computed when that same file is read back.
func zoneRRsFromSnapshot(snap *zoneSnapshot) []dns.RR {
	if snap == nil {
		return nil
	}
	var out []dns.RR
	for name := range snap.Data {
		od := getOwnerFrom(snap, name)
		if od == nil {
			continue
		}
		for _, rrt := range od.RRtypes.Keys() {
			rrset := od.RRtypes.GetOnlyRRSet(rrt)
			out = append(out, rrset.RRs...)
			out = append(out, rrset.RRSIGs...)
		}
	}
	return out
}

// ZoneDigestOfPublished computes the ZONEMD digest of the zone as currently
// published -- what a write-out would put in the file. Ordering is irrelevant
// to the result: ZoneDigest sorts canonically, so no ordering guarantee is made
// or needed here.
func (zd *ZoneData) ZoneDigestOfPublished() (string, error) {
	if zd == nil {
		return "", fmt.Errorf("no zone")
	}
	rrs := zoneRRsFromSnapshot(zd.publishedSnapshot())
	if len(rrs) == 0 {
		return "", fmt.Errorf("zone %s: nothing published to digest", zd.ZoneName)
	}
	return ZoneDigestHex(zd.ZoneName, rrs, ZonemdSchemeSimple, zoneFileStateAlg)
}

// zoneDigestOfWorkingData computes the digest over zd.Data -- the zone as just
// parsed, before any snapshot has been installed.
//
// The parse site is where the file digest has to be taken, for exactly the
// reason fileSerial is taken there: it is the last moment at which the
// in-memory zone is what the file says, and nothing else. A digest taken later
// includes load-time signing and republication, and would never match the file
// it is supposed to identify.
func (zd *ZoneData) zoneDigestOfWorkingData() (string, error) {
	if zd == nil || zd.Data == nil {
		return "", fmt.Errorf("no zone data")
	}
	var rrs []dns.RR
	for tuple := range zd.Data.Iter() {
		od := tuple.Val
		for _, rrt := range od.RRtypes.Keys() {
			rrset := od.RRtypes.GetOnlyRRSet(rrt)
			rrs = append(rrs, rrset.RRs...)
			rrs = append(rrs, rrset.RRSIGs...)
		}
	}
	if len(rrs) == 0 {
		return "", fmt.Errorf("zone %s: no data to digest", zd.ZoneName)
	}
	return ZoneDigestHex(zd.ZoneName, rrs, ZonemdSchemeSimple, zoneFileStateAlg)
}

// CompareZoneFileState compares the file tdns has just read against the
// identity it recorded the last time it read or wrote that file.
//
// A missing record is ZoneFileUnknown, not ZoneFileChanged. Every zone looks
// like that the first time this code runs against an existing database, and
// treating "I have never seen this file" as "someone tampered with this file"
// would turn an upgrade into a fleet-wide false alarm.
func (zd *ZoneData) CompareZoneFileState() (ZoneFileVerdict, *ZoneFileIdentity, error) {
	if zd == nil || zd.KeyDB == nil {
		return ZoneFileUnknown, nil, fmt.Errorf("no zone or no database")
	}

	zd.mu.Lock()
	cur := zd.fileDigest
	zd.mu.Unlock()

	return zd.KeyDB.CompareZoneFileDigest(zd.ZoneName, cur)
}

// CompareZoneFileDigest compares a digest just computed from a zone file
// against the identity recorded for that zone.
//
// Split out of CompareZoneFileState because a RELOAD has to ask the question
// before it has adopted the file: the parse happens on a scratch ZoneData, and
// the answer is what decides whether that scratch zone is published at all.
// Reading the digest off the live zone at that point would answer for the file
// the zone is already serving, which is never the file being considered.
//
// An empty digest is ZoneFileUnknown, like a missing record: it means the
// comparison has no left-hand side, not that the file differs.
func (kdb *KeyDB) CompareZoneFileDigest(zone, digest string) (ZoneFileVerdict, *ZoneFileIdentity, error) {
	if kdb == nil {
		return ZoneFileUnknown, nil, fmt.Errorf("no database")
	}

	prev, have, err := kdb.GetZoneFileState(zone)
	if err != nil {
		return ZoneFileUnknown, nil, err
	}
	if !have {
		return ZoneFileUnknown, nil, nil
	}
	if digest == "" {
		// Nothing to compare against on our side either -- a zone that reached
		// this point without passing the parse site, e.g. a transferred zone.
		return ZoneFileUnknown, prev, nil
	}
	if strings.EqualFold(digest, prev.Digest) {
		return ZoneFileUnchanged, prev, nil
	}
	return ZoneFileChanged, prev, nil
}

// RecordZoneFileState stores the identity of the file as it now stands, both in
// the database and on the zone.
func (zd *ZoneData) RecordZoneFileState(serial uint32, digest string) error {
	if zd == nil || zd.KeyDB == nil {
		return fmt.Errorf("no zone or no database")
	}
	if err := zd.KeyDB.SetZoneFileState(zd.ZoneName, serial, digest); err != nil {
		return err
	}
	zd.mu.Lock()
	zd.fileDigest = digest
	zd.mu.Unlock()
	return nil
}

// ZoneFileVerdict is what comparing the file against its recorded identity says.
type ZoneFileVerdict int

const (
	// ZoneFileUnchanged: the digest matches. The journal was computed against
	// this exact file and replays normally.
	ZoneFileUnchanged ZoneFileVerdict = iota
	// ZoneFileChanged: the digest differs. Someone edited or replaced the file,
	// in a way that changed the zone rather than merely its formatting.
	ZoneFileChanged
	// ZoneFileUnknown: nothing recorded, so there is no basis for comparison.
	// The upgrade case, and the first load of any zone.
	ZoneFileUnknown
)

func (v ZoneFileVerdict) String() string {
	switch v {
	case ZoneFileUnchanged:
		return "unchanged"
	case ZoneFileChanged:
		return "changed"
	default:
		return "unknown"
	}
}
