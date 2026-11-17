/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The KSK rollover target: which keys the parent should hold a DS for, and
 * the DS and CDS RRsets derived from them. No network I/O. The delivery to
 * the parent is the delegation syncher's (delsync_ds.go, SYNC-DS).
 */
package tdns

import (
	"database/sql"
	"fmt"

	"github.com/miekg/dns"
)

type kskForDSRow struct {
	keyid uint16
	flags uint16
	keyrr string
	ri    sql.NullInt64
}

// RolloverTargetKeySnapshot is the keystore-load result the DS delivery
// works from: the rollover engine takes it once when it decides to push and
// hands it to the syncher, so that UPDATE, NOTIFY and API all describe the
// same key set however the keystore moves meanwhile. Read-only after
// construction.
type RolloverTargetKeySnapshot struct {
	Rows            []kskForDSRow
	IndexLow        int
	IndexHigh       int
	IndexRangeKnown bool
}

// loadTargetKSKsForRollover is the canonical SQL query for "the keys
// belonging in the rollover-target DS RRset": one row per KSK (SEP) whose ds
// column is 1, which under multi-DS is every state from created through
// retired (created is included for the multi-DS pre-publish DS at the
// parent). ComputeTargetDSSetForZone (DS) and ComputeTargetCDSSetForZone
// (CDS) both derive their set from these rows; if they diverged, a
// NOTIFY-pushed CDS would not match an UPDATE-pushed DS.
//
// indexLow/indexHigh are min/max rollover_index when every contributing key
// has a RolloverKeyState row; otherwise indexRangeKnown is false and callers
// must not treat the indices as authoritative.
func loadTargetKSKsForRollover(kdb *KeyDB, childZone string) (rows []kskForDSRow, indexLow, indexHigh int, indexRangeKnown bool, err error) {
	childZone = dns.Fqdn(childZone)
	const q = `
SELECT k.keyid, k.flags, k.keyrr, r.rollover_index
FROM DnssecKeyStore k
LEFT JOIN RolloverKeyState r ON k.zonename = r.zone AND k.keyid = r.keyid
WHERE k.zonename = ? AND k.ds = 1
  AND (CAST(k.flags AS INTEGER) & ?) != 0
ORDER BY COALESCE(r.rollover_index, 2147483646) ASC, k.keyid ASC`

	sqlRows, err := kdb.Query(q, childZone, int(dns.SEP))
	if err != nil {
		return nil, 0, 0, false, fmt.Errorf("loadTargetKSKsForRollover: %w", err)
	}
	defer sqlRows.Close()

	for sqlRows.Next() {
		var keyid, flags int
		var keyrr string
		var ri sql.NullInt64
		if err := sqlRows.Scan(&keyid, &flags, &keyrr, &ri); err != nil {
			return nil, 0, 0, false, fmt.Errorf("loadTargetKSKsForRollover scan: %w", err)
		}
		rows = append(rows, kskForDSRow{
			keyid: uint16(keyid),
			flags: uint16(flags),
			keyrr: keyrr,
			ri:    ri,
		})
	}
	if err := sqlRows.Err(); err != nil {
		return nil, 0, 0, false, err
	}
	sqlRows.Close()

	// An in-flight KSK algorithm rollover keeps its old-algorithm head
	// ACTIVE through the drain (plan A2), but the parent must stop
	// serving that key's DS before the head leaves the DNSKEY RRset
	// (RFC 6781 section 4.1.4, plan A4): a validator that supports the old
	// algorithm but not the new one holds DS {A,B} and, once A is gone
	// from the child, has no supported path, which is bogus, where DS {B}
	// alone would have made it insecure. So the target set is the set
	// above minus the roll's old head, from the spawn on: the push that
	// follows the D-7 wait swaps DS(A) for DS(B) in one step, and the
	// drain then covers the parent DS TTL before A is withdrawn. Once
	// the roll is cleared (completion, or an abort) the old head is a
	// plain active key again and, if still present, returns to the set,
	// which is what lets an abort push DS(A) back.
	zrow, zerr := LoadRolloverZoneRow(kdb, childZone)
	if zerr != nil {
		// Fail closed: without the row the old head cannot be filtered,
		// and a push with {DS(A), DS(B)} is the order A4 exists to prevent.
		return nil, 0, 0, false, fmt.Errorf("loadTargetKSKsForRollover: read rollover state for %s: %w", childZone, zerr)
	}
	algRoll, aerr := kskAlgRollFromRow(zrow)
	if aerr != nil {
		return nil, 0, 0, false, fmt.Errorf("loadTargetKSKsForRollover: %w", aerr)
	}
	if algRoll != nil {
		kept := rows[:0]
		for _, row := range rows {
			if row.keyid != algRoll.OldHeadKeyID {
				kept = append(kept, row)
			}
		}
		rows = kept
	}

	indexRangeKnown = len(rows) > 0
	for _, row := range rows {
		if !row.ri.Valid {
			indexRangeKnown = false
			break
		}
	}

	if indexRangeKnown {
		for i, row := range rows {
			v := int(row.ri.Int64)
			if i == 0 {
				indexLow, indexHigh = v, v
			} else {
				if v < indexLow {
					indexLow = v
				}
				if v > indexHigh {
					indexHigh = v
				}
			}
		}
	}
	return rows, indexLow, indexHigh, indexRangeKnown, nil
}

// loadRolloverTargetSnapshot takes the snapshot of the rollover target the DS
// delivery works from.
func loadRolloverTargetSnapshot(kdb *KeyDB, childZone string) (*RolloverTargetKeySnapshot, error) {
	rows, low, high, idxOK, err := loadTargetKSKsForRollover(kdb, dns.Fqdn(childZone))
	if err != nil {
		return nil, err
	}
	return &RolloverTargetKeySnapshot{
		Rows:            rows,
		IndexLow:        low,
		IndexHigh:       high,
		IndexRangeKnown: idxOK,
	}, nil
}

// dsSetFromSnapshot derives the DS RRset from a snapshot of the target keys.
// Digest is SHA-256 only in this phase. DS owner names use child as FQDN; the
// TTL is the policy's DS TTL when one is set.
func dsSetFromSnapshot(snap *RolloverTargetKeySnapshot, childZone string, digest uint8, pol *DnssecPolicy) ([]dns.RR, error) {
	childZone = dns.Fqdn(childZone)
	out := make([]dns.RR, 0, len(snap.Rows))
	for _, row := range snap.Rows {
		rr, err := dns.NewRR(row.keyrr)
		if err != nil {
			return nil, fmt.Errorf("dsSetFromSnapshot: parse DNSKEY keyid=%d: %w", row.keyid, err)
		}
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, fmt.Errorf("dsSetFromSnapshot: keyid %d is not DNSKEY", row.keyid)
		}
		ds := dk.ToDS(digest)
		if ds == nil {
			return nil, fmt.Errorf("dsSetFromSnapshot: ToDS failed for keyid %d", row.keyid)
		}
		ds.Hdr.Name = childZone
		applyChildDSFallbackTTL(&ds.Hdr, pol)
		out = append(out, ds)
	}
	return out, nil
}

// cdsSetFromSnapshot is the CDS counterpart of dsSetFromSnapshot, for the DS
// engine's publication of the rollover target's CDS. CDS owner names use
// child as FQDN; TTL is 120s to match ops_cds.go.
func cdsSetFromSnapshot(snap *RolloverTargetKeySnapshot, childZone string) ([]dns.RR, int, int, bool, error) {
	childZone = dns.Fqdn(childZone)
	out := make([]dns.RR, 0, len(snap.Rows))
	for _, row := range snap.Rows {
		rr, err := dns.NewRR(row.keyrr)
		if err != nil {
			return nil, 0, 0, false, fmt.Errorf("cdsSetFromSnapshot: parse DNSKEY keyid=%d: %w", row.keyid, err)
		}
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, 0, 0, false, fmt.Errorf("cdsSetFromSnapshot: keyid %d is not DNSKEY", row.keyid)
		}
		ds := dk.ToDS(uint8(dns.SHA256))
		if ds == nil {
			return nil, 0, 0, false, fmt.Errorf("cdsSetFromSnapshot: ToDS failed for keyid %d", row.keyid)
		}
		c := &dns.CDS{DS: *ds}
		c.Hdr = dns.RR_Header{
			Name:   childZone,
			Rrtype: dns.TypeCDS,
			Class:  dns.ClassINET,
			Ttl:    120,
		}
		out = append(out, c)
	}
	return out, snap.IndexLow, snap.IndexHigh, snap.IndexRangeKnown, nil
}

// ComputeTargetDSSetForZone returns the DS RRset the parent should publish for
// this child: one DS per KSK (SEP) whose ds column is 1. The state machine
// writes ds by the zone's DS model (keyrow_ds.go): under multi-DS from created
// through retired, and 0 for the old-algorithm head of an in-flight KSK
// algorithm rollover, which loadTargetKSKsForRollover also filters out on its
// own.
//
// Digest is SHA-256 only in this phase. DS owner names use child as FQDN.
// indexLow/indexHigh are min/max rollover_index when every contributing key
// has a RolloverKeyState row; otherwise indexRangeKnown is false and callers
// must not treat the indices as authoritative for RolloverZoneState.
func ComputeTargetDSSetForZone(kdb *KeyDB, childZone string, digest uint8, pol *DnssecPolicy) (ds []dns.RR, indexLow, indexHigh int, indexRangeKnown bool, err error) {
	snap, err := loadRolloverTargetSnapshot(kdb, childZone)
	if err != nil {
		return nil, 0, 0, false, err
	}
	ds, err = dsSetFromSnapshot(snap, childZone, digest, pol)
	if err != nil {
		return nil, 0, 0, false, err
	}
	return ds, snap.IndexLow, snap.IndexHigh, snap.IndexRangeKnown, nil
}

// ComputeTargetCDSSetForZone returns the CDS RRset that mirrors the rollover
// target's DS set, derived from the same KSK rows ComputeTargetDSSetForZone
// uses, so an UPDATE-pushed DS RRset and a NOTIFY-pushed CDS RRset always
// describe the same keys.
//
// indexLow/indexHigh and indexRangeKnown are the rollover's claim of
// CDS-RRset ownership for cleanup-time comparison
// (RolloverZoneState.last_published_cds_index_low/high). When not every
// contributing key has a RolloverKeyState row, indexRangeKnown is false and
// the caller must not persist the range.
func ComputeTargetCDSSetForZone(kdb *KeyDB, childZone string) (cds []dns.RR, indexLow, indexHigh int, indexRangeKnown bool, err error) {
	snap, err := loadRolloverTargetSnapshot(kdb, childZone)
	if err != nil {
		return nil, 0, 0, false, err
	}
	return cdsSetFromSnapshot(snap, childZone)
}
