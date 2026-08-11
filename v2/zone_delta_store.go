/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Phase 2 persistence: the zone FILE remains the source of truth, and the
// database carries the changes that have happened since the file was last
// written. Boot is "parse the file, then replay the deltas"; write-zone/sync/
// freeze folds the deltas into the file and drops them.
//
// This is deliberately NOT the DB-as-source-of-truth model. Nothing here
// stores zone content -- only differences, and only until they reach the file.

const (
	ZoneDeltaDel = "del"
	ZoneDeltaAdd = "add"
)

// ZoneDeltaRR is one record of one delta, in presentation form.
type ZoneDeltaRR struct {
	Action string // ZoneDeltaDel | ZoneDeltaAdd
	RR     string
}

// ZoneDeltaRecord is one published delta: everything that changed between two
// consecutive serials of a zone.
type ZoneDeltaRecord struct {
	FromSerial uint32
	ToSerial   uint32
	RRs        []ZoneDeltaRR
}

// PersistZoneDelta records one published delta for zone.
//
// Deletes are written before adds, matching both IXFR ordering and the order
// the applier itself uses: replacing an RRset is a delete of the old set
// followed by the new records, and replaying those in the other order would
// leave the RRset empty.
//
// An empty delta is not persisted. Serial-only advances (outbound_soa_serial =
// unixtime, for instance) publish with no content change, and recording those
// would grow the table without ever changing a replay's outcome.
func (kdb *KeyDB) PersistZoneDelta(zone string, fromSerial, toSerial uint32, removed, added []core.RRset) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("PersistZoneDelta: no database")
	}
	zone = dns.Fqdn(zone)

	rows := make([]ZoneDeltaRR, 0, len(removed)+len(added))
	for _, rrset := range removed {
		for _, rr := range rrset.RRs {
			rows = append(rows, ZoneDeltaRR{Action: ZoneDeltaDel, RR: rr.String()})
		}
	}
	for _, rrset := range added {
		for _, rr := range rrset.RRs {
			rows = append(rows, ZoneDeltaRR{Action: ZoneDeltaAdd, RR: rr.String()})
		}
	}
	if len(rows) == 0 {
		return nil
	}

	const insertSql = `
INSERT INTO ZoneDelta (zone, fromserial, toserial, seq, action, rr) VALUES (?, ?, ?, ?, ?, ?)`

	tx, err := kdb.Begin("PersistZoneDelta")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	for i, row := range rows {
		if _, err := tx.Exec(insertSql, zone, fromSerial, toSerial, i, row.Action, row.RR); err != nil {
			return fmt.Errorf("PersistZoneDelta: zone %s serial %d->%d: %v",
				zone, fromSerial, toSerial, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("PersistZoneDelta: commit: %v", err)
	}
	committed = true
	return nil
}

// LoadZoneDeltas returns every persisted delta for zone, grouped by delta and
// ordered for replay.
//
// Ordering is by id -- insertion order -- rather than by serial. Serials wrap
// (RFC 1982), so ordering a replay by them would silently misorder the tail of
// a long-lived zone's history.
func (kdb *KeyDB) LoadZoneDeltas(zone string) ([]ZoneDeltaRecord, error) {
	if kdb == nil || kdb.DB == nil {
		return nil, fmt.Errorf("LoadZoneDeltas: no database")
	}
	zone = dns.Fqdn(zone)

	const selectSql = `
SELECT fromserial, toserial, action, rr FROM ZoneDelta WHERE zone=? ORDER BY id ASC`

	rows, err := kdb.DB.Query(selectSql, zone)
	if err != nil {
		return nil, fmt.Errorf("LoadZoneDeltas: %v", err)
	}
	defer rows.Close()

	var out []ZoneDeltaRecord
	for rows.Next() {
		var fromSerial, toSerial uint32
		var action, rr string
		if err := rows.Scan(&fromSerial, &toSerial, &action, &rr); err != nil {
			return nil, fmt.Errorf("LoadZoneDeltas: scan: %v", err)
		}
		// Consecutive rows of the same delta are grouped. They are contiguous
		// because they were inserted contiguously and we are reading in id
		// order.
		if n := len(out); n > 0 && out[n-1].FromSerial == fromSerial && out[n-1].ToSerial == toSerial {
			out[n-1].RRs = append(out[n-1].RRs, ZoneDeltaRR{Action: action, RR: rr})
			continue
		}
		out = append(out, ZoneDeltaRecord{
			FromSerial: fromSerial,
			ToSerial:   toSerial,
			RRs:        []ZoneDeltaRR{{Action: action, RR: rr}},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("LoadZoneDeltas: %v", err)
	}
	return out, nil
}

// DeleteZoneDeltas drops every persisted delta for zone and reports how many
// rows went. Called once the changes have reached the zone file: from that
// point the file already contains them, and replaying would double-apply.
func (kdb *KeyDB) DeleteZoneDeltas(zone string) (int64, error) {
	if kdb == nil || kdb.DB == nil {
		return 0, fmt.Errorf("DeleteZoneDeltas: no database")
	}
	zone = dns.Fqdn(zone)

	res, err := kdb.DB.Exec(`DELETE FROM ZoneDelta WHERE zone=?`, zone)
	if err != nil {
		return 0, fmt.Errorf("DeleteZoneDeltas: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// The delete succeeded; only the count is unavailable.
		return 0, nil
	}
	return n, nil
}

// ZoneDeltaActions turns a persisted delta back into update-section records,
// ready for the applier. Deletes become CLASS=ANY RRset deletes only when the
// delta removed the whole RRset; individual records use CLASS=NONE, which is
// what the applier's ClassNONE branch expects.
func ZoneDeltaActions(rec ZoneDeltaRecord) ([]dns.RR, error) {
	var actions []dns.RR
	for _, row := range rec.RRs {
		rr, err := dns.NewRR(row.RR)
		if err != nil {
			return nil, fmt.Errorf("delta %d->%d: cannot parse %q: %v",
				rec.FromSerial, rec.ToSerial, row.RR, err)
		}
		if rr == nil {
			return nil, fmt.Errorf("delta %d->%d: %q is not a resource record",
				rec.FromSerial, rec.ToSerial, row.RR)
		}
		switch row.Action {
		case ZoneDeltaDel:
			rr.Header().Class = dns.ClassNONE
			rr.Header().Ttl = 0
		case ZoneDeltaAdd:
			rr.Header().Class = dns.ClassINET
		default:
			return nil, fmt.Errorf("delta %d->%d: unknown action %q",
				rec.FromSerial, rec.ToSerial, row.Action)
		}
		actions = append(actions, rr)
	}
	return actions, nil
}
