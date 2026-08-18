/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
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
	// MaxID is the highest ZoneDelta row id belonging to this delta. Used to
	// bound a delete to the deltas a written zone file already contains.
	MaxID int64
}

// PersistZoneDelta records one published delta for zone.
//
// Deletes are written before adds, matching both IXFR ordering and the order
// the applier itself uses: replacing an RRset is a delete of the old set
// followed by the new records, and replaying those in the other order would
// leave the RRset empty.
//
// RRSIGs are deliberately NOT persisted. computeZoneDelta carries signature
// changes in RRset.RRSIGs, and only RRset.RRs is read here.
//
// The reason is validity windows. A stored RRSIG is a signature with a fixed
// inception and expiration; replaying it after a long outage would republish a
// signature that expired while the server was down -- and the longer the
// outage, the more certain that becomes. The applier re-signs added RRsets on
// the replay path, so the signatures are regenerated fresh instead, which is
// correct regardless of how long the gap was.
//
// Two consequences worth knowing:
//
//   - Replay depends on the zone being able to sign, i.e. online-signing or
//     inline-signing. A zone that accepts updates without either was already
//     producing unsigned RRsets when the update was first applied, so replay
//     reproduces that state rather than causing it; ReplayPersistedDeltas warns
//     when it sees the combination.
//
//   - A resign-only change (identical RRs, new RRSIGs) yields no rows at all
//     and is not persisted, so routine re-signing never churns this table.
//
// The apex SOA is likewise absent, because diffOwner strips it for IXFR wire
// framing. That is exactly what we want: the serial is restored explicitly at
// the end of a replay, and a replayed SOA record would fight that.
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

	// A delta must advance the serial, and must not land on one the journal
	// already holds. Both are guarded by UNIQUE (zone, toserial, seq) in the
	// schema -- but a UNIQUE violation reaches the operator as
	//
	//	UNIQUE constraint failed: ZoneDelta.zone, ZoneDelta.toserial, ZoneDelta.seq
	//
	// which names a table and says nothing about the zone, the situation, or
	// what to do. That is what a live zone did report, on every single update,
	// after its journal was left anchored to a file that had been replaced: the
	// zone was serving below the journal's serial range and every publish
	// collided with rows already there.
	//
	// Diagnose it here instead, while we still know which serials are involved
	// and can name the command that inspects them. The constraint stays as the
	// backstop it should have been all along.
	if !serialNewer(toSerial, fromSerial) {
		return fmt.Errorf("PersistZoneDelta: zone %s: refusing to record a delta that does not"+
			" advance the serial (%d -> %d). The journal is anchored to a serial the zone is"+
			" no longer at, which happens when the zone file is replaced behind the server."+
			" Inspect it with `zone journal status`", zone, fromSerial, toSerial)
	}
	if have, err := kdb.zoneDeltaExistsAtSerial(zone, toSerial); err != nil {
		return err
	} else if have {
		return fmt.Errorf("PersistZoneDelta: zone %s: the journal already holds a delta ending at"+
			" serial %d, so this change (%d -> %d) would collide with it. The zone is publishing"+
			" into serials the journal has already used -- inspect it with `zone journal status`",
			zone, toSerial, fromSerial, toSerial)
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
SELECT id, fromserial, toserial, action, rr FROM ZoneDelta WHERE zone=? ORDER BY id ASC`

	rows, err := kdb.DB.Query(selectSql, zone)
	if err != nil {
		return nil, fmt.Errorf("LoadZoneDeltas: %v", err)
	}
	defer rows.Close()

	var out []ZoneDeltaRecord
	for rows.Next() {
		var rowID int64
		var fromSerial, toSerial uint32
		var action, rr string
		if err := rows.Scan(&rowID, &fromSerial, &toSerial, &action, &rr); err != nil {
			return nil, fmt.Errorf("LoadZoneDeltas: scan: %v", err)
		}
		// Consecutive rows of the same delta are grouped. They are contiguous
		// because they were inserted contiguously and we are reading in id
		// order.
		if n := len(out); n > 0 && out[n-1].FromSerial == fromSerial && out[n-1].ToSerial == toSerial {
			out[n-1].RRs = append(out[n-1].RRs, ZoneDeltaRR{Action: action, RR: rr})
			out[n-1].MaxID = rowID
			continue
		}
		out = append(out, ZoneDeltaRecord{
			MaxID:      rowID,
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
		// The delete succeeded; only the count is unavailable. Callers cannot
		// otherwise tell that apart from "no rows deleted", and WriteZone only
		// logs when n > 0, so without this the path is entirely silent.
		lg.Warn("DeleteZoneDeltas: rows deleted but the count is unavailable",
			"zone", zone, "error", err)
		return 0, nil
	}
	return n, nil
}

// DeleteZoneDeltasThroughID drops every delta row up to and including maxID,
// and reports how many went.
//
// Bounded by row id because that is what a caller can capture ATOMICALLY with
// the content it has read. A purge loads the journal, writes what it holds to
// an artefact, and then deletes -- and an update publishing in between persists
// a delta that is not in the artefact. An unbounded delete would remove that
// row too: content destroyed AND unrecorded, which is precisely the failure
// this command exists not to be. Rows created after the snapshot have higher
// ids and survive.
//
// Same reasoning as DeleteZoneDeltasThroughSerial, one layer down: bound the
// delete by what was actually observed, never by a ceiling read separately.
func (kdb *KeyDB) DeleteZoneDeltasThroughID(zone string, maxID int64) (int64, error) {
	if kdb == nil || kdb.DB == nil {
		return 0, fmt.Errorf("DeleteZoneDeltasThroughID: no database")
	}
	if maxID <= 0 {
		return 0, nil
	}
	zone = dns.Fqdn(zone)

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	res, err := kdb.DB.Exec(`DELETE FROM ZoneDelta WHERE zone=? AND id<=?`, zone, maxID)
	if err != nil {
		return 0, fmt.Errorf("DeleteZoneDeltasThroughID: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		lg.Warn("DeleteZoneDeltasThroughID: rows deleted but the count is unavailable",
			"zone", zone, "through_id", maxID, "error", err)
		return 0, nil
	}
	return n, nil
}

// ZoneDeltaActions turns a persisted delta back into update-section records,
// ready for the applier.
//
// EVERY delete becomes a per-record CLASS=NONE delete; nothing here emits
// CLASS=ANY. A journalled RRset removal is stored as one row per record, and
// deleting them individually reaches the same end state, so the RRset case
// needs no separate representation. (The comment here previously claimed a
// CLASS=ANY branch that has never existed, which invited someone to go looking
// for it -- or to add a redundant one.)
//
// The translation itself lives in instructionActions, shared with the
// update-instruction file format: a stored delta and a hand-written
// instruction list are the same thing in two places, and two copies of "del
// means CLASS=NONE, ttl 0" is two chances to fix only one of them.
func ZoneDeltaActions(rec ZoneDeltaRecord) ([]dns.RR, error) {
	return instructionActions(rec.RRs,
		fmt.Sprintf("delta %d->%d", rec.FromSerial, rec.ToSerial))
}

// DeleteZoneDeltasThroughSerial drops every delta whose ToSerial is not newer
// than serial -- i.e. exactly those the freshly written zone file already
// contains -- and leaves anything newer for replay.
//
// Bound by CONTENT, not by time. Reading a row-id ceiling before the write
// leaves a window in which a publish lands in the file while its delta row
// survives the drop; that retained row then starts from a serial the file has
// already passed and fails the chain check on the next load, producing the
// false "the file has been edited or replaced" accusation. "Is this change
// already in the file?" is a question about the file's serial, and answering it
// that way has no window.
//
// Comparison is RFC 1982 serial arithmetic, so a wrapped serial behaves like
// every other serial comparison in this package. That is also why the filter
// cannot be pushed into SQL as `toserial <= ?`.
func (kdb *KeyDB) DeleteZoneDeltasThroughSerial(zone string, serial uint32) (int64, error) {
	if kdb == nil || kdb.DB == nil {
		return 0, fmt.Errorf("DeleteZoneDeltasThroughSerial: no database")
	}

	deltas, err := kdb.LoadZoneDeltas(zone)
	if err != nil {
		return 0, err
	}

	var maxID int64
	for _, d := range deltas {
		if d.ToSerial == serial || !serialNewer(d.ToSerial, serial) {
			if d.MaxID > maxID {
				maxID = d.MaxID
			}
		}
	}
	if maxID == 0 {
		return 0, nil
	}

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	res, err := kdb.DB.Exec(`DELETE FROM ZoneDelta WHERE zone=? AND id<=?`, zone, maxID)
	if err != nil {
		return 0, fmt.Errorf("DeleteZoneDeltasThroughSerial: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		lg.Warn("DeleteZoneDeltasThroughSerial: rows deleted but the count is unavailable",
			"zone", zone, "through_serial", serial, "error", err)
		return 0, nil
	}
	return n, nil
}

// zoneDeltaExistsAtSerial reports whether the journal already holds a delta
// ending at toSerial. Exact equality, not serial arithmetic: this asks about
// the UNIQUE key, which is an exact-match index.
func (kdb *KeyDB) zoneDeltaExistsAtSerial(zone string, toSerial uint32) (bool, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var one int
	err := kdb.DB.QueryRow(
		`SELECT 1 FROM ZoneDelta WHERE zone=? AND toserial=? LIMIT 1`, zone, toSerial).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("PersistZoneDelta: checking for an existing delta at serial %d: %v",
			toSerial, err)
	}
	return true, nil
}

// TruncateZoneDeltasAfterSerial drops the tail of a zone's journal, keeping
// the chain up to and including the delta that ends at serial.
//
// A journal is a chain, and that constrains what may be removed from it. Every
// delta's FromSerial is its predecessor's ToSerial, and replay refuses a chain
// with a gap -- so dropping a delta from the MIDDLE would leave a journal that
// can never be replayed again. Only a suffix can go. That is what this does,
// and it is why there is no "delete this one record from the journal": the way
// to correct a log is to append a correction, which here means an ordinary
// zone update that undoes the record.
//
// serial must name a delta that actually exists, rather than being any old
// number the tail is measured from. "Keep everything up to 2026081704" is
// unambiguous when that is a real boundary in the chain and a guess otherwise,
// and guessing here silently discards changes.
func (kdb *KeyDB) TruncateZoneDeltasAfterSerial(zone string, serial uint32) (int64, error) {
	if kdb == nil || kdb.DB == nil {
		return 0, fmt.Errorf("TruncateZoneDeltasAfterSerial: no database")
	}
	zone = dns.Fqdn(zone)

	deltas, err := kdb.LoadZoneDeltas(zone)
	if err != nil {
		return 0, err
	}
	if len(deltas) == 0 {
		return 0, nil
	}

	keepThrough := int64(-1)
	var available []uint32
	for _, d := range deltas {
		available = append(available, d.ToSerial)
		if d.ToSerial == serial {
			keepThrough = d.MaxID
		}
	}
	if keepThrough < 0 {
		return 0, fmt.Errorf("zone %s: no journal delta ends at serial %d;"+
			" the chain's boundaries are %v", zone, serial, available)
	}

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	res, err := kdb.DB.Exec(`DELETE FROM ZoneDelta WHERE zone=? AND id>?`, zone, keepThrough)
	if err != nil {
		return 0, fmt.Errorf("TruncateZoneDeltasAfterSerial: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		lg.Warn("TruncateZoneDeltasAfterSerial: rows deleted but the count is unavailable",
			"zone", zone, "after_serial", serial, "error", err)
		return 0, nil
	}
	return n, nil
}

// LastZoneDeltaSerial returns the ToSerial of the most recently stored delta
// for zone, and whether there is one at all.
//
// This is what a new delta chains from. Chaining from the last published serial
// instead looks equivalent and is not: a zone that re-signs or republishes
// during load advances its published serial well past the serial its FILE
// carries, so the first change after a load would be journalled as starting
// from a serial the file has never had. The next load then reads the file,
// compares it against that base, finds a mismatch, and refuses the whole
// journal -- losing every change and reporting the file as tampered with.
//
// Anchoring the first delta to the file (ZoneData.fileSerial) and every
// subsequent one to the journal's own tail makes the chain continuous by
// construction, from a base the next load will actually see.
func (kdb *KeyDB) LastZoneDeltaSerial(zone string) (uint32, bool, error) {
	if kdb == nil || kdb.DB == nil {
		return 0, false, fmt.Errorf("LastZoneDeltaSerial: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var toSerial sql.NullInt64
	err := kdb.DB.QueryRow(
		`SELECT toserial FROM ZoneDelta WHERE zone=? ORDER BY id DESC LIMIT 1`, zone).Scan(&toSerial)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("LastZoneDeltaSerial: %v", err)
	}
	if !toSerial.Valid {
		return 0, false, nil
	}
	return uint32(toSerial.Int64), true, nil
}

// ReplaceZoneJournal atomically swaps a zone's whole journal for a single
// delta. Used by the merge: after reconciling with a replaced zone file, the
// old chain describes a file that no longer exists, and the one delta that
// matters is "the difference between the file in hand and what is now served".
//
// One transaction, because the intermediate state -- old chain gone, new delta
// not yet written -- is a zone with no record of its unwritten changes at all.
// A crash there would lose them.
func (kdb *KeyDB) ReplaceZoneJournal(zone string, fromSerial, toSerial uint32,
	removed, added []core.RRset) error {

	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("ReplaceZoneJournal: no database")
	}
	if !serialNewer(toSerial, fromSerial) {
		return fmt.Errorf("ReplaceZoneJournal: zone %s: %d -> %d does not advance the serial",
			zone, fromSerial, toSerial)
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

	tx, err := kdb.Begin("ReplaceZoneJournal")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	if _, err := tx.Exec(`DELETE FROM ZoneDelta WHERE zone=?`, zone); err != nil {
		return fmt.Errorf("ReplaceZoneJournal: clearing the old chain: %v", err)
	}

	const insertSql = `
INSERT INTO ZoneDelta (zone, fromserial, toserial, seq, action, rr) VALUES (?, ?, ?, ?, ?, ?)`
	for i, row := range rows {
		if _, err := tx.Exec(insertSql, zone, fromSerial, toSerial, i, row.Action, row.RR); err != nil {
			return fmt.Errorf("ReplaceZoneJournal: zone %s serial %d->%d: %v",
				zone, fromSerial, toSerial, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ReplaceZoneJournal: commit: %v", err)
	}
	committed = true
	return nil
}
