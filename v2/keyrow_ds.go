/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/miekg/dns"
)

// The ds column for the zones tdns owns (design §3.4, amended 2026-09-14):
// whether a key should have a DS at the parent, by the zone's DS model and
// the key's state. Written by tdns's own state machine at its transitions;
// NULL, "unknown", wherever tdns has no say. A reader that finds NULL on a
// SEP row leaves the parent alone.
//
// KSK, by model:
//
//	state         multi-DS   none / double-signature
//	created           1           0      (multi-DS pushes the DS before the DNSKEY)
//	ds-published      1           1      (its DS was placed)
//	published         1           0      (tdns #635: no DS for a published key)
//	standby           1           1
//	active            1           1      (the algorithm rollover's old head: 0)
//	retired           1           0      (multi-DS keeps it until the withdraw phase)
//	removed           0           0
//
// A ZSK is 0 in every state. The three multi-provider states, and every key
// of a multi-provider zone, stay NULL until the owner writes them (S3).

// DsDifference is one place where the ds column, as the one-time pass fills
// it, disagrees with what the code before the column derived from the state
// (dsBelongsAtParent). Kind names the allowed difference; anything else is a
// defect.
type DsDifference struct {
	KeyID uint16
	State string
	Kind  string
}

const (
	// DsDiffPublishedOutsideMultiDS: a published KSK outside multi-DS counted
	// as having its DS before (tdns #635); it has none.
	DsDiffPublishedOutsideMultiDS = "published-ksk-outside-multi-ds"
	// DsDiffAlgRollOldHead: the old head of an in-flight algorithm rollover
	// is active but must have no DS.
	DsDiffAlgRollOldHead = "alg-roll-old-head"
	// DsDiffMultiDSCreated and DsDiffMultiDSRetired: under multi-DS the old
	// intent reader never applied; the rollover target counted created and
	// retired keys as DS-bearing, and so does the column.
	DsDiffMultiDSCreated = "multi-ds-created"
	DsDiffMultiDSRetired = "multi-ds-retired"
)

// DsFillReport is what the one-time pass did for one zone.
type DsFillReport struct {
	Zone        string
	Filled      int // rows that had ds unset and got it
	Changed     int // rows rewritten by a refresh after a DS model change
	Differences []DsDifference
}

// tdnsOwnKeyStates are the states tdns's own state machine moves keys
// through; the column is defined for them only.
var tdnsOwnKeyStates = map[string]bool{
	DnskeyStateCreated: true, DnskeyStateDsPublished: true, DnskeyStatePublished: true,
	DnskeyStateStandby: true, DnskeyStateActive: true, DnskeyStateRetired: true,
	DnskeyStateRemoved: true,
}

// dsFlagFor is the ds column of a tdns zone's key by DS model, state and SEP
// bit. Not Valid means tdns has no say: a multi-provider zone, or a state an
// owner stages.
func dsFlagFor(model DSModel, state string, sep bool) sql.NullBool {
	if model == DSModelMultiProvider || !tdnsOwnKeyStates[state] {
		return sql.NullBool{}
	}
	if !sep {
		return sql.NullBool{Bool: false, Valid: true}
	}
	multi := model == DSModelMultiDS
	var ds bool
	switch state {
	case DnskeyStateCreated, DnskeyStatePublished, DnskeyStateRetired:
		ds = multi
	case DnskeyStateDsPublished, DnskeyStateStandby, DnskeyStateActive:
		ds = true
	}
	return sql.NullBool{Bool: ds, Valid: true}
}

// dsModelForKeyWrite is the model a writer resolves ds with. Known for a
// loaded zone with a policy bound; a multi-provider zone answers with its
// model, which dsFlagFor turns into "no say".
func dsModelForKeyWrite(zone string) (DSModel, bool) {
	zd, ok := Zones.Get(dns.Fqdn(zone))
	if !ok || zd == nil {
		return DSModelNone, false
	}
	if zd.Options[OptMultiProvider] {
		return DSModelMultiProvider, true
	}
	if zd.DnssecPolicy == nil {
		return DSModelNone, false
	}
	return dsModelForZone(zd), true
}

// algRollOldHeadTx is the old head of an in-flight KSK algorithm rollover,
// read on the caller's transaction; 0 when no roll is in flight.
func algRollOldHeadTx(tx *Tx, zone string) (uint16, error) {
	var from, old sql.NullInt64
	err := tx.QueryRow(`SELECT alg_roll_from_alg, alg_roll_old_head_keyid FROM RolloverZoneState WHERE zone = ?`, zone).Scan(&from, &old)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !from.Valid || !old.Valid {
		return 0, nil
	}
	return uint16(old.Int64), nil
}

// dsForKeyTx resolves ds for one row on the caller's transaction: the zone's
// model and the key's SEP bit through dsFlagFor, and 0 for the old head of
// an in-flight algorithm rollover. Not Valid when tdns has no say, or when
// the zone is not loaded with a policy yet; the one-time pass fills it then.
// The two write functions call it for every row whose caller left ds open.
func dsForKeyTx(tx *Tx, zone string, keyid uint16, state string, flags uint16) (sql.NullBool, error) {
	model, known := dsModelForKeyWrite(zone)
	if !known {
		return sql.NullBool{}, nil
	}
	ds := dsFlagFor(model, state, flags&dns.SEP != 0)
	if !ds.Valid || !ds.Bool {
		return ds, nil
	}
	oldHead, err := algRollOldHeadTx(tx, dns.Fqdn(zone))
	if err != nil {
		return sql.NullBool{}, fmt.Errorf("read the algorithm-roll state of %s: %w", zone, err)
	}
	if oldHead != 0 && oldHead == keyid {
		ds.Bool = false
	}
	return ds, nil
}

// refreshKeyRowFlagsTx rewrites a row's flags from its state and the zone's
// model without changing the state. The algorithm rollover uses it on the
// old head: once the roll is recorded ds resolves to 0, and once an abort
// has cleared the roll, back to what the model says.
func refreshKeyRowFlagsTx(tx *Tx, zone string, keyid uint16) error {
	var state string
	if err := tx.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, keyid).Scan(&state); err != nil {
		return fmt.Errorf("read key %d of %s: %w", keyid, zone, err)
	}
	f, ok := keyFlagsForState(state)
	if !ok {
		return fmt.Errorf("key %d of %s is in state %q, which has no flags", keyid, zone, state)
	}
	_, err := setKeyRowTx(tx, zone, keyid, state, f, state)
	return err
}

// FillDsForZone fills ds for the zone's rows that have it unset, per the
// zone's model, once its policy is known. NULL-gated: rows that carry ds keep
// it. Reports what it filled and where the column disagrees with what the
// code before it derived from the state (dsBelongsAtParent). A
// multi-provider zone gets nothing from tdns.
func (kdb *KeyDB) FillDsForZone(zd *ZoneData) (DsFillReport, error) {
	return kdb.fillDsForZone(zd, false)
}

// RefreshDsForZone re-resolves ds for every row of the zone in one of tdns's
// own states, unset or not: what a bind of a policy with another DS model
// needs, since the rows written under the old model carry its answers and
// no transition rewrites them (a published KSK is 1 under multi-DS and 0
// under none). Rows in an owner's states are not touched.
func (kdb *KeyDB) RefreshDsForZone(zd *ZoneData) (DsFillReport, error) {
	return kdb.fillDsForZone(zd, true)
}

func (kdb *KeyDB) fillDsForZone(zd *ZoneData, force bool) (DsFillReport, error) {
	rep := DsFillReport{Zone: zd.ZoneName}
	if zd.Options[OptMultiProvider] || zd.DnssecPolicy == nil {
		return rep, nil
	}
	model := dsModelForZone(zd)
	zone := dns.Fqdn(zd.ZoneName)
	var oldHead uint16
	if st, err := LoadKskAlgRollState(kdb, zone); err != nil {
		return rep, fmt.Errorf("FillDsForZone: read the rollover state of %s: %w", zone, err)
	} else if st != nil {
		oldHead = st.OldHeadKeyID
	}
	rows, err := kdb.DB.Query(`SELECT keyid, state, flags, ds FROM DnssecKeyStore WHERE zonename=? AND (ds IS NULL OR ? = 1) ORDER BY keyid`, zone, boolInt(force))
	if err != nil {
		return rep, fmt.Errorf("FillDsForZone: read %s: %w", zone, err)
	}
	type todo struct {
		keyid uint16
		state string
		sep   bool
		had   sql.NullInt64
		ds    sql.NullBool
	}
	var todos []todo
	for rows.Next() {
		var keyid, flags int
		var state string
		var had sql.NullInt64
		if err := rows.Scan(&keyid, &state, &flags, &had); err != nil {
			rows.Close()
			return rep, err
		}
		sep := flags&int(dns.SEP) != 0
		ds := dsFlagFor(model, state, sep)
		if ds.Valid && ds.Bool && uint16(keyid) == oldHead {
			ds.Bool = false
		}
		todos = append(todos, todo{uint16(keyid), state, sep, had, ds})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return rep, err
	}
	if len(todos) == 0 {
		return rep, nil
	}
	tx, err := kdb.Begin("FillDsForZone")
	if err != nil {
		return rep, err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	for _, td := range todos {
		if !td.ds.Valid {
			continue
		}
		if td.had.Valid {
			// A refresh: rewrite only what the model changes.
			if (td.had.Int64 != 0) == td.ds.Bool {
				continue
			}
			if _, err := tx.Exec(`UPDATE DnssecKeyStore SET ds=? WHERE zonename=? AND keyid=?`, boolInt(td.ds.Bool), zone, td.keyid); err != nil {
				return rep, fmt.Errorf("RefreshDsForZone: %s keyid %d: %w", zone, td.keyid, err)
			}
			rep.Changed++
			continue
		}
		if _, err := tx.Exec(`UPDATE DnssecKeyStore SET ds=? WHERE zonename=? AND keyid=? AND ds IS NULL`, boolInt(td.ds.Bool), zone, td.keyid); err != nil {
			return rep, fmt.Errorf("FillDsForZone: %s keyid %d: %w", zone, td.keyid, err)
		}
		rep.Filled++
		if !td.sep {
			continue
		}
		old, _ := dsBelongsAtParent(td.state)
		if old == td.ds.Bool {
			continue
		}
		kind := "unexpected"
		switch {
		case td.keyid == oldHead && old && !td.ds.Bool:
			kind = DsDiffAlgRollOldHead
		case model != DSModelMultiDS && td.state == DnskeyStatePublished && old && !td.ds.Bool:
			kind = DsDiffPublishedOutsideMultiDS
		case model == DSModelMultiDS && td.state == DnskeyStateCreated && !old && td.ds.Bool:
			kind = DsDiffMultiDSCreated
		case model == DSModelMultiDS && td.state == DnskeyStateRetired && !old && td.ds.Bool:
			kind = DsDiffMultiDSRetired
		}
		rep.Differences = append(rep.Differences, DsDifference{KeyID: td.keyid, State: td.state, Kind: kind})
	}
	if err := tx.Commit(); err != nil {
		return rep, err
	}
	committed = true
	for _, d := range rep.Differences {
		lg := lgSigner.Info
		if d.Kind == "unexpected" {
			lg = lgSigner.Error
		}
		lg("ds column: the one-time pass disagrees with the state-derived DS intent",
			"zone", zone, "keyid", d.KeyID, "state", d.State, "kind", d.Kind)
	}
	return rep, nil
}

// dsModelOfPolicy is the DS model a policy's rollover method implies.
func dsModelOfPolicy(pol *DnssecPolicy) DSModel {
	if pol == nil {
		return DSModelNone
	}
	switch pol.Rollover.Method {
	case RolloverMethodMultiDS:
		return DSModelMultiDS
	case RolloverMethodDoubleSignature:
		return DSModelDoubleSignature
	}
	return DSModelNone
}

// reconcileDsAfterBind runs after a policy is bound to a zone: rows with ds
// unset get it, and if the bind changed the zone's DS model, every row in
// one of tdns's own states is re-resolved, since the rows written under the
// old model carry its answers and nothing else rewrites them. oldPol is the
// policy bound before, nil for a first bind.
func reconcileDsAfterBind(kdb *KeyDB, zd *ZoneData, oldPol *DnssecPolicy) {
	if kdb == nil || zd == nil || zd.Options[OptMultiProvider] || zd.DnssecPolicy == nil {
		return
	}
	changed := oldPol != nil && dsModelOfPolicy(oldPol) != dsModelOfPolicy(zd.DnssecPolicy)
	rep, err := kdb.fillDsForZone(zd, changed)
	if err != nil {
		lgSigner.Error("ds column: the pass after the policy bind failed", "zone", zd.ZoneName, "err", err)
		return
	}
	if changed {
		lgSigner.Info("ds column: the DS model changed with the policy; rows re-resolved",
			"zone", zd.ZoneName, "from", dsModelOfPolicy(oldPol).String(), "to", dsModelForZone(zd).String(), "changed", rep.Changed, "filled", rep.Filled)
	} else if rep.Filled > 0 {
		lgSigner.Info("ds column: filled from the zone's DS model", "zone", zd.ZoneName, "rows", rep.Filled, "model", dsModelForZone(zd).String())
	}
}

// fillDsForPolicyZones runs the one-time pass over every loaded zone with a
// policy bound. Cheap when there is nothing to do: one count per zone. Stops
// between zones when the worker's context ends.
func fillDsForPolicyZones(ctx context.Context, kdb *KeyDB) {
	for _, zd := range Zones.Items() {
		if ctx.Err() != nil {
			return
		}
		if zd.DnssecPolicy == nil || zd.Options[OptMultiProvider] {
			continue
		}
		var n int
		if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND ds IS NULL`, dns.Fqdn(zd.ZoneName)).Scan(&n); err != nil || n == 0 {
			continue
		}
		reconcileDsAfterBind(kdb, zd, nil)
	}
}
