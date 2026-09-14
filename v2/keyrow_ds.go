/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
	"errors"
)

// The ds column for the zones tdns owns (design §3.4, amended 2026-09-14):
// whether a key should have a DS at the parent, by the zone's DS model and
// the key's state. Written by tdns's own state machine at its transitions;
// NULL, "unknown", wherever tdns has no say.

// DsDifference is one place where the ds column, as the one-time pass fills
// it, disagrees with what the code before the column derived from the state.
// Kind names the allowed difference; anything else is a defect.
type DsDifference struct {
	KeyID uint16
	Kind  string
}

const (
	// DsDiffPublishedOutsideMultiDS: a published KSK outside multi-DS counted
	// as having its DS before (tdns #635); it has none.
	DsDiffPublishedOutsideMultiDS = "published-ksk-outside-multi-ds"
	// DsDiffAlgRollOldHead: the old head of an in-flight algorithm rollover
	// is active but must have no DS.
	DsDiffAlgRollOldHead = "alg-roll-old-head"
)

// DsFillReport is what the one-time pass did for one zone.
type DsFillReport struct {
	Zone        string
	Filled      int
	Differences []DsDifference
}

var errDsNotImplemented = errors.New("the ds column is not written yet")

// dsFlagFor is the ds column of a tdns zone's key by DS model, state and SEP
// bit. Not Valid means tdns has no say: a multi-provider zone, or a state an
// owner stages.
func dsFlagFor(model DSModel, state string, sep bool) sql.NullBool { return sql.NullBool{} }

// FillDsForZone fills ds for the zone's rows that have it unset, per the
// zone's model, once its policy is known. NULL-gated: rows that carry ds keep
// it. Reports what it filled and where the column disagrees with the state.
func (kdb *KeyDB) FillDsForZone(zd *ZoneData) (DsFillReport, error) {
	return DsFillReport{}, errDsNotImplemented
}
