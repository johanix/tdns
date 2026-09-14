package tdns

import (
	"testing"
)

// T1a.1: every state x role gives the pub and sign of the design's §3.4
// tables, and ds stays unset in S1a. The expectations are written out here
// rather than read from the code's table, so a wrong table fails.
var wantKeyFlags = map[string]struct{ pub, sign bool }{
	DnskeyStateCreated:     {false, false},
	DnskeyStateDsPublished: {false, false},
	DnskeyStatePublished:   {true, false},
	DnskeyStateStandby:     {true, false},
	DnskeyStateActive:      {true, true},
	DnskeyStateRetired:     {true, false},
	DnskeyStateRemoved:     {false, false},
	DnskeyStateMpdist:      {true, false},
	DnskeyStateForeign:     {true, false},
	DnskeyStateMpremove:    {false, false},
}

func TestKeyFlagsTableFollowsTheDesign(t *testing.T) {
	for state, want := range wantKeyFlags {
		f, ok := keyFlagsForState(state)
		if !ok {
			t.Errorf("state %q: not in the flag table", state)
			continue
		}
		if f.Pub != want.pub || f.Sign != want.sign {
			t.Errorf("state %q: pub=%v sign=%v, want pub=%v sign=%v", state, f.Pub, f.Sign, want.pub, want.sign)
		}
		if f.DS.Valid {
			t.Errorf("state %q: ds is set (%v); S1a leaves it unset", state, f.DS.Bool)
		}
	}
	if _, ok := keyFlagsForState("no-such-state"); ok {
		t.Error("an unknown state is in the flag table")
	}
}

// The same table, through the write function: a row inserted with only a
// state carries the flags of that state, whatever its role.
func TestInsertedRowsCarryTheFlagsOfTheirState(t *testing.T) {
	kdb := newTestKeyDB(t)
	rng := newTestRand(1)
	const zone = "flags.example."
	for _, state := range keyStatesForRowTests {
		for _, role := range keyRolesForRowTests {
			keyid := insertTestKeyRow(t, kdb, zone, state, role, rng)
			pub, sign, ds := readKeyRowFlags(t, kdb, zone, keyid)
			want := wantKeyFlags[state]
			if flagString(pub) != boolFlag(want.pub) || flagString(sign) != boolFlag(want.sign) {
				t.Errorf("%s %s: pub=%s sign=%s, want pub=%s sign=%s", state, role, flagString(pub), flagString(sign), boolFlag(want.pub), boolFlag(want.sign))
			}
			if ds != nil {
				t.Errorf("%s %s: ds=%s, want NULL", state, role, flagString(ds))
			}
		}
	}
}

func boolFlag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// The state writer sets the flags of the new state in the same statement.
func TestStateWriteSetsTheNewStatesFlags(t *testing.T) {
	kdb := newTestKeyDB(t)
	rng := newTestRand(2)
	const zone = "transition.example."
	keyid := insertTestKeyRow(t, kdb, zone, DnskeyStatePublished, "ZSK", rng)
	for _, next := range []string{DnskeyStateStandby, DnskeyStateActive, DnskeyStateRetired, DnskeyStateRemoved} {
		tx, err := kdb.Begin("test")
		if err != nil {
			t.Fatal(err)
		}
		f, _ := keyFlagsForState(next)
		if _, err := setKeyRowTx(tx, zone, keyid, next, f, ""); err != nil {
			tx.Rollback()
			t.Fatalf("to %s: %v", next, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		pub, sign, _ := readKeyRowFlags(t, kdb, zone, keyid)
		want := wantKeyFlags[next]
		if flagString(pub) != boolFlag(want.pub) || flagString(sign) != boolFlag(want.sign) {
			t.Errorf("after %s: pub=%s sign=%s, want %s/%s", next, flagString(pub), flagString(sign), boolFlag(want.pub), boolFlag(want.sign))
		}
	}
}

// expectOld is a compare-and-set: a stale expectation writes nothing.
func TestStateWriteRefusesAStaleExpectation(t *testing.T) {
	kdb := newTestKeyDB(t)
	rng := newTestRand(3)
	const zone = "cas.example."
	keyid := insertTestKeyRow(t, kdb, zone, DnskeyStateStandby, "KSK", rng)
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	f, _ := keyFlagsForState(DnskeyStateActive)
	if _, err := setKeyRowTx(tx, zone, keyid, DnskeyStateActive, f, DnskeyStatePublished); err == nil {
		t.Error("a write expecting the wrong old state succeeded")
	}
	tx.Rollback()
	var state string
	if err := kdb.DB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, keyid).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != DnskeyStateStandby {
		t.Errorf("state changed to %q under a stale expectation", state)
	}
}
