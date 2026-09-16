package tdns

import (
	"database/sql"
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

// A write that leaves the state as it is keeps the timestamp the row has:
// "setstate published" on a published key does not restart its propagation
// clock. An empty one is still filled, which is how a legacy key without
// published_at gets one.
func TestSameStateWriteKeepsAnExistingTimestamp(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "restamp.example."
	keyid := insertTestKeyRow(t, kdb, zone, DnskeyStateCreated, "ZSK", newTestRand(31))
	write := func(state string) {
		t.Helper()
		tx, err := kdb.Begin("test")
		if err != nil {
			t.Fatal(err)
		}
		f, _ := keyFlagsForState(state)
		if _, err := setKeyRowTx(tx, zone, keyid, state, f, ""); err != nil {
			tx.Rollback()
			t.Fatalf("to %s: %v", state, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	publishedAt := func() string {
		t.Helper()
		var v string
		if err := kdb.DB.QueryRow(`SELECT COALESCE(published_at,'') FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, keyid).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	write(DnskeyStatePublished)
	if publishedAt() == "" {
		t.Fatal("created→published did not stamp published_at")
	}
	const old = "2026-01-01T00:00:00Z"
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET published_at=? WHERE zonename=? AND keyid=?`, old, zone, keyid); err != nil {
		t.Fatal(err)
	}
	write(DnskeyStatePublished)
	if got := publishedAt(); got != old {
		t.Errorf("published→published re-stamped published_at to %s; want the old %s kept", got, old)
	}
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET published_at='' WHERE zonename=? AND keyid=?`, zone, keyid); err != nil {
		t.Fatal(err)
	}
	write(DnskeyStatePublished)
	if publishedAt() == "" {
		t.Error("published→published left an empty published_at empty; a legacy key must get one")
	}
}

// The writers enforce what they can see of the invariants: sign implies pub
// (I1), and ds only on a key with the SEP bit (I3). An owner passing flags by
// hand cannot write a row the checker would report.
func TestWritersRefuseSignWithoutPub(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "i1.example."
	rng := newTestRand(32)
	row := testKeyRow(zone, DnskeyStateActive, "ZSK", rng)
	row.RowFlags = &KeyRowFlags{Pub: false, Sign: true}
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertKeyRowTx(tx, row); err == nil {
		t.Error("insert with sign and no pub was accepted")
	}
	tx.Rollback()

	keyid := insertTestKeyRow(t, kdb, zone, DnskeyStateStandby, "ZSK", rng)
	tx, err = kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setKeyRowTx(tx, zone, keyid, DnskeyStateActive, KeyRowFlags{Pub: false, Sign: true}, ""); err == nil {
		t.Error("state write with sign and no pub was accepted")
	}
	tx.Rollback()
	var state string
	if err := kdb.DB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, keyid).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != DnskeyStateStandby {
		t.Errorf("the refused write changed the state to %q", state)
	}
}

func TestWritersRefuseDsOnAKeyWithoutTheSepBit(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "i3.example."
	rng := newTestRand(33)
	row := testKeyRow(zone, DnskeyStateActive, "ZSK", rng)
	row.RowFlags = &KeyRowFlags{Pub: true, Sign: true, DS: sql.NullBool{Bool: true, Valid: true}}
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertKeyRowTx(tx, row); err == nil {
		t.Error("insert of a ZSK with ds set was accepted")
	}
	tx.Rollback()

	zsk := insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "ZSK", rng)
	tx, err = kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setKeyRowTx(tx, zone, zsk, DnskeyStateActive, KeyRowFlags{Pub: true, Sign: true, DS: sql.NullBool{Bool: true, Valid: true}}, ""); err == nil {
		t.Error("state write setting ds on a ZSK was accepted")
	}
	tx.Rollback()

	// A KSK may carry ds.
	ksk := insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "KSK", rng)
	tx, err = kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setKeyRowTx(tx, zone, ksk, DnskeyStateActive, KeyRowFlags{Pub: true, Sign: true, DS: sql.NullBool{Bool: true, Valid: true}}, ""); err != nil {
		t.Errorf("ds on a KSK refused: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, _, ds := readKeyRowFlags(t, kdb, zone, ksk); flagString(ds) != "1" {
		t.Errorf("ds=%s on the KSK, want 1", flagString(ds))
	}
}
