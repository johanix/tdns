package tdns

import (
	"os"
	"path/filepath"
	"testing"
)

// T1a.4: an older binary writes rows without the flags. On the next open the
// flags come back from the state (the backfill is NULL-gated and runs at every
// open), and I8 holds again.
func TestRowsWrittenWithoutFlagsGetThemOnReopen(t *testing.T) {
	f := filepath.Join(t.TempDir(), "keys.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatal(err)
	}
	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	const zone = "older.example."
	rng := newTestRand(4)
	keyids := map[string]uint16{}
	for _, state := range keyStatesForRowTests {
		keyids[state] = insertRawTestKeyRow(t, kdb, zone, state, "KSK", rng)
		if pub, sign, _ := readKeyRowFlags(t, kdb, zone, keyids[state]); pub != nil || sign != nil {
			t.Fatalf("%s: a raw insert set the flags (pub=%s sign=%s); the test cannot show the backfill", state, flagString(pub), flagString(sign))
		}
	}
	if vs := violationsByInvariant(CheckKeyRowInvariants(kdb, zone))["I8"]; len(vs) != len(keyStatesForRowTests) {
		t.Errorf("before the reopen, I8 reported %d rows, want %d: %s", len(vs), len(keyStatesForRowTests), violationList(vs))
	}
	if err := kdb.Close(); err != nil {
		t.Fatal(err)
	}

	kdb, err = NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer kdb.Close()
	for state, keyid := range keyids {
		pub, sign, _ := readKeyRowFlags(t, kdb, zone, keyid)
		want := wantKeyFlags[state]
		if flagString(pub) != boolFlag(want.pub) || flagString(sign) != boolFlag(want.sign) {
			t.Errorf("%s after reopen: pub=%s sign=%s, want %s/%s", state, flagString(pub), flagString(sign), boolFlag(want.pub), boolFlag(want.sign))
		}
	}
	if vs := CheckKeyRowInvariants(kdb, zone); len(vs) != 0 {
		t.Errorf("after the reopen: %s", violationList(vs))
	}
	assertKeySetsAgree(t, kdb, zone)
}

// The backfill leaves a row that already has its flags alone: an explicit
// value written by an owner is not overwritten from the state.
func TestBackfillDoesNotOverwriteFlagsAlreadySet(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "keep.example."
	keyid := insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "KSK", newTestRand(5))
	// Values the table would not give an active key: they must survive.
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET pub=0, sign=0, ds=1 WHERE zonename=? AND keyid=?`, zone, keyid); err != nil {
		t.Fatal(err)
	}
	if _, err := kdb.BackfillKeyRowFlags(); err != nil {
		t.Fatal(err)
	}
	pub, sign, ds := readKeyRowFlags(t, kdb, zone, keyid)
	if flagString(pub) != "0" || flagString(sign) != "0" || flagString(ds) != "1" {
		t.Errorf("pub=%s sign=%s ds=%s after the backfill, want 0/0/1", flagString(pub), flagString(sign), flagString(ds))
	}
}
