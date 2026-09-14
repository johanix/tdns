package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Design R1: while S1a is the running code, the process compares the signing
// and served sets computed from the states with the sets computed from the
// columns at startup, and in test builds refuses to start on a mismatch.
func TestStrictStartupRefusesAColumnMismatch(t *testing.T) {
	f := filepath.Join(t.TempDir(), "keys.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatal(err)
	}
	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	const zone = "mismatch.example."
	keyid := insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "ZSK", newTestRand(6))
	// Not a state write, so the guard trigger does not apply: this is a flag
	// that disagrees with its state, the R1 case.
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET sign=0 WHERE zonename=? AND keyid=?`, zone, keyid); err != nil {
		t.Fatal(err)
	}
	if err := kdb.Close(); err != nil {
		t.Fatal(err)
	}

	prev := KeyColumnsStrict
	t.Cleanup(func() { KeyColumnsStrict = prev })

	KeyColumnsStrict = true
	if _, err := NewKeyDB(f, false, nil); err == nil {
		t.Error("strict open succeeded on a keystore whose columns disagree with the states")
	} else if !strings.Contains(err.Error(), zone) {
		t.Errorf("the refusal does not name the zone: %v", err)
	}

	KeyColumnsStrict = false
	kdb, err = NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("non-strict open: %v", err)
	}
	defer kdb.Close()
	diffs := kdb.CheckKeyColumnEquivalence()
	if len(diffs) != 1 || !strings.Contains(diffs[0], zone) {
		t.Errorf("equivalence check: %v, want one difference naming %s", diffs, zone)
	}
}

func TestStrictStartupAcceptsAConsistentKeystore(t *testing.T) {
	f := filepath.Join(t.TempDir(), "keys.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatal(err)
	}
	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	rng := newTestRand(7)
	for _, state := range keyStatesForRowTests {
		insertTestKeyRow(t, kdb, "ok.example.", state, "KSK", rng)
	}
	kdb.Close()
	prev := KeyColumnsStrict
	t.Cleanup(func() { KeyColumnsStrict = prev })
	KeyColumnsStrict = true
	kdb, err = NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("strict open refused a consistent keystore: %v", err)
	}
	kdb.Close()
}
