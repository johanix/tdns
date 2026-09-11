package tdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Plan commit 4: the alg_roll_* columns round-trip, clear atomically, and
// an existing database gains them on upgrade.

const ktStateZone = "algstate.example."

func ktSetAlgRoll(t *testing.T, kdb *KeyDB, st KskAlgRollState) {
	t.Helper()
	if err := EnsureRolloverZoneRow(kdb, ktStateZone); err != nil {
		t.Fatalf("EnsureRolloverZoneRow: %v", err)
	}
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := setKskAlgRollTx(tx, ktStateZone, st); err != nil {
		tx.Rollback()
		t.Fatalf("setKskAlgRollTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestKskAlgRollStateRoundTrip(t *testing.T) {
	kdb := newTestKeyDB(t)

	// No row at all: not rolling.
	if st, err := LoadKskAlgRollState(kdb, ktStateZone); err != nil || st != nil {
		t.Fatalf("no row: st=%v err=%v, want nil/nil", st, err)
	}
	// Row present, columns NULL: not rolling.
	if err := EnsureRolloverZoneRow(kdb, ktStateZone); err != nil {
		t.Fatalf("EnsureRolloverZoneRow: %v", err)
	}
	if st, err := LoadKskAlgRollState(kdb, ktStateZone); err != nil || st != nil {
		t.Fatalf("NULL columns: st=%v err=%v, want nil/nil", st, err)
	}

	started := time.Date(2026, 9, 10, 10, 14, 2, 0, time.UTC)
	ktSetAlgRoll(t, kdb, KskAlgRollState{
		FromAlg: dns.ED25519, ToAlg: dns.RSASHA256, StartedAt: started,
		NewHeadKeyID: 4242, OldHeadKeyID: 1717,
	})
	st, err := LoadKskAlgRollState(kdb, ktStateZone)
	if err != nil || st == nil {
		t.Fatalf("after set: st=%v err=%v", st, err)
	}
	if st.FromAlg != dns.ED25519 || st.ToAlg != dns.RSASHA256 || !st.StartedAt.Equal(started) ||
		st.NewHeadKeyID != 4242 || st.OldHeadKeyID != 1717 || st.OldHeadRetireAt != nil {
		t.Fatalf("round trip mismatch: %+v", st)
	}

	// The drain clock is stamped separately, at DS confirm.
	retireAt := started.Add(3 * time.Hour)
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := setKskAlgRollOldHeadRetireAtTx(tx, ktStateZone, retireAt); err != nil {
		tx.Rollback()
		t.Fatalf("setKskAlgRollOldHeadRetireAtTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	st, err = LoadKskAlgRollState(kdb, ktStateZone)
	if err != nil {
		t.Fatalf("LoadKskAlgRollState: %v", err)
	}
	if st == nil || st.OldHeadRetireAt == nil || !st.OldHeadRetireAt.Equal(retireAt) {
		t.Fatalf("old_head_retire_at not persisted: %+v", st)
	}

	// The row projection agrees with the loader and costs no query.
	row, err := LoadRolloverZoneRow(kdb, ktStateZone)
	if err != nil || row == nil {
		t.Fatalf("LoadRolloverZoneRow: row=%v err=%v", row, err)
	}
	p, perr := kskAlgRollFromRow(row)
	if perr != nil {
		t.Fatalf("kskAlgRollFromRow: %v", perr)
	}
	if p == nil || p.FromAlg != st.FromAlg || p.ToAlg != st.ToAlg || !p.StartedAt.Equal(st.StartedAt) ||
		p.NewHeadKeyID != st.NewHeadKeyID || p.OldHeadKeyID != st.OldHeadKeyID ||
		p.OldHeadRetireAt == nil || !p.OldHeadRetireAt.Equal(*st.OldHeadRetireAt) {
		t.Fatalf("kskAlgRollFromRow = %+v, want %+v", p, st)
	}

	// Clear: everything NULL again, not rolling.
	tx, err = kdb.Begin("test")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := clearKskAlgRollTx(tx, ktStateZone); err != nil {
		tx.Rollback()
		t.Fatalf("clearKskAlgRollTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if st, err := LoadKskAlgRollState(kdb, ktStateZone); err != nil || st != nil {
		t.Fatalf("after clear: st=%v err=%v, want nil/nil", st, err)
	}
	row, err = LoadRolloverZoneRow(kdb, ktStateZone)
	if err != nil || row == nil {
		t.Fatalf("LoadRolloverZoneRow after clear: row=%v err=%v", row, err)
	}
	if row.AlgRollToAlg.Valid || row.AlgRollStartedAt.Valid || row.AlgRollNewHeadKeyID.Valid ||
		row.AlgRollOldHeadKeyID.Valid || row.AlgRollOldHeadRetireAt.Valid {
		t.Fatalf("clear left a column set: %+v", row)
	}
}

// An existing database created before the columns existed gains them on
// upgrade via dbMigrateSchema, and reads as "not rolling".
func TestKskAlgRollStateMigration(t *testing.T) {
	kdb := newTestKeyDB(t)
	if _, err := kdb.DB.Exec(`DROP TABLE RolloverZoneState`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	// The pre-feature shape (a subset of columns is enough to prove the
	// ADD COLUMN path; the loader selects every column).
	if _, err := kdb.DB.Exec(`CREATE TABLE RolloverZoneState (
		zone TEXT NOT NULL PRIMARY KEY,
		last_ds_submitted_index_low INTEGER, last_ds_submitted_index_high INTEGER, last_ds_submitted_at TEXT,
		last_ds_confirmed_index_low INTEGER, last_ds_confirmed_index_high INTEGER, last_ds_confirmed_at TEXT,
		rollover_phase TEXT NOT NULL DEFAULT 'idle', rollover_phase_at TEXT,
		rollover_in_progress INTEGER NOT NULL DEFAULT 0, next_rollover_index INTEGER NOT NULL DEFAULT 0,
		manual_rollover_requested_at TEXT, manual_rollover_earliest TEXT,
		observe_started_at TEXT, observe_next_poll_at TEXT, observe_backoff_seconds INTEGER
	)`); err != nil {
		t.Fatalf("create old shape: %v", err)
	}
	if _, err := kdb.DB.Exec(`INSERT INTO RolloverZoneState (zone) VALUES (?)`, ktStateZone); err != nil {
		t.Fatalf("insert: %v", err)
	}

	dbMigrateSchema(kdb.DB)

	row, err := LoadRolloverZoneRow(kdb, ktStateZone)
	if err != nil {
		t.Fatalf("LoadRolloverZoneRow after migration: %v", err)
	}
	if row == nil || row.AlgRollFromAlg.Valid {
		t.Fatalf("migrated row must exist and read as not rolling: %+v", row)
	}
	if st, err := LoadKskAlgRollState(kdb, ktStateZone); err != nil || st != nil {
		t.Fatalf("after migration: st=%v err=%v, want nil/nil", st, err)
	}
	// And the columns are writable.
	ktSetAlgRoll(t, kdb, KskAlgRollState{FromAlg: dns.ED25519, ToAlg: dns.RSASHA256, StartedAt: time.Now(), NewHeadKeyID: 1001, OldHeadKeyID: 1000})
	if st, err := LoadKskAlgRollState(kdb, ktStateZone); err != nil || st == nil || st.ToAlg != dns.RSASHA256 {
		t.Fatalf("write after migration failed: st=%+v err=%v", st, err)
	}
}

// The KSK in-flight predicate honours the persisted marker even when the
// key shape alone reads as settled.
func TestKskAlgRollInFlightHonoursMarker(t *testing.T) {
	kdb := newTestKeyDB(t)
	ktGenKSK(t, kdb, ktStateZone, DnskeyStateActive, dns.RSASHA256)
	if st, _ := kskAlgRollInFlight(kdb, ktStateZone, dns.RSASHA256); st.InFlight {
		t.Fatalf("settled zone must not be in flight: %+v", st)
	}
	ktSetAlgRoll(t, kdb, KskAlgRollState{FromAlg: dns.ED25519, ToAlg: dns.RSASHA256, StartedAt: time.Now(), NewHeadKeyID: 1001, OldHeadKeyID: 1000})
	st, err := kskAlgRollInFlight(kdb, ktStateZone, dns.RSASHA256)
	if err != nil {
		t.Fatalf("kskAlgRollInFlight: %v", err)
	}
	if !st.InFlight || st.FromAlg() != dns.ED25519 {
		t.Fatalf("marker must make the roll in flight ED25519→RSASHA256: %+v", st)
	}
}

// The six alg_roll_* columns are all-or-nothing. A record with the marker
// set but a companion NULL or out of range is corrupt and must be reported,
// not read as a roll of key 0.
func TestKskAlgRollFromRowRejectsIncompleteRecord(t *testing.T) {
	kdb := newTestKeyDB(t)
	ktSetAlgRoll(t, kdb, KskAlgRollState{FromAlg: 15, ToAlg: 8, StartedAt: time.Now().UTC().Truncate(time.Second), NewHeadKeyID: 1001, OldHeadKeyID: 1000})
	for _, c := range []struct{ name, sql string }{
		{"old head NULL", `UPDATE RolloverZoneState SET alg_roll_old_head_keyid = NULL WHERE zone = ?`},
		{"new head 0", `UPDATE RolloverZoneState SET alg_roll_new_head_keyid = 0 WHERE zone = ?`},
		{"to alg out of range", `UPDATE RolloverZoneState SET alg_roll_to_alg = 300 WHERE zone = ?`},
		{"started_at NULL", `UPDATE RolloverZoneState SET alg_roll_started_at = NULL WHERE zone = ?`},
	} {
		if _, err := kdb.DB.Exec(c.sql, ktStateZone); err != nil {
			t.Fatalf("%s: corrupt the row: %v", c.name, err)
		}
		if st, err := LoadKskAlgRollState(kdb, ktStateZone); err == nil {
			t.Fatalf("%s: got %+v, want an error", c.name, st)
		}
		ktSetAlgRoll(t, kdb, KskAlgRollState{FromAlg: 15, ToAlg: 8, StartedAt: time.Now().UTC().Truncate(time.Second), NewHeadKeyID: 1001, OldHeadKeyID: 1000})
	}
}
