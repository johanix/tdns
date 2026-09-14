package tdns

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// T1a.3: fixture keystores, generated once from the code before the key
// columns and committed under testdata/keyfixtures, pass the migration with
// I1-I8 holding and the reference and column sets equal (T1a.2).
//
// The fixtures are the reference. They are regenerated only on purpose:
//
//	TDNS_WRITE_KEY_FIXTURES=1 go test -run TestWriteKeyFixtures .
//
// Each holds one zone, built through the writers of the day it was made, and
// dumped as SQL with the schema of that day, so loading one exercises the
// same path an operator's keystore takes.
var keyFixtures = []struct {
	name   string
	zone   string
	states map[string]int // state -> row count
	build  func(t *testing.T, kdb *KeyDB, zone string)
}{
	{
		// No automated rollover, with a standby KSK beside the active pair.
		name: "none-standby-ksk", zone: "none.example.",
		states: map[string]int{DnskeyStateActive: 2, DnskeyStateStandby: 2},
		build: func(t *testing.T, kdb *KeyDB, zone string) {
			fixtureActivePair(t, kdb, zone)
			fixtureStaged(t, kdb, zone, "KSK", DnskeyStateStandby)
			fixtureStaged(t, kdb, zone, "ZSK", DnskeyStateStandby)
		},
	},
	{
		// Multi-DS mid-pipeline: one KSK at ds-published, one at published.
		name: "multi-ds-pipeline", zone: "multids.example.",
		states: map[string]int{DnskeyStateActive: 2, DnskeyStateDsPublished: 1, DnskeyStatePublished: 1},
		build: func(t *testing.T, kdb *KeyDB, zone string) {
			ksk, _ := fixtureActivePair(t, kdb, zone)
			if err := RegisterBootstrapActiveKSK(kdb, zone, ksk, RolloverMethodMultiDS, dns.ED25519); err != nil {
				t.Fatal(err)
			}
			for _, st := range []string{DnskeyStateDsPublished, DnskeyStatePublished} {
				keyid, _, err := GenerateKskRolloverCreated(kdb, zone, "fixture", dns.ED25519, RolloverMethodMultiDS)
				if err != nil {
					t.Fatal(err)
				}
				fixtureTransition(t, kdb, zone, keyid, DnskeyStateDsPublished)
				if st == DnskeyStatePublished {
					fixtureTransition(t, kdb, zone, keyid, DnskeyStatePublished)
				}
			}
		},
	},
	{
		// A KSK algorithm rollover in flight: the old head is still active
		// beside the new one, and the zone row records the roll.
		name: "alg-roll-in-flight", zone: "algroll.example.",
		states: map[string]int{DnskeyStateActive: 3},
		build: func(t *testing.T, kdb *KeyDB, zone string) {
			oldHead, _ := fixtureActivePair(t, kdb, zone)
			if err := RegisterBootstrapActiveKSK(kdb, zone, oldHead, RolloverMethodDoubleSignature, dns.ED25519); err != nil {
				t.Fatal(err)
			}
			if err := EnsureRolloverZoneRow(kdb, zone); err != nil {
				t.Fatal(err)
			}
			tx, err := kdb.Begin("fixture")
			if err != nil {
				t.Fatal(err)
			}
			ri, err := nextRolloverIndexTx(tx, zone)
			if err != nil {
				t.Fatal(err)
			}
			pkc, _, err := kdb.GenerateKeypair(zone, "fixture", DnskeyStateActive, dns.TypeDNSKEY, dns.ECDSAP256SHA256, "KSK", tx)
			if err != nil {
				t.Fatal(err)
			}
			if err := insertRolloverKeyStateTx(tx, zone, pkc.KeyId, ri, RolloverMethodDoubleSignature); err != nil {
				t.Fatal(err)
			}
			if err := setRolloverInProgressTx(tx, zone, true); err != nil {
				t.Fatal(err)
			}
			if err := setKskAlgRollTx(tx, zone, KskAlgRollState{
				FromAlg: dns.ED25519, ToAlg: dns.ECDSAP256SHA256, StartedAt: time.Now().UTC(),
				NewHeadKeyID: pkc.KeyId, OldHeadKeyID: oldHead,
			}); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		},
	},
	{
		// A ZSK pipeline with a standby and a retired key.
		name: "zsk-pipeline", zone: "zsk.example.",
		states: map[string]int{DnskeyStateActive: 2, DnskeyStateStandby: 1, DnskeyStateRetired: 1},
		build: func(t *testing.T, kdb *KeyDB, zone string) {
			fixtureActivePair(t, kdb, zone)
			fixtureStaged(t, kdb, zone, "ZSK", DnskeyStateStandby)
			if _, _, err := kdb.RolloverKey(zone, "ZSK", nil); err != nil {
				t.Fatal(err)
			}
			fixtureStaged(t, kdb, zone, "ZSK", DnskeyStateStandby)
		},
	},
	{
		// Multi-provider rows beside the own active pair: an mpdist KSK, a
		// foreign KSK written as tdns-mp writes it, and a ZSK on its way out.
		name: "multi-provider", zone: "mp.example.",
		states: map[string]int{DnskeyStateActive: 2, DnskeyStateMpdist: 1, DnskeyStateForeign: 1, DnskeyStateMpremove: 1},
		build: func(t *testing.T, kdb *KeyDB, zone string) {
			fixtureActivePair(t, kdb, zone)
			if _, _, err := kdb.GenerateKeypair(zone, "fixture", DnskeyStateMpdist, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
				t.Fatal(err)
			}
			foreign := testDNSKEY(zone, "KSK", newTestRand(42))
			if _, err := kdb.DB.Exec(`INSERT OR IGNORE INTO DnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, 'foreign', '', ?)`,
				zone, DnskeyStateForeign, foreign.KeyTag(), foreign.Flags, dns.AlgorithmToString[foreign.Algorithm], foreign.String()); err != nil {
				t.Fatal(err)
			}
			fixtureStaged(t, kdb, zone, "ZSK", DnskeyStateMpremove)
		},
	},
	{
		// A removed key.
		name: "removed-key", zone: "removed.example.",
		states: map[string]int{DnskeyStateActive: 2, DnskeyStateRemoved: 1},
		build: func(t *testing.T, kdb *KeyDB, zone string) {
			fixtureActivePair(t, kdb, zone)
			fixtureStaged(t, kdb, zone, "ZSK", DnskeyStateStandby, DnskeyStateRemoved)
		},
	},
}

func fixtureActivePair(t *testing.T, kdb *KeyDB, zone string) (ksk, zsk uint16) {
	t.Helper()
	k, _, err := kdb.GenerateKeypair(zone, "fixture", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil)
	if err != nil {
		t.Fatal(err)
	}
	z, _, err := kdb.GenerateKeypair(zone, "fixture", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil)
	if err != nil {
		t.Fatal(err)
	}
	return k.KeyId, z.KeyId
}

// fixtureStaged generates a key the way the key state worker does (staged
// as published) and walks it through the given states.
func fixtureStaged(t *testing.T, kdb *KeyDB, zone, role string, states ...string) uint16 {
	t.Helper()
	keyid, err := GenerateAndStageKey(kdb, zone, "fixture", dns.ED25519, role)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range states {
		fixtureTransition(t, kdb, zone, keyid, st)
	}
	return keyid
}

func fixtureTransition(t *testing.T, kdb *KeyDB, zone string, keyid uint16, state string) {
	t.Helper()
	if err := UpdateDnssecKeyState(kdb, zone, keyid, state); err != nil {
		t.Fatalf("%s/%d -> %s: %v", zone, keyid, state, err)
	}
}

func keyFixturePath(name string) string { return filepath.Join("testdata", "keyfixtures", name+".sql") }

// TestWriteKeyFixtures regenerates the fixtures. Skipped unless asked for.
func TestWriteKeyFixtures(t *testing.T) {
	if os.Getenv("TDNS_WRITE_KEY_FIXTURES") == "" {
		t.Skip("set TDNS_WRITE_KEY_FIXTURES=1 to regenerate the fixtures")
	}
	for _, fx := range keyFixtures {
		f := filepath.Join(t.TempDir(), fx.name+".db")
		if err := os.WriteFile(f, nil, 0664); err != nil {
			t.Fatal(err)
		}
		kdb, err := NewKeyDB(f, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		fx.build(t, kdb, fx.zone)
		dump := dumpKeyFixture(t, kdb)
		kdb.Close()
		if err := os.WriteFile(keyFixturePath(fx.name), []byte(dump), 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", keyFixturePath(fx.name))
	}
}

// dumpKeyFixture renders the key-related tables as SQL: each table's CREATE
// statement as sqlite recorded it, then one INSERT per row.
func dumpKeyFixture(t *testing.T, kdb *KeyDB) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "-- keystore fixture written %s by TestWriteKeyFixtures; do not edit\n", time.Now().UTC().Format("2006-01-02"))
	for _, table := range []string{"DnssecKeyStore", "RolloverZoneState", "RolloverKeyState"} {
		var ddl string
		if err := kdb.DB.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&ddl); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		fmt.Fprintf(&b, "%s;\n", ddl)
		rows, err := kdb.DB.Query(`SELECT * FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			var lits []string
			for _, v := range vals {
				lits = append(lits, sqlLiteral(v))
			}
			fmt.Fprintf(&b, "INSERT INTO %s (%s) VALUES (%s);\n", table, strings.Join(cols, ", "), strings.Join(lits, ", "))
		}
		rows.Close()
	}
	return b.String()
}

func sqlLiteral(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case int64:
		return fmt.Sprint(x)
	case float64:
		return fmt.Sprint(x)
	case bool:
		if x {
			return "1"
		}
		return "0"
	case []byte:
		return "'" + strings.ReplaceAll(string(x), "'", "''") + "'"
	case string:
		return "'" + strings.ReplaceAll(x, "'", "''") + "'"
	case time.Time:
		return "'" + x.UTC().Format(time.RFC3339) + "'"
	default:
		return "'" + strings.ReplaceAll(fmt.Sprint(x), "'", "''") + "'"
	}
}

// loadKeyFixture restores a fixture into a fresh file and opens it the way
// the daemon does, migrations included.
func loadKeyFixture(t *testing.T, name string) *KeyDB {
	t.Helper()
	script, err := os.ReadFile(keyFixturePath(name))
	if err != nil {
		t.Fatalf("fixture %s: %v (regenerate with TDNS_WRITE_KEY_FIXTURES=1)", name, err)
	}
	f := filepath.Join(t.TempDir(), name+".db")
	raw, err := sql.Open("sqlite3", f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(string(script)); err != nil {
		t.Fatalf("restore fixture %s: %v", name, err)
	}
	raw.Close()
	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("open fixture %s: %v", name, err)
	}
	t.Cleanup(func() { kdb.Close() })
	return kdb
}

func fixtureStates(t *testing.T, kdb *KeyDB, zone string) map[string]int {
	t.Helper()
	rows, err := kdb.DB.Query(`SELECT state, COUNT(*) FROM DnssecKeyStore WHERE zonename=? GROUP BY state`, zone)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			t.Fatal(err)
		}
		out[st] = n
	}
	return out
}

func statesString(m map[string]int) string {
	var ks []string
	for k, n := range m {
		ks = append(ks, fmt.Sprintf("%s:%d", k, n))
	}
	sort.Strings(ks)
	return strings.Join(ks, " ")
}

func TestKeyFixturesMigrateWithTheInvariantsHolding(t *testing.T) {
	for _, fx := range keyFixtures {
		t.Run(fx.name, func(t *testing.T) {
			kdb := loadKeyFixture(t, fx.name)
			if got := fixtureStates(t, kdb, fx.zone); statesString(got) != statesString(fx.states) {
				t.Fatalf("rows: %s, want %s (was the fixture regenerated?)", statesString(got), statesString(fx.states))
			}
			if vs := CheckKeyRowInvariants(kdb, fx.zone); len(vs) != 0 {
				t.Errorf("after the migration: %s", violationList(vs))
			}
			assertKeySetsAgree(t, kdb, fx.zone)
			if diffs := kdb.CheckKeyColumnEquivalence(); len(diffs) != 0 {
				t.Errorf("equivalence: %v", diffs)
			}
		})
	}
}
