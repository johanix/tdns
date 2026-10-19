package tdns

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// openKeystoreLikeDaemon creates the keystore file and opens it the way
// InitializeKeyDB does: an empty file at 0664, then NewKeyDB.
func openKeystoreLikeDaemon(t *testing.T, f string) *KeyDB {
	t.Helper()
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatal(err)
	}
	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	t.Cleanup(func() { kdb.Close() })
	return kdb
}

func journalModeOf(t *testing.T, db *sql.DB) string {
	t.Helper()
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	return strings.ToLower(mode)
}

// The keystore opens in WAL mode, and a file an older tdns left in the
// rollback journal switches on its first open; the mode stays in the file.
func TestKeystoreOpensInWALMode(t *testing.T) {
	dir := t.TempDir()

	kdb := openKeystoreLikeDaemon(t, filepath.Join(dir, "new.db"))
	if mode := journalModeOf(t, kdb.DB); mode != "wal" {
		t.Errorf("a new keystore: journal_mode %q, want wal", mode)
	}

	old := filepath.Join(dir, "old.db")
	raw, err := sql.Open("sqlite3", old) // the open before WAL
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE OlderTdns (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if mode := journalModeOf(t, raw); mode != "delete" {
		t.Fatalf("the older file: journal_mode %q, want delete (the test needs a rollback-journal file)", mode)
	}
	raw.Close()

	okdb, err := NewKeyDB(old, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB on the older file: %v", err)
	}
	if mode := journalModeOf(t, okdb.DB); mode != "wal" {
		t.Errorf("the older file after NewKeyDB: journal_mode %q, want wal", mode)
	}
	okdb.Close()

	raw, err = sql.Open("sqlite3", old)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if mode := journalModeOf(t, raw); mode != "wal" {
		t.Errorf("the older file, opened again without options: journal_mode %q, want wal (the mode is kept in the file)", mode)
	}
}

// The path goes into a URI. One with characters a URI or the driver reads as
// syntax still opens the file at that path, and no other.
func TestKeystoreOpensAtAnAwkwardPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a dir?with #odd %41 chars&x=y")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "keys.db")
	kdb := openKeystoreLikeDaemon(t, f)
	if mode := journalModeOf(t, kdb.DB); mode != "wal" {
		t.Errorf("journal_mode %q, want wal", mode)
	}
	if err := kdb.SaveOutgoingSerial("awkward.example.", 7); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := kdb.Close(); err != nil {
		t.Fatal(err)
	}

	// The last close checkpoints the WAL into the file and removes it.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != "keys.db" {
		t.Fatalf("files in the keystore directory: %q, want only keys.db", names)
	}
	raw, err := sql.Open("sqlite3", keystoreDSN(f))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var serial uint32
	if err := raw.QueryRow(`SELECT serial FROM OutgoingSerials WHERE zone=?`, "awkward.example.").Scan(&serial); err != nil || serial != 7 {
		t.Fatalf("reading the write back: serial %d, err %v", serial, err)
	}
}

func isDatabaseLocked(err error) bool {
	if err == nil {
		return false
	}
	var se sqlite3.Error
	if errors.As(err, &se) && (se.Code == sqlite3.ErrBusy || se.Code == sqlite3.ErrLocked) {
		return true
	}
	return strings.Contains(err.Error(), "database is locked") || strings.Contains(err.Error(), "database table is locked")
}

// Many key-row writes at once, with other writers and readers in between,
// never fail with "database is locked". The KeyDB's own transactions
// (UpdateKeyRow) take turns, as the KeyDB runs one at a time. Beside them,
// on other connections of the same pool: transactions that read and then
// write, begun on KeyDB.DB directly as a multi-provider owner does; plain
// statement writes; and the keystore read that follows every key-row commit
// (servedDnskeyRRs, via republishSigningKeysForZone).
func TestKeystoreConcurrentKeyRowWritesAreNotLocked(t *testing.T) {
	kdb := openKeystoreLikeDaemon(t, filepath.Join(t.TempDir(), "keys.db"))

	const (
		zones       = 8
		keysPerZone = 4
		keyWriters  = 4
		rounds      = 10
		txWriters   = 4
		txPerWriter = 80
		stmtWriters = 2
		readers     = 4
	)
	type keyRef struct {
		zone  string
		keyid uint16
	}
	rng := newTestRand(11)
	var keys []keyRef
	zoneNames := make([]string, zones)
	for z := 0; z < zones; z++ {
		zoneNames[z] = fmt.Sprintf("wal%d.example.", z)
		for k := 0; k < keysPerZone; k++ {
			keyid := insertTestKeyRow(t, kdb, zoneNames[z], DnskeyStatePublished, "ZSK", rng)
			keys = append(keys, keyRef{zoneNames[z], keyid})
		}
	}
	// published -> standby -> published ...; the last round decides.
	roundState := func(r int) string {
		if r%2 == 0 {
			return DnskeyStateStandby
		}
		return DnskeyStatePublished
	}

	var (
		mu       sync.Mutex
		locked   []string
		lockedBy = map[string]int{}
		other    []string
		keyTurns sync.Mutex // the KeyDB's one transaction at a time
		writers  sync.WaitGroup
		rdrs     sync.WaitGroup
		done     = make(chan struct{})
	)
	report := func(who string, err error) {
		if err == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if isDatabaseLocked(err) {
			locked = append(locked, who+": "+err.Error())
			lockedBy[who]++
		} else {
			other = append(other, who+": "+err.Error())
		}
	}

	for w := 0; w < keyWriters; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for r := 0; r < rounds; r++ {
				state := roundState(r)
				flags, _ := keyFlagsForState(state)
				for i := w; i < len(keys); i += keyWriters {
					keyTurns.Lock()
					err := UpdateKeyRow(kdb, keys[i].zone, keys[i].keyid, state, flags)
					keyTurns.Unlock()
					report("UpdateKeyRow", err)
				}
			}
		}(w)
	}
	for w := 0; w < txWriters; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; i < txPerWriter; i++ {
				zone := zoneNames[(w+i)%zones]
				err := func() error {
					tx, err := kdb.DB.Begin()
					if err != nil {
						return err
					}
					defer tx.Rollback()
					var serial uint32
					if err := tx.QueryRow(`SELECT serial FROM OutgoingSerials WHERE zone=?`, zone).Scan(&serial); err != nil && err != sql.ErrNoRows {
						return err
					}
					if _, err := tx.Exec(`INSERT OR REPLACE INTO OutgoingSerials (zone, serial, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, zone, serial+1); err != nil {
						return err
					}
					return tx.Commit()
				}()
				report("read-then-write transaction", err)
			}
		}(w)
	}
	for w := 0; w < stmtWriters; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; i < txPerWriter; i++ {
				report("statement write", kdb.SaveOutgoingSerial(fmt.Sprintf("stmt%d.example.", w), uint32(i)))
			}
		}(w)
	}
	for r := 0; r < readers; r++ {
		rdrs.Add(1)
		go func(r int) {
			defer rdrs.Done()
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				_, err := servedDnskeyRRs(kdb, zoneNames[(r+i)%zones], nil)
				report("keystore read", err)
			}
		}(r)
	}
	writers.Wait()
	close(done)
	rdrs.Wait()

	if len(locked) > 0 {
		t.Errorf("%d operations failed on a lock %v; the first: %s", len(locked), lockedBy, locked[0])
	}
	if len(other) > 0 {
		t.Errorf("%d operations failed otherwise; the first: %s", len(other), other[0])
	}

	want := roundState(rounds - 1)
	for _, k := range keys {
		var state string
		if err := kdb.DB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, k.zone, k.keyid).Scan(&state); err != nil {
			t.Fatalf("read %s/%d: %v", k.zone, k.keyid, err)
		}
		if state != want {
			t.Errorf("%s/%d: state %q, want %q", k.zone, k.keyid, state, want)
		}
	}
	var total int
	if err := kdb.DB.QueryRow(`SELECT COALESCE(SUM(serial), 0) FROM OutgoingSerials WHERE zone LIKE 'wal%'`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != txWriters*txPerWriter {
		t.Errorf("the read-then-write transactions counted to %d, want %d", total, txWriters*txPerWriter)
	}
}
