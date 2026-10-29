package tdns

import (
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func inMemoryTestKeyDB(t *testing.T) *KeyDB {
	t.Helper()
	kdb, err := NewKeyDBInMemory(t.Name())
	if err != nil {
		t.Fatalf("NewKeyDBInMemory: %v", err)
	}
	t.Cleanup(func() { kdb.Close() })
	return kdb
}

// keystoreHasTable reports whether db has the table.
func keystoreHasTable(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// memdbHasTable opens a connection of its own to the memdb database named
// path and reports whether it has the table. The connection is closed before
// it returns, so it does not keep the database alive.
func memdbHasTable(t *testing.T, path, table string) bool {
	t.Helper()
	db, err := sql.Open("sqlite3", keystoreDSN(path)+"&vfs=memdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	return keystoreHasTable(t, db, table)
}

// Writers that read and then write in one transaction, and readers, all at
// once on one in-memory keystore through the pool's connections: none of them
// may fail with "database is locked" (or SQLITE_LOCKED). The transactions
// start with BEGIN IMMEDIATE, so each writer waits out the busy timeout for
// the one before it rather than failing when it upgrades its read lock.
func TestInMemoryKeyDBConcurrentWritersAndReaders(t *testing.T) {
	kdb := inMemoryTestKeyDB(t)
	if _, err := kdb.DB.Exec(`CREATE TABLE Writes (writer INTEGER, n INTEGER)`); err != nil {
		t.Fatal(err)
	}

	const writers, txs, readers = 8, 20, 4
	errs := make(chan error, writers*txs+readers)
	var wg, writing sync.WaitGroup
	done := make(chan struct{})
	for w := 0; w < writers; w++ {
		wg.Add(1)
		writing.Add(1)
		go func() {
			defer wg.Done()
			defer writing.Done()
			for i := 0; i < txs; i++ {
				if err := inMemoryWrite(kdb, w); err != nil {
					errs <- fmt.Errorf("writer %d, tx %d: %w", w, i, err)
					return
				}
			}
		}()
	}
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if err := inMemoryRead(kdb); err != nil {
					errs <- fmt.Errorf("reader %d: %w", r, err)
					return
				}
			}
		}()
	}
	writing.Wait()
	close(done)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM Writes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != writers*txs {
		t.Fatalf("%d rows written, want %d", n, writers*txs)
	}
}

func inMemoryWrite(kdb *KeyDB, w int) error {
	tx, err := kdb.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM Writes WHERE writer=?`, w).Scan(&n); err != nil {
		return err
	}
	// Long enough for the other writers to begin too: with a deferred
	// transaction, they would hold read locks here, and all but one would
	// fail to upgrade them, without waiting.
	time.Sleep(time.Millisecond)
	if _, err := tx.Exec(`INSERT INTO Writes (writer, n) VALUES (?, ?)`, w, n+1); err != nil {
		return err
	}
	return tx.Commit()
}

func inMemoryRead(kdb *KeyDB) error {
	rows, err := kdb.DB.Query(`SELECT writer, n FROM Writes`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var w, n int
		if err := rows.Scan(&w, &n); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Two in-memory keystores, even under the same name, are two databases, and
// each has the keystore's tables.
func TestInMemoryKeyDBsAreSeparate(t *testing.T) {
	a, err := NewKeyDBInMemory("same")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewKeyDBInMemory("same")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if _, err := a.DB.Exec(`CREATE TABLE OnlyInA (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if !keystoreHasTable(t, a.DB, "OnlyInA") || keystoreHasTable(t, b.DB, "OnlyInA") {
		t.Fatal("a table made in one keystore is not in that one alone")
	}
	for _, kdb := range []*KeyDB{a, b} {
		if !keystoreHasTable(t, kdb.DB, "DnssecKeyStore") {
			t.Fatal("a keystore has no DnssecKeyStore table")
		}
	}
}

// The keystore stays when the pool closes every connection it has used: the
// connector holds one of its own.
func TestInMemoryKeyDBOutlivesItsPoolConnections(t *testing.T) {
	kdb := inMemoryTestKeyDB(t)
	kdb.DB.SetMaxIdleConns(0) // the pool closes each connection after use
	if _, err := kdb.DB.Exec(`CREATE TABLE Kept (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := kdb.DB.Exec(`INSERT INTO Kept (x) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	var x int
	if err := kdb.DB.QueryRow(`SELECT x FROM Kept`).Scan(&x); err != nil || x != 1 {
		t.Fatalf("the row written before the pool's connections closed: %d, %v", x, err)
	}
}

// Closing the KeyDB, or its sql.DB as tdns-mp's tests do, frees the database.
func TestInMemoryKeyDBCloseFreesIt(t *testing.T) {
	for name, closeIt := range map[string]func(*KeyDB) error{
		"KeyDB.Close": func(kdb *KeyDB) error { return kdb.Close() },
		"DB.Close":    func(kdb *KeyDB) error { return kdb.DB.Close() },
	} {
		t.Run(name, func(t *testing.T) {
			path := "/tdns-keystore-" + t.Name()
			kdb, err := newKeyDBInMemoryAt(path)
			if err != nil {
				t.Fatal(err)
			}
			if !memdbHasTable(t, path, "DnssecKeyStore") {
				t.Fatalf("%s: no keystore to free", path)
			}
			if err := closeIt(kdb); err != nil {
				t.Fatal(err)
			}
			if memdbHasTable(t, path, "DnssecKeyStore") {
				t.Fatalf("%s is still there after %s", path, name)
			}
		})
	}
}

// An in-memory keystore writes no files: not in the temporary directory, where
// SQLite puts its temporary files, and not in the working directory.
func TestInMemoryKeyDBWritesNoFiles(t *testing.T) {
	tmp, cwd := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Chdir(cwd)

	kdb, err := NewKeyDBInMemory(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := kdb.Begin("writes")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := tx.Exec(`INSERT INTO Sig0TrustStore (zonename, keyid, source, keyrr) VALUES (?, ?, 'file', 'x')`,
			fmt.Sprintf("z%d.example.", i), i); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := kdb.Close(); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{tmp, cwd} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			t.Errorf("%s: %s", dir, e.Name())
		}
	}
}
