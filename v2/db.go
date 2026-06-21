/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"database/sql"
	"fmt"
	"os"

	core "github.com/johanix/tdns/v2/core"
	_ "github.com/mattn/go-sqlite3"
)

func (tx *Tx) Commit() error {
	// log.Printf("---> Committing KeyDB transaction: %s", tx.context)
	err := tx.Tx.Commit()
	tx.KeyDB.Ctx = ""
	if err != nil {
		lgConfig.Error("error committing KeyDB transaction", "context", tx.context, "err", err)
	}
	return err
}

func (tx *Tx) Rollback() error {
	// log.Printf("<--- Rolling back KeyDB transaction: %s", tx.context)
	err := tx.Tx.Rollback()
	tx.KeyDB.Ctx = ""
	if err != nil {
		lgConfig.Error("error rolling back KeyDB transaction", "context", tx.context, "err", err)
	}
	return err
}

func (tx *Tx) Exec(query string, args ...interface{}) (sql.Result, error) {
	// log.Printf("---> Executing KeyDB Exec: %s with args: %v in context: %s", query, args, tx.context)
	result, err := tx.Tx.Exec(query, args...)
	if err != nil {
		lgConfig.Error("error executing KeyDB Exec", "context", tx.context, "err", err)
	}
	return result, err
}

func (tx *Tx) Query(query string, args ...interface{}) (*sql.Rows, error) {
	// log.Printf("---> Executing KeyDB query: %s with args: %v in context: %s", query, args, tx.context)
	rows, err := tx.Tx.Query(query, args...)
	if err != nil {
		lgConfig.Error("error executing KeyDB query", "context", tx.context, "err", err)
	}
	return rows, err
}

func (tx *Tx) QueryRow(query string, args ...interface{}) *sql.Row {
	// log.Printf("Querying row: %s with args: %v in context: %s", query, args, tx.context)
	return tx.Tx.QueryRow(query, args...)
}

func (db *KeyDB) Prepare(q string) (*sql.Stmt, error) {
	return db.DB.Prepare(q)
}

func (db *KeyDB) Begin(context string) (*Tx, error) {
	// log.Printf("---> Beginning KeyDB transaction: %s", context)
	if db.Ctx != "" {
		lgConfig.Error("KeyDB transaction already in progress", "context", db.Ctx)
		return nil, fmt.Errorf("KeyDB transaction already in progress: %s", db.Ctx)
	}
	db.Ctx = context
	tx, err := db.DB.Begin()
	if err != nil {
		lgConfig.Error("error beginning transaction", "context", context, "err", err)
		return nil, err
	}
	return &Tx{Tx: tx, KeyDB: db, context: context}, nil
}

func (db *KeyDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return db.DB.Query(query, args...)
}

func (db *KeyDB) QueryRow(query string, args ...interface{}) *sql.Row {
	return db.DB.QueryRow(query, args...)
}

func (db *KeyDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return db.DB.Exec(query, args...)
}

func (db *KeyDB) Close() error {
	return db.DB.Close()
}

// dbSetupTables creates the tables defined in DefaultTables on the given database connection.
// It prepares and executes each table schema; prepare errors are logged and execution errors call log.Fatalf (terminating the process).
// If Globals.Verbose is true, progress is logged. It always returns false.
func dbSetupTables(db *sql.DB) bool {
	lgConfig.Debug("setting up missing tables")

	for t, s := range DefaultTables {
		stmt, err := db.Prepare(s)
		if err != nil {
			Fatal("failed to prepare db schema", "table", t, "schema", s, "err", err)
		}
		_, err = stmt.Exec()
		if err != nil {
			Fatal("failed to set up db schema", "schema", s, "err", err)
		}
	}

	dbMigrateSchema(db)
	dbMigrateData(db)
	return false
}

// dbMigrateData performs one-shot data-shape migrations that need to
// run after dbMigrateSchema has ensured the column shape is correct.
// Each block must be idempotent: re-running on an already-migrated
// database is a no-op.
func dbMigrateData(db *sql.DB) {
	// C16: copy old standby_at values to the new published_at column.
	// The old single-state code stamped standby_at when the engine
	// moved a key into the served zone DNSKEY RRset — what the new
	// state machine calls published_at.
	if dbColumnExists(db, "RolloverKeyState", "published_at") {
		_, err := db.Exec(`UPDATE RolloverKeyState
SET published_at = standby_at
WHERE published_at IS NULL AND standby_at IS NOT NULL AND standby_at != ''`)
		if err != nil {
			lgConfig.Error("data migration: copy standby_at to published_at failed", "err", err)
		}
	}

	// C18: rename existing SEP keys in the old "standby" state to the
	// new "published" state. The old code reached the "standby" string
	// at T_publish (DNSKEY just entered zone, propagation incomplete).
	// The new state machine names that "published" and adds a separate
	// "standby" string for genuine propagated-standby. After this
	// migration, the new TransitionRolloverKskPublishedToStandby will
	// pick up these keys on the next tick and promote them to the new
	// "standby" once their propagation gate elapses.
	//
	// Idempotence: gated on standby_at being NULL — once the new
	// genuine-standby transition has stamped standby_at on a key, we
	// know it has been through the new state machine and shouldn't be
	// retroactively renamed.
	//
	// SEP-only: ZSK "published" semantics are unchanged.
	_, err := db.Exec(`UPDATE DnssecKeyStore
SET state = 'published'
WHERE state = 'standby' AND (CAST(flags AS INTEGER) & 1) = 1
  AND zonename || '|' || keyid IN (
    SELECT zone || '|' || keyid
    FROM RolloverKeyState
    WHERE standby_at IS NULL OR standby_at = ''
  )`)
	if err != nil {
		lgConfig.Error("data migration: rename old standby SEP keys to published failed", "err", err)
	}
}

// dbMigrateSchema adds columns that may be missing from tables created by older schema versions.
// Uses ALTER TABLE ADD COLUMN which is a no-op if the column already exists (SQLite ignores duplicates via error check).
func dbMigrateSchema(db *sql.DB) {
	migrations := []struct {
		table  string
		column string
		ddl    string
	}{
		{"DnssecKeyStore", "published_at", "ALTER TABLE DnssecKeyStore ADD COLUMN published_at TEXT DEFAULT ''"},
		{"DnssecKeyStore", "active_at", "ALTER TABLE DnssecKeyStore ADD COLUMN active_at TEXT DEFAULT ''"},
		{"DnssecKeyStore", "retired_at", "ALTER TABLE DnssecKeyStore ADD COLUMN retired_at TEXT DEFAULT ''"},
		// ZSK active_seq: monotonic per-key roll counter (operator feedback),
		// MAX(active_seq)+1 over the zone's ZSK rows, stamped at standby→active.
		{"DnssecKeyStore", "active_seq", "ALTER TABLE DnssecKeyStore ADD COLUMN active_seq INTEGER"},
		{"Sig0KeyStore", "parent_state", "ALTER TABLE Sig0KeyStore ADD COLUMN parent_state INTEGER DEFAULT 0"},
		// Rollover overhaul phase 2: softfail-state columns on RolloverZoneState.
		// All NULL/0-default so existing testbed rows remain valid post-migration.
		{"RolloverZoneState", "hardfail_count", "ALTER TABLE RolloverZoneState ADD COLUMN hardfail_count INTEGER NOT NULL DEFAULT 0"},
		{"RolloverZoneState", "next_push_at", "ALTER TABLE RolloverZoneState ADD COLUMN next_push_at TEXT"},
		{"RolloverZoneState", "last_softfail_at", "ALTER TABLE RolloverZoneState ADD COLUMN last_softfail_at TEXT"},
		{"RolloverZoneState", "last_softfail_category", "ALTER TABLE RolloverZoneState ADD COLUMN last_softfail_category TEXT"},
		{"RolloverZoneState", "last_softfail_detail", "ALTER TABLE RolloverZoneState ADD COLUMN last_softfail_detail TEXT"},
		{"RolloverZoneState", "last_success_at", "ALTER TABLE RolloverZoneState ADD COLUMN last_success_at TEXT"},
		{"RolloverZoneState", "last_attempt_started_at", "ALTER TABLE RolloverZoneState ADD COLUMN last_attempt_started_at TEXT"},
		{"RolloverZoneState", "last_poll_at", "ALTER TABLE RolloverZoneState ADD COLUMN last_poll_at TEXT"},
		// Rollover NOTIFY-scheme phase 2: scheme + CDS-cleanup ownership.
		// last_attempt_scheme is diagnostic-only ("UPDATE", "NOTIFY", or
		// "UPDATE,NOTIFY" when a parallel send had at least one wire-level
		// NOERROR). last_published_cds_index_low/high are engine-functional:
		// a non-NULL pair asserts ownership of the current child-apex CDS
		// RRset for cleanup-time comparison.
		{"RolloverZoneState", "last_attempt_scheme", "ALTER TABLE RolloverZoneState ADD COLUMN last_attempt_scheme TEXT"},
		{"RolloverZoneState", "last_published_cds_index_low", "ALTER TABLE RolloverZoneState ADD COLUMN last_published_cds_index_low INTEGER"},
		{"RolloverZoneState", "last_published_cds_index_high", "ALTER TABLE RolloverZoneState ADD COLUMN last_published_cds_index_high INTEGER"},
		// Last-observed DS RRset from the parent-agent poll. Stored as
		// CSV-of-keyids (NOT a rollover_index range) so a polled answer
		// can include keyids that have no RolloverKeyState row (parent
		// has stale DS for a key the child has already removed, for
		// example). Updated on every successful poll regardless of
		// whether the polled set matches the engine's expected set;
		// the operator's "DS observed" status line shows the latest
		// poll rather than the latest confirmed match.
		{"RolloverZoneState", "last_ds_observed_keyids", "ALTER TABLE RolloverZoneState ADD COLUMN last_ds_observed_keyids TEXT"},
		{"RolloverZoneState", "last_ds_observed_at", "ALTER TABLE RolloverZoneState ADD COLUMN last_ds_observed_at TEXT"},
		// Parent's DSYNC RRset advertisement state, snapshotted on every
		// pickRolloverSchemes call (i.e. every push attempt). NULL means
		// "never observed yet"; 0/1 reflect the most recent observation.
		// Used by the auto-rollover status renderer to distinguish
		// "parent doesn't advertise this scheme" from "engine hasn't
		// pushed via this scheme yet".
		{"RolloverZoneState", "parent_advertises_update", "ALTER TABLE RolloverZoneState ADD COLUMN parent_advertises_update INTEGER"},
		{"RolloverZoneState", "parent_advertises_notify", "ALTER TABLE RolloverZoneState ADD COLUMN parent_advertises_notify INTEGER"},
		// Split of the old "standby" state into "published" (DNSKEY in
		// zone, propagation incomplete) + "standby" (propagation
		// complete, ready for AtomicRollover). published_at carries
		// the moment the DNSKEY entered the served zone — what the
		// old single-state code stored in standby_at.
		//
		// Migration of existing data is handled separately in
		// migrateOldStandbyToPublished (called after the column add)
		// because it requires both copying timestamp values and
		// updating state strings on DnssecKeyStore. Doing that here
		// would mix DDL-style migrations (idempotent column adds) with
		// data-shape migrations (one-shot state transitions).
		{"RolloverKeyState", "published_at", "ALTER TABLE RolloverKeyState ADD COLUMN published_at TEXT"},
	}

	for _, m := range migrations {
		if dbColumnExists(db, m.table, m.column) {
			continue
		}
		_, err := db.Exec(m.ddl)
		if err != nil {
			lgConfig.Error("failed to add column in schema migration", "table", m.table, "column", m.column, "err", err)
		} else {
			lgConfig.Info("added column in schema migration", "table", m.table, "column", m.column)
		}
	}
}

// validTableName checks that a table name contains only safe characters.
func validTableName(name string) bool {
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return len(name) > 0
}

// dbColumnExists checks whether a column exists in a table using PRAGMA table_info.
func dbColumnExists(db *sql.DB, table, column string) bool {
	if !validTableName(table) {
		return false
	}
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			continue
		}
		if name == column {
			return true
		}
	}
	return false
}

// NewKeyDB creates and initializes a KeyDB backed by the sqlite3 file at dbfile.
// It validates that dbfile is provided, ensures the file is writable, opens the sqlite3 database, and sets up required tables.
// If force is true, existing default tables are dropped before setup.
// On success it returns a KeyDB with caches, an update channel, and Options set to the provided map; on failure it returns an error describing the problem.
func NewKeyDB(dbfile string, force bool, options map[AuthOption]string) (*KeyDB, error) {
	// dbfile := viper.GetString("db.file")
	if dbfile == "" {
		return nil, fmt.Errorf("error: DB filename unspecified")
	}
	lgConfig.Debug("opening TDNS sqlite db", "file", dbfile)
	if err := os.Chmod(dbfile, 0664); err != nil {
		return nil, fmt.Errorf("NewKeyDB: TDNS Error trying to ensure that db %s is writable: %v", dbfile, err)
	}
	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		return nil, fmt.Errorf("NewKeyDB: TDNS Error from sql.Open: %v", err)
	}

	if force {
		for table := range DefaultTables {
			if !validTableName(table) {
				return nil, fmt.Errorf("NewKeyDB: invalid table name %q", table)
			}
			sqlcmd := "DROP TABLE " + table
			_, err = db.Exec(sqlcmd)
			if err != nil {
				return nil, fmt.Errorf("NewKeyDB: TDNS Error when dropping table %s: %v", table, err)
			}
		}
	}
	dbSetupTables(db)
	return &KeyDB{
		DB:                  db,
		DBFile:              dbfile,
		KeystoreSig0Cache:   make(map[string]*Sig0ActiveKeys),
		TruststoreSig0Cache: NewSig0StoreT(),
		KeystoreDnskeyCache: make(map[string]*DnssecKeys),
		UpdateQ:             make(chan UpdateRequest),
		KeyBootstrapperQ:    make(chan KeyBootstrapperRequest, 10),
		Options:             options,
	}, nil
}

func NewSig0StoreT() *Sig0StoreT {
	return &Sig0StoreT{
		Map: core.NewCmap[Sig0Key](),
	}
}
