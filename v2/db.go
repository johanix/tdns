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
	return false
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
		{"DnssecKeyStore", "retired_at", "ALTER TABLE DnssecKeyStore ADD COLUMN retired_at TEXT DEFAULT ''"},
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
