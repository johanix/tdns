/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	cmap "github.com/orcaman/concurrent-map/v2"
)

func (tx *Tx) Commit() error {
	// log.Printf("---> Committing KeyDB transaction: %s", tx.context)
	err := tx.Tx.Commit()
	tx.KeyDB.Ctx = ""
	if err != nil {
		log.Printf("<--- Error committing KeyDB transaction (%s): %v", tx.context, err)
	}
	return err
}

func (tx *Tx) Rollback() error {
	// log.Printf("<--- Rolling back KeyDB transaction: %s", tx.context)
	err := tx.Tx.Rollback()
	tx.KeyDB.Ctx = ""
	if err != nil {
		log.Printf("<--- Error rolling back KeyDB transaction (%s): %v", tx.context, err)
	}
	return err
}

func (tx *Tx) Exec(query string, args ...interface{}) (sql.Result, error) {
	// log.Printf("---> Executing KeyDB Exec: %s with args: %v in context: %s", query, args, tx.context)
	result, err := tx.Tx.Exec(query, args...)
	if err != nil {
		log.Printf("<--- Error executing KeyDB Exec (%s): %v", tx.context, err)
	}
	return result, err
}

func (tx *Tx) Query(query string, args ...interface{}) (*sql.Rows, error) {
	// log.Printf("---> Executing KeyDB query: %s with args: %v in context: %s", query, args, tx.context)
	rows, err := tx.Tx.Query(query, args...)
	if err != nil {
		log.Printf("<--- Error executing KeyDB query (%s): %v", tx.context, err)
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
		log.Printf("<--- Error: KeyDB transaction already in progress: %s", db.Ctx)
		return nil, fmt.Errorf("KeyDB transaction already in progress: %s", db.Ctx)
	}
	db.Ctx = context
	tx, err := db.DB.Begin()
	if err != nil {
		log.Printf("Error beginning transaction (%s): %v", context, err)
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

func dbSetupTables(db *sql.DB) bool {
	if Globals.Verbose {
		log.Printf("Setting up missing tables\n")
	}

	for t, s := range DefaultTables {
		stmt, err := db.Prepare(s)
		if err != nil {
			log.Printf("dbSetupTables: Error from %s schema \"%s\": %v\n", t, s, err)
		}
		_, err = stmt.Exec()
		if err != nil {
			log.Fatalf("Failed to set up db schema: %s. Error: %v", s, err)
		}
	}

	return false
}

func NewKeyDB(dbfile string, force bool) (*KeyDB, error) {
	// dbfile := viper.GetString("db.file")
	if dbfile == "" {
		return nil, fmt.Errorf("error: DB filename unspecified")
	}
	if Globals.Verbose {
		log.Printf("NewKeyDB: TDNS using sqlite db in file %s\n", dbfile)
	}
	if err := os.Chmod(dbfile, 0664); err != nil {
		return nil, fmt.Errorf("NewKeyDB: TDNS Error trying to ensure that db %s is writable: %v", dbfile, err)
	}
	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		return nil, fmt.Errorf("NewKeyDB: TDNS Error from sql.Open: %v", err)
	}

	if force {
		for table := range DefaultTables {
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
	}, nil
}

func NewSig0StoreT() *Sig0StoreT {
	return &Sig0StoreT{
		Map: cmap.New[Sig0Key](),
	}
}
