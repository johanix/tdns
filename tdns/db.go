/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"crypto"
	"database/sql"
	"fmt"
	"log"
	"os"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

var DefaultTables = map[string]string{

	"ChildDnskeys": `CREATE TABLE IF NOT EXISTS 'ChildDnskeys' (
id		  INTEGER PRIMARY KEY,
parent		  TEXT,
child		  TEXT,
keyid		  INTEGER,
trusted		  INTEGER,
keyrr		  TEXT,
comment		  TEXT,
UNIQUE (parent, child, keyid)
)`,

	"ChildDelegationData": `CREATE TABLE IF NOT EXISTS 'ChildDelegationData' (
id		  INTEGER PRIMARY KEY,
parent		  TEXT,
child		  TEXT,
owner		  TEXT,
rrtype		  TEXT,
rr		  TEXT,
UNIQUE (owner,rr)
)`,

	// The Sig0TrustStore contains public SIG(0) keys that we use to validate
	// signed DNS Updates received (from child zones)
	"Sig0TrustStore": `CREATE TABLE IF NOT EXISTS 'Sig0TrustStore' (
id		  INTEGER PRIMARY KEY,
zonename	  TEXT,
keyid		  INTEGER,
validated	  INTEGER,
trusted		  INTEGER,
source		  TEXT,
keyrr		  TEXT,
comment		  TEXT,
UNIQUE (zonename, keyid)
)`,

	// The Sig0KeyStore should contain both the private and public SIG(0) keys for
	// each zone that we're managing parent sync for.
	"Sig0KeyStore": `CREATE TABLE IF NOT EXISTS 'Sig0KeyStore' (
id		  INTEGER PRIMARY KEY,
zonename	  TEXT,
state		  TEXT,
keyid		  INTEGER,
algorithm	  TEXT,
creator	  	  TEXT,
privatekey	  TEXT,
keyrr		  TEXT,
comment		  TEXT,
UNIQUE (zonename, keyid)
)`,

	// The DnssecKeyStore should contain both the private and public DNSSEC keys for
	// each zone that we're managing signing for.
	"DnssecKeyStore": `CREATE TABLE IF NOT EXISTS 'DnssecKeyStore' (
id		  INTEGER PRIMARY KEY,
zonename	  TEXT,
state		  TEXT,
keyid		  INTEGER,
flags		  INTEGER,
algorithm	  TEXT,
creator	  	  TEXT,
privatekey	  TEXT,
keyrr		  TEXT,
comment		  TEXT,
UNIQUE (zonename, keyid)
)`,
}

// Migrating all DB access to own interface to be able to have local receiver functions.
type PrivateKeyCache struct {
	K          crypto.PrivateKey
	PrivateKey string // This is only used when reading from file with ReadKeyNG()
	CS         crypto.Signer
	RR         dns.RR
	KeyType    uint16
	Algorithm  uint8
	KeyId      uint16
	KeyRR      dns.KEY
	DnskeyRR   dns.DNSKEY
}

type Sig0KeyCache struct {
	K     crypto.PrivateKey
	CS    crypto.Signer
	RR    dns.RR
	KeyRR dns.KEY
}

type Sig0ActiveKeys struct {
	Keys []*PrivateKeyCache
}

type DnssecKeyCache struct {
	K     crypto.PrivateKey
	CS    crypto.Signer
	RR    dns.RR
	KeyRR dns.DNSKEY
}

type DnssecActiveKeys struct {
	KSKs []*PrivateKeyCache
	ZSKs []*PrivateKeyCache
}

type Tx struct {
	*sql.Tx
	KeyDB   *KeyDB
	context string
}

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

type KeyDB struct {
	DB *sql.DB
	mu sync.Mutex
	// Sig0Cache   map[string]*Sig0KeyCache
	Sig0Cache   map[string]*Sig0ActiveKeys
	DnssecCache map[string]*DnssecActiveKeys // map[zonename]*DnssecActiveKeys
	Ctx         string
	UpdateQ     chan UpdateRequest
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

// func tableExists(db *sql.DB, name string) bool {
//
// 	var match string
// 	var err error
//
// 	sqlcmd := fmt.Sprintf("SELECT name FROM sqlite_master WHERE type='table' AND name='%s'", name)
// 	row := db.QueryRow(sqlcmd)
//
// 	switch err = row.Scan(&match); err {
// 	case sql.ErrNoRows:
// 		fmt.Printf("Error: tableExists: table %s not found.\n", name)
// 		return false
// 	case nil:
// 		// all ok
// 		fmt.Printf("tableExists: found table '%s'\n", match)
// 		return true
// 	default:
// 		panic(err)
// 	}
// 	return false
// }

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
		log.Printf("NewKeyDB: using sqlite db in file %s\n", dbfile)
	}
	if err := os.Chmod(dbfile, 0664); err != nil {
		return nil, fmt.Errorf("NewKeyDB: Error trying to ensure that db %s is writable: %v", dbfile, err)
	}
	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		return nil, fmt.Errorf("NewKeyDB: Error from sql.Open: %v", err)
	}

	if force {
		for table := range DefaultTables {
			sqlcmd := "DROP TABLE " + table
			_, err = db.Exec(sqlcmd)
			if err != nil {
				return nil, fmt.Errorf("NewKeyDB: Error when dropping table %s: %v", table, err)
			}
		}
	}
	dbSetupTables(db)
	return &KeyDB{
		DB:          db,
		Sig0Cache:   make(map[string]*Sig0ActiveKeys),
		DnssecCache: make(map[string]*DnssecActiveKeys),
		UpdateQ:     make(chan UpdateRequest),
	}, nil
}
