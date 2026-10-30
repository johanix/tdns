package tdns

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync/atomic"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// inMemoryKeystores numbers the in-memory keystores, so that each one gets a
// database of its own.
var inMemoryKeystores atomic.Uint64

// NewKeyDBInMemory opens a KeyDB with no file behind it, for tests. Each call
// gets a new, empty keystore with the same tables, the same transactions
// (_txlock=immediate) and the same busy timeout as a keystore that NewKeyDB
// opens, but none of the files that a suite opening hundreds of keystores
// would otherwise create, sync and remove. name only labels the database; a
// test's name will do. The keystore lives until kdb.Close or kdb.DB.Close.
//
// It uses SQLite's memdb VFS: every connection in the pool opens the same
// database by its name, and the connections lock it as they would a file, so
// one that meets a lock waits out the busy timeout. Its journal is in memory
// too. There is no WAL, so a commit waits for the reads in progress, as in a
// file keystore that could not switch to WAL.
func NewKeyDBInMemory(name string) (*KeyDB, error) {
	return newKeyDBInMemoryAt(fmt.Sprintf("/tdns-keystore-%d-%s", inMemoryKeystores.Add(1), name))
}

// newKeyDBInMemoryAt opens the in-memory keystore named path, which starts
// with "/" so that every connection opens the same database.
func newKeyDBInMemoryAt(path string) (*KeyDB, error) {
	return newKeyDBInMemoryDSN(keystoreDSN(path) + "&vfs=memdb")
}

// newKeyDBInMemoryDSN opens the in-memory keystore that dsn names; the dsn
// selects the memdb VFS.
func newKeyDBInMemoryDSN(dsn string) (*KeyDB, error) {
	drv := &sqlite3.SQLiteDriver{}
	keep, err := drv.Open(dsn)
	if err != nil {
		return nil, fmt.Errorf("NewKeyDBInMemory: %v", err)
	}
	return openKeyDB(sql.OpenDB(&inMemoryConnector{dsn: dsn, drv: drv, keep: keep}), "", nil)
}

// inMemoryConnector opens the pool's connections to one memdb database.
// SQLite frees such a database when its last connection closes, and
// database/sql closes the connections it does not need, so the connector
// holds one of its own until the pool closes: sql.DB.Close calls Close here.
type inMemoryConnector struct {
	dsn  string
	drv  *sqlite3.SQLiteDriver
	keep driver.Conn
}

func (c *inMemoryConnector) Connect(context.Context) (driver.Conn, error) { return c.drv.Open(c.dsn) }

func (c *inMemoryConnector) Driver() driver.Driver { return c.drv }

func (c *inMemoryConnector) Close() error { return c.keep.Close() }
