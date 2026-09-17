package tdns

import (
	"time"
)

// Zone transactions: a publish hold on one zone, declared by the writer.
//
//	{start tx  <zone> <id> <flags>}
//	   ... changes ...
//	{commit tx <zone> <id>}
//
// See docs/2026-09-17-publish-gate-and-transactions.md. While a zone has an
// open transaction nothing publishes it; what any writer stages in the
// meantime goes out with the commit that closes the hold. A transaction is not
// isolation and there is no rollback.
//
// STUBS. This file is the API surface the step's tests are written against;
// nothing in it holds anything yet. CreateAutoZoneHeld creates the zone the way
// CreateAutoZone does today, so the tests fail the way the defect they
// describe fails.

// TxID names one transaction on one zone. A writer that queues its markers
// chooses the id; BeginTx allocates one.
type TxID string

// TxFlags are the flags of a transaction's start marker.
type TxFlags uint8

const (
	// TxUrgent asks for the commit that closes the hold to publish at once
	// instead of through the gate. It is sticky for the hold: if any
	// transaction of the hold carried it, the closing commit is urgent.
	TxUrgent TxFlags = 1 << iota
)

// The UpdateRequest commands of the two markers.
const (
	UpdateCmdTxBegin  = "TX-BEGIN"
	UpdateCmdTxCommit = "TX-COMMIT"
)

// txHoldLimit is how long a transaction may stay open before its commit is
// taken for lost. A constant as far as configuration goes: there is no knob.
// A variable only so that a test does not have to wait thirty seconds.
var txHoldLimit = 30 * time.Second

// txImplemented gates the tests of this step until the step's last commit.
const txImplemented = false

// BeginTx opens a transaction on the zone, in-process, and returns its id.
// For a writer that also stages in-process; a writer that queues its changes
// queues its markers too.
func (zd *ZoneData) BeginTx(flags TxFlags) TxID {
	return ""
}

// CommitTx commits an in-process transaction. When the commit closes the hold
// on a zone that is not Ready, or the hold was urgent, the publish happens in
// the caller and its outcome is the return value.
func (zd *ZoneData) CommitTx(id TxID) error {
	return nil
}

// txOpenCount reports how many transactions are open on the zone.
func (zd *ZoneData) txOpenCount() int {
	return 0
}

// txStoppedPublishes reports how many publishes the zone's holds have stopped.
func (zd *ZoneData) txStoppedPublishes() uint64 {
	return 0
}

// CreateAutoZoneHeld is CreateAutoZone for a zone whose first content is a
// transaction: the zone is registered, holds the returned transaction, and has
// no snapshot until that transaction commits.
func (kdb *KeyDB) CreateAutoZoneHeld(zonename string, addrs []string, nsNames []string) (*ZoneData, TxID, error) {
	zd, err := kdb.CreateAutoZone(zonename, addrs, nsNames)
	return zd, "", err
}
