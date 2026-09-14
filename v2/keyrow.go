/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
	"errors"
)

// KeyRowFlags are the mechanism columns of a DnssecKeyStore row, kept beside
// the lifecycle state and written together with it (design §3.1):
//
//	pub  - the key is in the zone's DNSKEY RRset
//	sign - the key signs (its role comes from the DNSKEY flags)
//	ds   - the key should have a DS at the parent; not Valid means unknown
//
// The signer and the DNSKEY publisher read only these. Whichever state
// machine owns the zone reads the state and writes the flags.
type KeyRowFlags struct {
	Pub  bool
	Sign bool
	DS   sql.NullBool
}

// KeyRow is one DnssecKeyStore row as insertKeyRowTx stores it. RowFlags nil
// means the flags follow from State through the flag table; an owner passes
// them explicitly. Replace selects INSERT OR REPLACE over INSERT.
type KeyRow struct {
	Zone        string
	State       string
	Keyid       uint16
	Flags       uint16
	Algorithm   string
	Creator     string
	PrivateKey  string
	KeyRR       string
	Comment     string
	PublishedAt string
	ActiveAt    string
	RetiredAt   string
	ActiveSeq   *int64
	RowFlags    *KeyRowFlags
	Replace     bool
}

// KeyColumnsStrict makes a mismatch between the key columns and the states
// they were derived from refuse to open the keystore instead of being logged
// (design R1). Test builds set it; TDNS_STRICT_KEY_COLUMNS sets it too.
var KeyColumnsStrict bool

var errKeyRowsNotImplemented = errors.New("keystore key columns are not implemented yet")

func keyFlagsForState(state string) (KeyRowFlags, bool) { return KeyRowFlags{}, false }

// RegisterKeyStateFlags adds an owner's states to the flag table.
func RegisterKeyStateFlags(table map[string]KeyRowFlags) {}

func setKeyRowTx(tx *Tx, zone string, keyid uint16, state string, f KeyRowFlags, expectOld string) (string, error) {
	return "", errKeyRowsNotImplemented
}

func insertKeyRowTx(tx *Tx, row KeyRow) error { return errKeyRowsNotImplemented }

// InsertKeyRowTx is insertKeyRowTx for an owner writing its own rows.
func InsertKeyRowTx(tx *Tx, row KeyRow) error { return insertKeyRowTx(tx, row) }

// BackfillKeyRowFlags derives pub and sign from state for every row that has
// them unset. It runs at every open; an owner that inserts rows outside
// insertKeyRowTx calls it afterwards.
func (kdb *KeyDB) BackfillKeyRowFlags() (int64, error) { return 0, errKeyRowsNotImplemented }

// CheckKeyColumnEquivalence compares, per zone, the signing set and the served
// DNSKEY set computed from the states with the same sets computed from the
// columns, and describes every difference.
func (kdb *KeyDB) CheckKeyColumnEquivalence() []string { return []string{"not implemented"} }

// KeyInvariantViolation is one finding of CheckKeyInvariants: which invariant
// (I1..I9 of the test plan), in which zone, for which key.
type KeyInvariantViolation struct {
	Invariant string
	Zone      string
	KeyID     uint16
	Detail    string
}

func (v KeyInvariantViolation) String() string { return v.Invariant + " " + v.Zone + " " + v.Detail }

// CheckKeyInvariants checks I1-I9 for one zone: the row-level invariants
// against the keystore, and the served-zone ones (I5, I6, I7) against zd's
// snapshot when the zone is loaded.
func CheckKeyInvariants(kdb *KeyDB, zd *ZoneData) []KeyInvariantViolation {
	return []KeyInvariantViolation{{Invariant: "I0", Detail: "not implemented"}}
}

// CheckKeyRowInvariants is CheckKeyInvariants for a zone that is not loaded.
func CheckKeyRowInvariants(kdb *KeyDB, zone string) []KeyInvariantViolation {
	return []KeyInvariantViolation{{Invariant: "I0", Zone: zone, Detail: "not implemented"}}
}
