/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
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
// them explicitly. Replace selects INSERT OR REPLACE over INSERT. The
// timestamps are stored as given: the key generator stamps active_at for a
// key it mints active, a bulk import carries the exported values.
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

// keyStateFlags is the flag table of design §3.4 for pub and sign: what each
// lifecycle state means to the DNSKEY publisher and to the signer. ds is not
// in it: it depends on the zone's DS model as well as on the state, and is
// written by the state machine that owns the zone at the transition.
//
// The three multi-provider states are here while tdns still names them
// (structs.go); an owner registers its own through RegisterKeyStateFlags.
var keyStateFlags = map[string]KeyRowFlags{
	DnskeyStateCreated:     {},
	DnskeyStateDsPublished: {},
	DnskeyStatePublished:   {Pub: true},
	DnskeyStateStandby:     {Pub: true},
	DnskeyStateActive:      {Pub: true, Sign: true},
	DnskeyStateRetired:     {Pub: true},
	DnskeyStateRemoved:     {},
	DnskeyStateMpdist:      {Pub: true},
	DnskeyStateForeign:     {Pub: true},
	DnskeyStateMpremove:    {},
}

var (
	ownerKeyStateFlagsMu sync.RWMutex
	ownerKeyStateFlags   = map[string]KeyRowFlags{}
)

// RegisterKeyStateFlags adds an owner's states to the flag table, or replaces
// tdns's entry for a state the owner takes over. Register before the keystore
// is opened, so the backfill at open knows the states; an owner that inserts
// rows outside insertKeyRowTx calls BackfillKeyRowFlags afterwards.
func RegisterKeyStateFlags(table map[string]KeyRowFlags) {
	ownerKeyStateFlagsMu.Lock()
	defer ownerKeyStateFlagsMu.Unlock()
	for state, f := range table {
		ownerKeyStateFlags[state] = f
	}
}

// keyFlagsForState is the flag table lookup: the owner's entry first, then
// tdns's. ok is false for a state neither knows.
func keyFlagsForState(state string) (KeyRowFlags, bool) {
	ownerKeyStateFlagsMu.RLock()
	f, ok := ownerKeyStateFlags[state]
	ownerKeyStateFlagsMu.RUnlock()
	if ok {
		return f, true
	}
	f, ok = keyStateFlags[state]
	return f, ok
}

// knownKeyStates lists every state in the flag table, sorted.
func knownKeyStates() []string {
	ownerKeyStateFlagsMu.RLock()
	defer ownerKeyStateFlagsMu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for s := range keyStateFlags {
		seen[s] = true
		out = append(out, s)
	}
	for s := range ownerKeyStateFlags {
		if !seen[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var errKeyRowNotFound = errors.New("key not found")

// setKeyRowTx is the only UPDATE of DnssecKeyStore.state. It writes the state
// and its flags in one statement, stamps the timestamp the new state owns
// (published_at, active_at or retired_at), and returns the state the row was
// in. With expectOld set it is a compare-and-set: a row in another state is
// left alone and an error returned. ds is written only when f.DS is Valid;
// otherwise the column keeps what it has.
//
// A write that leaves the state as it is keeps a timestamp the row already
// has: setting a published key published again must not restart its
// propagation clock. It still fills one that is empty, which is how the key
// state worker stamps a legacy key that has none.
//
// The invariants the writer can see are enforced here rather than left to the
// checker: sign implies pub (I1), and ds only on a key with the SEP bit (I3).
func setKeyRowTx(tx *Tx, zone string, keyid uint16, state string, f KeyRowFlags, expectOld string) (string, error) {
	var old string
	var flags int
	err := tx.QueryRow(`SELECT state, flags FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, keyid).Scan(&old, &flags)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("key with keyid %d not found in zone %s: %w", keyid, zone, errKeyRowNotFound)
		}
		return "", fmt.Errorf("error querying DnssecKeyStore: %v", err)
	}
	if expectOld != "" && old != expectOld {
		return "", fmt.Errorf("key with keyid %d in zone %s is not in state %s", keyid, zone, expectOld)
	}
	if !f.DS.Valid {
		// The caller left ds open: the zone's DS model decides (keyrow_ds.go).
		ds, err := dsForKeyTx(tx, zone, keyid, state, uint16(flags))
		if err != nil {
			return "", fmt.Errorf("key with keyid %d in zone %s to state %s: %w", keyid, zone, state, err)
		}
		f.DS = ds
	}
	if err := checkKeyRowFlags(f, uint16(flags)); err != nil {
		return "", fmt.Errorf("key with keyid %d in zone %s to state %s: %w", keyid, zone, state, err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	q := `UPDATE DnssecKeyStore SET state=?, pub=?, sign=?`
	args := []any{state, boolInt(f.Pub), boolInt(f.Sign)}
	if f.DS.Valid {
		q += `, ds=?`
		args = append(args, boolInt(f.DS.Bool))
	}
	stamp := func(col string) {
		if old == state {
			// Keep a timestamp the row has; fill one it lacks.
			q += `, ` + col + ` = CASE WHEN ` + col + ` IS NULL OR ` + col + ` = '' THEN ? ELSE ` + col + ` END`
		} else {
			q += `, ` + col + `=?`
		}
		args = append(args, now)
	}
	switch state {
	case DnskeyStatePublished:
		stamp("published_at")
	case DnskeyStateActive:
		stamp("active_at")
	case DnskeyStateRetired:
		stamp("retired_at")
	}
	q += ` WHERE zonename=? AND keyid=?`
	args = append(args, zone, keyid)
	if expectOld != "" {
		q += ` AND state=?`
		args = append(args, expectOld)
	}
	res, err := tx.Exec(q, args...)
	if err != nil {
		return "", fmt.Errorf("error updating DnssecKeyStore: %v", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", fmt.Errorf("no rows updated for key %d in zone %s", keyid, zone)
	}
	return old, nil
}

// checkKeyRowFlags is what a writer can verify of the invariants: I1, sign
// implies pub; I3, ds only on a key with the SEP bit.
func checkKeyRowFlags(f KeyRowFlags, flags uint16) error {
	if f.Sign && !f.Pub {
		return errors.New("sign set without pub: a key cannot sign without being in the DNSKEY RRset")
	}
	if f.DS.Valid && f.DS.Bool && flags&dns.SEP == 0 {
		return errors.New("ds set on a key without the SEP bit")
	}
	return nil
}

// insertKeyRowTx is the only INSERT into DnssecKeyStore.
func insertKeyRowTx(tx *Tx, row KeyRow) error {
	f := KeyRowFlags{}
	if row.RowFlags != nil {
		f = *row.RowFlags
	} else {
		var ok bool
		if f, ok = keyFlagsForState(row.State); !ok {
			return fmt.Errorf("insertKeyRowTx: no flags known for key state %q (zone %s, keyid %d); register the state with RegisterKeyStateFlags or pass the flags", row.State, row.Zone, row.Keyid)
		}
	}
	if !f.DS.Valid {
		// The caller left ds open: the zone's DS model decides (keyrow_ds.go).
		ds, err := dsForKeyTx(tx, row.Zone, row.Keyid, row.State, row.Flags)
		if err != nil {
			return fmt.Errorf("insertKeyRowTx: %s keyid %d: %w", row.Zone, row.Keyid, err)
		}
		f.DS = ds
	}
	if err := checkKeyRowFlags(f, row.Flags); err != nil {
		return fmt.Errorf("insertKeyRowTx: %s keyid %d: %w", row.Zone, row.Keyid, err)
	}
	var comment, ds any
	if row.Comment != "" {
		comment = row.Comment
	}
	if f.DS.Valid {
		ds = boolInt(f.DS.Bool)
	}
	var seq any
	if row.ActiveSeq != nil {
		seq = *row.ActiveSeq
	}
	q := `INSERT INTO DnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq, pub, sign, ds)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if row.Replace {
		q = `INSERT OR REPLACE INTO DnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq, pub, sign, ds)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	}
	_, err := tx.Exec(q, row.Zone, row.State, int(row.Keyid), int(row.Flags), row.Algorithm, row.Creator,
		row.PrivateKey, row.KeyRR, comment, row.PublishedAt, row.ActiveAt, row.RetiredAt, seq,
		boolInt(f.Pub), boolInt(f.Sign), ds)
	if err != nil {
		return fmt.Errorf("insertKeyRowTx: %s keyid %d: %w", row.Zone, row.Keyid, err)
	}
	return nil
}

// InsertKeyRowTx is insertKeyRowTx for an owner writing its own rows.
func InsertKeyRowTx(tx *Tx, row KeyRow) error { return insertKeyRowTx(tx, row) }

// keyFlagBackfillSql is the NULL-gated backfill, built from the flag table so
// the table stays the one source: a row with pub or sign unset gets each
// unset one from its state. A state the table does not know stays unset, and
// I8 reports it.
func keyFlagBackfillSql() string {
	var pub, sign strings.Builder
	for _, state := range knownKeyStates() {
		f, _ := keyFlagsForState(state)
		fmt.Fprintf(&pub, " WHEN '%s' THEN %d", state, boolInt(f.Pub))
		fmt.Fprintf(&sign, " WHEN '%s' THEN %d", state, boolInt(f.Sign))
	}
	return `UPDATE DnssecKeyStore SET pub = COALESCE(pub, CASE state` + pub.String() + ` END),
sign = COALESCE(sign, CASE state` + sign.String() + ` END)
WHERE pub IS NULL OR sign IS NULL`
}

func backfillKeyRowFlags(db *sql.DB) (int64, error) {
	res, err := db.Exec(keyFlagBackfillSql())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// BackfillKeyRowFlags derives pub and sign from state for every row that has
// them unset. It runs at every open; an owner that inserts rows outside
// insertKeyRowTx calls it afterwards. Returns the number of rows touched.
func (kdb *KeyDB) BackfillKeyRowFlags() (int64, error) { return backfillKeyRowFlags(kdb.DB) }

// The sets the code before the key columns computed from the states, kept
// while S1a is the running code so that startup can compare them with the
// columns (design R1). S4 removes them with the state names. The comparison
// covers the states that code knew, tdns's own table: a state an owner
// registers beyond them has no "old way" to compare with and is left out of
// both sides.
const (
	stateSigningKeysSql = `SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND state='active'`
	stateServedKeysSql  = `SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND state IN ('active','published','standby','retired','mpdist','foreign')`
)

var (
	columnSigningKeysSql = `SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND sign=1 AND state IN (` + sqlStateList(keyStateFlags) + `)`
	columnServedKeysSql  = `SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND pub=1 AND state IN (` + sqlStateList(keyStateFlags) + `)`
)

// sqlStateList renders the states of a flag table as a quoted, sorted SQL list.
func sqlStateList(table map[string]KeyRowFlags) string {
	var states []string
	for s := range table {
		states = append(states, "'"+s+"'")
	}
	sort.Strings(states)
	return strings.Join(states, ",")
}

// CheckKeyColumnEquivalence compares, per zone, the signing set and the served
// DNSKEY set computed from the states with the same sets computed from the
// columns, and describes every difference.
func (kdb *KeyDB) CheckKeyColumnEquivalence() []string {
	zones, err := kdb.keystoreZones()
	if err != nil {
		return []string{fmt.Sprintf("listing keystore zones: %v", err)}
	}
	var diffs []string
	for _, zone := range zones {
		for _, c := range []struct{ what, ref, col string }{
			{"signing set", stateSigningKeysSql, columnSigningKeysSql},
			{"served DNSKEY set", stateServedKeysSql, columnServedKeysSql},
		} {
			ref, err1 := kdb.keyidList(c.ref, zone)
			col, err2 := kdb.keyidList(c.col, zone)
			if err1 != nil || err2 != nil {
				diffs = append(diffs, fmt.Sprintf("zone %s: %s: %v %v", zone, c.what, err1, err2))
				continue
			}
			if fmt.Sprint(ref) != fmt.Sprint(col) {
				diffs = append(diffs, fmt.Sprintf("zone %s: %s from state %v, from the columns %v", zone, c.what, ref, col))
			}
		}
	}
	return diffs
}

func (kdb *KeyDB) keystoreZones() ([]string, error) {
	rows, err := kdb.DB.Query(`SELECT DISTINCT zonename FROM DnssecKeyStore ORDER BY zonename`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var z string
		if err := rows.Scan(&z); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

func (kdb *KeyDB) keyidList(q, zone string) ([]int, error) {
	rows, err := kdb.DB.Query(q, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var k int
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	sort.Ints(out)
	return out, rows.Err()
}

// checkKeyColumnsAtOpen guards the open: the columns must exist and every
// row in a known state must carry pub and sign, or the signer and the DNSKEY
// publisher would read nothing; that refuses the open in every mode. Then
// the equivalence check runs: every difference is logged, and in strict
// mode the open fails.
func (kdb *KeyDB) checkKeyColumnsAtOpen() error {
	for _, col := range []string{"pub", "sign", "ds"} {
		if !dbColumnExists(kdb.DB, "DnssecKeyStore", col) {
			return fmt.Errorf("keystore: DnssecKeyStore has no %q column; the schema migration failed", col)
		}
	}
	var unset int
	states := sqlStateList(keyStateFlags)
	ownerKeyStateFlagsMu.RLock()
	if len(ownerKeyStateFlags) > 0 {
		states += "," + sqlStateList(ownerKeyStateFlags)
	}
	ownerKeyStateFlagsMu.RUnlock()
	err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE (pub IS NULL OR sign IS NULL) AND state IN (` + states + `)`).Scan(&unset)
	if err != nil {
		return fmt.Errorf("keystore: counting key rows without flags: %w", err)
	}
	if unset > 0 {
		return fmt.Errorf("keystore: %d key row(s) in a known state have pub or sign unset; the backfill at open failed", unset)
	}
	diffs := kdb.CheckKeyColumnEquivalence()
	if len(diffs) == 0 {
		return nil
	}
	for _, d := range diffs {
		lgConfig.Error("keystore: the key columns disagree with the states", "diff", d)
	}
	if KeyColumnsStrict || os.Getenv("TDNS_STRICT_KEY_COLUMNS") != "" {
		return fmt.Errorf("keystore: the key columns disagree with the states (strict mode): %s", strings.Join(diffs, "; "))
	}
	return nil
}

func nullBoolPtr(v sql.NullInt64) *bool {
	if !v.Valid {
		return nil
	}
	b := v.Int64 != 0
	return &b
}
