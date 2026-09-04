/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

// The ledger of RFC 9615 signal names this server has published, and the sole
// authority for deleting one. See docs/2026-09-03-signal-name-withdrawal.md.
//
// Publication is content-gated (signalRRsEqual) against what is already at the
// name; a record we did not put there is not ours to remove, and zone data
// carries no provenance, so removal reads this table instead. A publication
// this table has forgotten is indistinguishable from one that never happened,
// which makes the whole mechanism fail closed: a lost keystore leaves records
// behind rather than deleting an operator's own.

package tdns

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// The two publishers, as recorded in SignalPublication.source.
const (
	// signalSourceHsyncparam: the transfer-driven republisher, acting on a
	// customer zone's apex HSYNCPARAM under the use-hsyncparam option.
	signalSourceHsyncparam = "hsyncparam"
	// signalSourceAtNs: the child's own SIG(0) bootstrap ceremony, which puts
	// the KEY at the signal name before the self-signed UPDATE goes out.
	signalSourceAtNs = "at-ns"
)

// SignalPublication is one published signal name: the RRset of the prefix's
// types at Owner, in the local primary zone Target, holding the bootstrap data
// of Zone as served by nameserver NS.
type SignalPublication struct {
	Target string
	Owner  string
	Zone   string
	NS     string
	Prefix string
	Source string
}

// signalLedgerEmpty is the fast path for the overwhelmingly common deployment
// that has never published at a signal name. The reconciler runs on every zone
// after every refresh; without this it would be a database query per zone per
// refresh to learn there is nothing to reconcile.
//
// Process-wide rather than per-KeyDB because a daemon has one keystore; a test
// process with several sees only a stale hint, never a wrong answer.
// Conservative in the direction that matters: it starts false (assume rows
// exist) and only becomes true once a count has actually said so, so a
// mis-tracked write costs a query, never a missed withdrawal.
var signalLedgerEmpty atomic.Bool

// signalLedgerMu serializes ledger WRITES with the empty-flag update.
//
// Without it the flag can go wrongly true: RefreshSignalLedgerEmpty counts
// zero, a concurrent RecordSignalPublication inserts a row, and the stale count
// is then stored as "empty" -- which makes every reconciler take the fast path
// and skip withdrawal entirely, silently, until something else recomputes it.
// A wrong "false" only costs a query; a wrong "true" disables the feature with
// nothing in the log, so this is worth a mutex on a path that writes a handful
// of rows per refresh at most.
var signalLedgerMu sync.Mutex

// RefreshSignalLedgerEmpty recomputes the empty-ledger fast path from the
// table. Called when the KeyDB is opened and after every delete.
func (kdb *KeyDB) RefreshSignalLedgerEmpty() {
	signalLedgerMu.Lock()
	defer signalLedgerMu.Unlock()
	kdb.refreshSignalLedgerEmptyLocked()
}

// refreshSignalLedgerEmptyLocked is RefreshSignalLedgerEmpty with the caller
// already holding signalLedgerMu.
func (kdb *KeyDB) refreshSignalLedgerEmptyLocked() {
	if kdb == nil || kdb.DB == nil {
		return
	}
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM SignalPublication`).Scan(&n); err != nil {
		// Cannot prove it is empty, so do not claim it: the reconciler falls
		// back to querying, which reports the real error at the real call site.
		signalLedgerEmpty.Store(false)
		return
	}
	signalLedgerEmpty.Store(n == 0)
}

// RecordSignalPublication records one published signal name, keyed on
// (target, owner). The publisher calls this on every refresh that finds the
// name published -- including the change-gated pass that wrote nothing -- so
// the statement is an upsert whose UPDATE is guarded on something having
// actually changed. A re-publish of an unchanged name is then a statement that
// modifies no row: no write, no journal, and published_at keeps meaning "when
// this server first put the record there" rather than "the last time anyone
// asked".
func (kdb *KeyDB) RecordSignalPublication(p SignalPublication) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("RecordSignalPublication: no database")
	}
	// Held across the insert AND the flag update: see signalLedgerMu.
	signalLedgerMu.Lock()
	defer signalLedgerMu.Unlock()
	_, err := kdb.DB.Exec(
		`INSERT INTO SignalPublication (target, owner, zone, ns, prefix, source, published_at)
		 VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(target, owner) DO UPDATE SET
		     zone = excluded.zone, ns = excluded.ns,
		     prefix = excluded.prefix, source = excluded.source
		 WHERE zone <> excluded.zone OR ns <> excluded.ns
		    OR prefix <> excluded.prefix OR source <> excluded.source`,
		p.Target, p.Owner, p.Zone, p.NS, p.Prefix, p.Source)
	if err != nil {
		return fmt.Errorf("RecordSignalPublication(%s in %s): %w", p.Owner, p.Target, err)
	}
	signalLedgerEmpty.Store(false)
	return nil
}

// ForgetSignalPublication drops one row, after the record it describes has been
// withdrawn (or found to be gone already). Deleting a row that does not exist is
// not an error.
func (kdb *KeyDB) ForgetSignalPublication(target, owner string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("ForgetSignalPublication: no database")
	}
	signalLedgerMu.Lock()
	defer signalLedgerMu.Unlock()
	_, err := kdb.DB.Exec(`DELETE FROM SignalPublication WHERE target = ? AND owner = ?`, target, owner)
	if err != nil {
		return fmt.Errorf("ForgetSignalPublication(%s in %s): %w", owner, target, err)
	}
	kdb.refreshSignalLedgerEmptyLocked()
	return nil
}

// SignalLedgerReadable reports whether there is a ledger to consult at all.
// A deployment with no keystore has published nothing and can withdraw
// nothing, and the reconciler runs on every zone after every refresh -- saying
// "no database" that often is noise, not news.
func SignalLedgerReadable(kdb *KeyDB) bool {
	return kdb != nil && kdb.DB != nil
}

// SignalPublicationsForZone lists what has been published FOR a zone -- the
// question the reconciler asks about the zone it just refreshed.
func (kdb *KeyDB) SignalPublicationsForZone(zone string) ([]SignalPublication, error) {
	return kdb.signalPublicationsWhere(`zone = ?`, zone)
}

// SignalPublicationsForTarget lists what has been published INTO a zone -- the
// question a target zone asks on behalf of published-for zones that are no
// longer served here at all.
func (kdb *KeyDB) SignalPublicationsForTarget(target string) ([]SignalPublication, error) {
	return kdb.signalPublicationsWhere(`target = ?`, target)
}

// AllSignalPublications lists the whole ledger, for the one-shot sweep at the
// end of startup.
func (kdb *KeyDB) AllSignalPublications() ([]SignalPublication, error) {
	return kdb.signalPublicationsWhere(``)
}

func (kdb *KeyDB) signalPublicationsWhere(where string, args ...any) ([]SignalPublication, error) {
	if kdb == nil || kdb.DB == nil {
		return nil, fmt.Errorf("signalPublicationsWhere: no database")
	}
	q := `SELECT target, owner, zone, ns, prefix, source FROM SignalPublication`
	if where != "" {
		q += ` WHERE ` + where
	}
	rows, err := kdb.DB.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("signalPublications: %w", err)
	}
	defer rows.Close()

	var out []SignalPublication
	for rows.Next() {
		var p SignalPublication
		if err := rows.Scan(&p.Target, &p.Owner, &p.Zone, &p.NS, &p.Prefix, &p.Source); err != nil {
			return nil, fmt.Errorf("signalPublications: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("signalPublications: %w", err)
	}
	return out, nil
}
