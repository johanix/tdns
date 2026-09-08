/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

// Package externaldb is the external-db delegation store: the store half of
// a delegation backend, kept in a shared MariaDB that a registry provisioning
// system reads. It exists as its own module so that its driver is linked
// into exactly the binaries whose main imports it -- tdns-agent -- and no
// other (docs/2026-09-08-childsync-proxy.md §5.8, amendment A-3).
//
// It holds the delegation handoff and nothing else. The KeyDB, with its key
// material, truststore and journal, stays sqlite, local and private (D-8).
// And it does not inherit the KeyDB's process-wide single-transaction gate:
// an ordinary database/sql pool with per-call transactions is what a store
// shared with a second process needs (D-9).
package externaldb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

func init() {
	tdns.RegisterDelegationStore(tdns.DelegationStoreExternalDB, New)
}

// Store is one zone's handle on the external database. Several zones with
// the same DSN share the connection pool.
type Store struct {
	db      *sql.DB
	d       *dialect
	prefix  string
	timeout time.Duration
}

var pools = struct {
	sync.Mutex
	byKey map[string]*sql.DB
}{byKey: map[string]*sql.DB{}}

// New is the DelegationStoreFactory registered as "external-db".
func New(spec tdns.DelegationBackendSpec, _ *tdns.KeyDB, _ *tdns.ZoneData) (tdns.DelegationStore, error) {
	return Open(spec.Conf.ExternalDB)
}

// Open connects, optionally creates the tables, and verifies the schema.
// A database that cannot be reached, or whose schema does not fit, is an
// error here -- which parseconfig turns into the ZONE's ConfigError, not the
// daemon's fatal (§5.8.4).
func Open(c tdns.ExternalDBConf) (*Store, error) {
	driver := strings.ToLower(strings.TrimSpace(c.Driver))
	if driver == "" {
		driver = "mysql"
	}
	d, ok := dialects[driver]
	if !ok {
		return nil, fmt.Errorf("external-db: unsupported driver %q (mysql)", c.Driver)
	}
	if c.DSN.Value() == "" {
		return nil, errors.New("external-db: dsn is required")
	}
	dsn, err := d.dsn(c)
	if err != nil {
		return nil, err
	}
	prefix := c.TablePrefix
	if prefix == "" {
		prefix = DefaultTablePrefix
	}
	db, err := openPool(d.driverName, dsn, c.MaxOpenConns)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, d: d, prefix: prefix, timeout: timeoutOf(c)}

	ctx, cancel := s.ctx()
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("external-db: cannot reach the database: %w", err)
	}
	if c.AutoMigrate {
		if err := s.Migrate(ctx); err != nil {
			return nil, err
		}
	}
	if err := s.VerifySchema(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func openPool(driver, dsn string, maxOpen int) (*sql.DB, error) {
	pools.Lock()
	defer pools.Unlock()
	key := driver + "\x00" + dsn
	if db, ok := pools.byKey[key]; ok {
		return db, nil
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("external-db: open: %w", err)
	}
	if maxOpen <= 0 {
		maxOpen = 8
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetConnMaxIdleTime(5 * time.Minute)
	pools.byKey[key] = db
	return db, nil
}

func (s *Store) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.timeout)
}

func (s *Store) table(t string) string { return s.prefix + t }

// q renders "?" markers in the dialect's placeholder style.
func (s *Store) q(sql string) string {
	if s.d.placeholder(1) == "?" {
		return sql
	}
	var b strings.Builder
	n := 0
	for _, ch := range sql {
		if ch == '?' {
			n++
			b.WriteString(s.d.placeholder(n))
			continue
		}
		b.WriteRune(ch)
	}
	return b.String()
}

func (s *Store) Name() string { return tdns.DelegationStoreExternalDB }

// rrText is the stored form: TTL 0, class IN -- the same normalisation the
// sqlite store applies, so the two agree on what a record IS.
func rrText(rr dns.RR) string {
	c := dns.Copy(rr)
	c.Header().Ttl = 0
	c.Header().Class = dns.ClassINET
	return c.String()
}

// rrHash is the key column for the unbounded rr text: its SHA-256, the value
// UNHEX(SHA2(rr, 256)) would give, so a consumer can verify it in SQL.
func rrHash(text string) []byte {
	h := sha256.Sum256([]byte(text))
	return h[:]
}

func newChangeID() ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("external-db: change id: %w", err)
	}
	return id, nil
}

// channelOf names the channel an update arrived on, for the log. The
// UpdateRequest does not carry it, so this is what its flags say: a
// validated request came over DNS UPDATE, an internal one from this server,
// and the rest from the scanner or the API.
func channelOf(ur tdns.UpdateRequest) string {
	switch {
	case ur.InternalUpdate:
		return "internal"
	case ur.Validated:
		return "update"
	case strings.Contains(strings.ToLower(ur.Description), "api"):
		return "dsync-api"
	}
	return "scanner"
}

// logAction appends one row to the change log and returns its revision.
func (s *Store) logAction(ctx context.Context, tx *sql.Tx, changeID []byte, parent, child, op, owner, rrtype string, rr *string, channel string) (int64, error) {
	var rrv sql.NullString
	if rr != nil {
		rrv = sql.NullString{String: *rr, Valid: true}
	}
	res, err := tx.ExecContext(ctx, s.q(fmt.Sprintf(
		`INSERT INTO %s (change_id, parent, child, op, owner, rrtype, rr, channel, principal, applied_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NOW(3))`,
		s.table("delegation_log"))),
		changeID, parent, child, op, owner, rrtype, rrv, channel)
	if err != nil {
		return 0, fmt.Errorf("external-db: log %s %s %s: %w", op, owner, rrtype, err)
	}
	rev, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("external-db: log revision: %w", err)
	}
	return rev, nil
}

func (s *Store) upsertState(ctx context.Context, tx *sql.Tx, parent, child, owner, rrtype, rr, origin string, rev int64) error {
	_, err := tx.ExecContext(ctx, s.q(fmt.Sprintf(s.d.upsertState, s.table("delegation"))),
		parent, child, owner, rrtype, rr, rrHash(rr), origin, rev)
	if err != nil {
		return fmt.Errorf("external-db: upsert %s %s: %w", owner, rrtype, err)
	}
	return nil
}

// ApplyChildUpdate records one child update as one change: every action goes
// to the log under one change_id and to the state table, in one transaction.
// A consumer reading the log in revision order and stopping at a change_id
// boundary never sees half a change (§5.8.2).
func (s *Store) ApplyChildUpdate(parentZone string, ur tdns.UpdateRequest) (err error) {
	ctx, cancel := s.ctx()
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("external-db: begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	changeID, err := newChangeID()
	if err != nil {
		return err
	}
	channel := channelOf(ur)

	for _, rr := range ur.Actions {
		owner := rr.Header().Name
		rrtype := dns.TypeToString[rr.Header().Rrtype]
		child := tdns.ChildZoneFromOwner(owner, parentZone)
		text := rrText(rr)

		switch rr.Header().Class {
		case dns.ClassNONE:
			if _, err = s.logAction(ctx, tx, changeID, parentZone, child, "del-rr", owner, rrtype, &text, channel); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, s.q(fmt.Sprintf(
				`DELETE FROM %s WHERE parent = ? AND owner = ? AND rrtype = ? AND rr_hash = ?`, s.table("delegation"))),
				parentZone, owner, rrtype, rrHash(text)); err != nil {
				return fmt.Errorf("external-db: delete RR: %w", err)
			}
		case dns.ClassANY:
			if _, err = s.logAction(ctx, tx, changeID, parentZone, child, "del-rrset", owner, rrtype, nil, channel); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, s.q(fmt.Sprintf(
				`DELETE FROM %s WHERE parent = ? AND owner = ? AND rrtype = ?`, s.table("delegation"))),
				parentZone, owner, rrtype); err != nil {
				return fmt.Errorf("external-db: delete RRset: %w", err)
			}
		case dns.ClassINET:
			var rev int64
			if rev, err = s.logAction(ctx, tx, changeID, parentZone, child, "add", owner, rrtype, &text, channel); err != nil {
				return err
			}
			if err = s.upsertState(ctx, tx, parentZone, child, owner, rrtype, text, "asserted", rev); err != nil {
				return err
			}
		default:
			// Unknown class: skipped, as the sqlite store skips it.
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("external-db: commit: %w", err)
	}
	return nil
}

// GetDelegationData reads the intended state. A child with no rows is an
// empty map and a nil error; an error means the store could not be read.
func (s *Store) GetDelegationData(parentZone, childZone string) (map[string]map[uint16][]dns.RR, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, s.q(fmt.Sprintf(
		`SELECT owner, rrtype, rr FROM %s WHERE parent = ? AND child = ?`, s.table("delegation"))), parentZone, childZone)
	if err != nil {
		return nil, fmt.Errorf("external-db: query: %w", err)
	}
	defer rows.Close()
	out := map[string]map[uint16][]dns.RR{}
	for rows.Next() {
		var owner, rrtype, text string
		if err := rows.Scan(&owner, &rrtype, &text); err != nil {
			return nil, fmt.Errorf("external-db: scan: %w", err)
		}
		rr, err := dns.NewRR(text)
		if err != nil {
			continue // a row that does not parse is not this child's delegation
		}
		t := rr.Header().Rrtype
		if out[owner] == nil {
			out[owner] = map[uint16][]dns.RR{}
		}
		out[owner][t] = append(out[owner][t], rr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("external-db: rows: %w", err)
	}
	return out, nil
}

func (s *Store) ListChildren(parentZone string) ([]string, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, s.q(fmt.Sprintf(
		`SELECT DISTINCT child FROM %s WHERE parent = ? ORDER BY child`, s.table("delegation"))), parentZone)
	if err != nil {
		return nil, fmt.Errorf("external-db: query: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("external-db: scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AdoptChildDelegation implements tdns.DelegationAdopter: the rows are
// written only if the store holds nothing for the child, as one change on
// the "adopt" channel, marked observed.
func (s *Store) AdoptChildDelegation(parentZone, childZone string, rrs []dns.RR) (n int, err error) {
	ctx, cancel := s.ctx()
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("external-db: begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var existing int
	if err = tx.QueryRowContext(ctx, s.q(fmt.Sprintf(
		`SELECT COUNT(*) FROM %s WHERE parent = ? AND child = ?`, s.table("delegation"))), parentZone, childZone).Scan(&existing); err != nil {
		return 0, fmt.Errorf("external-db: count: %w", err)
	}
	if existing > 0 {
		return 0, tx.Commit()
	}
	changeID, err := newChangeID()
	if err != nil {
		return 0, err
	}
	for _, rr := range rrs {
		owner := rr.Header().Name
		rrtype := dns.TypeToString[rr.Header().Rrtype]
		text := rrText(rr)
		var rev int64
		if rev, err = s.logAction(ctx, tx, changeID, parentZone, childZone, "add", owner, rrtype, &text, "adopt"); err != nil {
			return n, err
		}
		if err = s.upsertState(ctx, tx, parentZone, childZone, owner, rrtype, text, "observed", rev); err != nil {
			return n, err
		}
		n++
	}
	if err = tx.Commit(); err != nil {
		return n, fmt.Errorf("external-db: commit: %w", err)
	}
	return n, nil
}

// LogEntry is one row of the change log, for tests and for an operator's
// inspection.
type LogEntry struct {
	Revision  int64
	ChangeID  []byte
	Child     string
	Op        string
	Owner     string
	RRtype    string
	RR        string
	Channel   string
	AppliedAt time.Time
}

// Log reads a parent's change log from a revision, in order: the consumer's
// incremental read (§5.8.2).
func (s *Store) Log(ctx context.Context, parentZone string, afterRevision int64) ([]LogEntry, error) {
	rows, err := s.db.QueryContext(ctx, s.q(fmt.Sprintf(
		`SELECT revision, change_id, child, op, owner, rrtype, COALESCE(rr, ''), channel, applied_at FROM %s WHERE parent = ? AND revision > ? ORDER BY revision`,
		s.table("delegation_log"))), parentZone, afterRevision)
	if err != nil {
		return nil, fmt.Errorf("external-db: log query: %w", err)
	}
	defer rows.Close()
	var out []LogEntry
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.Revision, &e.ChangeID, &e.Child, &e.Op, &e.Owner, &e.RRtype, &e.RR, &e.Channel, &e.AppliedAt); err != nil {
			return nil, fmt.Errorf("external-db: log scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Origins reports, per stored RR of a child, where it came from.
func (s *Store) Origins(ctx context.Context, parentZone, childZone string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, s.q(fmt.Sprintf(
		`SELECT rr, origin FROM %s WHERE parent = ? AND child = ?`, s.table("delegation"))), parentZone, childZone)
	if err != nil {
		return nil, fmt.Errorf("external-db: query: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var rr, origin string
		if err := rows.Scan(&rr, &origin); err != nil {
			return nil, err
		}
		out[rr] = origin
	}
	return out, rows.Err()
}
