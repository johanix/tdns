/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	_ "github.com/mattn/go-sqlite3"
)

var DefaultTables = map[string]string{

	"ChildDnskeys": `CREATE TABLE IF NOT EXISTS 'ChildDnskeys' (
id		  INTEGER PRIMARY KEY,
parent	  TEXT,
child	  TEXT,
keyid	  INTEGER,
trusted	  INTEGER,
keyrr	  TEXT,
comment	  TEXT,
UNIQUE (parent, child, keyid)
)`,

	"ChildDelegationData": `CREATE TABLE IF NOT EXISTS 'ChildDelegationData' (
id		  INTEGER PRIMARY KEY,
parent	  TEXT,
child	  TEXT,
owner	  TEXT,
rrtype	  TEXT,
rr		  TEXT,
UNIQUE (owner,rr)
)`,

	// The Sig0TrustStore contains public SIG(0) keys that we use to validate
	// signed DNS Updates received (from child zones)
	"Sig0TrustStore": `CREATE TABLE IF NOT EXISTS 'Sig0TrustStore' (
id		  		  INTEGER PRIMARY KEY,
zonename	  	  TEXT,
keyid		      INTEGER,
validated	      INTEGER DEFAULT 0,
trusted		      INTEGER DEFAULT 0,
dnssecvalidated	  INTEGER DEFAULT 0,
source		      TEXT,
keyrr		      TEXT,
comment		      TEXT,
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
parent_state	  INTEGER DEFAULT 0,
UNIQUE (zonename, keyid)
)`,

	// The DnssecKeyStore should contain both the private and public DNSSEC keys for
	// each zone that we're managing signing for.
	// State: created, published, ds-published, standby, active, retired, removed.
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
published_at              TEXT DEFAULT '',
retired_at                TEXT DEFAULT '',
UNIQUE (zonename, keyid)
)`,

	// OutgoingSerials persists the outgoing SOA serial per zone.
	// Prevents serial regression on restart (which causes signers to ignore NOTIFYs).
	"OutgoingSerials": `CREATE TABLE IF NOT EXISTS 'OutgoingSerials' (
		zone       TEXT NOT NULL PRIMARY KEY,
		serial     INTEGER NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`,

	"RolloverKeyState": `CREATE TABLE IF NOT EXISTS 'RolloverKeyState' (
		zone                 TEXT NOT NULL,
		keyid                INTEGER NOT NULL,
		rollover_index       INTEGER NOT NULL,
		rollover_method      TEXT,
		rollover_state_at    TEXT,
		ds_submitted_at      TEXT,
		ds_observed_at       TEXT,
		standby_at           TEXT,
		active_at            TEXT,
		active_seq           INTEGER,
		last_rollover_error  TEXT,
		PRIMARY KEY (zone, keyid)
	)`,

	"RolloverZoneState": `CREATE TABLE IF NOT EXISTS 'RolloverZoneState' (
		zone                           TEXT NOT NULL PRIMARY KEY,
		last_ds_submitted_index_low    INTEGER,
		last_ds_submitted_index_high    INTEGER,
		last_ds_submitted_at           TEXT,
		last_ds_confirmed_index_low    INTEGER,
		last_ds_confirmed_index_high    INTEGER,
		last_ds_confirmed_at           TEXT,
		rollover_phase                 TEXT NOT NULL DEFAULT 'idle',
		rollover_phase_at              TEXT,
		rollover_in_progress           INTEGER NOT NULL DEFAULT 0,
		next_rollover_index            INTEGER NOT NULL DEFAULT 0,
		manual_rollover_requested_at   TEXT,
		manual_rollover_earliest       TEXT,
		observe_started_at             TEXT,
		observe_next_poll_at           TEXT,
		observe_backoff_seconds        INTEGER,
		hardfail_count                 INTEGER NOT NULL DEFAULT 0,
		next_push_at                   TEXT,
		last_softfail_at               TEXT,
		last_softfail_category         TEXT,
		last_softfail_detail           TEXT,
		last_success_at                TEXT,
		last_attempt_started_at        TEXT,
		last_poll_at                   TEXT,
		last_attempt_scheme            TEXT,
		last_published_cds_index_low   INTEGER,
		last_published_cds_index_high  INTEGER,
		last_ds_observed_keyids        TEXT,
		last_ds_observed_at            TEXT
	)`,

	// ZoneSigningState holds per-zone signing-loop state. max_observed_ttl
	// is the maximum RRset TTL seen during the most recent full zone-sign
	// pass; written once at end-of-pass. Used by the rollover worker's
	// pending-child-withdraw phase to compute effective_margin =
	// max(policy.clamping.margin, max_observed_ttl), bounding the wait by
	// the longest-lived RRSIG that could still be cached at resolvers.
	"ZoneSigningState": `CREATE TABLE IF NOT EXISTS 'ZoneSigningState' (
		zone              TEXT NOT NULL PRIMARY KEY,
		max_observed_ttl  INTEGER NOT NULL DEFAULT 0,
		updated_at        TEXT
	)`,

	// RolloverCdsPublication records the most recent successful CDS
	// publication via the NOTIFY-scheme rollover push path. Sparse —
	// only zones that have actually run a NOTIFY publish-and-sign at
	// least once appear here. Distinct from
	// RolloverZoneState.last_published_cds_index_*, which is the
	// cleanup-time ownership marker (cleared by Trigger-1 cleanup).
	// These columns preserve historical fact across cleanup so the
	// operator can still see "CDS was published [keyids] at <time>"
	// in status output after the rollover has completed.
	//
	// Storage shape: keyids is a comma-separated list (e.g.
	// "12345,56789,43215") rendered straight to status output. Range
	// encoding (low/high index pair) was rejected: it loses keyid
	// identity if the engine ever publishes a non-contiguous
	// sequence and is harder to read in operator-facing tools.
	"RolloverCdsPublication": `CREATE TABLE IF NOT EXISTS 'RolloverCdsPublication' (
		zone           TEXT NOT NULL PRIMARY KEY,
		keyids         TEXT NOT NULL,
		published_at   TEXT NOT NULL
	)`,

	// RolloverDaemonSentinel is a single-row table written by the auth
	// daemon on startup with its PID and start time. CLI --offline
	// writers (rollover-overhaul phase 12b) read this and refuse to
	// run if the recorded PID is still alive — racing the rollover
	// tick from outside the daemon process produces non-deterministic
	// state. Stale rows (PID gone) are treated as "no daemon";
	// cleanup on graceful shutdown is best-effort.
	"RolloverDaemonSentinel": `CREATE TABLE IF NOT EXISTS 'RolloverDaemonSentinel' (
		id         INTEGER PRIMARY KEY,
		pid        INTEGER NOT NULL,
		started_at TEXT NOT NULL,
		appname    TEXT
	)`,
}

// Note that there is no DNSSEC TrustStore, because whatever DNSSEC keys we have
// looked up and validated are only cached in memory and not in the database as this data will expire.
