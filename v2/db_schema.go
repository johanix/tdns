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
active_at                 TEXT DEFAULT '',
retired_at                TEXT DEFAULT '',
active_seq                INTEGER,
	UNIQUE (zonename, keyid)
)`,

	// TsigKeystore holds global TSIG secrets (one row per key name). The in-memory
	// TsigKeyStore is a read-through cache; this table is authoritative.
	"TsigKeystore": `CREATE TABLE IF NOT EXISTS 'TsigKeystore' (
id          INTEGER PRIMARY KEY,
keyname     TEXT NOT NULL,
algorithm   TEXT NOT NULL,
secret      TEXT NOT NULL,
origin      TEXT NOT NULL,
owner       TEXT NOT NULL DEFAULT '',
creator     TEXT DEFAULT '',
created_at  TEXT DEFAULT '',
comment     TEXT DEFAULT '',
UNIQUE (keyname)
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
		published_at         TEXT,
		standby_at           TEXT,
		active_at            TEXT,
		active_seq           INTEGER,
		last_rollover_error  TEXT,
		PRIMARY KEY (zone, keyid)
	)`,

	// ZskRolloverState holds per-zone manual ZSK-rollover requests (the
	// `auto-rollover asap --zsk` / `cancel --zsk` mechanism). ZSK rollover
	// has no parent-DS coordination, so unlike RolloverZoneState (KSK) this
	// carries only the manual-request fields. Separate table to avoid
	// entangling ZSK state with the KSK rollover-phase machine.
	"ZskRolloverState": `CREATE TABLE IF NOT EXISTS 'ZskRolloverState' (
		zone                          TEXT NOT NULL PRIMARY KEY,
		manual_rollover_requested_at  TEXT,
		manual_rollover_earliest      TEXT
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
		last_ds_observed_at            TEXT,
		parent_advertises_update       INTEGER,
		parent_advertises_notify       INTEGER
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

	// ZonePolicyOverride records per-zone DNSSEC policy state.
	//
	// `policy` / `set_at` are the sparse CLI OVERRIDE (INTENT): a policy set
	// dynamically via `zone dnssec policy-set`, overriding the policy named in
	// the zone's YAML config. Only zones whose policy was changed live have a
	// non-empty `policy`. The effective policy for a zone is the override if
	// present, else the config base — this lets a live policy change survive
	// restart without the server rewriting the operator's YAML.
	//
	// `applied_policy` / `applied_source` / `applied_at` are the LAST-APPLIED
	// record (P0-2 / Plan B): the policy the zone was last successfully SIGNED
	// under, so intent vs reality is always comparable on reload and restart.
	// applied_source is 'config' | 'command'. These three columns are added by
	// dbMigrateSchema (ALTER TABLE), not this CREATE, so an existing database
	// gains them on upgrade; they are nullable and filled by the CLI-row data
	// migration (dbMigrateData) and the refresh-engine runtime backfill. A row
	// may therefore have applied_* set with an empty `policy` (config-only
	// zone, no CLI override) or vice versa — the two concerns are independent.
	"ZonePolicyOverride": `CREATE TABLE IF NOT EXISTS 'ZonePolicyOverride' (
		zone    TEXT NOT NULL PRIMARY KEY,
		policy  TEXT NOT NULL,
		set_at  TEXT
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

	// ZoneDelta persists in-flight content changes for zones whose source of
	// truth is still the zone FILE. Each row is one RR of one published delta.
	//
	// The zone file is authoritative; these rows are what has happened to the
	// zone since the file was last written. On load, the file is parsed and
	// then the deltas are replayed over it in order. On write-zone / sync /
	// freeze the changes reach the file, and the rows for that zone are
	// deleted -- the file now contains them, so replaying would double-apply.
	//
	// Replay order is `id`, i.e. insertion order, NOT toserial. Serials are
	// mod-2^32 (RFC 1982) and wrap; ordering a replay by a wrapping number
	// would silently reorder the tail of a long-lived zone's history. The
	// serials are carried for diagnostics and for matching against the
	// zone file's own serial, not for sequencing.
	//
	// UNIQUE columns are VARCHAR rather than TEXT (house rule at the head of
	// this file).
	// ZoneFileState records the identity of the zone file as tdns last read or
	// wrote it: SOA serial plus a ZONEMD digest of its contents. One row per
	// zone -- this is a "what does the file look like now" record, not a
	// history -- so the zone is the primary key and writes are upserts.
	//
	// digest_variant identifies WHICH computation produced the digest. The
	// value is private to tdns and has nothing to do with the RFC's scheme or
	// algorithm registries: it exists because a fix to the digest code changes
	// every stored digest, and a row written by the previous version has to
	// read as "no basis for comparison" rather than as "this file has been
	// edited" -- which, across a fleet of signed zones, is the difference
	// between a silent re-baseline and every zone reporting tampering at once.
	// See zoneFileDigestVariant.
	"ZoneFileState": `CREATE TABLE IF NOT EXISTS 'ZoneFileState' (
		zone           VARCHAR(255) NOT NULL PRIMARY KEY,
		serial         INTEGER NOT NULL,
		digest         VARCHAR(128) NOT NULL,
		scheme         INTEGER NOT NULL,
		algorithm      INTEGER NOT NULL,
		digest_variant INTEGER NOT NULL DEFAULT 0,
		updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
	)`,

	// One row per zone: when a primary was last seen alive, and which copy
	// that was about. Read at first bind to restore the zone's SOA EXPIRE
	// budget across a restart; see zone_refresh_state.go for why this is not
	// a column on ZoneFileState.
	//
	// A new table needs no dbMigrateSchema entry -- dbSetupTables runs
	// CREATE TABLE IF NOT EXISTS over this map at every startup, so an
	// existing database picks it up on the first run of the new binary.
	"ZoneRefreshState": `CREATE TABLE IF NOT EXISTS 'ZoneRefreshState' (
		zone           VARCHAR(255) NOT NULL PRIMARY KEY,
		last_confirmed TEXT NOT NULL,
		serial         INTEGER NOT NULL
	)`,

	"ZoneDelta": `CREATE TABLE IF NOT EXISTS 'ZoneDelta' (
		id         INTEGER PRIMARY KEY,
		zone       VARCHAR(255) NOT NULL,
		fromserial INTEGER NOT NULL,
		toserial   INTEGER NOT NULL,
		seq        INTEGER NOT NULL,
		action     VARCHAR(8) NOT NULL,
		rr         TEXT NOT NULL,
		UNIQUE (zone, toserial, seq)
	)`,

	// Credentials for the DSYNC API scheme
	// (docs/2026-08-11-dsync-api-scheme.md §10). One row per <parent zone,
	// username> pair, which is the tuple HTTP Basic authenticates.
	//
	// principal is the DNS name the update policy is evaluated against --
	// what the SIG(0) signer name is on the DDNS path. It defaults to the
	// username, and exists separately so the username can be a human-readable
	// account name where an operator prefers that.
	//
	// keyhash is SHA-256 of the key, hex. Not a slow KDF, and that is only
	// safe because AddDsyncApiCredential generates the key itself with 256
	// bits of entropy: a slow KDF exists to make low-entropy secrets
	// expensive to guess, and a secret that cannot be guessed does not need
	// one. If tdns ever accepts an operator-chosen key here, this must become
	// argon2id in the same commit.
	//
	// expires is a Unix time; 0 means never. disabled is a kill switch that
	// keeps the row for the audit trail.
	//
	// UNIQUE columns are VARCHAR rather than TEXT (house rule at the head of
	// this file).
	"DsyncApiCredential": `CREATE TABLE IF NOT EXISTS 'DsyncApiCredential' (
		id         INTEGER PRIMARY KEY,
		parentzone VARCHAR(255) NOT NULL,
		username   VARCHAR(255) NOT NULL,
		principal  VARCHAR(255) NOT NULL,
		keyhash    VARCHAR(64) NOT NULL,
		created    INTEGER NOT NULL,
		expires    INTEGER NOT NULL DEFAULT 0,
		disabled   INTEGER NOT NULL DEFAULT 0,
		comment    TEXT,
		UNIQUE (parentzone, username)
	)`,

	// Certificate credentials for the DSYNC API scheme. A separate table
	// because there is no column-migration machinery, and because a
	// certificate credential has neither a key hash nor a username: the
	// identity is a pin or a DNS name, keyed with the mechanism.
	//
	// identity is canonicalised (core.CanonicalizeName) for tls-pkix and
	// stored verbatim for tls-pin (standard-encoding base64 SPKI SHA-256).
	"DsyncApiCertCredential": `CREATE TABLE IF NOT EXISTS 'DsyncApiCertCredential' (
		id         INTEGER PRIMARY KEY,
		parentzone VARCHAR(255) NOT NULL,
		authmech   VARCHAR(16)  NOT NULL,
		identity   VARCHAR(255) NOT NULL,
		principal  VARCHAR(255) NOT NULL,
		created    INTEGER NOT NULL,
		expires    INTEGER NOT NULL DEFAULT 0,
		disabled   INTEGER NOT NULL DEFAULT 0,
		comment    TEXT,
		UNIQUE (parentzone, authmech, identity)
	)`,
}

// Note that there is no DNSSEC TrustStore, because whatever DNSSEC keys we have
// looked up and validated are only cached in memory and not in the database as this data will expire.
