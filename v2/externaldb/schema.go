/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package externaldb

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// The schema is a published interface: once a provisioning consumer reads
// these tables, their shape is a contract (design §5.8.1, §5.8.2). Three
// tables, and the consumer writes only the third:
//
//   - <prefix>delegation      current intended state, a materialised view of
//     the log maintained in the same transaction;
//   - <prefix>delegation_log  the append-only truth: one row per action,
//     grouped by change_id, ordered by revision;
//   - <prefix>delegation_ack  the consumer's watermark, written by the
//     consumer and read by tdns.
//
// origin, op and status are VARCHAR + CHECK rather than ENUM: an ENUM has no
// PostgreSQL equivalent that survives a schema diff, and adding a value to
// one is a table rebuild.
//
// The name columns are ascii, and that is not cosmetic: it keeps the primary
// key under InnoDB's 3072-byte limit. rr is unbounded (a long TXT, a
// post-quantum KEY), so its SHA-256 is what sits in the key. tdns computes
// and writes rr_hash; it is not a generated column, because MariaDB refuses
// a PRIMARY KEY on one (error 1903) -- learned from the first live run. A
// consumer can still verify a row with rr_hash = UNHEX(SHA2(rr, 256)).

const DefaultTablePrefix = "tdns_"

var mariadbDDL = []string{
	`CREATE TABLE IF NOT EXISTS %sdelegation (
    parent      VARCHAR(255) CHARACTER SET ascii NOT NULL,
    child       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    owner       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    rrtype      VARCHAR(16)  CHARACTER SET ascii NOT NULL,
    rr          TEXT NOT NULL,
    rr_hash     BINARY(32) NOT NULL,
    origin      VARCHAR(16) NOT NULL,
    revision    BIGINT      NOT NULL,
    updated_at  DATETIME(3) NOT NULL,
    PRIMARY KEY (parent, owner, rrtype, rr_hash),
    KEY (parent, child),
    KEY (revision),
    CONSTRAINT %schk_origin CHECK (origin IN ('observed','asserted'))
)`,
	`CREATE TABLE IF NOT EXISTS %sdelegation_log (
    revision    BIGINT AUTO_INCREMENT PRIMARY KEY,
    change_id   BINARY(16)   NOT NULL,
    parent      VARCHAR(255) CHARACTER SET ascii NOT NULL,
    child       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    op          VARCHAR(16)  NOT NULL,
    owner       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    rrtype      VARCHAR(16)  CHARACTER SET ascii NOT NULL,
    rr          TEXT,
    channel     VARCHAR(16)  NOT NULL,
    principal   VARCHAR(255),
    applied_at  DATETIME(3)  NOT NULL,
    KEY (change_id),
    KEY (parent, revision),
    CONSTRAINT %schk_op CHECK (op IN ('add','del-rr','del-rrset'))
)`,
	`CREATE TABLE IF NOT EXISTS %sdelegation_ack (
    consumer    VARCHAR(64)  CHARACTER SET ascii NOT NULL,
    parent      VARCHAR(255) CHARACTER SET ascii NOT NULL,
    revision    BIGINT       NOT NULL,
    status      VARCHAR(16)  NOT NULL,
    detail      TEXT,
    acked_at    DATETIME(3)  NOT NULL,
    PRIMARY KEY (consumer, parent)
)`,
}

// expectedColumns is what the startup check verifies: every table present,
// every column tdns reads or writes present.
var expectedColumns = map[string][]string{
	"delegation":     {"parent", "child", "owner", "rrtype", "rr", "rr_hash", "origin", "revision", "updated_at"},
	"delegation_log": {"revision", "change_id", "parent", "child", "op", "owner", "rrtype", "rr", "channel", "principal", "applied_at"},
	"delegation_ack": {"consumer", "parent", "revision", "status", "detail", "acked_at"},
}

// DDL renders the schema for a prefix, for an operator to run: tdns ships the
// DDL, the DBA runs it, and auto-migrate is the lab shortcut.
func DDL(prefix string) string {
	var b strings.Builder
	for _, stmt := range mariadbDialect.ddl {
		b.WriteString(renderDDL(stmt, prefix))
		b.WriteString(";\n\n")
	}
	return b.String()
}

func renderDDL(stmt, prefix string) string {
	return strings.ReplaceAll(stmt, "%s", prefix)
}

// Migrate creates the tables that are absent. It never alters an existing
// table: a schema somebody else's application also reads is not something to
// change behind their back.
func (s *Store) Migrate(ctx context.Context) error {
	for _, stmt := range s.d.ddl {
		if _, err := s.db.ExecContext(ctx, renderDDL(stmt, s.prefix)); err != nil {
			return fmt.Errorf("external-db: creating tables: %w", err)
		}
	}
	return nil
}

// VerifySchema checks that the tables and columns tdns needs exist, and
// names what is missing. A mismatch is the zone's ConfigError, not the
// daemon's fatal: one misconfigured zone must not take down a daemon serving
// others.
func (s *Store) VerifySchema(ctx context.Context) error {
	const q = `SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ?`
	var problems []string
	names := make([]string, 0, len(expectedColumns))
	for t := range expectedColumns {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		table := s.prefix + t
		rows, err := s.db.QueryContext(ctx, q, table)
		if err != nil {
			return fmt.Errorf("external-db: reading the schema of %s: %w", table, err)
		}
		have := map[string]bool{}
		for rows.Next() {
			var col string
			if err := rows.Scan(&col); err != nil {
				rows.Close()
				return fmt.Errorf("external-db: reading the schema of %s: %w", table, err)
			}
			have[strings.ToLower(col)] = true
		}
		// rows.Next returns false at the end AND on an error, and only the
		// first is a complete column list.
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("external-db: reading the schema of %s: %w", table, err)
		}
		rows.Close()
		if len(have) == 0 {
			problems = append(problems, fmt.Sprintf("table %s is missing", table))
			continue
		}
		var missing []string
		for _, col := range expectedColumns[t] {
			if !have[col] {
				missing = append(missing, col)
			}
		}
		if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf("table %s lacks column(s) %s", table, strings.Join(missing, ", ")))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("external-db: schema check failed: %s (run the shipped DDL -- see the childsync-proxy operator guide -- or set auto-migrate on a database tdns owns)",
			strings.Join(problems, "; "))
	}
	return nil
}
