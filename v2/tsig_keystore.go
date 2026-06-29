/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

const insertTsigKeystoreSql = `
INSERT INTO TsigKeystore (keyname, algorithm, secret, origin, owner, creator, created_at, comment)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

const getTsigKeystoreByNameSql = `
SELECT keyname, algorithm, secret, origin, owner, creator, created_at, comment
FROM TsigKeystore WHERE keyname=?`

// TsigKeystoreRow is one row in the TsigKeystore table.
type TsigKeystoreRow struct {
	Keyname   string
	Algorithm string
	Secret    string
	Origin    string
	Owner     string
	Creator   string
	CreatedAt string
	Comment   string
}

// insertTsigKeystore validates the key spec and inserts a row. keyname is
// canonicalised on write. origin must be non-empty ('config' or 'api').
func insertTsigKeystore(tx *Tx, row TsigKeystoreRow) error {
	if row.Origin != "config" && row.Origin != "api" {
		return fmt.Errorf("tsig keystore: origin %q must be config or api", row.Origin)
	}
	if err := validateTsigKeySpec(row.Keyname, row.Algorithm, row.Secret); err != nil {
		return err
	}
	keyname := dns.CanonicalName(row.Keyname)
	createdAt := row.CreatedAt
	if createdAt == "" {
		createdAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := tx.Exec(insertTsigKeystoreSql,
		keyname,
		dns.CanonicalName(row.Algorithm),
		row.Secret,
		row.Origin,
		row.Owner,
		row.Creator,
		createdAt,
		row.Comment,
	)
	return err
}

// getTsigKeystoreByName loads one row by canonical keyname. Returns sql.ErrNoRows
// when absent.
func getTsigKeystoreByName(q rowQuerier, keyname string) (TsigKeystoreRow, error) {
	var row TsigKeystoreRow
	err := q.QueryRow(getTsigKeystoreByNameSql, dns.CanonicalName(keyname)).Scan(
		&row.Keyname,
		&row.Algorithm,
		&row.Secret,
		&row.Origin,
		&row.Owner,
		&row.Creator,
		&row.CreatedAt,
		&row.Comment,
	)
	return row, err
}

type rowQuerier interface {
	QueryRow(query string, args ...interface{}) *sql.Row
}
