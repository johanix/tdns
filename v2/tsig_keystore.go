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

const listTsigKeystoreSql = `
SELECT keyname, algorithm, secret, origin, owner, creator, created_at, comment
FROM TsigKeystore ORDER BY keyname`

const deleteTsigKeystoreSql = `DELETE FROM TsigKeystore WHERE keyname=?`

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

type rowsQuerier interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

func tsigKeystoreEffectiveOwner(row TsigKeystoreRow) string {
	if row.Owner != "" {
		return row.Owner
	}
	return row.Origin
}

func tsigKeystoreRowToDetails(row TsigKeystoreRow) TsigDetails {
	return TsigDetails{
		Name:      row.Keyname,
		Algorithm: row.Algorithm,
		Secret:    row.Secret,
	}
}

func tsigKeystoreRowToInfo(row TsigKeystoreRow) TsigKeyInfo {
	return TsigKeyInfo{
		Name:      row.Keyname,
		Algorithm: row.Algorithm,
		Origin:    row.Origin,
		Owner:     tsigKeystoreEffectiveOwner(row),
		Created:   row.CreatedAt,
	}
}

func scanTsigKeystoreRow(rows *sql.Rows) (TsigKeystoreRow, error) {
	var row TsigKeystoreRow
	err := rows.Scan(
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

func listTsigKeystore(q rowsQuerier) ([]TsigKeystoreRow, error) {
	rows, err := q.Query(listTsigKeystoreSql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TsigKeystoreRow
	for rows.Next() {
		row, err := scanTsigKeystoreRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func deleteTsigKeystore(tx *Tx, keyname string) error {
	_, err := tx.Exec(deleteTsigKeystoreSql, dns.CanonicalName(keyname))
	return err
}

// LoadTsigKeystoreInto replaces the in-memory store with every TsigKeystore row.
func (kdb *KeyDB) LoadTsigKeystoreInto(store *TsigKeyStore) error {
	rows, err := listTsigKeystore(kdb)
	if err != nil {
		return err
	}
	details := make([]TsigDetails, len(rows))
	for i, row := range rows {
		details[i] = tsigKeystoreRowToDetails(row)
	}
	store.ReplaceAll(details)
	return nil
}

// ApplyTsigCacheDelta refreshes changed keys from the DB and removes deleted names
// from the in-memory store. Called after a successful keystore tx commit (§4).
func ApplyTsigCacheDelta(store *TsigKeyStore, kdb *KeyDB, delta *TsigCacheDelta) error {
	if store == nil || kdb == nil || delta == nil {
		return nil
	}
	for _, name := range delta.Deleted {
		store.Delete(name)
	}
	for _, name := range delta.Changed {
		row, err := getTsigKeystoreByName(kdb, name)
		if err == sql.ErrNoRows {
			store.Delete(name)
			continue
		}
		if err != nil {
			return err
		}
		store.Add(tsigKeystoreRowToDetails(row))
	}
	return nil
}

func (delta *TsigCacheDelta) markChanged(name string) {
	if delta == nil {
		return
	}
	c := dns.CanonicalName(name)
	for _, existing := range delta.Changed {
		if existing == c {
			return
		}
	}
	delta.Changed = append(delta.Changed, c)
}

func (delta *TsigCacheDelta) markDeleted(name string) {
	if delta == nil {
		return
	}
	c := dns.CanonicalName(name)
	for _, existing := range delta.Deleted {
		if existing == c {
			return
		}
	}
	delta.Deleted = append(delta.Deleted, c)
}
