/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

const promoteTsigKeystoreToConfigSql = `
UPDATE TsigKeystore SET origin='config', owner='config' WHERE keyname=?`

const forceTsigKeystoreFromConfigSql = `
UPDATE TsigKeystore SET algorithm=?, secret=?, origin='config', owner='config', creator='config'
WHERE keyname=?`

// TsigReconcileOptions controls three-mode config-key reconcile (§6).
type TsigReconcileOptions struct {
	Force     bool
	Overwrite []string // per-key override (from reload-tsig --interactive)
}

// TsigReconcileResult summarizes a config-key reconcile pass.
type TsigReconcileResult struct {
	Conflicts        []string
	WithheldRemovals []string
	TsigCacheDelta   *TsigCacheDelta
}

// ReconcileConfigTsigKeys applies keys.tsig to TsigKeystore without silent overwrite.
// isReferenced returns true when a config-origin key removed from the YAML is still
// referenced and must be retained.
func (kdb *KeyDB) ReconcileConfigTsigKeys(entries []TsigDetails, opts TsigReconcileOptions, isReferenced func(string) bool) (TsigReconcileResult, error) {
	result := TsigReconcileResult{TsigCacheDelta: &TsigCacheDelta{}}
	want := make(map[string]TsigDetails, len(entries))
	for _, t := range entries {
		want[dns.CanonicalName(t.Name)] = t
	}
	overwrite := make(map[string]bool, len(opts.Overwrite))
	for _, name := range opts.Overwrite {
		overwrite[dns.CanonicalName(name)] = true
	}

	tx, err := kdb.Begin("ReconcileConfigTsigKeys")
	if err != nil {
		return result, err
	}
	var txSuccess bool
	defer func() {
		if txSuccess {
			if err := tx.Commit(); err != nil {
				lgConfig.Error("ReconcileConfigTsigKeys commit failed", "err", err)
			}
		} else {
			tx.Rollback()
		}
	}()

	for name, t := range want {
		existing, err := getTsigKeystoreByName(tx, name)
		if err == sql.ErrNoRows {
			if err := insertTsigKeystore(tx, TsigKeystoreRow{
				Keyname:   t.Name,
				Algorithm: t.Algorithm,
				Secret:    t.Secret,
				Origin:    "config",
				Owner:     "config",
				Creator:   "config",
			}); err != nil {
				return result, err
			}
			result.TsigCacheDelta.markChanged(name)
			continue
		}
		if err != nil {
			return result, err
		}
		if tsigDetailsMatchRow(t, existing) {
			if existing.Origin != "config" {
				if _, err := tx.Exec(promoteTsigKeystoreToConfigSql, name); err != nil {
					return result, err
				}
				result.TsigCacheDelta.markChanged(name)
			}
			continue
		}
		if opts.Force || overwrite[name] {
			if _, err := tx.Exec(forceTsigKeystoreFromConfigSql,
				dns.CanonicalName(t.Algorithm),
				t.Secret,
				name,
			); err != nil {
				return result, err
			}
			result.TsigCacheDelta.markChanged(name)
			continue
		}
		result.Conflicts = append(result.Conflicts, name)
		lgConfig.Warn("keys.tsig: key has a different secret/algorithm than the stored row; not updated (use config reload-tsig --force or --interactive)",
			"key", name, "stored_origin", existing.Origin)
	}

	rows, err := listTsigKeystore(tx)
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		if row.Origin != "config" {
			continue
		}
		if _, ok := want[row.Keyname]; ok {
			continue
		}
		if isReferenced != nil && isReferenced(row.Keyname) {
			result.WithheldRemovals = append(result.WithheldRemovals, row.Keyname)
			lgConfig.Warn("keys.tsig: config key removed from YAML but still referenced by a live zone; not dropped",
				"key", row.Keyname)
			continue
		}
		if err := deleteTsigKeystore(tx, row.Keyname); err != nil {
			return result, err
		}
		result.TsigCacheDelta.markDeleted(row.Keyname)
	}

	txSuccess = true
	return result, nil
}

func formatTsigReconcileMsg(res TsigReconcileResult) string {
	var parts []string
	parts = append(parts, "TSIG config keys reconciled.")
	if n := len(res.TsigCacheDelta.Changed) + len(res.TsigCacheDelta.Deleted); n > 0 {
		parts = append(parts, fmt.Sprintf("%d cache update(s).", n))
	}
	if len(res.Conflicts) > 0 {
		parts = append(parts, fmt.Sprintf("%d secret conflict(s) withheld: %s (use config reload-tsig --force or --interactive).",
			len(res.Conflicts), strings.Join(res.Conflicts, ", ")))
	}
	if len(res.WithheldRemovals) > 0 {
		parts = append(parts, fmt.Sprintf("%d removed key(s) withheld (still referenced): %s.",
			len(res.WithheldRemovals), strings.Join(res.WithheldRemovals, ", ")))
	}
	return strings.Join(parts, " ")
}
