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

// TsigKeyMgmt implements DB CRUD for the global TSIG keystore. Mutations return
// TsigCacheDelta on the response for post-commit cache refresh (§4); they do not
// touch the in-memory TsigKeyStore directly. conf supplies live zone refcounts.
func (kdb *KeyDB) TsigKeyMgmt(conf *Config, tx *Tx, kp KeystorePost) (*KeystoreResponse, error) {
	resp := &KeystoreResponse{Time: time.Now(), TsigCacheDelta: &TsigCacheDelta{}}

	localtx := false
	var err error
	var txSuccess bool

	if tx == nil {
		tx, err = kdb.Begin("TsigKeyMgmt")
		if err != nil {
			return nil, err
		}
		localtx = true
	}
	defer func() {
		if localtx {
			if txSuccess {
				if err := tx.Commit(); err != nil {
					lgSigner.Error("TsigKeyMgmt commit failed", "err", err)
				}
			} else {
				tx.Rollback()
			}
		}
	}()

	refCount := func(name string) int {
		if conf == nil {
			return 0
		}
		return conf.tsigKeyZoneRefCount(name)
	}

	switch kp.SubCommand {
	case "list":
		rows, err := listTsigKeystore(tx)
		if err != nil {
			return resp, err
		}
		resp.TsigKeys = make([]TsigKeyInfo, len(rows))
		for i, row := range rows {
			info := tsigKeystoreRowToInfo(row)
			info.RefCount = refCount(row.Keyname)
			resp.TsigKeys[i] = info
		}
		resp.Msg = fmt.Sprintf("%d TSIG key(s)", len(rows))
		resp.TsigCacheDelta = nil

	case "add":
		if err := kdb.tsigKeyMgmtAdd(conf, tx, kp, resp); err != nil {
			return resp, err
		}

	case "generate":
		algo := kp.TsigAlgorithm
		if algo == "" {
			algo = "hmac-sha256"
		}
		secret, err := GenerateTsigSecret(algo)
		if err != nil {
			return resp, err
		}
		kp.TsigAlgorithm = algo
		kp.TsigSecret = secret
		if kp.TsigKeyname == "" {
			return resp, fmt.Errorf("generate requires a TSIG key name")
		}
		if err := kdb.tsigKeyMgmtAdd(conf, tx, kp, resp); err != nil {
			return resp, err
		}
		resp.Msg = fmt.Sprintf("TSIG key %q generated (%s)", kp.TsigKeyname, algo)

	case "setowner":
		name := kp.TsigKeyname
		if name == "" {
			name = kp.Keyname
		}
		if kp.Owner == "" {
			return resp, fmt.Errorf("setowner requires owner")
		}
		existing, err := getTsigKeystoreByName(tx, name)
		if err == sql.ErrNoRows {
			return resp, fmt.Errorf("TSIG key %q not found", name)
		}
		if err != nil {
			return resp, err
		}
		if existing.Origin != "api" {
			return resp, fmt.Errorf("TSIG key %q has origin=%q; set owner via keys.tsig", name, existing.Origin)
		}
		if err := updateTsigKeystoreOwner(tx, name, kp.Owner); err != nil {
			return resp, err
		}
		resp.TsigCacheDelta = nil
		resp.Msg = fmt.Sprintf("TSIG key %q owner set to %q", name, kp.Owner)

	case "delete":
		name := kp.TsigKeyname
		if name == "" {
			name = kp.Keyname
		}
		existing, err := getTsigKeystoreByName(tx, name)
		if err == sql.ErrNoRows {
			return resp, fmt.Errorf("TSIG key %q not found", name)
		}
		if err != nil {
			return resp, err
		}
		if existing.Origin != "api" {
			return resp, fmt.Errorf("TSIG key %q has origin=%q and cannot be deleted via keystore (manage via keys.tsig)", name, existing.Origin)
		}
		if n := refCount(name); n > 0 {
			return resp, fmt.Errorf("TSIG key %q is referenced by %d zone(s); remove references first", name, n)
		}
		if err := deleteTsigKeystore(tx, name); err != nil {
			return resp, err
		}
		resp.TsigCacheDelta.markDeleted(name)
		resp.Msg = fmt.Sprintf("TSIG key %q deleted", name)

	case "import":
		if err := kdb.tsigKeyMgmtImport(conf, tx, kp, resp); err != nil {
			return resp, err
		}

	case "purge":
		if err := kdb.tsigKeyMgmtPurge(conf, tx, kp, resp); err != nil {
			return resp, err
		}

	default:
		return resp, fmt.Errorf("unknown tsig-mgmt subcommand: %q", kp.SubCommand)
	}

	txSuccess = true
	return resp, nil
}

func (kdb *KeyDB) tsigKeyMgmtAdd(_ *Config, tx *Tx, kp KeystorePost, resp *KeystoreResponse) error {
	owner := kp.Owner
	if owner == "" {
		owner = "api"
	}
	creator := kp.Creator
	if creator == "" {
		creator = "api-request"
	}
	row := TsigKeystoreRow{
		Keyname:   kp.TsigKeyname,
		Algorithm: kp.TsigAlgorithm,
		Secret:    kp.TsigSecret,
		Origin:    "api",
		Owner:     owner,
		Creator:   creator,
	}
	if row.Keyname == "" {
		return fmt.Errorf("add requires a TSIG key name")
	}
	if row.Algorithm == "" {
		row.Algorithm = "hmac-sha256"
	}
	existing, err := getTsigKeystoreByName(tx, row.Keyname)
	if err == nil {
		if tsigDetailsMatchRow(TsigDetails{Name: row.Keyname, Algorithm: row.Algorithm, Secret: row.Secret}, existing) {
			resp.Msg = fmt.Sprintf("TSIG key %q unchanged", row.Keyname)
			resp.TsigCacheDelta = nil
			return nil
		}
		if !kp.Force {
			return fmt.Errorf("TSIG key %q already exists with a different secret/algorithm (use --force)", row.Keyname)
		}
		if err := overwriteTsigKeystore(tx, row); err != nil {
			return err
		}
	} else if err != sql.ErrNoRows {
		return err
	} else if err := insertTsigKeystore(tx, row); err != nil {
		return err
	}
	resp.TsigCacheDelta.markChanged(row.Keyname)
	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("TSIG key %q added", row.Keyname)
	}
	return nil
}

func overwriteApproved(name string, kp KeystorePost) bool {
	if kp.Force {
		return true
	}
	c := dns.CanonicalName(name)
	for _, n := range kp.TsigOverwrite {
		if dns.CanonicalName(n) == c {
			return true
		}
	}
	return false
}

func (kdb *KeyDB) tsigKeyMgmtImport(conf *Config, tx *Tx, kp KeystorePost, resp *KeystoreResponse) error {
	if kp.TsigImportData == "" {
		return fmt.Errorf("import requires tsig import data")
	}
	if kp.TsigImportFormat == "" {
		return fmt.Errorf("import requires format (bind or nsd)")
	}
	keys, err := extractTsigImportKeys(kp.TsigImportData, kp.TsigImportFormat)
	if err != nil {
		return err
	}
	owner := kp.Owner
	if owner == "" {
		owner = "api"
	}
	creator := kp.Creator
	if creator == "" {
		creator = "api-request"
	}

	var imported, unchanged, conflicts int
	resp.TsigImport = make([]TsigKeyDisposition, 0, len(keys))
	for _, t := range keys {
		disp := TsigKeyDisposition{Name: t.Name}
		existing, err := getTsigKeystoreByName(tx, t.Name)
		if err == sql.ErrNoRows {
			row := TsigKeystoreRow{
				Keyname: t.Name, Algorithm: t.Algorithm, Secret: t.Secret,
				Origin: "api", Owner: owner, Creator: creator,
			}
			if err := insertTsigKeystore(tx, row); err != nil {
				return err
			}
			resp.TsigCacheDelta.markChanged(t.Name)
			disp.Status = "imported"
			imported++
		} else if err != nil {
			return err
		} else if tsigDetailsMatchRow(t, existing) {
			disp.Status = "unchanged"
			unchanged++
		} else if overwriteApproved(t.Name, kp) {
			row := TsigKeystoreRow{
				Keyname: t.Name, Algorithm: t.Algorithm, Secret: t.Secret,
				Origin: "api", Owner: owner, Creator: creator,
			}
			if err := overwriteTsigKeystore(tx, row); err != nil {
				return err
			}
			resp.TsigCacheDelta.markChanged(t.Name)
			disp.Status = "imported"
			imported++
		} else {
			disp.Status = "conflict"
			conflicts++
		}
		resp.TsigImport = append(resp.TsigImport, disp)
	}

	resp.Msg = fmt.Sprintf("import: %d imported, %d unchanged, %d conflict(s)", imported, unchanged, conflicts)
	if conflicts > 0 {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("%d key(s) withheld due to secret/algorithm conflict (use --force or --interactive)", conflicts)
	}
	return nil
}

func (kdb *KeyDB) tsigKeyMgmtPurge(conf *Config, tx *Tx, kp KeystorePost, resp *KeystoreResponse) error {
	refCount := func(name string) int {
		if conf == nil {
			return 0
		}
		return conf.tsigKeyZoneRefCount(name)
	}
	rows, err := listTsigKeystore(tx)
	if err != nil {
		return err
	}
	var candidates []TsigKeystoreRow
	for _, row := range rows {
		if row.Origin != "api" || tsigKeystoreEffectiveOwner(row) != "api" {
			continue
		}
		if refCount(row.Keyname) > 0 {
			continue
		}
		candidates = append(candidates, row)
	}

	resp.TsigKeys = make([]TsigKeyInfo, len(candidates))
	for i, row := range candidates {
		resp.TsigKeys[i] = tsigKeystoreRowToInfo(row)
	}

	if !kp.Force && len(kp.TsigOverwrite) == 0 {
		resp.TsigCacheDelta = nil
		resp.Msg = fmt.Sprintf("DRY RUN: would purge %d TSIG key(s) (origin=api, owner=api, zero refs). Pass --force to delete.", len(candidates))
		return nil
	}

	toDelete := candidates
	if !kp.Force && len(kp.TsigOverwrite) > 0 {
		approved := make(map[string]bool, len(kp.TsigOverwrite))
		for _, n := range kp.TsigOverwrite {
			approved[dns.CanonicalName(n)] = true
		}
		toDelete = nil
		for _, row := range candidates {
			if approved[row.Keyname] {
				toDelete = append(toDelete, row)
			}
		}
	}

	for _, row := range toDelete {
		if err := deleteTsigKeystore(tx, row.Keyname); err != nil {
			return err
		}
		resp.TsigCacheDelta.markDeleted(row.Keyname)
	}
	resp.Msg = fmt.Sprintf("Purged %d TSIG key(s)", len(toDelete))
	return nil
}
