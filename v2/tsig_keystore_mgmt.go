/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
	"fmt"
	"time"
)

// TsigKeyMgmt implements DB CRUD for the global TSIG keystore. Mutations return
// TsigCacheDelta on the response for post-commit cache refresh (§4); they do not
// touch the in-memory TsigKeyStore directly.
func (kdb *KeyDB) TsigKeyMgmt(tx *Tx, kp KeystorePost) (*KeystoreResponse, error) {
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

	switch kp.SubCommand {
	case "list":
		rows, err := listTsigKeystore(kdb)
		if err != nil {
			return resp, err
		}
		resp.TsigKeys = make([]TsigKeyInfo, len(rows))
		for i, row := range rows {
			resp.TsigKeys[i] = tsigKeystoreRowToInfo(row)
		}
		resp.Msg = fmt.Sprintf("%d TSIG key(s)", len(rows))
		resp.TsigCacheDelta = nil

	case "add":
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
		if err := insertTsigKeystore(tx, row); err != nil {
			return resp, err
		}
		resp.TsigCacheDelta.markChanged(row.Keyname)
		resp.Msg = fmt.Sprintf("TSIG key %q added", kp.TsigKeyname)

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
		if err := deleteTsigKeystore(tx, name); err != nil {
			return resp, err
		}
		resp.TsigCacheDelta.markDeleted(name)
		resp.Msg = fmt.Sprintf("TSIG key %q deleted", name)

	default:
		return resp, fmt.Errorf("unknown tsig-mgmt subcommand: %q", kp.SubCommand)
	}

	txSuccess = true
	return resp, nil
}
