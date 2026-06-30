/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
	"fmt"
)

// migrateDynamicConfigTsigKeys imports legacy dynamic-zones YAML keys: entries into
// TsigKeystore (origin=api, owner=api), then rewrites the file without a keys: block.
// Idempotent: names already in the store are skipped. All-or-nothing on DB failure.
func (conf *Config) migrateDynamicConfigTsigKeys(cf *DynamicConfigFile) error {
	if cf == nil || cf.Keys == nil || len(cf.Keys.Tsig) == 0 {
		return nil
	}
	if conf.Internal.KeyDB == nil {
		return fmt.Errorf("dynamic TSIG key migration requires KeyDB")
	}
	kdb := conf.Internal.KeyDB
	tx, err := kdb.Begin("MigrateDynamicTsigKeys")
	if err != nil {
		return err
	}
	var txSuccess bool
	defer func() {
		if !txSuccess {
			tx.Rollback()
		}
	}()

	delta := &TsigCacheDelta{}
	migrated := 0
	for _, k := range cf.Keys.Tsig {
		if err := validateTsigKeySpec(k.Name, k.Algorithm, k.Secret); err != nil {
			return fmt.Errorf("dynamic key %q: %w", k.Name, err)
		}
		_, err := getTsigKeystoreByName(tx, k.Name)
		if err == nil {
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		if err := insertTsigKeystore(tx, TsigKeystoreRow{
			Keyname:   k.Name,
			Algorithm: k.Algorithm,
			Secret:    k.Secret,
			Origin:    "api",
			Owner:     "api",
			Creator:   "dynamic-config-migration",
		}); err != nil {
			return err
		}
		delta.markChanged(k.Name)
		migrated++
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	txSuccess = true

	if conf.Internal.TsigKeyStore != nil && len(delta.Changed) > 0 {
		if err := ApplyTsigCacheDelta(conf.Internal.TsigKeyStore, kdb, delta); err != nil {
			return fmt.Errorf("migrated keys but cache refresh failed: %w", err)
		}
	}

	zones := cf.Zones
	cf.Keys = nil
	if err := conf.writeDynamicConfigFile(zones); err != nil {
		return fmt.Errorf("migrated %d key(s) but failed to rewrite dynamic config: %w", migrated, err)
	}
	if migrated > 0 {
		lg.Info("migrated dynamic TSIG keys from YAML to keystore", "count", migrated)
	} else {
		lg.Info("cleared legacy dynamic TSIG keys block from config file (keys already in keystore)")
	}
	return nil
}
