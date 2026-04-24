/*
 * Copyright (c) Johan Stenstam, <johani@johani.org>
 */
package tdns

import (
	"crypto"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

func (kdb *KeyDB) Sig0KeyMgmt(tx *Tx, kp KeystorePost) (*KeystoreResponse, error) {

	const (
		addSig0KeySql = `
INSERT OR REPLACE INTO Sig0KeyStore (zonename, state, keyid, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?)`
		setStateSig0KeySql = "UPDATE Sig0KeyStore SET state=? WHERE zonename=? AND keyid=?"
		deleteSig0KeySql   = `DELETE FROM Sig0KeyStore WHERE zonename=? AND keyid=?`
		getAllSig0KeysSql  = `SELECT zonename, state, keyid, algorithm, creator, privatekey, keyrr FROM Sig0KeyStore`
		getSig0KeySql      = `
SELECT zonename, state, keyid, algorithm, creator, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND keyid=?`
	)

	var resp = KeystoreResponse{Time: time.Now()}
	var res sql.Result

	var localtx = false
	var err error
	var txSuccess bool

	if tx == nil {
		tx, err = kdb.Begin("Sig0KeyMgmt")
		if err != nil {
			return nil, err
		}
		localtx = true
	}
	defer func() {
		if localtx {
			if txSuccess {
				if err := tx.Commit(); err != nil {
					lgSigner.Error("Sig0KeyMgmt commit failed", "err", err)
				}
			} else {
				tx.Rollback()
			}
		}
	}()

	lgSigner.Debug("Sig0KeyMgmt request", "subcommand", kp.SubCommand)

	switch kp.SubCommand {
	case "list":
		rows, err := kdb.Query(getAllSig0KeysSql)
		if err != nil {
			lgSigner.Error("kdb.Query failed", "sql", getAllSig0KeysSql, "err", err)
			return &resp, fmt.Errorf("error from kdb.Query(%s): %v", getAllSig0KeysSql, err)
		}
		defer rows.Close()

		var keyname, state, algorithm, creator, privatekey, keyrrstr string
		var keyid int

		tmp2 := map[string]Sig0Key{}
		for rows.Next() {
			err := rows.Scan(&keyname, &state, &keyid, &algorithm, &creator, &privatekey, &keyrrstr)
			if err != nil {
				return &resp, fmt.Errorf("error from rows.Scan(): %v", err)
			}
			if len(privatekey) < 10 {
				privatekey = "ULTRA SECRET KEY"
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			tmp2[mapkey] = Sig0Key{
				Name:       keyname,
				State:      state,
				Algorithm:  algorithm,
				Creator:    creator,
				PrivateKey: "-***-",
				Keystr:     keyrrstr,
			}
		}
		resp.Sig0keys = tmp2
		resp.Msg = "Here are all the SIG(0) keys that we know"

	// XXX: FIXME: "add" should also add the public key to the TrustStore.
	case "add": // AKA "import"
		pkc := kp.PrivateKeyCache
		lgSigner.Info("importing private key", "type", fmt.Sprintf("%T", pkc.K))

		// Convert private key to PEM format for storage
		// If pkc.K is nil (e.g., when received via JSON API), reconstruct it from pkc.PrivateKey
		var privkey crypto.PrivateKey
		if pkc.K != nil {
			privkey = pkc.K
		} else {
			// Reconstruct from PrivateKey string (BIND format) and public key RR
			// We need to parse the private key using the public key RR
			if pkc.KeyType == dns.TypeKEY {
				bindFormat, err := PrivKeyToBindFormat(pkc.PrivateKey, dns.AlgorithmToString[pkc.Algorithm])
				if err != nil {
					return &resp, fmt.Errorf("failed to convert private key to BIND format: %v", err)
				}
				reconstructedPkc, err := PrepareKeyCache(bindFormat, pkc.KeyRR.String())
				if err != nil {
					return &resp, fmt.Errorf("failed to reconstruct private key: %v", err)
				}
				privkey = reconstructedPkc.K
			} else {
				return &resp, fmt.Errorf("unsupported key type for reconstruction: %d", pkc.KeyType)
			}
		}

		privkeyPEM, err := PrivateKeyToPEM(privkey)
		if err != nil {
			lgSigner.Error("PrivateKeyToPEM failed", "err", err)
			return &resp, fmt.Errorf("failed to convert private key to PEM: %v", err)
		}

		res, err = tx.Exec(addSig0KeySql, pkc.KeyRR.Header().Name, kp.State, pkc.KeyRR.KeyTag(),
			dns.AlgorithmToString[pkc.Algorithm], "tdns-cli", privkeyPEM, pkc.KeyRR.String())
		if err != nil {
			lgSigner.Error("failed to add SIG(0) key", "err", err)
			return &resp, err
		} else {
			rows, _ := res.RowsAffected()
			resp.Msg = fmt.Sprintf("Updated %d rows.\nAdded private+public key to KeyStore.", rows)
		}

		// Now also add the public key to the TrustStore.
		tspost := TruststorePost{
			Command:    "truststore",
			SubCommand: "add",
			Keyname:    pkc.KeyRR.Header().Name,
			Keyid:      int(pkc.KeyRR.KeyTag()),
			Validated:  true,
			Trusted:    true, // we implicitly trust keys that we have added ourselves
			Src:        "keystore",
			KeyRR:      pkc.KeyRR.String(),
		}
		tsresp, err := kdb.Sig0TrustMgmt(tx, tspost)
		if err != nil {
			return nil, err
		}
		delete(kdb.KeystoreSig0Cache, kp.Keyname+"+"+kp.State)
		resp.Msg += fmt.Sprintf("\nAdded public key to TrustStore: %s", tsresp.Msg)

	case "generate":
		lgSigner.Info("generating new SIG(0) keypair", "name", kp.Keyname)
		if kp.Keyname == "" {
			kp.Keyname = kp.Zone
		}
		pkc, msg, err := kdb.GenerateKeypair(kp.Keyname, kp.Creator, kp.State, dns.TypeKEY, kp.Algorithm, "", tx)
		if err != nil {
			lgSigner.Error("GenerateKeypair failed", "err", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		resp.Msg = msg
		tspost := TruststorePost{
			Command:    "truststore",
			SubCommand: "add",
			Keyname:    pkc.KeyRR.Header().Name,
			Keyid:      int(pkc.KeyRR.KeyTag()),
			Validated:  true,
			Trusted:    true, // we implicitly trust keys that we have generated ourselves
			Src:        "keystore",
			KeyRR:      pkc.KeyRR.String(),
		}
		tsresp, err := kdb.Sig0TrustMgmt(tx, tspost)
		if err != nil {
			return nil, err
		}
		delete(kdb.KeystoreSig0Cache, kp.Keyname+"+"+kp.State)
		resp.Msg += fmt.Sprintf("\nAdded public key of newly generated keypair to TrustStore: %s", tsresp.Msg)
		txSuccess = true
		return &resp, err

	case "export":
		row := tx.QueryRow(getSig0KeySql, kp.Zone, kp.Keyid)
		var zonename, state, algorithm, creator, privatekey, keyrrstr string
		var keyid int
		err := row.Scan(&zonename, &state, &keyid, &algorithm, &creator, &privatekey, &keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("SIG(0) key for zone %q keyid %d not found", kp.Zone, kp.Keyid)
				return &resp, nil
			}
			return &resp, fmt.Errorf("error from row.Scan(): %v", err)
		}
		mapkey := fmt.Sprintf("%s::%d", zonename, keyid)
		resp.Sig0keys = map[string]Sig0Key{
			mapkey: {
				Name:       zonename,
				State:      state,
				Keyid:      uint16(keyid),
				Algorithm:  algorithm,
				Creator:    creator,
				PrivateKey: privatekey, // unredacted: export intentionally surfaces it
				Keystr:     keyrrstr,
			},
		}
		resp.Msg = fmt.Sprintf("Exported SIG(0) key %s keyid %d", zonename, keyid)

	case "setstate":
		res, err = tx.Exec(setStateSig0KeySql, kp.State, kp.Keyname, kp.Keyid)
		if err != nil {
			lgSigner.Error("failed to set SIG(0) key state", "err", err)
			return &resp, err
		} else {
			rows, _ := res.RowsAffected()
			if rows > 0 {
				resp.Msg = fmt.Sprintf("Updated %d rows", rows)
			} else {
				resp.Msg = fmt.Sprintf("Key with name \"%s\" and keyid %d not found.", kp.Keyname, kp.Keyid)
			}
		}

		// We don't know the old state, so we delete all entries for this key.
		delete(kdb.KeystoreSig0Cache, kp.Keyname+"+"+Sig0StateCreated)
		delete(kdb.KeystoreSig0Cache, kp.Keyname+"+"+Sig0StatePublished)
		delete(kdb.KeystoreSig0Cache, kp.Keyname+"+"+Sig0StateActive)
		delete(kdb.KeystoreSig0Cache, kp.Keyname+"+"+Sig0StateRetired)

	case "setparentstate":
		const setParentStateSql = "UPDATE Sig0KeyStore SET parent_state=? WHERE zonename=? AND keyid=?"
		res, err = tx.Exec(setParentStateSql, kp.ParentState, kp.Keyname, kp.Keyid)
		if err != nil {
			lgSigner.Error("failed to set SIG(0) key parent_state", "err", err)
			return &resp, err
		}
		rows, _ := res.RowsAffected()
		if rows > 0 {
			resp.Msg = fmt.Sprintf("Updated parent_state to %d for key %s (keyid %d)", kp.ParentState, kp.Keyname, kp.Keyid)
		} else {
			resp.Msg = fmt.Sprintf("Key with name %q and keyid %d not found", kp.Keyname, kp.Keyid)
		}

	case "delete":
		const getSig0KeySql = `
SELECT zonename, state, keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND keyid=?`

		// 1. Find key, if not --> error
		row := tx.QueryRow(getSig0KeySql, kp.Zone, kp.Keyid)

		var zone, state, algorithm, privatekey, keyrr string
		var keyid int
		err := row.Scan(&zone, &state, &keyid, &algorithm, &privatekey, &keyrr)
		if err != nil {
			lgSigner.Error("failed to scan SIG(0) key for delete", "err", err)
			if err == sql.ErrNoRows {
				return &resp, fmt.Errorf("key %s (keyid %d) not found", kp.Keyname, kp.Keyid)
			}
			return &resp, err
		}
		if uint16(keyid) != kp.Keyid || zone != kp.Zone {
			lgSigner.Warn("SIG(0) key not found for delete", "keyname", kp.Keyname, "keyid", kp.Keyid)
			resp.Msg = fmt.Sprintf("key %s %d not found", kp.Keyname, kp.Keyid)
			return &resp, nil
		}

		// 3. Return all good, now untrusted
		res, err = tx.Exec(deleteSig0KeySql, kp.Keyname, kp.Keyid)
		if err != nil {
			lgSigner.Error("failed to delete SIG(0) key", "err", err)
			return &resp, err
		}
		rows, _ := res.RowsAffected()
		resp.Msg = fmt.Sprintf("SIG(0) key %s (keyid %d) deleted from KeyStore (%d rows)", kp.Keyname, kp.Keyid, rows)

		// Now also delete it from the TrustStore.
		tspost := TruststorePost{
			Command:    "truststore",
			SubCommand: "delete",
			Keyname:    kp.Keyname,
			Keyid:      int(kp.Keyid),
		}
		tsresp, err := kdb.Sig0TrustMgmt(tx, tspost)
		if err != nil {
			return &resp, err
		}
		resp.Msg += fmt.Sprintf("\nAlso deleted the public key from TrustStore:\n%s", tsresp.Msg)
		// Also delete from the cache
		delete(kdb.KeystoreSig0Cache, kp.Keyname+"+"+state)

	default:
		lgSigner.Warn("unknown Sig0KeyMgmt subcommand", "subcommand", kp.SubCommand)
	}

	txSuccess = true
	return &resp, nil
}

func (kdb *KeyDB) DnssecKeyMgmt(tx *Tx, kp KeystorePost) (*KeystoreResponse, error) {
	// dump.P(kp)

	const (
		addDnskeySql = `
INSERT OR REPLACE INTO DnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		setStateDnskeySql = "UPDATE DnssecKeyStore SET state=? WHERE zonename=? AND keyid=?"
		deleteDnskeySql   = `DELETE FROM DnssecKeyStore WHERE zonename=? AND keyid=?`
		getAllDnskeysSql  = `SELECT zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr FROM DnssecKeyStore`
		getDnskeySql      = `
SELECT zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND keyid=?`
	)

	var localtx = false
	var err error
	var txSuccess bool

	if tx == nil {
		tx, err = kdb.Begin("DnssecKeyMgmt")
		if err != nil {
			return nil, err
		}
		localtx = true
	}
	defer func() {
		if localtx {
			if txSuccess {
				if err := tx.Commit(); err != nil {
					lgSigner.Error("DnssecKeyMgmt commit failed", "err", err)
				}
			} else {
				lgSigner.Debug("DnssecKeyMgmt rollback")
				tx.Rollback()
			}
		}
	}()

	var resp = KeystoreResponse{Time: time.Now()}
	var res sql.Result

	switch kp.SubCommand {
	case "list":
		rows, err := tx.Query(getAllDnskeysSql)
		if err != nil {
			return nil, fmt.Errorf("error from tx.Query(%s): %v", getAllDnskeysSql, err)
		}
		defer rows.Close()

		var keyname, state, algorithm, creator, privatekey, keyrrstr string
		var keyid, flags int

		tmp2 := map[string]DnssecKey{}
		for rows.Next() {
			err := rows.Scan(&keyname, &state, &keyid, &flags, &algorithm, &creator, &privatekey, &keyrrstr)
			if err != nil {
				return nil, fmt.Errorf("error from rows.Scan(): %v", err)
			}
			if len(privatekey) < 10 {
				privatekey = "ULTRA SECRET KEY"
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			dk := DnssecKey{
				Name:       keyname,
				State:      state,
				Flags:      uint16(flags),
				Algorithm:  algorithm,
				Creator:    creator,
				PrivateKey: "-***-",
				Keystr:     keyrrstr,
			}
			tmp2[mapkey] = dk
		}
		resp.Dnskeys = tmp2
		resp.Msg = "Here are all the DNSSEC keys that we know"

	case "add": // AKA "import"
		pkc := kp.PrivateKeyCache

		// Convert private key to PEM format for storage
		// If pkc.K is nil (e.g., when received via JSON API), reconstruct it from pkc.PrivateKey
		var privkey crypto.PrivateKey
		if pkc.K != nil {
			privkey = pkc.K
		} else {
			// Reconstruct from PrivateKey string (BIND format) and public key RR
			// We need to parse the private key using the public key RR
			if pkc.KeyType == dns.TypeDNSKEY {
				bindFormat, err := PrivKeyToBindFormat(pkc.PrivateKey, dns.AlgorithmToString[pkc.Algorithm])
				if err != nil {
					return &resp, fmt.Errorf("failed to convert private key to BIND format: %v", err)
				}
				reconstructedPkc, err := PrepareKeyCache(bindFormat, pkc.DnskeyRR.String())
				if err != nil {
					return &resp, fmt.Errorf("failed to reconstruct private key: %v", err)
				}
				privkey = reconstructedPkc.K
			} else {
				return &resp, fmt.Errorf("unsupported key type for reconstruction: %d", pkc.KeyType)
			}
		}

		privkeyPEM, err := PrivateKeyToPEM(privkey)
		if err != nil {
			lgSigner.Error("PrivateKeyToPEM failed", "err", err)
			return &resp, fmt.Errorf("failed to convert private key to PEM: %v", err)
		}

		res, err = tx.Exec(addDnskeySql, pkc.DnskeyRR.Header().Name, kp.State, pkc.DnskeyRR.KeyTag(), pkc.DnskeyRR.Flags,
			dns.AlgorithmToString[pkc.Algorithm], "tdns-cli", privkeyPEM, pkc.DnskeyRR.String())

		if err != nil {
			lgSigner.Error("failed to add DNSKEY", "err", err)
			return &resp, err
		} else {
			lgSigner.Debug("DNSKEY added successfully")
			rows, _ := res.RowsAffected()
			resp.Msg = fmt.Sprintf("Updated %d rows", rows)
		}
		delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+kp.State)

	case "generate":
		_, msg, err := kdb.GenerateKeypair(kp.Zone, "api-request", kp.State, dns.TypeDNSKEY, kp.Algorithm, kp.KeyType, tx)
		if err != nil {
			lgSigner.Error("GenerateKeypair failed", "err", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
		}
		resp.Msg = msg
		delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+kp.State)
		if err == nil {
			txSuccess = true
		}
		return &resp, err

	case "setstate":
		allowed := map[string]bool{
			DnskeyStateCreated: true, DnskeyStatePublished: true, DnskeyStateDsPublished: true,
			DnskeyStateStandby: true, DnskeyStateActive: true, DnskeyStateRetired: true, DnskeyStateRemoved: true,
		}
		if !allowed[kp.State] {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("invalid dnssec state %q", kp.State)
			return &resp, fmt.Errorf("invalid dnssec state %q", kp.State)
		}
		res, err = tx.Exec(setStateDnskeySql, kp.State, kp.Keyname, kp.Keyid)
		if err != nil {
			lgSigner.Error("failed to set DNSKEY state", "err", err)
			return &resp, err
		} else {
			rows, _ := res.RowsAffected()
			if rows > 0 {
				resp.Msg = fmt.Sprintf("Updated %d rows", rows)
			} else {
				resp.Msg = fmt.Sprintf("Key with name \"%s\" and keyid %d not found.", kp.Keyname, kp.Keyid)
			}
		}
		delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+kp.State)

	case "rollover":
		keytype := kp.KeyType
		if keytype == "" {
			keytype = "ZSK"
		}
		oldKeyid, newKeyid, err := kdb.RolloverKey(kp.Zone, keytype, tx)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		resp.Msg = fmt.Sprintf("%s rollover for zone %s: active key %d retired, standby key %d now active", keytype, kp.Zone, oldKeyid, newKeyid)

	case "delete":
		const getDnskeySql = `
SELECT zonename, state, keyid, flags, algorithm, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND keyid=?`

		// 1. Find key, if not --> error
		row := tx.QueryRow(getDnskeySql, kp.Zone, kp.Keyid)

		var zone, state, algorithm, privatekey, keyrr string
		var keyid, flags int
		err := row.Scan(&zone, &state, &keyid, &flags, &algorithm, &privatekey, &keyrr)
		if err != nil {
			lgSigner.Error("failed to scan DNSKEY for delete", "err", err)
			if err == sql.ErrNoRows {
				return &resp, fmt.Errorf("key %s (keyid %d) not found", kp.Keyname, kp.Keyid)
			}
			return &resp, err
		}
		if uint16(keyid) != kp.Keyid || zone != kp.Zone {
			lgSigner.Warn("DNSKEY not found for delete", "keyname", kp.Keyname, "keyid", kp.Keyid)
			resp.Msg = fmt.Sprintf("key %s %d not found", kp.Keyname, kp.Keyid)
			return &resp, nil
		}

		targetState := DnskeyStateRemoved

		// Inline state update using the existing tx (calling UpdateDnssecKeyState
		// would try to Begin a second transaction and deadlock).
		updateRes, err := tx.Exec(`UPDATE DnssecKeyStore SET state=? WHERE zonename=? AND keyid=?`,
			targetState, kp.Zone, kp.Keyid)
		if err != nil {
			lgSigner.Error("failed to transition DNSKEY for delete", "err", err)
			return &resp, err
		}
		if rows, _ := updateRes.RowsAffected(); rows == 0 {
			err = fmt.Errorf("no rows updated for key %d in zone %s", kp.Keyid, kp.Zone)
			return &resp, err
		}
		resp.Msg = fmt.Sprintf("Key %s (keyid %d) transitioned to %s", kp.Keyname, kp.Keyid, targetState)
		delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+state)
		delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+targetState)

	case "clear":
		if kp.Zone == "" {
			resp.Error = true
			resp.ErrorMsg = "zone is required for clear"
			return &resp, fmt.Errorf("zone is required for clear")
		}
		result, err := tx.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=?`, kp.Zone)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		count, _ := result.RowsAffected()
		// Invalidate all caches for this zone (mutex protects iteration during concurrent access)
		kdb.mu.Lock()
		for key := range kdb.KeystoreDnskeyCache {
			if strings.HasPrefix(key, kp.Zone+"+") {
				delete(kdb.KeystoreDnskeyCache, key)
			}
		}
		kdb.mu.Unlock()
		lgSigner.Info("all DNSSEC keys cleared", "zone", kp.Zone, "count", count)

		// Immediately generate 1 active ZSK + 1 active KSK so the zone can be signed.
		// Standby keys will be generated by KeyStateWorker on its next tick.
		zd, zoneExists := Zones.Get(kp.Zone)
		if !zoneExists || zd.DnssecPolicy == nil {
			resp.Msg = fmt.Sprintf("Deleted all %d DNSSEC keys for zone %s. Zone not found or has no DNSSEC policy; no new keys generated.", count, kp.Zone)
			return &resp, nil
		}

		alg := zd.DnssecPolicy.Algorithm
		var generated []string

		// Generate 1 active ZSK
		zskPkc, _, err := kdb.GenerateKeypair(kp.Zone, "clear-regen", DnskeyStateActive, dns.TypeDNSKEY, alg, "ZSK", tx)
		if err != nil {
			lgSigner.Error("clear: failed to generate active ZSK", "zone", kp.Zone, "err", err)
		} else {
			generated = append(generated, fmt.Sprintf("ZSK %d (active)", zskPkc.KeyId))
		}

		// Generate 1 active KSK
		kskPkc, _, err := kdb.GenerateKeypair(kp.Zone, "clear-regen", DnskeyStateActive, dns.TypeDNSKEY, alg, "KSK", tx)
		if err != nil {
			lgSigner.Error("clear: failed to generate active KSK", "zone", kp.Zone, "err", err)
		} else {
			generated = append(generated, fmt.Sprintf("KSK %d (active)", kskPkc.KeyId))
		}

		resp.Msg = fmt.Sprintf("Deleted %d keys for zone %s. Generated: %s. Standby keys will follow via KeyStateWorker.",
			count, kp.Zone, strings.Join(generated, ", "))

	default:
		resp.Msg = fmt.Sprintf("Unknown keystore dnssec sub-command: %s", kp.SubCommand)
		lgSigner.Warn("unknown DnssecKeyMgmt subcommand", "subcommand", kp.SubCommand)
		resp.Error = true
		resp.ErrorMsg = resp.Msg
	}

	txSuccess = true
	return &resp, nil
}

func (kdb *KeyDB) GetSig0Keys(zonename, state string) (*Sig0ActiveKeys, error) {
	const (
		fetchSig0PrivKeySql = `
SELECT keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND state=?`
	)

	if sak, ok := kdb.KeystoreSig0Cache[zonename+"+"+state]; ok {
		return sak, nil
	}

	rows, err := kdb.Query(fetchSig0PrivKeySql, zonename, state)
	if err != nil {
		lgSigner.Error("failed to query SIG(0) keys", "sql", fetchSig0PrivKeySql, "zone", zonename, "err", err)
		return nil, err
	}
	defer rows.Close()

	var algorithm, privatekey, keyrrstr string
	var keyid int

	var keyfound bool
	var sak Sig0ActiveKeys

	for rows.Next() {
		err := rows.Scan(&keyid, &algorithm, &privatekey, &keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				// This is not an error, so lets just return an empty Sig0ActiveKeys
				lgSigner.Debug("no SIG(0) key found", "state", state, "zone", zonename)
				return &sak, nil
			}
			lgSigner.Error("rows.Scan failed", "err", err)
			return nil, err
		}

		if keyfound {
			lgSigner.Warn("multiple SIG(0) keys found", "state", state, "zone", zonename)
			// XXX: Should we return an error here?
			continue
		}

		// Parse private key, detecting old BIND format or new PEM format
		_, alg, bindFormat, err := ParsePrivateKeyFromDB(privatekey, algorithm, keyrrstr)
		if err != nil {
			lgSigner.Error("ParsePrivateKeyFromDB failed", "err", err)
			return nil, err
		}

		// Use PrepareKeyCache with the BIND format (it handles both old and new keys this way)
		pkc, err := PrepareKeyCache(bindFormat, keyrrstr)
		if err != nil {
			lgSigner.Error("PrepareKeyCache failed", "err", err)
			return nil, err
		}

		// Ensure the parsed algorithm matches
		if pkc.Algorithm != alg {
			lgSigner.Warn("algorithm mismatch", "stored", alg, "parsed", pkc.Algorithm)
			return nil, fmt.Errorf("error: algorithm mismatch for key %s: stored=%d, parsed=%d", keyrrstr, alg, pkc.Algorithm)
		}

		sak.Keys = append(sak.Keys, pkc)
		keyfound = true
	}

	if !keyfound {
		// This is not an error, so lets just return an empty Sig0ActiveKeys
		lgSigner.Debug("no SIG(0) key found", "state", state, "zone", zonename)
		return &sak, nil
	}

	lgSigner.Debug("GetSig0Keys returned keys", "zone", zonename, "state", state, "keys", sak)

	kdb.KeystoreSig0Cache[zonename+"+"+state] = &sak

	return &sak, err
}

// GetSig0KeyRaw returns the raw database column values for a SIG(0) key.
// Used for transferring key material between agents via RFI CONFIG.
func (kdb *KeyDB) GetSig0KeyRaw(zonename, state string) (algorithm, privatekey, keyrr string, found bool, err error) {
	const sql = `SELECT algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND state=?`

	rows, err := kdb.Query(sql, zonename, state)
	if err != nil {
		return "", "", "", false, err
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&algorithm, &privatekey, &keyrr)
		if err != nil {
			return "", "", "", false, err
		}
		return algorithm, privatekey, keyrr, true, nil
	}
	if err := rows.Err(); err != nil {
		return "", "", "", false, err
	}
	return "", "", "", false, nil
}

func (kdb *KeyDB) GetDnssecKeys(zonename, state string) (*DnssecKeys, error) {
	const (
		fetchDnssecPrivKeySql = `
SELECT keyid, flags, algorithm, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND state=?`
	)

	// XXX: Should use this once we've found all the bugs in the sqlite code
	if state == DnskeyStateActive {
		if dak, ok := kdb.KeystoreDnskeyCache[zonename+"+"+state]; ok {
			return dak, nil
		}
	}

	var dk DnssecKeys

	rows, err := kdb.Query(fetchDnssecPrivKeySql, zonename, state)
	if err != nil {
		lgSigner.Error("failed to query DNSSEC keys", "sql", fetchDnssecPrivKeySql, "zone", zonename, "err", err)
		return nil, err
	}
	defer rows.Close()

	var algorithm, privatekey, keyrrstr, logmsg string
	var flags, keyid int

	var keysfound bool

	for rows.Next() {
		err := rows.Scan(&keyid, &flags, &algorithm, &privatekey, &keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				lgSigner.Debug("no active DNSSEC key found", "zone", zonename)
				return &dk, nil
			}
			lgSigner.Error("rows.Scan failed", "err", err)
			return nil, err
		}

		keysfound = true

		// Parse private key, detecting old BIND format or new PEM format
		_, alg, bindFormat, err := ParsePrivateKeyFromDB(privatekey, algorithm, keyrrstr)
		if err != nil {
			lgSigner.Error("ParsePrivateKeyFromDB failed", "err", err)
			return nil, err
		}

		// Use PrepareKeyCache with the BIND format (it handles both old and new keys this way)
		pkc, err := PrepareKeyCache(bindFormat, keyrrstr)
		if err != nil {
			lgSigner.Error("PrepareKeyCache failed", "err", err)
			return nil, err
		}

		// Ensure the parsed algorithm matches
		if pkc.Algorithm != alg {
			lgSigner.Warn("algorithm mismatch", "stored", alg, "parsed", pkc.Algorithm)
			return nil, fmt.Errorf("error: algorithm mismatch for key %s: stored=%d, parsed=%d", keyrrstr, alg, pkc.Algorithm)
		}

		if (flags & 0x0001) != 0 {
			dk.KSKs = append(dk.KSKs, pkc)
			//log.Printf("Adding KSK to DAK: flags: %d key: %s", flags, pkc.DnskeyRR.String())
			logmsg += fmt.Sprintf("%d (KSK) ", keyid)
		} else {
			dk.ZSKs = append(dk.ZSKs, pkc)
			// log.Printf("Adding ZSK to DAK: flags: %d key: %s", flags, pkc.DnskeyRR.String())
			logmsg += fmt.Sprintf("%d (ZSK) ", keyid)
		}
	}

	// No keys found is not an error
	if !keysfound {
		lgSigner.Debug("no DNSSEC keys found", "state", state, "zone", zonename)
		return &dk, nil
	}

	// No KSK found is a hard error
	if len(dk.KSKs) == 0 {
		lgSigner.Warn("no DNSSEC KSK found", "state", state, "zone", zonename)
		return &dk, nil
	}

	// When using a CSK it will have the flags = 257, but also be used as a ZSK.
	if len(dk.ZSKs) == 0 {
		lgSigner.Info("no DNSSEC ZSK found, reusing KSK as CSK", "state", state, "zone", zonename)
		dk.ZSKs = append(dk.ZSKs, dk.KSKs[0])
	}

	lgSigner.Debug("GetDnssecKeys returned keys", "zone", zonename, "state", state, "keys", logmsg)

	kdb.KeystoreDnskeyCache[zonename+"+"+state] = &dk

	return &dk, err
}

func (kdb *KeyDB) PromoteDnssecKey(zonename string, keyid uint16, oldstate, newstate string) (err error) {
	const getDnskeySql = `
    SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`
	const updateDnskeyStateSql = `
    UPDATE DnssecKeyStore SET state=? WHERE zonename=? AND keyid=? AND state=?`

	tx, err := kdb.Begin("PromoteDnssecKey")
	if err != nil {
		return fmt.Errorf("error beginning transaction: %v", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			if commitErr := tx.Commit(); commitErr != nil {
				err = fmt.Errorf("commit failed: %w", commitErr)
			}
		}
	}()

	// Look up the key in the DnssecKeyStore table
	var currentState string
	err = tx.QueryRow(getDnskeySql, zonename, keyid).Scan(&currentState)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("key with keyid %d not found in zone %s", keyid, zonename)
		}
		return fmt.Errorf("error querying DnssecKeyStore: %v", err)
	}

	// Verify the current state
	if currentState != oldstate {
		return fmt.Errorf("key with keyid %d in zone %s is not in state %s", keyid, zonename, oldstate)
	}

	// Update the state in the DnssecKeyStore table
	res, err := tx.Exec(updateDnskeyStateSql, newstate, zonename, keyid, oldstate)
	if err != nil {
		return fmt.Errorf("error updating DnssecKeyStore: %v", err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %v", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no rows updated, key with keyid %d in zone %s might not be in state %s", keyid, zonename, oldstate)
	}

	// Delete cached data for both old and new states
	delete(kdb.KeystoreDnskeyCache, zonename+"+"+oldstate)
	delete(kdb.KeystoreDnskeyCache, zonename+"+"+newstate)

	return nil
}

// GenerateAndStageKey generates a new DNSSEC key and stages it (created → published).
func GenerateAndStageKey(kdb *KeyDB, zone, creator string, alg uint8, keytype string) (uint16, error) {
	pkc, _, err := kdb.GenerateKeypair(zone, creator, DnskeyStateCreated, dns.TypeDNSKEY, alg, keytype, nil)
	if err != nil {
		return 0, fmt.Errorf("GenerateAndStageKey: key generation failed: %w", err)
	}

	keyid := pkc.KeyId

	if err := UpdateDnssecKeyState(kdb, zone, keyid, DnskeyStatePublished); err != nil {
		return 0, fmt.Errorf("GenerateAndStageKey: state transition to published failed: %w", err)
	}

	lgSigner.Info("generated and staged DNSSEC key", "zone", zone, "keyid", keyid, "keytype", keytype, "state", DnskeyStatePublished)
	return keyid, nil
}

// DefaultDnskeyTTL is the assumed DNSKEY RRset TTL when the actual TTL is not readily available.
const DefaultDnskeyTTL = 3600 * time.Second

// KeyInventoryItem is a lightweight DNSKEY entry for inventory responses.
// Does not include private key material — only the metadata needed for key classification.
type KeyInventoryItem struct {
	KeyTag    uint16
	Algorithm uint8
	Flags     uint16
	State     string // "created","published","standby","active","retired","removed"
	KeyRR     string // Full DNSKEY RR string (public key data, no private key)
}

// GetKeyInventory returns the complete DNSKEY inventory for a zone — all keys
// across all states. Used by the signer to respond to RFI KEYSTATE requests.
// Returns lightweight entries (keytag, algorithm, flags, state, keyrr) without private keys.
func GetKeyInventory(kdb *KeyDB, zonename string) ([]KeyInventoryItem, error) {
	const inventorySql = `SELECT keyid, flags, algorithm, state, COALESCE(keyrr, '') FROM DnssecKeyStore WHERE zonename=?`

	rows, err := kdb.Query(inventorySql, zonename)
	if err != nil {
		return nil, fmt.Errorf("GetKeyInventory: query failed for zone %s: %w", zonename, err)
	}
	defer rows.Close()

	var entries []KeyInventoryItem
	for rows.Next() {
		var keyid, flags int
		var algorithm string
		var state, keyrr string
		if err := rows.Scan(&keyid, &flags, &algorithm, &state, &keyrr); err != nil {
			return nil, fmt.Errorf("GetKeyInventory: scan failed: %w", err)
		}
		alg, ok := dns.StringToAlgorithm[algorithm]
		if !ok {
			lgSigner.Warn("GetKeyInventory: unknown algorithm, skipping key", "zone", zonename, "keyid", keyid, "algorithm", algorithm)
			continue
		}
		entries = append(entries, KeyInventoryItem{
			KeyTag:    uint16(keyid),
			Algorithm: alg,
			Flags:     uint16(flags),
			State:     state,
			KeyRR:     keyrr,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetKeyInventory: rows iteration failed: %w", err)
	}

	return entries, nil
}

// DnssecKeyWithTimestamps extends KeyInventoryItem with lifecycle timestamps.
// Used by the KeyStateWorker for time-based state transitions.
type DnssecKeyWithTimestamps struct {
	ZoneName    string
	KeyTag      uint16
	Algorithm   uint8
	Flags       uint16
	State       string
	KeyRR       string
	PublishedAt *time.Time
	RetiredAt   *time.Time
}

// GetDnssecKeysByState returns all DNSSEC keys in a given state, with lifecycle timestamps.
// If zone is empty, returns keys across all zones.
func GetDnssecKeysByState(kdb *KeyDB, zone string, state string) ([]DnssecKeyWithTimestamps, error) {
	var query string
	var args []interface{}

	if zone == "" {
		query = `SELECT zonename, keyid, flags, algorithm, state, COALESCE(keyrr, ''), COALESCE(published_at, ''), COALESCE(retired_at, '') FROM DnssecKeyStore WHERE state=?`
		args = []interface{}{state}
	} else {
		query = `SELECT zonename, keyid, flags, algorithm, state, COALESCE(keyrr, ''), COALESCE(published_at, ''), COALESCE(retired_at, '') FROM DnssecKeyStore WHERE zonename=? AND state=?`
		args = []interface{}{zone, state}
	}

	rows, err := kdb.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("GetDnssecKeysByState: query failed: %w", err)
	}
	defer rows.Close()

	var entries []DnssecKeyWithTimestamps
	for rows.Next() {
		var zonename, algorithm, st, keyrr, publishedAtStr, retiredAtStr string
		var keyid, flags int
		if err := rows.Scan(&zonename, &keyid, &flags, &algorithm, &st, &keyrr, &publishedAtStr, &retiredAtStr); err != nil {
			return nil, fmt.Errorf("GetDnssecKeysByState: scan failed: %w", err)
		}

		alg, ok := dns.StringToAlgorithm[algorithm]
		if !ok {
			lgSigner.Warn("GetDnssecKeysByState: unknown algorithm, skipping key", "zone", zonename, "keyid", keyid, "algorithm", algorithm)
			continue
		}
		entry := DnssecKeyWithTimestamps{
			ZoneName:  zonename,
			KeyTag:    uint16(keyid),
			Algorithm: alg,
			Flags:     uint16(flags),
			State:     st,
			KeyRR:     keyrr,
		}

		if publishedAtStr != "" {
			if t, err := time.Parse(time.RFC3339, publishedAtStr); err == nil {
				entry.PublishedAt = &t
			}
		}
		if retiredAtStr != "" {
			if t, err := time.Parse(time.RFC3339, retiredAtStr); err == nil {
				entry.RetiredAt = &t
			}
		}

		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetDnssecKeysByState: rows iteration failed: %w", err)
	}

	return entries, nil
}

// UpdateDnssecKeyState transitions a DNSSEC key to a new state and sets the
// appropriate lifecycle timestamp. When transitioning to "published", sets
// published_at. When transitioning to "retired", sets retired_at.
// Invalidates the cache for both old and new states.
func UpdateDnssecKeyState(kdb *KeyDB, zonename string, keyid uint16, newstate string) (err error) {
	tx, err := kdb.Begin("UpdateDnssecKeyState")
	if err != nil {
		return fmt.Errorf("error beginning transaction: %v", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			if commitErr := tx.Commit(); commitErr != nil {
				err = fmt.Errorf("commit failed: %w", commitErr)
			}
		}
	}()

	// Get the current state so we can invalidate the right cache entry
	var oldstate string
	err = tx.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zonename, keyid).Scan(&oldstate)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("key with keyid %d not found in zone %s", keyid, zonename)
		}
		return fmt.Errorf("error querying DnssecKeyStore: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	var res sql.Result
	switch newstate {
	case DnskeyStatePublished:
		res, err = tx.Exec(`UPDATE DnssecKeyStore SET state=?, published_at=? WHERE zonename=? AND keyid=?`,
			newstate, now, zonename, keyid)
	case DnskeyStateRetired:
		res, err = tx.Exec(`UPDATE DnssecKeyStore SET state=?, retired_at=? WHERE zonename=? AND keyid=?`,
			newstate, now, zonename, keyid)
	default:
		res, err = tx.Exec(`UPDATE DnssecKeyStore SET state=? WHERE zonename=? AND keyid=?`,
			newstate, zonename, keyid)
	}

	if err != nil {
		return fmt.Errorf("error updating DnssecKeyStore: %v", err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		err = fmt.Errorf("no rows updated for key %d in zone %s", keyid, zonename)
		return err
	}

	// Invalidate caches for both old and new states
	delete(kdb.KeystoreDnskeyCache, zonename+"+"+oldstate)
	delete(kdb.KeystoreDnskeyCache, zonename+"+"+newstate)

	lgSigner.Info("DNSKEY state updated", "zone", zonename, "keyid", keyid, "oldstate", oldstate, "newstate", newstate)
	return nil
}

// RolloverKey performs a manual key rollover for the specified zone and key type.
// It swaps the oldest standby key to active and the current active key to retired.
// Returns the old active keyid and the new active keyid.
// If tx is non-nil, uses the existing transaction; otherwise begins its own.
func (kdb *KeyDB) RolloverKey(zonename string, keytype string, tx *Tx) (uint16, uint16, error) {
	var expectedFlags uint16
	switch keytype {
	case "ZSK":
		expectedFlags = 256
	case "KSK", "CSK":
		expectedFlags = 257
	default:
		return 0, 0, fmt.Errorf("invalid keytype %q, must be ZSK or KSK", keytype)
	}

	// Get active keys of this type
	activeKeys, err := GetDnssecKeysByState(kdb, zonename, DnskeyStateActive)
	if err != nil {
		return 0, 0, fmt.Errorf("error getting active keys: %w", err)
	}

	var activeKey *DnssecKeyWithTimestamps
	for i, k := range activeKeys {
		if k.Flags == expectedFlags {
			activeKey = &activeKeys[i]
			break
		}
	}
	if activeKey == nil {
		return 0, 0, fmt.Errorf("no active %s found for zone %s", keytype, zonename)
	}

	// Get standby keys of this type
	standbyKeys, err := GetDnssecKeysByState(kdb, zonename, DnskeyStateStandby)
	if err != nil {
		return 0, 0, fmt.Errorf("error getting standby keys: %w", err)
	}

	var standbyKey *DnssecKeyWithTimestamps
	for i, k := range standbyKeys {
		if k.Flags == expectedFlags {
			standbyKey = &standbyKeys[i]
			break
		}
	}
	if standbyKey == nil {
		return 0, 0, fmt.Errorf("no standby %s available for rollover in zone %s", keytype, zonename)
	}

	// Use existing transaction or begin a new one
	localtx := false
	if tx == nil {
		tx, err = kdb.Begin("RolloverKey")
		if err != nil {
			return 0, 0, fmt.Errorf("error beginning transaction: %w", err)
		}
		localtx = true
	}

	now := time.Now().UTC().Format(time.RFC3339)
	var txErr error

	defer func() {
		if localtx {
			if txErr != nil {
				tx.Rollback()
			} else {
				tx.Commit()
			}
		}
	}()

	// standby → active
	_, txErr = tx.Exec(`UPDATE DnssecKeyStore SET state=? WHERE zonename=? AND keyid=?`,
		DnskeyStateActive, zonename, standbyKey.KeyTag)
	if txErr != nil {
		return 0, 0, fmt.Errorf("standby→active transition failed: %w", txErr)
	}

	// active → retired (set retired_at)
	_, txErr = tx.Exec(`UPDATE DnssecKeyStore SET state=?, retired_at=? WHERE zonename=? AND keyid=?`,
		DnskeyStateRetired, now, zonename, activeKey.KeyTag)
	if txErr != nil {
		return 0, 0, fmt.Errorf("active→retired transition failed: %w", txErr)
	}

	// Invalidate all relevant caches
	delete(kdb.KeystoreDnskeyCache, zonename+"+"+DnskeyStateActive)
	delete(kdb.KeystoreDnskeyCache, zonename+"+"+DnskeyStateStandby)
	delete(kdb.KeystoreDnskeyCache, zonename+"+"+DnskeyStateRetired)

	lgSigner.Info("key rollover completed", "zone", zonename, "keytype", keytype,
		"old_active", activeKey.KeyTag, "new_active", standbyKey.KeyTag)

	return activeKey.KeyTag, standbyKey.KeyTag, nil
}
