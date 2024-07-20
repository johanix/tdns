/*
 * Copyright (c) Johan Stenstam, <johani@johani.org>
 */
package tdns

import (
	"database/sql"
	"fmt"
	"log"

	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

func (kdb *KeyDB) Sig0KeyMgmt(kp KeystorePost) (*KeystoreResponse, error) {

	const (
		addSig0KeySql = `
INSERT OR REPLACE INTO Sig0KeyStore (zonename, state, keyid, algorithm, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?)`
		setStateSig0KeySql = "UPDATE Sig0KeyStore SET state=? WHERE zonename=? AND keyid=?"
		deleteSig0KeySql   = `DELETE FROM Sig0KeyStore WHERE zonename=? AND keyid=?`
		getAllSig0KeysSql  = `SELECT zonename, state, keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore`
		getSig0KeySql      = `
SELECT zonename, state, keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND keyid=?`
	)

	var resp = KeystoreResponse{Time: time.Now()}
	var res sql.Result

	tx, err := kdb.Begin("Sig0KeyMgmt")
	if err != nil {
		return &resp, err
	}

	defer func() {
		if err == nil {
			err1 := tx.Commit()
			log.Printf("Sig0KeyMgmt: err=%v tx.Commit() ok, err1=%v", err, err1)
			if err1 != nil {
				resp.Error = true
				resp.ErrorMsg = err1.Error()
			}
		} else {
			log.Printf("Error: %v. Rollback.", err)
			err1 := tx.Rollback()
			if err1 != nil {
				resp.Error = true
				resp.ErrorMsg = err1.Error()
			}
			// log.Printf("Sig0KeyMgmt: tx.Rollback() ok, err1=%v", err1)
		}
	}()

	log.Printf("Sig0KeyMgmt: request: %s", kp.SubCommand)

	switch kp.SubCommand {
	case "list":
		rows, err := kdb.Query(getAllSig0KeysSql)
		if err != nil {
			log.Printf("Error from kdb.Query(%s): %v", getAllSig0KeysSql, err)
			return &resp, fmt.Errorf("Error from kdb.Query(%s): %v", getAllSig0KeysSql, err)
		}
		defer rows.Close()

		var keyname, state, algorithm, privatekey, keyrrstr string
		var keyid int

		tmp2 := map[string]Sig0Key{}
		for rows.Next() {
			err := rows.Scan(&keyname, &state, &keyid, &algorithm, &privatekey, &keyrrstr)
			if err != nil {
				return nil, fmt.Errorf("Error from rows.Scan(): %v", err)
			}
			if len(privatekey) < 10 {
				privatekey = "ULTRA SECRET KEY"
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			tmp2[mapkey] = Sig0Key{
				Name:       keyname,
				State:      state,
				Algorithm:  algorithm,
				PrivateKey: fmt.Sprintf("%s*****%s", privatekey[0:4], privatekey[len(privatekey)-4:]),
				Keystr:     keyrrstr,
			}
		}
		resp.Sig0keys = tmp2
		resp.Msg = "Here are all the SIG(0) keys that we know"

	case "add": // AKA "import"
		pkc := kp.PrivateKeyCache
		res, err = tx.Exec(addSig0KeySql, pkc.KeyRR.Header().Name, kp.State, pkc.KeyRR.KeyTag(),
			dns.AlgorithmToString[pkc.Algorithm], pkc.K, pkc.KeyRR.String())
		// log.Printf("tx.Exec(%s, %s, %d, %s, %s)", addSig0KeySql, kp.Keyname, kp.Keyid, "***", kp.KeyRR)
		if err != nil {
			log.Printf("Error: %v", err)
			return &resp, err
		} else {
			rows, _ := res.RowsAffected()
			resp.Msg = fmt.Sprintf("Updated %d rows", rows)
		}

	case "setstate":
		res, err = tx.Exec(setStateSig0KeySql, kp.State, kp.Keyname, kp.Keyid)
		// log.Printf("tx.Exec(%s, %s, %s, %d)", setStateSig0KeySql, kp.State, kp.Keyname, kp.Keyid)
		if err != nil {
			log.Printf("Error: %v", err)
			return &resp, err
		} else {
			rows, _ := res.RowsAffected()
			if rows > 0 {
				resp.Msg = fmt.Sprintf("Updated %d rows", rows)
			} else {
				resp.Msg = fmt.Sprintf("Key with name \"%s\" and keyid %d not found.", kp.Keyname, kp.Keyid)
			}
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
			log.Printf("Error: %v", err)
			if err == sql.ErrNoRows {
				return &resp, fmt.Errorf("key %s (keyid %d) not found", kp.Keyname, kp.Keyid)
			}
			return &resp, err
		}
		if uint16(keyid) != kp.Keyid || zone != kp.Zone {
			log.Printf("keystore sig0 delete: key %s %d not found", kp.Keyname, kp.Keyid)
			resp.Msg = fmt.Sprintf("key %s %d not found", kp.Keyname, kp.Keyid)
			return &resp, nil
		}

		// 3. Return all good, now untrusted
		res, err = tx.Exec(deleteSig0KeySql, kp.Keyname, kp.Keyid)
		// log.Printf("tx.Exec(%s, %s, %d)", deleteSig0KeySql, kp.Keyname, kp.Keyid)
		if err != nil {
			log.Printf("Error: %v", err)
			return &resp, err
		}
		rows, _ := res.RowsAffected()
		resp.Msg = fmt.Sprintf("SIG(0) key %s (keyid %d) deleted (%d rows)", kp.Keyname, kp.Keyid, rows)

	default:
		log.Printf("Sig0KeyMgmt: Unknown SubCommand: %s", kp.SubCommand)
	}

	return &resp, nil
}

func (kdb *KeyDB) DnssecKeyMgmt(kp KeystorePost) (*KeystoreResponse, error) {

	const (
		addDnskeySql = `
INSERT OR REPLACE INTO DnssecKeyStore (zonename, state, keyid, flags,algorithm, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?)`
		setStateDnskeySql = "UPDATE DnssecKeyStore SET state=? WHERE zonename=? AND keyid=?"
		deleteDnskeySql   = `DELETE FROM DnssecKeyStore WHERE zonename=? AND keyid=?`
		getAllDnskeysSql  = `SELECT zonename, state, keyid, flags, algorithm, privatekey, keyrr FROM DnssecKeyStore`
		getDnskeySql      = `
SELECT zonename, state, keyid, flags, algorithm, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND keyid=?`
	)

	var resp = KeystoreResponse{Time: time.Now()}
	var res sql.Result

	tx, err := kdb.Begin("DnssecKeyMgmt")
	if err != nil {
		return &resp, err
	}

	defer func() {
		//		log.Printf("DnssecKeyMgmt: deferred tx.Commit()/tx.Rollback()")
		if err == nil {
			err1 := tx.Commit()
			if err1 != nil {
				log.Printf("DnssecKeyMgmt: tx.Commit() ok, err1=%v", err1)
				resp.Error = true
				resp.ErrorMsg = err1.Error()
			}
		} else {
			log.Printf("Error: %v. Rollback.", err)
			err1 := tx.Rollback()
			if err1 != nil {
				log.Printf("DnssecKeyMgmt: tx.Rollback() ok, err1=%v", err1)
				resp.Error = true
				resp.ErrorMsg = err1.Error()
			}
		}
	}()

	switch kp.SubCommand {
	case "list":
		rows, err := tx.Query(getAllDnskeysSql)
		if err != nil {
			return nil, fmt.Errorf("Error from kdb.Query(%s): %v", getAllDnskeysSql, err)
		}
		defer rows.Close()

		var keyname, state, algorithm, privatekey, keyrrstr string
		var keyid, flags int

		tmp2 := map[string]DnssecKey{}
		for rows.Next() {
			err := rows.Scan(&keyname, &state, &keyid, &flags, &algorithm, &privatekey, &keyrrstr)
			if err != nil {
				return nil, fmt.Errorf("Error from rows.Scan(): %v", err)
			}
			if len(privatekey) < 10 {
				privatekey = "ULTRA SECRET KEY"
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			tmp2[mapkey] = DnssecKey{
				Name:       keyname,
				State:      state,
				Flags:      uint16(flags),
				Algorithm:  algorithm,
				PrivateKey: fmt.Sprintf("%s*****%s", privatekey[0:5], privatekey[len(privatekey)-5:]),
				Keystr:     keyrrstr,
			}
		}
		resp.Dnskeys = tmp2
		resp.Msg = "Here are all the DNSSEC keys that we know"

	case "add": // AKA "import"
		//		res, err = tx.Exec(addDnskeySql, kp.Keyname, kp.State, kp.Keyid, kp.Flags, dns.AlgorithmToString[kp.Algorithm],
		//			kp.PrivateKey, kp.DnskeyRR)

		pkc := kp.PrivateKeyCache
		res, err = tx.Exec(addDnskeySql, pkc.DnskeyRR.Header().Name, kp.State, pkc.DnskeyRR.KeyTag(), pkc.DnskeyRR.Flags,
			dns.AlgorithmToString[pkc.Algorithm], pkc.K, pkc.DnskeyRR.String())

		// log.Printf("tx.Exec(%s, %s, %s, %d, %d, %s, %s, %s)", addDnskeySql, kp.Keyname, kp.State, kp.Keyid, kp.Flags, dns.AlgorithmToString[kp.Algorithm], "***", kp.DnskeyRR)
		if err != nil {
			log.Printf("Error from tx.Exec(): %v", err)
			return &resp, err
		} else {
			log.Printf("tx.Exec(): all ok")
			rows, _ := res.RowsAffected()
			resp.Msg = fmt.Sprintf("Updated %d rows", rows)
		}

	case "setstate":
		res, err = tx.Exec(setStateDnskeySql, kp.State, kp.Keyname, kp.Keyid)
		// log.Printf("tx.Exec(%s, %s, %s, %d)", setStateDnskeySql, kp.State, kp.Keyname, kp.Keyid)
		if err != nil {
			log.Printf("Error from tx.Exec(): %v", err)
			return &resp, err
		} else {
			rows, _ := res.RowsAffected()
			if rows > 0 {
				resp.Msg = fmt.Sprintf("Updated %d rows", rows)
			} else {
				resp.Msg = fmt.Sprintf("Key with name \"%s\" and keyid %d not found.", kp.Keyname, kp.Keyid)
			}
		}

	case "delete":
		const getDnskeySql = `
SELECT zonename, state, keyid, flags, algorithm, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND keyid=?`

		// 1. Find key, if not --> error
		row := tx.QueryRow(getDnskeySql, kp.Zone, kp.Keyid)

		var zone, state, algorithm, privatekey, keyrr string
		var keyid, flags int
		err := row.Scan(&zone, &state, &keyid, &flags, &algorithm, &privatekey, &keyrr)
		if err != nil {
			log.Printf("Error: %v", err)
			if err == sql.ErrNoRows {
				return &resp, fmt.Errorf("key %s (keyid %d) not found", kp.Keyname, kp.Keyid)
			}
			return &resp, err
		}
		if uint16(keyid) != kp.Keyid || zone != kp.Zone {
			log.Printf("keystore sig0 delete: key %s %d not found", kp.Keyname, kp.Keyid)
			resp.Msg = fmt.Sprintf("key %s %d not found", kp.Keyname, kp.Keyid)
			return &resp, nil
		}

		// 3. Return all good, now untrusted
		res, err = tx.Exec(deleteDnskeySql, kp.Keyname, kp.Keyid)
		log.Printf("tx.Exec(%s, %s, %d)", deleteDnskeySql, kp.Keyname, kp.Keyid)
		if err != nil {
			log.Printf("Error from tx.Exec(): %v", err)
			//			resp.Error = true
			//			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		rows, _ := res.RowsAffected()
		resp.Msg = fmt.Sprintf("Key %s (keyid %d) deleted (%d rows)", kp.Keyname, kp.Keyid, rows)

	default:
		log.Printf("DnssecKeyMgmt: Unknown SubCommand: %s", kp.SubCommand)
	}

	return &resp, nil
}

func (kdb *KeyDB) GetSig0ActiveKeys(zonename string) (*Sig0ActiveKeys, error) {
	const (
		fetchSig0PrivKeySql = `
SELECT keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND state='active'`
	)

	if sak, ok := kdb.Sig0Cache[zonename]; ok {
		return sak, nil
	}

	rows, err := kdb.Query(fetchSig0PrivKeySql, zonename)
	if err != nil {
		log.Printf("Error from kdb.Query(%s, %s): %v", fetchSig0PrivKeySql, zonename, err)
		return nil, err
	}
	defer rows.Close()

	var algorithm, privatekey, keyrrstr string
	var keyid int

	var keyfound bool
	var sak Sig0ActiveKeys

	for rows.Next() {
		err := rows.Scan(&keyid, &algorithm, &privatekey, &keyrrstr)
		// log.Printf("rows.Scan() returned err=%v, keyid=%d, algorithm=%s, privatekey=%s, keyrrstr=%s", err, keyid, algorithm, privatekey, keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				// This is not an error, so lets just return an empty Sig0ActiveKeys
				log.Printf("No active SIG(0) key found for zone %s", zonename)
				return &sak, nil
			}
			log.Printf("Error from rows.Scan(): %v", err)
			return nil, err
		}
		keyfound = true
		pkc, err := PrepareKeyCache(privatekey, keyrrstr, algorithm)
		if err != nil {
			log.Printf("Error from tdns.PrepareKeyCache(): %v", err)
			return nil, err
		}
		sak.Keys = append(sak.Keys, pkc)
	}

	if !keyfound {
		// This is not an error, so lets just return an empty Sig0ActiveKeys
		log.Printf("No active SIG(0) key found for zone %s", zonename)
		return &sak, nil
	}

	if Globals.Debug {
		log.Printf("GetSig0ActiveKey(%s) returned keys %v", zonename, sak)
	}

	kdb.Sig0Cache[zonename] = &sak

	return &sak, err
}

func (kdb *KeyDB) GetDnssecActiveKeys(zonename string) (*DnssecActiveKeys, error) {
	const (
		fetchDnssecPrivKeySql = `
SELECT keyid, flags, algorithm, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND state='active'`
	)

	if data, ok := kdb.DnssecCache[zonename]; ok {
		return data, nil
	}

	var dak DnssecActiveKeys

	rows, err := kdb.Query(fetchDnssecPrivKeySql, zonename)
	if err != nil {
		log.Printf("Error from kdb.Query(%s, %s): %v", fetchDnssecPrivKeySql, zonename, err)
		return nil, err
	}
	defer rows.Close()

	var algorithm, privatekey, keyrrstr string
	var flags, keyid int

	var keyfound bool

	for rows.Next() {
		err := rows.Scan(&keyid, &flags, &algorithm, &privatekey, &keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("No active DNSSEC key found for zone %s", zonename)
				return nil, err
			}
			log.Printf("Error from rows.Scan(): %v", err)
			return nil, err
		}
		keyfound = true
		pkc, err := PrepareKeyCache(privatekey, keyrrstr, algorithm)
		if err != nil {
			log.Printf("Error from tdns.PrepareKey(): %v", err)
			return nil, err

		}

		if (flags & 0x0100) != 0 {
			dak.KSKs = append(dak.KSKs, pkc)
		} else {
			dak.ZSKs = append(dak.ZSKs, pkc)
		}
	}

	if !keyfound {
		log.Printf("No active DNSSEC key found for zone %s", zonename)
		return nil, sql.ErrNoRows
	}

	// No KSK found is a hard error
	if len(dak.KSKs) == 0 {
		log.Printf("No active DNSSEC KSK found for zone %s", zonename)
		return nil, sql.ErrNoRows
	}

	// When using a CSK it will have the flags = 257, but also be used as a ZSK.
	if len(dak.ZSKs) == 0 {
		dak.ZSKs = append(dak.ZSKs, dak.KSKs[0])
	}

	if Globals.Debug {
		log.Printf("GetDnssecKey(%s) returned key %v", zonename, dak)
	}

	kdb.DnssecCache[zonename] = &dak

	return &dak, err
}
