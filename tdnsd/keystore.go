/*
 * Johan Stenstam, <johani@johani.org>
 */
package main

import (
	"crypto"
	"database/sql"
	"fmt"
	"log"

	"time"

	"github.com/johanix/tdns/tdns"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	// "github.com/spf13/viper"
	// "gopkg.in/yaml.v3"
)

func (kdb *KeyDB) Sig0Mgmt(kp tdns.KeystorePost) (tdns.KeystoreResponse, error) {

	const (
		addSig0KeySql = `
INSERT OR REPLACE INTO Sig0KeyStore (zonename, state, keyid, algorithm, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?)`
		setStateSig0KeySql = "UPDATE Sig0KeyStore SET state=? WHERE zonename=? AND keyid=?"
		deleteSig0KeySql   = `DELETE FROM Sig0KeyStore WHERE zonename=? AND keyid=?`
		getAllSig0KeysSql  = `SELECT zonename, state, keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore`
		getSig0KeySql      = `
SELECT zonename, state, keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND keyid=?`
	)

	var resp = tdns.KeystoreResponse{Time: time.Now()}
	var res sql.Result

	tx, err := kdb.Begin()
	if err != nil {
		return resp, err
	}

	defer func() {
		if err == nil {
			tx.Commit()
		} else {
			log.Printf("Error: %v. Rollback.", err)
			tx.Rollback()
		}
	}()

	switch kp.SubCommand {
	case "list":
		rows, err := tx.Query(getAllSig0KeysSql)
		if err != nil {
			log.Fatalf("Error from kdb.Query(%s): %v", getAllSig0KeysSql, err)
		}
		defer rows.Close()

		var keyname, state, algorithm, privatekey, keyrrstr string
		var keyid int

		tmp2 := map[string]tdns.Sig0Key{}
		for rows.Next() {
			err := rows.Scan(&keyname, &state, &keyid, &algorithm, &privatekey, &keyrrstr)
			if err != nil {
				log.Fatalf("Error from rows.Scan(): %v", err)
			}
			if len(privatekey) < 10 {
				privatekey = "ULTRA SECRET KEY"
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			tmp2[mapkey] = tdns.Sig0Key{
				Name:       keyname,
				State:      state,
				Algorithm:  algorithm,
				PrivateKey: fmt.Sprintf("%s*****%s", privatekey[0:5], privatekey[len(privatekey)-5:]),
				Keystr:     keyrrstr,
			}
		}
		resp.Sig0keys = tmp2
		resp.Msg = "Here are all the SIG(0) keys that we know"

	case "add": // AKA "import"
		res, err = tx.Exec(addSig0KeySql, kp.Keyname, kp.State, kp.Keyid, dns.AlgorithmToString[kp.Algorithm],
			kp.PrivateKey, kp.KeyRR)
		log.Printf("tx.Exec(%s, %s, %d, %s, %s)", addSig0KeySql, kp.Keyname, kp.Keyid, "***", kp.KeyRR)
		if err != nil {
			log.Printf("Error: %v", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
		} else {
			rows, _ := res.RowsAffected()
			resp.Msg = fmt.Sprintf("Updated %d rows", rows)
		}

	case "setstate":
		res, err = tx.Exec(setStateSig0KeySql, kp.State, kp.Keyname, kp.Keyid)
		log.Printf("tx.Exec(%s, %s, %s, %d)", setStateSig0KeySql, kp.State, kp.Keyname, kp.Keyid)
		if err != nil {
			log.Printf("Error: %v", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
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
			resp.Error = true
			if err == sql.ErrNoRows {
				resp.ErrorMsg = fmt.Sprintf("Key %s (keyid %d) not found", kp.Keyname, kp.Keyid)
			} else {
				resp.ErrorMsg = err.Error()
			}
			return resp, err
		}
		if uint16(keyid) != kp.Keyid || zone != kp.Zone {
			log.Printf("keystore sig0 delete: key %s %d not found", kp.Keyname, kp.Keyid)
			resp.Msg = fmt.Sprintf("key %s %d not found", kp.Keyname, kp.Keyid)
			return resp, nil
		}

		// 3. Return all good, now untrusted
		res, err = tx.Exec(deleteSig0KeySql, kp.Keyname, kp.Keyid)
		log.Printf("tx.Exec(%s, %s, %d)", deleteSig0KeySql, kp.Keyname, kp.Keyid)
		if err != nil {
			log.Printf("Error: %v", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return resp, err
		}
		rows, _ := res.RowsAffected()
		resp.Msg = fmt.Sprintf("Key %s (keyid %d) deleted (%d rows)", kp.Keyname, kp.Keyid, rows)

	default:
		log.Printf("Sig0Mgmt: Unknown SubCommand: %s", kp.SubCommand)
	}
	return resp, nil
}

func (kdb *KeyDB) GetSig0Key(zonename string) (crypto.PrivateKey, crypto.Signer, *dns.KEY, error) {
	const (
		fetchSig0PrivKeySql = `
SELECT keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND state='active'`
	)

	var cs crypto.Signer
	var k crypto.PrivateKey
	var rr dns.RR
	var keyrr *dns.KEY

	tx, err := kdb.Begin()
	if err != nil {
		return k, cs, keyrr, err
	}

	rows, err := tx.Query(fetchSig0PrivKeySql, zonename)
	if err != nil {
		log.Printf("Error from kdb.Query(%s, %s): %v", fetchSig0PrivKeySql, zonename, err)
		return k, cs, nil, err
	}
	defer rows.Close()

	var algorithm, privatekey, keyrrstr string
	var keyid int

	var keyfound bool

	for rows.Next() {
		err := rows.Scan(&keyid, &algorithm, &privatekey, &keyrrstr)
		log.Printf("rows.Scan() returned err=%v, keyid=%d, algorithm=%s, privatekey=%s, keyrrstr=%s", err, keyid, algorithm, privatekey, keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("No active SIG(0) key found for zone %s", zonename)
				return k, cs, nil, err
			}
			log.Printf("Error from rows.Scan(): %v", err)
			return k, cs, nil, err
		}
		keyfound = true
		k, cs, rr, _, _, err = tdns.PrepareKey(privatekey, keyrrstr, algorithm)
		if err != nil {
			log.Printf("Error from tdns.PrepareKey(): %v", err)
			return k, cs, nil, err
		}
	}

	if !keyfound {
		log.Printf("No active SIG(0) key found for zone %s", zonename)
		return k, cs, nil, sql.ErrNoRows
	}

	if tdns.Globals.Debug {
		log.Printf("GetSig0Key(%s) returned key %v\nk=%v\ncs=%v\n", zonename, rr, k, cs)
	}

	keyrr = rr.(*dns.KEY)

	return k, cs, keyrr, err
}
