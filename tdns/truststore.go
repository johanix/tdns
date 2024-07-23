/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// XXX: These should die
type TAtmp map[string]TmpAnchor

type TmpAnchor struct {
	Name   string
	Dnskey string
}

type Sig0tmp map[string]TmpSig0Key

type TmpSig0Key struct {
	Name string
	Key  string
}

func (kdb *KeyDB) Sig0TrustMgmt(tp TruststorePost) (*TruststoreResponse, error) {

	const (
		addkeysql = `
INSERT OR REPLACE INTO Sig0TrustStore (zonename, keyid, trusted, validated, source, keyrr) VALUES (?, ?, ?, ?, ?, ?)`
		getallchildsig0keyssql = `
SELECT zonename, keyid, trusted, validated, source, keyrr FROM Sig0TrustStore`
		getonechildsig0keyssql = `
SELECT child, keyid, trusted, validated, source, keyrr FROM Sig0TrustStore WHERE zonename=? AND keyid=?`
		childsig0keyupdatetrustsql = `
UPDATE Sig0TrustStore SET trusted=? WHERE zonename=? AND keyid=?`
		deleteSig0KeySql = `
DELETE FROM Sig0TrustStore WHERE zonename=? AND keyid=?`
	)

	var resp = TruststoreResponse{
		Time: time.Now(),
	}
	var res sql.Result

	tx, err := kdb.Begin("Sig0TrustStoreMgmt")
	if err != nil {
		return &resp, err
	}

	defer func() {
		if err == nil {
			err1 := tx.Commit()
			if err1 != nil {
				log.Printf("Sig0TrustStoreMgmt: tx.Commit() error=%v", err1)
			}
		} else {
			log.Printf("Error: %v. Rollback.", err)
			err1 := tx.Rollback()
			if err1 != nil {
				log.Printf("ChildSig0Mgmt: tx.Rollback() error=%v", err1)
			}
		}
	}()

	switch tp.SubCommand {
	case "list":

		rows, err := tx.Query(getallchildsig0keyssql)
		if err != nil {
			return nil, fmt.Errorf("Error from kdb.Query(%s): %v", getallchildsig0keyssql, err)
		}
		defer rows.Close()

		var keyname, keyrrstr, source string
		var keyid int
		var trusted, validated bool

		tmp2 := map[string]Sig0Key{}
		for rows.Next() {
			err := rows.Scan(&keyname, &keyid, &trusted, &validated, &source, &keyrrstr)
			if err != nil {
				return nil, fmt.Errorf("Error from rows.Scan(): %v", err)
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			tmp2[mapkey] = Sig0Key{
				Name:      keyname,
				Validated: validated,
				Trusted:   trusted,
				Source:    source,
				Keystr:    keyrrstr,
			}
		}
		resp.ChildSig0keys = tmp2
		resp.Msg = "Here are all the child SIG(0) keys that we know"

	case "add":
		// 1. If src=file and key is supplied then add it (but as untrusted)
		// 2. If src=dns then schedule some soort of DNS fetching exercise.
		if tp.Src == "file" {
			_, err = tx.Exec(addkeysql, tp.Keyname, tp.Keyid, false, false, tp.Src, tp.KeyRR)
			if err != nil {
				log.Printf("Error adding SIG(0) key to TrustStore: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s: SIG(0) key with keyid %d added (not yet trusted)", tp.Keyname, tp.Keyid)
			}
		} else if tp.Src == "keystore" {
			_, err = tx.Exec(addkeysql, tp.Keyname, tp.Keyid, true, true, tp.Src, tp.KeyRR)
			if err != nil {
				log.Printf("Error adding SIG(0) key to TrustStore: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s: SIG(0) key with keyid %d imported from KeyStore to TrustStore", tp.Keyname, tp.Keyid)
			}
		} else if tp.Src == "child-update" {
			_, err = tx.Exec(addkeysql, tp.Keyname, tp.Keyid, true, true, tp.Src, tp.KeyRR)
			if err != nil {
				log.Printf("Error adding SIG(0) key to TrustStore: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s: SIG(0) key with keyid %d (trusted=%v) added to TrustStore on child request",
					tp.Keyname, tp.Keyid, tp.Trusted)
			}
		} else if tp.Src == "dns" {
			resp.Msg = fmt.Sprintf("Zone %s: SIG(0) key to be fetched via DNS (not yet done)", tp.Keyname)
			// schedule some sort of DNS fetching exercise.
		}

	case "delete":

		// 1. Find key, if not --> error
		row := tx.QueryRow(getonechildsig0keyssql, tp.Keyname, tp.Keyid)

		var zone, keyrr, source string
		var keyid int
		var trusted, validated bool

		err := row.Scan(&zone, &keyid, &trusted, &validated, &source, &keyrr)
		if err != nil {
			log.Printf("Error: %v", err)
			if err == sql.ErrNoRows {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("key %s (keyid %d) not found", tp.Keyname, tp.Keyid)
				// return &resp, fmt.Errorf("key %s (keyid %d) not found", tp.Keyname, tp.Keyid)
			}
			// return &resp, err
		}
		if keyid != tp.Keyid || zone != tp.Keyname {
			log.Printf("truststore sig0 delete: key %s (keyid %d) not found", tp.Keyname, tp.Keyid)
			resp.Msg = fmt.Sprintf("key %s (keyid %d) not found", tp.Keyname, tp.Keyid)
			// return &resp, nil
		}

		// 3. Return all good, now untrusted
		res, err = tx.Exec(deleteSig0KeySql, tp.Keyname, tp.Keyid)
		// log.Printf("tx.Exec(%s, %s, %d)", deleteSig0KeySql, kp.Keyname, kp.Keyid)
		if err != nil {
			log.Printf("Error deleting SIG(0) key from TrustStore: %v", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
			// return &resp, err
		}
		rows, _ := res.RowsAffected()
		resp.Msg = fmt.Sprintf("SIG(0) key %s (keyid %d) deleted from TrustStore (%d rows)", tp.Keyname, tp.Keyid, rows)

	case "trust":
		// 1. Find key, if not --> error
		// 2. Set key trusted, if not --> error
		// 3. Return all good, now trusted
		res, err = tx.Exec(childsig0keyupdatetrustsql, true,
			tp.Keyname, tp.Keyid)
		if err != nil {
			log.Printf("Error: %v", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
		} else {
			rows, _ := res.RowsAffected()
			resp.Msg = fmt.Sprintf("Updated %d rows", rows)
		}

	case "untrust":
		// 1. Find key, if not --> error
		// 2. Set key trusted, if not --> error
		// 3. Return all good, now untrusted
		res, err = tx.Exec(childsig0keyupdatetrustsql, false,
			tp.Keyname, tp.Keyid)
		log.Printf("tx.Exec(%s, %v, %s, %d)", childsig0keyupdatetrustsql,
			false, tp.Keyname, tp.Keyid)
		if err != nil {
			log.Printf("Error: %v", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
		} else {
			rows, _ := res.RowsAffected()
			resp.Msg = fmt.Sprintf("Updated %d rows", rows)
		}

	default:
		log.Printf("Sig0TrustStoreMgmt: Unknown SubCommand: %s", tp.SubCommand)
	}

	return &resp, nil
}

func (kdb *KeyDB) LoadDnskeyTrustAnchors() error {
	// If a validator trusted key config file is found, read it in.
	tafile := viper.GetString("validator.dnskey.trusted.file")
	if tafile != "" {
		cfgdata, err := os.ReadFile(tafile)
		if err != nil {
			return fmt.Errorf("Error from ReadFile(%s): %v", tafile, err)
		}

		var tatmp TAtmp
		//	   var tastore = tdns.NewTAStore()

		err = yaml.Unmarshal(cfgdata, &tatmp)
		if err != nil {
			return fmt.Errorf("Error from yaml.Unmarshal(TAtmp): %v", err)
		}

		for k, v := range tatmp {
			k = dns.Fqdn(k)
			rr, err := dns.NewRR(v.Dnskey)
			if err != nil {
				return fmt.Errorf("Error from dns.NewRR(%s): %v", v.Dnskey, err)
			}

			if dnskeyrr, ok := rr.(*dns.DNSKEY); ok {
				mapkey := fmt.Sprintf("%s::%d", k, dnskeyrr.KeyTag())
				TAStore.Map.Set(mapkey, TrustAnchor{
					Name:      k,
					Validated: true, // always trust config
					Dnskey:    *dnskeyrr,
				})
			}
		}
		//	   conf.Internal.TrustedDnskeys = tastore
	}
	return nil
}

// 1. Load SIG(0) public keys from config, write to DB (i.e. config overrides DB)

func (kdb *KeyDB) LoadSig0ChildKeys() error {

	const (
		loadsig0sql = "SELECT zonename, keyid, trusted, validated, keyrr FROM Sig0TrustStore"
		addkeysql   = `
INSERT OR REPLACE INTO Sig0TrustStore (zonename, keyid, trusted, validated, source, keyrr) VALUES (?, ?, ?, ?, ?, ?)`
		getonechildsig0keyssql = `
SELECT child, keyid, validated, trusted, source, keyrr FROM Sig0TrustStore WHERE zonename=? AND keyid=?`
		insertchildsig0key = `
       	INSERT OR REPLACE INTO Sig0TrustStore(zonename, keyid, trusted, validated, source, keyrr)
       VALUES (?, ?, ?, ?, ?, ?)`
	)

	log.Printf("*** Enter LoadChildSig0Keys() ***")
	// dump.P(kdb)

	// tx, err := kdb.Begin("LoadChildSig0Keys")
	// if err != nil {
	//		return err
	//	}

	rows, err := kdb.Query(loadsig0sql)
	if err != nil {
		return fmt.Errorf("Error from kdb.Query(%s): %v", loadsig0sql, err)
	}
	defer rows.Close()

	var keyname, keyrrstr string
	var keyid int
	var trusted, validated bool

	for rows.Next() {
		err := rows.Scan(&keyname, &keyid, &trusted, &validated, &keyrrstr)
		if err != nil {
			return fmt.Errorf("Error from rows.Scan(): %v", err)
		}

		rr, err := dns.NewRR(keyrrstr)
		if err != nil {
			return fmt.Errorf("Error from dns.NewRR(%s): %v", keyrrstr, err)
		}

		if keyrr, ok := rr.(*dns.KEY); ok {
			mapkey := fmt.Sprintf("%s::%d", keyname, keyrr.KeyTag())
			Sig0Store.Map.Set(mapkey, Sig0Key{
				Name:      keyname,
				Validated: validated,
				Trusted:   trusted,
				Key:       *keyrr,
			})
		}
	}
	// err1 := tx.Commit()
	// if err1 != nil {
	//		log.Printf("LoadChildSig0Keys: tx.Commit() error=%v", err1)
	// }

	// If a validator trusted key config file is found, read it in.
	sig0file := viper.GetString("validator.sig0.trusted.file")
	if sig0file != "" {
		cfgdata, err := os.ReadFile(sig0file)
		if err != nil {
			return fmt.Errorf("Error from ReadFile(%s): %v", sig0file, err)
		}

		var sig0tmp Sig0tmp

		tx, err := kdb.Begin("LoadSig0ChildKeys (again)")
		if err != nil {
			return err
		}

		err = yaml.Unmarshal(cfgdata, &sig0tmp)
		if err != nil {
			return fmt.Errorf("Error from yaml.Unmarshal(Sig0config): %v", err)
		}

		for k, v := range sig0tmp {
			k = dns.Fqdn(k)
			rr, err := dns.NewRR(v.Key)
			if err != nil {
				return fmt.Errorf("Error from dns.NewRR(%s): %v", v.Key, err)
			}

			if keyrr, ok := rr.(*dns.KEY); ok {
				log.Printf("* LoadChildSig0Keys: loading key %s", k)
				mapkey := fmt.Sprintf("%s::%d", k, keyrr.KeyTag())
				Sig0Store.Map.Set(mapkey, Sig0Key{
					Name:      k,
					Keyid:     keyrr.KeyTag(),
					Validated: true, // always trust config
					Trusted:   true, // always trust config
					Source:    "file",
					Key:       *keyrr,
				})
				_, err = tx.Exec(insertchildsig0key, k, keyrr.KeyTag(), true, true, "file", keyrr.String())
				if err != nil {
					log.Printf("LoadSig0ChildKeys: Error from tx.Exec(%s): %v",
						insertchildsig0key, err)
					continue
				}
			} else {
				log.Printf("LoadSig0ChildKeys: Key %s is not a KEY?", rr.String())
			}
		}
		err1 := tx.Commit()
		if err1 != nil {
			log.Printf("LoadSig0ChildKeys: tx.Commit() error=%v", err1)
		}
	}
	return nil
}

// XXX: This should not be a method of ZoneData, but rather a function.
// If key not found *TrustAnchor is nil
func (zd *ZoneData) FindSig0TrustedKey(signer string, keyid uint16) (*Sig0Key, error) {
	mapkey := fmt.Sprintf("%s::%d", signer, keyid)

	// 1. Try to fetch the key from the Sig0Store cache
	// if sk, ok := Sig0Store.Map.Get(mapkey); ok {
	//	return &sk, nil
	// }

	const (
		fetchsig0trustanchor = "SELECT validated, trusted, keyrr FROM Sig0TrustStore WHERE zonename=? AND keyid=?"
	)

	// 2. Try to fetch the key from the Sig0TrustStore database
	rows, err := zd.KeyDB.Query(fetchsig0trustanchor, signer, keyid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var validated, trusted bool
		var keyrrstr string
		err = rows.Scan(&validated, &trusted, &keyrrstr)
		if err != nil {
			return nil, err
		}
		rr, err := dns.NewRR(keyrrstr)
		if err != nil {
			return nil, err
		}
		keyrr, ok := rr.(*dns.KEY)
		if !ok {
			return nil, fmt.Errorf("FindSig0TrustedKey: Error: SIG(0) key %s in KeyDB is not a KEY RR", signer)
		}
		sk := Sig0Key{
			Name:      signer,
			Validated: validated,
			Trusted:   trusted,
			Key:       *keyrr,
		}
		Sig0Store.Map.Set(mapkey, sk)
		return &sk, nil
	}

	// 3. Try to fetch the key from the Sig0KeyStore database.
	// XXX: Note that if the key is present and active in the KeyStore (because it is for a
	// zone that we are authoritative for) but not in the TrustStore then we will import it
	// into the TrustStore automatically.

	sak, err := zd.KeyDB.GetSig0ActiveKeys(signer)
	if err != nil {
		return nil, err
	}

	if len(sak.Keys) > 0 {
		for _, key := range sak.Keys {
			if key.KeyRR.KeyTag() == keyid {
				// This key that is present and active in the KeyStore is not present in the TrustStore
				// Let's add it now.
				tspost := TruststorePost{
					Command:    "truststore",
					SubCommand: "add",
					Keyname:    signer,
					Keyid:      int(keyid),
					Src:        "keystore",
					KeyRR:      key.KeyRR.String(),
				}
				tsresp, err := zd.KeyDB.Sig0TrustMgmt(tspost)
				if err != nil {
					return nil, err
				}
				log.Printf("FindSig0TrustedKey: %s", tsresp.Msg)
				sa := Sig0Key{
					Name:      signer,
					Key:       key.KeyRR,
					Validated: true,
					Trusted:   true,
				}
				return &sa, nil
			}
		}
	}

	// 4. Try to fetch the key by looking up and validating the KEY RRset via DNS
	zd.Logger.Printf("FindSig0TrustedKey: SIG(0) key with id %s: not found in TrustStore, will fetch via DNS.", mapkey)
	rrset, err := zd.LookupRRset(signer, dns.TypeKEY, true)
	if err != nil {
		return nil, err
	}
	if rrset == nil {
		return nil, fmt.Errorf("SIG(0) trusted key %s not found", signer)
	}
	valid, err := zd.ValidateRRset(rrset, true)
	if err != nil {
		return nil, err
	}
	zd.Logger.Printf("FindSig0TrustedKey: Found %s KEY RRset (validated)", signer)
	for _, rr := range rrset.RRs {
		if keyrr, ok := rr.(*dns.KEY); ok {
			sk := Sig0Key{
				Name:      signer,
				Validated: valid,
				Key:       *keyrr,
			}
			// Sig0Store.Map.Set(signer+"::"+string(keyrr.KeyTag()), sk)
			return &sk, nil
		}
	}

	return nil, fmt.Errorf("SIG(0) trusted key %s not found in TrustStore", signer)
}
