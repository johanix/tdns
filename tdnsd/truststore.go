/*
 *
 */
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/johanix/tdns/tdns"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func (kdb *KeyDB) ChildSig0Mgmt(kp tdns.TruststorePost) (tdns.TruststoreResponse, error) {

	const (
		addkeysql = `
INSERT OR REPLACE INTO Sig0TrustStore (zonename, keyid, trusted, keyrr) VALUES (?, ?, ?, ?)`
		getallchildsig0keyssql = `
SELECT zonename, keyid, trusted, validated, keyrr FROM Sig0TrustStore`
		getonechildsig0keyssql = `
SELECT child, keyid, trusted, validated, keyrr FROM Sig0TrustStore WHERE zonename=? AND keyid=?`
		childsig0keyupdatetrustsql = `
UPDATE Sig0TrustStore SET trusted=? WHERE zonename=? AND keyid=?`
	)

	var resp = tdns.TruststoreResponse{Time: time.Now()}
	var res sql.Result

	tx, err := kdb.Begin()
	if err != nil {
		return resp, err
	}

	switch kp.SubCommand {
	case "list":

		rows, err := tx.Query(getallchildsig0keyssql)
		if err != nil {
			log.Fatalf("Error from kdb.Query(%s): %v", getallchildsig0keyssql, err)
		}
		defer rows.Close()

		var keyname, keyrrstr string
		var keyid int
		var trusted, validated bool

		tmp2 := map[string]tdns.Sig0Key{}
		for rows.Next() {
			err := rows.Scan(&keyname, &keyid, &trusted, &validated, &keyrrstr)
			if err != nil {
				log.Fatalf("Error from rows.Scan(): %v", err)
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			tmp2[mapkey] = tdns.Sig0Key{
				Name:      keyname,
				Validated: validated,
				Trusted:   trusted,
				Keystr:    keyrrstr,
			}
		}
		resp.ChildSig0keys = tmp2
		resp.Msg = "Here are all the child SIG(0) keys that we know"

	case "trust":
		// 1. Find key, if not --> error
		// 2. Set key trusted, if not --> error
		// 3. Return all good, now trusted
		res, err = tx.Exec(childsig0keyupdatetrustsql, true,
			kp.Keyname, kp.Keyid)
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
			kp.Keyname, kp.Keyid)
		log.Printf("tx.Exec(%s, %v, %s, %d)", childsig0keyupdatetrustsql,
			false, kp.Keyname, kp.Keyid)
		if err != nil {
			log.Printf("Error: %v", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
		} else {
			rows, _ := res.RowsAffected()
			resp.Msg = fmt.Sprintf("Updated %d rows", rows)
		}

	default:
		log.Printf("ChildSig0Mgmt: Unknown SubCommand: %s", kp.SubCommand)
	}
	if err == nil {
		tx.Commit()
	} else {
		log.Printf("Error: %v. Rollback.", err)
		tx.Rollback()
	}
	return resp, nil
}

func (kdb *KeyDB) LoadDnskeyTrustAnchors() error {
	// If a validator trusted key config file is found, read it in.
	tafile := viper.GetString("validator.dnskey.trusted.file")
	if tafile != "" {
		cfgdata, err := os.ReadFile(tafile)
		if err != nil {
			log.Fatalf("Error from ReadFile(%s): %v", tafile, err)
		}

		var tatmp TAtmp
		//	   var tastore = tdns.NewTAStore()

		err = yaml.Unmarshal(cfgdata, &tatmp)
		if err != nil {
			log.Fatalf("Error from yaml.Unmarshal(TAtmp): %v", err)
		}

		for k, v := range tatmp {
			k = dns.Fqdn(k)
			rr, err := dns.NewRR(v.Dnskey)
			if err != nil {
				log.Fatalf("Error from dns.NewRR(%s): %v", v.Dnskey, err)
			}

			if dnskeyrr, ok := rr.(*dns.DNSKEY); ok {
				mapkey := fmt.Sprintf("%s::%d", k, dnskeyrr.KeyTag())
				tdns.TAStore.Map.Set(mapkey, tdns.TrustAnchor{
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

func (kdb *KeyDB) LoadChildSig0Keys() error {

	const (
		loadsig0sql = "SELECT zonename, keyid, trusted, keyrr FROM Sig0TrustStore"
		addkeysql   = `
INSERT OR REPLACE INTO Sig0TrustStore (zonename, keyid, trusted, keyrr) VALUES (?, ?, ?, ?)`
		getonechildsig0keyssql = `
SELECT child, keyid, validated, trusted, keyrr FROM Sig0TrustStore WHERE zonename=? AND keyid=?`
		insertchildsig0key = `
       INSERT OR REPLACE INTO Sig0TrustStore(zonename, keyid, trusted, validated, keyrr)
       VALUES (?, ?, ?, ?, ?)`
	)

	log.Printf("*** Enter LoadChildSig0Keys() ***")

	rows, err := kdb.Query(loadsig0sql)
	if err != nil {
		log.Fatalf("Error from kdb.Query(%s): %v", loadsig0sql, err)
	}
	defer rows.Close()

	var keyname, keyrrstr string
	var keyid int
	var trusted bool

	for rows.Next() {
		err := rows.Scan(&keyname, &keyid, &trusted, &keyrrstr)
		if err != nil {
			log.Fatalf("Error from rows.Scan(): %v", err)
		}

		rr, err := dns.NewRR(keyrrstr)
		if err != nil {
			log.Fatalf("Error from dns.NewRR(%s): %v", keyrrstr, err)
		}

		if keyrr, ok := rr.(*dns.KEY); ok {
			mapkey := fmt.Sprintf("%s::%d", keyname, keyrr.KeyTag())
			tdns.Sig0Store.Map.Set(mapkey, tdns.Sig0Key{
				Name:      keyname,
				Validated: trusted,
				Key:       *keyrr,
			})
		}
	}

	// If a validator trusted key config file is found, read it in.
	sig0file := viper.GetString("validator.sig0.trusted.file")
	if sig0file != "" {
		cfgdata, err := os.ReadFile(sig0file)
		if err != nil {
			log.Fatalf("Error from ReadFile(%s): %v", sig0file, err)
		}

		var sig0tmp Sig0tmp

		tx, err := kdb.Begin()
		if err != nil {
			return err
		}

		err = yaml.Unmarshal(cfgdata, &sig0tmp)
		if err != nil {
			log.Fatalf("Error from yaml.Unmarshal(Sig0config): %v", err)
		}

		for k, v := range sig0tmp {
			k = dns.Fqdn(k)
			rr, err := dns.NewRR(v.Key)
			if err != nil {
				log.Fatalf("Error from dns.NewRR(%s): %v", v.Key, err)
			}

			if keyrr, ok := rr.(*dns.KEY); ok {
				log.Printf("* LoadChildSig0Keys: loading key %s", k)
				mapkey := fmt.Sprintf("%s::%d", k, keyrr.KeyTag())
				tdns.Sig0Store.Map.Set(mapkey, tdns.Sig0Key{
					Name:      k,
					Keyid:     keyrr.KeyTag(),
					Validated: true, // always trust config
					Trusted:   true, // always trust config
					Key:       *keyrr,
				})
				_, err = tx.Exec(insertchildsig0key, k, keyrr.KeyTag(), true, true, keyrr.String())
				if err != nil {
					log.Printf("LoadChildSigKeys: Error from tx.Exec(%s): %v",
						insertchildsig0key, err)
					continue
				}
			} else {
				log.Printf("LoadChildSig0Keys: Key %s is not a KEY?", rr.String())
			}
		}
		tx.Commit()
	}
	return nil
}