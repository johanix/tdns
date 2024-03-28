/*
 *
 */
package main

import (
	"database/sql"
	"fmt"
	"log"
	// "os"
	"time"

	"github.com/johanix/tdns/tdns"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	// "github.com/spf13/viper"
	// "gopkg.in/yaml.v3"
)

func (kdb *KeyDB) Sig0Mgmt(kp tdns.KeystorePost) (tdns.KeystoreResponse, error) {

	const (
		addsig0keysql     = `
INSERT OR REPLACE INTO Sig0KeyStore (zonename, keyid, algorithm, privatekey, keyrr) VALUES (?, ?, ?, ?, ?)`
		deletesig0keysql  = `DELETE FROM Sig0KeyStore WHERE zonename=? AND keyid=?`
		getallsig0keyssql = `SELECT zonename, keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore`
		getsig0keysql  = `
SELECT zonename, keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND keyid=?`
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
		rows, err := tx.Query(getallsig0keyssql)
		if err != nil {
			log.Fatalf("Error from kdb.Query(%s): %v", getallsig0keyssql, err)
		}
		defer rows.Close()

		var keyname, algorithm, privatekey, keyrrstr string
		var keyid int

		tmp2 := map[string]tdns.Sig0Key{}
		for rows.Next() {
			err := rows.Scan(&keyname, &keyid, &algorithm, &privatekey, &keyrrstr)
			if err != nil {
				log.Fatalf("Error from rows.Scan(): %v", err)
			}
			if len(privatekey) < 10 {
			   privatekey = "ULTRA SECRET KEY"
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			tmp2[mapkey] = tdns.Sig0Key{
				Name:		keyname,
				Algorithm:	algorithm,
				PrivateKey:	fmt.Sprintf("%s*****%s", privatekey[0:5], privatekey[len(privatekey)-5:]),
				Keystr: 	keyrrstr,
			}
		}
		resp.Sig0keys = tmp2
		resp.Msg = "Here are all the SIG(0) keys that we know"

	case "add": // AKA "import"
		res, err = tx.Exec(addsig0keysql, kp.Keyname, kp.Keyid, dns.AlgorithmToString[kp.Algorithm], kp.PrivateKey, kp.KeyRR)
		log.Printf("tx.Exec(%s, %s, %d, %s, %s)", addsig0keysql, kp.Keyname, kp.Keyid, "***", kp.KeyRR)
		if err != nil {
			log.Printf("Error: %v", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
		} else {
			rows, _ := res.RowsAffected()
			resp.Msg = fmt.Sprintf("Updated %d rows", rows)
		}

	case "delete":
		// 1. Find key, if not --> error
		row := tx.QueryRow(getsig0keysql, kp.Keyname, kp.Keyid)

		var keyname string
		var keyid int
		err := row.Scan(&keyname, &keyid)
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
		if uint16(keyid) != kp.Keyid || keyname != kp.Keyname {
 			log.Printf("keystore sig0 delete: key %s %d not found", kp.Keyname, kp.Keyid)
			resp.Msg = fmt.Sprintf("key %s %d not found", kp.Keyname, kp.Keyid)
			return resp, nil
		}

		// 3. Return all good, now untrusted
		res, err = tx.Exec(deletesig0keysql, kp.Keyname, kp.Keyid)
		log.Printf("tx.Exec(%s, %s, %d)", deletesig0keysql, kp.Keyname, kp.Keyid)
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

// func (kdb *KeyDB) LoadDnskeyTrustAnchors() error {
// 	// If a validator trusted key config file is found, read it in.
// 	tafile := viper.GetString("validator.dnskey.trusted.file")
// 	if tafile != "" {
// 		cfgdata, err := os.ReadFile(tafile)
// 		if err != nil {
// 			log.Fatalf("Error from ReadFile(%s): %v", tafile, err)
// 		}
// 
// 		var tatmp TAtmp
// 		//	   var tastore = tdns.NewTAStore()
// 
// 		err = yaml.Unmarshal(cfgdata, &tatmp)
// 		if err != nil {
// 			log.Fatalf("Error from yaml.Unmarshal(TAtmp): %v", err)
// 		}
// 
// 		for k, v := range tatmp {
// 			k = dns.Fqdn(k)
// 			rr, err := dns.NewRR(v.Dnskey)
// 			if err != nil {
// 				log.Fatalf("Error from dns.NewRR(%s): %v", v.Dnskey, err)
// 			}
// 
// 			if dnskeyrr, ok := rr.(*dns.DNSKEY); ok {
// 				mapkey := fmt.Sprintf("%s::%d", k, dnskeyrr.KeyTag())
// 				tdns.TAStore.Map.Set(mapkey, tdns.TrustAnchor{
// 					Name:      k,
// 					Validated: true, // always trust config
// 					Dnskey:    *dnskeyrr,
// 				})
// 			}
// 		}
// 		//	   conf.Internal.TrustedDnskeys = tastore
// 	}
// 	return nil
// }

// 1. Load SIG(0) public keys from config, write to DB (i.e. config overrides DB)

// func (kdb *KeyDB) LoadKnownSig0Keys() error {
// 
// 	const (
// 		loadsig0sql = "SELECT child, keyid, trusted, keyrr FROM ChildSig0Keys"
// 		addkeysql   = `
// INSERT OR REPLACE INTO ChildSig0Keys (child, keyid, trusted, keyrr) VALUES (?, ?, ?, ?)`
// 		//       	    getallchildsig0keyssql = `
// 		// SELECT owner, keyid, trusted, validated, keyrr FROM ChildSig0Keys`
// 		getonechildsig0keyssql = `
// SELECT child, keyid, validated, trusted, keyrr FROM ChildSig0Keys WHERE owner=? AND keyid=?`
// 		insertchildsig0key = `
//        INSERT OR REPLACE INTO ChildSig0Keys(child, keyid, trusted, validated, keyrr)
//        VALUES (?, ?, ?, ?, ?)`
// 	)
// 
// 	log.Printf("*** Enter LoadKnownSig0Keys() ***")
// 
// 	rows, err := kdb.Query(loadsig0sql)
// 	if err != nil {
// 		log.Fatalf("Error from kdb.Query(%s): %v", loadsig0sql, err)
// 	}
// 	defer rows.Close()
// 
// 	var keyname, keyrrstr string
// 	var keyid int
// 	var trusted bool
// 
// 	for rows.Next() {
// 		err := rows.Scan(&keyname, &keyid, &trusted, &keyrrstr)
// 		if err != nil {
// 			log.Fatalf("Error from rows.Scan(): %v", err)
// 		}
// 
// 		rr, err := dns.NewRR(keyrrstr)
// 		if err != nil {
// 			log.Fatalf("Error from dns.NewRR(%s): %v", keyrrstr, err)
// 		}
// 
// 		if keyrr, ok := rr.(*dns.KEY); ok {
// 			mapkey := fmt.Sprintf("%s::%d", keyname, keyrr.KeyTag())
// 			tdns.Sig0Store.Map.Set(mapkey, tdns.Sig0Key{
// 				Name:      keyname,
// 				Validated: trusted,
// 				Key:       *keyrr,
// 			})
// 		}
// 	}
// 
// 	// If a validator trusted key config file is found, read it in.
// 	sig0file := viper.GetString("validator.sig0.trusted.file")
// 	if sig0file != "" {
// 		cfgdata, err := os.ReadFile(sig0file)
// 		if err != nil {
// 			log.Fatalf("Error from ReadFile(%s): %v", sig0file, err)
// 		}
// 
// 		var sig0tmp Sig0tmp
// 
// 		tx, err := kdb.Begin()
// 		if err != nil {
// 			return err
// 		}
// 
// 		err = yaml.Unmarshal(cfgdata, &sig0tmp)
// 		if err != nil {
// 			log.Fatalf("Error from yaml.Unmarshal(Sig0config): %v", err)
// 		}
// 
// 		for k, v := range sig0tmp {
// 			k = dns.Fqdn(k)
// 			rr, err := dns.NewRR(v.Key)
// 			if err != nil {
// 				log.Fatalf("Error from dns.NewRR(%s): %v", v.Key, err)
// 			}
// 
// 			if keyrr, ok := rr.(*dns.KEY); ok {
// 				log.Printf("* LoadChildSig0Keys: loading key %s", k)
// 				mapkey := fmt.Sprintf("%s::%d", k, keyrr.KeyTag())
// 				tdns.Sig0Store.Map.Set(mapkey, tdns.Sig0Key{
// 					Name:      k,
// 					Keyid:     keyrr.KeyTag(),
// 					Validated: true, // always trust config
// 					Trusted:   true, // always trust config
// 					Key:       *keyrr,
// 				})
// 				_, err = tx.Exec(insertchildsig0key, k, keyrr.KeyTag(), true, true, keyrr.String())
// 				if err != nil {
// 					log.Printf("LoadKnownSigKeys: Error from tx.Exec(%s): %v",
// 						insertchildsig0key, err)
// 					continue
// 				}
// 			} else {
// 				log.Printf("LoadKnownSig0Keys: Key %s is not a KEY?", rr.String())
// 			}
// 		}
// 		tx.Commit()
// 	}
// 	return nil
// }
