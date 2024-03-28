/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	//        "fmt"
	"log"
	"sync"

	"github.com/miekg/dns"
	// "github.com/johanix/tdns/tdns"
)

type UpdateRequest struct {
	Cmd       string
	ZoneName  string
	Adds      []dns.RR
	Removes   []dns.RR
	Actions   []dns.RR // The Update section from the dns.Msg
	Validated bool     // Signature over update msg is validated
	Trusted   bool     // Content of update is trusted (via validation or policy)
}

func UpdaterEngine(conf *Config) error {
	updateq := conf.Internal.UpdateQ
	var ur UpdateRequest

	kdb := conf.Internal.KeyDB

	log.Printf("Updater: starting")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			case ur = <-updateq:
				switch ur.Cmd {
				case "UPDATE":
					if ur.ZoneName == "" {
						log.Printf("Updater: Request for update %d adds and %d removes.", len(ur.Adds), len(ur.Removes))
					} else {
						log.Printf("Updater: Request for update %d actions.", len(ur.Actions))
						err := kdb.ApplyUpdate(ur)
						if err != nil {
							log.Printf("Error from ApplyUpdate: %v", err)
						}
					}
				default:
					log.Printf("Unknown command: '%s'. Ignoring.", ur.Cmd)
				}
			}
		}
	}()
	wg.Wait()

	log.Println("Updater: terminating")
	return nil
}

// 1. Sort actions so that all removes come first.
// 2. To delete an RRset, only owner + rrtype is needed
// 3. To delete an exact RR we need owner, rrtype and the rr.String(). Problem is if
//    the TTL is not correct. Therefore we should always store RRs with TTL=0

func (kdb *KeyDB) ApplyUpdate(ur UpdateRequest) error {
	const (
		addkeysql = `
INSERT OR REPLACE INTO ChildSig0Keys (owner, keyid, validated, trusted, keyrr) VALUES (?, ?, ?, ?)`
		adddelsql = `
INSERT OR REPLACE INTO ChildDelegationData (owner, rrtype, rr) VALUES (?, ?, ?)`
		delkeyrrsql    = `DELETE FROM ChildSig0Keys WHERE owner=? AND keyid=? AND rr=?`
		deldelrrsql    = `DELETE FROM ChildDelegationData WHERE owner=? AND rrtype=? AND rr=?`
		delkeyrrsetsql = `DELETE FROM ChildSig0Keys WHERE owner=? AND rrtype=?`
		deldelrrsetsql = `DELETE FROM ChildDelegationData WHERE owner=? AND rrtype=?`
	)

	tx, err := kdb.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			tx.Commit()
		} else {
			log.Printf("AppyUpdate: Error: %v. Rollback.", err)
		}
	}()

	for _, rr := range ur.Actions {
		class := rr.Header().Class
		owner := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 0
		rrcopy.Header().Class = dns.ClassINET

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			sqlcmd := deldelrrsql
			if rrtype == dns.TypeKEY {
				sqlcmd = delkeyrrsql
			}
			log.Printf("ApplyUpdate: Remove RR: %s %s %s",
				owner, rrtypestr, rrcopy.String())
			_, err := tx.Exec(sqlcmd, owner, rrtypestr, rrcopy.String())
			if err != nil {
				log.Printf("Error from tx.Exec(%s, %s, %s): %v",
					sqlcmd, owner, rrcopy.String(), err)
				return err
			}

		case dns.ClassANY:
			// ClassANY: Remove RRset
			log.Printf("ApplyUpdate: Remove RRset: %s", rr.String())
			sqlcmd := deldelrrsetsql
			if rrtype == dns.TypeKEY {
				sqlcmd = delkeyrrsetsql
			}
			_, err := tx.Exec(sqlcmd, owner, rrtypestr)
			if err != nil {
				log.Printf("Error from tx.Exec(%s, %s, %s): %v",
					sqlcmd, owner, rrtypestr, err)
				return err
			}

		case dns.ClassINET:
			// log.Printf("ApplyUpdate: Add RR: %s", req.String())
		default:
			log.Printf("ApplyUpdate: Error: unknown class: %s", rr.String())
		}

		sqlcmd := adddelsql
		if rrtype == dns.TypeKEY {
			sqlcmd = addkeysql
		}

		switch rrtype {
		case dns.TypeKEY:
			key := rr.(*dns.KEY)
			keyid := key.KeyTag()
			log.Printf("ApplyUpdate: Add KEY with keyid=%d", keyid)
			_, err := tx.Exec(sqlcmd, owner, keyid,
				ur.Validated, ur.Trusted, rrcopy.String())
			if err != nil {
				log.Printf("Error from kdb.Exec(%s): %v", sqlcmd, err)
				return err
			}
		case dns.TypeNS, dns.TypeA, dns.TypeAAAA:
			log.Printf("ApplyUpdate: Add %s with RR=%s", rrtypestr, rrcopy.String())
			_, err := tx.Exec(sqlcmd, owner, rrtype, rrcopy.String())
			if err != nil {
				log.Printf("Error from kdb.Exec(%s): %v", sqlcmd, err)
				return err
			}
		default:
			log.Printf("ApplyUpdate: Error: request to add %s RR", rrtypestr)
		}
	}

	return nil
}
