/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
        "fmt"
	"log"
	"sync"

	"github.com/miekg/dns"
	"github.com/johanix/tdns/tdns"
)

type UpdateRequest struct {
	Cmd        string
	ZoneName   string
	Adds       []dns.RR
	Removes    []dns.RR
	Actions    []dns.RR // The Update section from the dns.Msg
	Validated  bool
}

func UpdaterEngine(conf *Config) error {
	updateq := conf.Internal.UpdateQ
	var ur UpdateRequest

//	kdb := NewKeyDB(false)
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
func (kdb *KeyDB) ApplyUpdate(ur UpdateRequest) error {
const (
      addkeysql = `
INSERT OR REPLACE INTO ChildSig0Keys (owner, keyid, trusted, keyrr) VALUES (?, ?, ?, ?)`
)

	for _, req := range ur.Actions {
		class := req.Header().Class
		switch class {
		case dns.ClassNONE:
			// log.Printf("ApplyUpdate: Remove RR: %s", req.String())
		case dns.ClassANY:
			//log.Printf("ApplyUpdate: Remove RRset: %s", req.String())
		case dns.ClassINET:
			// log.Printf("ApplyUpdate: Add RR: %s", req.String())
		default:
			log.Printf("ApplyUpdate: Error: unknown class: %s", req.String())
		}

		rrtype := req.Header().Rrtype

		switch rrtype {
		case dns.TypeKEY:
			keyname := req.Header().Name
			keyid := req.(*dns.KEY).KeyTag()
			switch class {
			case dns.ClassNONE:
				log.Printf("ApplyUpdate: Remove KEY with keyid=%d", keyid)
			case dns.ClassANY:
				log.Printf("ApplyUpdate: Remove RRset: %s", req.String())
			case dns.ClassINET:
				log.Printf("ApplyUpdate: Add KEY with keyid=%d", keyid)
				mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
				tmp := req.(*dns.KEY)
				tdns.Sig0Store.Map.Set(mapkey, tdns.Sig0Key{
							          Name: keyname,
								  Validated: ur.Validated,
								  Key: *tmp,
							       })
				_, err := kdb.Exec(addkeysql, keyname, keyid,
				       	  		      ur.Validated, tmp.String())
				if err != nil {
				       log.Printf("Error from kdb.Exec(%s): %v",
				       			 addkeysql, err)
				}
			default:
				log.Printf("ApplyUpdate: Error: unknown class: %s", req.String())
			}
		default:
			log.Printf("ApplyUpdate: At the moment only applying KEY updates")
		}

	}
	return nil
}
