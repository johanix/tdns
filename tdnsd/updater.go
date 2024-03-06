/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"sync"

	"github.com/miekg/dns"
)

type UpdateRequest struct {
	Cmd      string
	ZoneName string
	Adds     []dns.RR
	Removes  []dns.RR
	Actions  []dns.RR // The Update section from the dns.Msg
}

func UpdaterEngine(conf *Config) error {
	updateq := conf.Internal.UpdateQ
	var ur UpdateRequest

	kdb := NewKeyDB(false)

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
			keyid := req.(*dns.KEY).KeyTag()
			switch class {
			case dns.ClassNONE:
				log.Printf("ApplyUpdate: Remove KEY with keyid=%d", keyid)
			case dns.ClassANY:
				log.Printf("ApplyUpdate: Remove RRset: %s", req.String())
			case dns.ClassINET:
				log.Printf("ApplyUpdate: Add KEY with keyid=%d", keyid)
			default:
				log.Printf("ApplyUpdate: Error: unknown class: %s", req.String())
			}
		default:
		}

	}
	return nil
}
