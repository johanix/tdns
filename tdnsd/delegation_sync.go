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

type DelSyncRequest struct {
	Cmd      string
	ZoneName string
	Adds     []dns.RR
	Removes  []dns.RR
}

func DelegationSyncEngine(conf *Config) error {
	delsyncq := conf.Internal.DelegationSyncQ
	var ds DelSyncRequest

	kdb := conf.Internal.KeyDB
	_ = kdb

	log.Printf("DelegationSyncEngine: starting")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			case ds = <-delsyncq:
				switch ds.Cmd {
				case "SYNC-DELEGATION":
					log.Printf("DelegationSyncEngine: Request for delegation sync %d adds and %d removes.", len(ds.Adds), len(ds.Removes))

					// 1. Figure out which scheme to use
					// 2. Call handler for that scheme

				default:
					log.Printf("Unknown command: '%s'. Ignoring.", ds.Cmd)
				}
			}
		}
	}()
	wg.Wait()

	log.Println("DelegationSyncEngine: terminating")
	return nil
}
