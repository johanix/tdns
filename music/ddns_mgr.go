/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"fmt"
	"log"

	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// According to https://desec.readthedocs.io/en/latest/rate-limits.html
// these are the rate limits we have to plan for:
// dns_api_read: 10/s, 50/min
// dns_api_write_domain: 10/s, 300/min, 1000/h
// dns_api_write_rrsets: 2/s, 15/min, 30/h, 300/day

func DdnsMgr(mconf *Config, done <-chan struct{}) {

	ddnsfetch := mconf.Internal.DdnsFetch
	ddnsupdate := mconf.Internal.DdnsUpdate

	// we use the limit per minute
	var fetch_limit = viper.GetInt("signers.ddns.limits.fetch")   // per second
	var update_limit = viper.GetInt("signers.ddns.limits.update") // per second

	if fetch_limit == 0 {
		log.Fatalf("Error: signers.ddns.limits.fetch must be defined and > 0. Likely value: 5 (op/s).")
	}
	if update_limit == 0 {
		log.Fatalf("Error: signers.ddns.limits.update must be defined and > 0. Likely value: 2 (op/s).")
	}

	log.Println("Starting DDNS Manager. Will rate-limit DDNS requests (queries and updates).")

	// fetch_ticker := time.NewTicker(time.Minute)
	// update_ticker := time.NewTicker(time.Minute)
	fetch_ticker := time.NewTicker(5 * time.Second)
	update_ticker := time.NewTicker(5 * time.Second)

	//	go Recoverer("DDNS fetch routine", func() {
	// ddns fetcher
	go func() {
		var fetchOpQueue = []SignerOp{}
		var rl bool
		var err error
		var fdop, op SignerOp
		var fetch_ops, hold int
		for {
			select {
			case op = <-ddnsfetch:
				fetchOpQueue = append(fetchOpQueue, op)
				// fmt.Printf("ddnsmgr: request for '%s %s'\n", op.Owner, dns.TypeToString[op.RRtype])

			case <-fetch_ticker.C:
				if CliConf.Debug && len(fetchOpQueue) > 0 {
					log.Printf("DDNS fetch_ticker: Total ops last period: %d. Ops in queue: %d\n",
						fetch_ops, len(fetchOpQueue))
				}
				fetch_ops = 0
				for {
					if len(fetchOpQueue) == 0 {
						// fmt.Printf("DDNS fetch: queue empty, nothing to do\n")
						break
					}
					fdop = fetchOpQueue[0]
					fetchOpQueue = fetchOpQueue[1:]

					log.Printf("ddnsmgr: Fetch request to signer %s (%s) for '%s %s'\n",
						fdop.Signer.Name, fdop.Signer.Address,
						fdop.Owner, dns.TypeToString[fdop.RRtype])
					for {
						rl, hold, err = RLDdnsFetchRRset(fdop)
						if err != nil {
							log.Printf("ddnsmgr: Error from RLDdnsFetchRRset: %v\n", err)
						}
						// fmt.Printf("ddnsmgr: response from RLDdnsFetchRRset: rl: %v hold: %d err: %v\n", rl, hold, err)
						if !rl {
							// fmt.Printf("ddnsmgr: all ok, done with this request\n")
							break
						} else {
							fmt.Printf("ddnsmgr: fetch was rate-limited. Will sleep for %d seconds\n", hold)
							time.Sleep(time.Duration(hold) * time.Second)
						}
					}
					fetch_ops++
					if fetch_ops >= fetch_limit {
						break // the loop for this minute
					}

				}

			case <-done:
				fetch_ticker.Stop()
				log.Println("DDNS Mgr fetch ticker: stop signal received.")
			}
		}
	}()
	//	},
	//		func(interface{}) {
	//		   log.Printf("*** DDNS fetch routine bombed\n")
	//		   } )

	// ddns updater
	go func() {
		var updateOpQueue = []SignerOp{}
		var rl bool
		var err error
		var op, udop SignerOp
		var update_ops, hold int
		for {
			select {
			case op = <-ddnsupdate:
				updateOpQueue = append(updateOpQueue, op)
				// log.Printf("ddnsmgr: request for '%s %s'\n", op.Owner, dns.TypeToString[op.RRtype])

			case <-update_ticker.C:
				if CliConf.Debug && len(updateOpQueue) > 0 {
					log.Printf("DDNS update_ticker: Total ops last period: %d. Ops in queue: %d\n",
						update_ops, len(updateOpQueue))
				}
				update_ops = 0
				for {
					if len(updateOpQueue) == 0 {
						// fmt.Printf("DDNS update: queue empty, nothing to do\n")
						break
					}
					udop = updateOpQueue[0]
					updateOpQueue = updateOpQueue[1:]

					// log.Printf("ddnsmgr: update request for '%s %s'\n",
					// 			udop.Owner, dns.TypeToString[udop.RRtype])
					for {
						rl, hold, err = RLDdnsUpdate(udop)
						if err != nil {
							log.Printf("ddnsmgr: Error from RLDdnsUpdate: %v\n", err)
						}
						// fmt.Printf("ddnsmgr: response from RLDdnsUpdate: rl: %v hold: %d err: %v\n", rl, hold, err)
						if !rl {
							// fmt.Printf("ddnsmgr: all ok, done with this request\n")
							break
						} else {
							fmt.Printf("ddnsmgr: update was rate-limited. Will sleep for %d seconds\n", hold)
							time.Sleep(time.Duration(hold) * time.Second)
						}
					}
					update_ops++
					if update_ops >= update_limit {
						break // the loop for this minute
					}
				}

			case <-done:
				update_ticker.Stop()
				log.Println("DDNS Mgr update ticker: stop signal received.")

			}
		}
	}()
}
