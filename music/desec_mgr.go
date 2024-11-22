/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"fmt"
	"log"

	//	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
	// "github.com/DNSSEC-Provisioning/music/music"
)

// According to https://desec.readthedocs.io/en/latest/rate-limits.html
// these are the rate limits we have to plan for:
// dns_api_read: 10/s, 50/min
// dns_api_write_domain: 10/s, 300/min, 1000/h
// dns_api_write_rrsets: 2/s, 15/min, 30/h, 300/day

func DeSECmgr(mconf *Config, done <-chan struct{}) {

	desecfetch := mconf.Internal.DesecFetch
	desecupdate := mconf.Internal.DesecUpdate

	// we use the limit per minute
	var fetch_limit = viper.GetInt("signers.desec.limits.fetch")   // per second
	var update_limit = viper.GetInt("signers.desec.limits.update") // per second

	if fetch_limit == 0 {
		log.Fatalf("Error: signers.desec.limits.fetch must be defined and > 0. Likely value: 5 (op/s).")
	}
	if update_limit == 0 {
		log.Fatalf("Error: signers.desec.limits.update must be defined and > 0. Likely value: 2 (op/s).")
	}

	log.Println("Starting deSEC Manager. Will rate-limit deSEC API requests.")

	fetch_ticker := time.NewTicker(time.Minute)
	update_ticker := time.NewTicker(time.Minute)

	go func() {
		var fetchOpQueue = []SignerOp{}
		var rl bool
		var err error
		var fdop, op SignerOp
		var fetch_ops, hold int
		for {
			select {
			case op = <-desecfetch:
				fetchOpQueue = append(fetchOpQueue, op)

			case <-fetch_ticker.C:
				if CliConf.Debug && len(fetchOpQueue) > 0 {
					fmt.Printf("%v: deSEC fetch_ticker: Total ops last period: %d. Ops in queue: %d\n",
						time.Now(), fetch_ops, len(fetchOpQueue))
				}
				fetch_ops = 0

				for {
					if len(fetchOpQueue) == 0 {
						// nothing in queue
						break
					}
					fdop = fetchOpQueue[0]
					fetchOpQueue = fetchOpQueue[1:]

					log.Printf("deSECMgr: fetch request for '%s %s'\n",
						fdop.Owner, dns.TypeToString[fdop.RRtype])
					for {
						rl, hold, err = RLDesecFetchRRset(fdop)
						if err != nil {
							log.Printf("deSECmgr: Error from RLDesecFetchRRset: rl: %v hold: %d err: %v\n", rl, hold, err)
						}
						if !rl {
							// fmt.Printf("deSECmgr: fetch was rate-limited. Will sleep for %d seconds.\n", hold)
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
				log.Println("deSEC fetch ticker: stop signal received.")
			}
		}
	}()

	// deSEC updater
	go func() {
		var updateOpQueue = []SignerOp{}
		var rl bool
		var err error
		var op, udop SignerOp
		var update_ops, hold int
		for {
			select {
			case op = <-desecupdate:
				updateOpQueue = append(updateOpQueue, op)
				// fmt.Printf("deSEC Mgr: request for '%s %s'\n", op.Owner, dns.TypeToString[op.RRtype])

			case <-update_ticker.C:
				if CliConf.Debug && len(updateOpQueue) > 0 {
					fmt.Printf("%v: deSEC update_ticker: Total ops last period: %d. Ops in queue: %d\n",
						time.Now(), update_ops, len(updateOpQueue))
				}
				update_ops = 0
				for {
					if len(updateOpQueue) == 0 {
						// fmt.Printf("deSEC Update: queue empty, nothing to do\n")
						break
					}
					udop = updateOpQueue[0]
					updateOpQueue = updateOpQueue[1:]

					// log.Printf("deSEC Mgr: update request for '%s %s'\n",
					// 			udop.Owner, dns.TypeToString[udop.RRtype])
					for {
						rl, hold, err = RLDesecUpdate(udop)
						if err != nil {
							log.Printf("deSEC Mgr: Error from RLDesecUpdate: %v\n", err)
						}
						// fmt.Printf("deSEC Mgr: response from RLDdnsUpdate: rl: %v hold: %d err: %v\n", rl, hold, err)
						if !rl {
							// fmt.Printf("deSEC Mgr: all ok, done with this request\n")
							break
						} else {
							fmt.Printf("deSEC Mgr: update was rate-limited. Will sleep for %d seconds\n", hold)
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
				log.Println("deSEC Mgr update ticker: stop signal received.")

			}
		}
	}()
}
