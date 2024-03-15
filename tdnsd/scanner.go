/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"sync"
	"time"

	"github.com/spf13/viper"
)

type ScanRequest struct {
	Cmd      string
	ZoneName string
	RRtype   string
}

func ScannerEngine(conf *Config) error {
	scannerq := conf.Internal.ScannerQ
	interval := viper.GetInt("scanner.interval")
	if interval < 10 {
		interval = 10
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)

	var sr ScanRequest

	log.Printf("Scanner: starting")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			case <-ticker.C:
				// log.Printf("Time for periodic scan of all zones.")
				// cds_scanner("")
				// csync_scanner("")

			case sr = <-scannerq:
				switch sr.Cmd {
				case "SCAN":
					if sr.ZoneName == "" {
						log.Printf("Scanner: Request for manual %s scan.", sr.RRtype)
						// scanner.Run(sr.RRtype)
					} else {
						log.Printf("Scanner: Request for immediate scan of zone %s for RRtype %s",
							sr.ZoneName, sr.RRtype)
						switch sr.RRtype {
						case "CDS":
							// go cds_scanner(sr.ZoneName)
						case "CSYNC":
							// go csync_scanner(sr.ZoneName)
						case "DNSKEY":
							// go dnskey_scanner(sr.ZoneName)
						}
					}
				default:
					log.Printf("Unknown command: '%s'. Ignoring.", sr.Cmd)
				}
			}
		}
	}()
	wg.Wait()

	log.Println("Scanner: terminating")
	return nil
}
