/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"sync"

	"github.com/johanix/tdns/tdns"
)

func NotifyHandler(conf *tdns.Config) error {
	zonech := conf.Internal.RefreshZoneCh
	dnsnotifyq := conf.Internal.DnsNotifyQ
	scannerq := conf.Internal.ScannerQ

	log.Printf("*** DnsNotifyResponderEngine: starting")

	var dhr tdns.DnsNotifyRequest

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for dhr = range dnsnotifyq {
			tdns.NotifyResponder(&dhr, zonech, scannerq)
		}
	}()
	wg.Wait()

	log.Println("DnsNotifyResponderEngine: terminating")
	return nil
}
