/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"sync"

	"github.com/johanix/tdns/tdns"
)

func UpdateHandler(conf *tdns.Config) error {
	dnsupdateq := conf.Internal.DnsUpdateQ
	updateq := conf.Internal.UpdateQ

	log.Printf("*** DnsUpdateResponderEngine: starting")

	var dhr tdns.DnsUpdateRequest

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for dhr = range dnsupdateq {
			tdns.UpdateResponder(&dhr, updateq)
		}
	}()
	wg.Wait()

	log.Println("DnsUpdateResponderEngine: terminating")
	return nil
}
