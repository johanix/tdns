/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"sync"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

type DnsHandlerRequest struct {
	ResponseWriter dns.ResponseWriter
	Msg            *dns.Msg
	Qname          string
}

func UpdateHandler(conf *Config) error {
	dnsupdateq := conf.Internal.DnsUpdateQ
	updateq := conf.Internal.UpdateQ

	log.Printf("*** DnsUpdateResponderEngine: starting")

	var dhr tdns.DnsHandlerRequest

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			case dhr = <-dnsupdateq:
				tdns.UpdateResponder(&dhr, updateq)
			}
		}
	}()
	wg.Wait()

	log.Println("DnsUpdateResponderEngine: terminating")
	return nil
}
