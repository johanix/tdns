/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"

	"github.com/johanix/tdns/tdns"
)

func DnsEngine(conf *tdns.Config) error {
	addresses := viper.GetStringSlice("dnsengine.addresses")

	// verbose := viper.GetBool("dnsengine.verbose")
	// debug := viper.GetBool("dnsengine.debug")
	dns.HandleFunc(".", createHandler(conf))

	log.Printf("DnsEngine: addresses: %v", addresses)
	for _, addr := range addresses {
		for _, net := range []string{"udp", "tcp"} {
			go func(addr, net string) {
				log.Printf("DnsEngine: serving on %s (%s)\n", addr, net)
				server := &dns.Server{
					Addr:          addr,
					Net:           net,
					MsgAcceptFunc: tdns.MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
				}

				// Must bump the buffer size of incoming UDP msgs, as updates
				// may be much larger then queries
				server.UDPSize = dns.DefaultMsgSize // 4096
				if err := server.ListenAndServe(); err != nil {
					log.Printf("Failed to setup the %s server: %s\n", net, err.Error())
				} else {
					log.Printf("DnsEngine: listening on %s/%s\n", addr, net)
				}
			}(addr, net)
		}
	}
	return nil
}

func createHandler(conf *tdns.Config) func(w dns.ResponseWriter, r *dns.Msg) {
	dnsupdateq := conf.Internal.DnsUpdateQ
	dnsnotifyq := conf.Internal.DnsNotifyQ
	// kdb := conf.Internal.KeyDB

	return func(w dns.ResponseWriter, r *dns.Msg) {
		qname := r.Question[0].Name

		log.Printf("DnsHandler: qname: %s opcode: %s (%d)", qname, dns.OpcodeToString[r.Opcode], r.Opcode)

		switch r.Opcode {
		case dns.OpcodeNotify:
			// A DNS NOTIFY may trigger time consuming outbound queries
			dnsnotifyq <- tdns.DnsNotifyRequest{ResponseWriter: w, Msg: r, Qname: qname}
			// Not waiting for a result
			return

		case dns.OpcodeUpdate:
			// A DNS Update may trigger time consuming outbound queries
			dnsupdateq <- tdns.DnsUpdateRequest{
				ResponseWriter: w,
				Msg:            r,
				Qname:          qname,
				Status:         &tdns.UpdateStatus{},
			}
			// Not waiting for a result
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s", dns.OpcodeToString[r.Opcode])
		}
	}
}

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
