/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"sync"

	"context"

	edns0 "github.com/johanix/tdns/tdns/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func NotifyHandler(conf *Config) error {
	zonech := conf.Internal.RefreshZoneCh
	dnsnotifyq := conf.Internal.DnsNotifyQ
	scannerq := conf.Internal.ScannerQ

	log.Printf("*** DnsNotifyResponderEngine: starting")

	var dhr DnsNotifyRequest

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for dhr = range dnsnotifyq {
			NotifyResponder(&dhr, zonech, scannerq)
		}
	}()
	wg.Wait()

	log.Println("DnsNotifyResponderEngine: terminating")
	return nil
}

func NotifyResponder(dhr *DnsNotifyRequest, zonech chan ZoneRefresher, scannerq chan ScanRequest) error {

	qname := dhr.Qname
	ntype := dhr.Msg.Question[0].Qtype

	log.Printf("NotifyResponder: Received NOTIFY(%s) for zone %q", dns.TypeToString[ntype], qname)

	m := new(dns.Msg)
	m.SetReply(dhr.Msg)

	// Let's see if we can find the zone
	zd, _ := FindZone(qname)
	if zd == nil || (zd != nil && zd.IsChildDelegation(qname)) {
		log.Printf("NotifyResponder: Received Notify for unknown zone %q. Ignoring.", qname)
		m := new(dns.Msg)
		m.SetRcode(dhr.Msg, dns.RcodeRefused)
		dhr.ResponseWriter.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	if zd.Error && zd.ErrorType != RefreshError {
		log.Printf("NotifyResponder: Received Notify for zone %q, but it is in error state: %s", qname, zd.ErrorMsg)
		m := new(dns.Msg)
		m.SetRcode(dhr.Msg, dns.RcodeServerFailure)
		dhr.ResponseWriter.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	// log.Printf("NotifyResponder: The qname %s seems to belong to the known zone %s", qname, zd.ZoneName)

	switch ntype {
	case dns.TypeSOA:
		zonech <- ZoneRefresher{
			Name:      qname, // send zone name into RefreshEngine
			ZoneStore: zd.ZoneStore,
		}
		log.Printf("NotifyResponder: Received NOTIFY(%s) for %q Refreshing.",
			dns.TypeToString[ntype], qname)

	case dns.TypeCDS, dns.TypeCSYNC:
		log.Printf("NotifyResponder: Received a NOTIFY(%s) for %q. This should trigger a scan for the %s %s RRset",
			dns.TypeToString[ntype], qname, qname, dns.TypeToString[ntype])
		scannerq <- ScanRequest{
			Cmd:       "SCAN",
			ChildZone: qname,
			ZoneData:  zd,
			RRtype:    ntype,
		}

	case dns.TypeDNSKEY:
		log.Printf("NotifyResponder: Received a NOTIFY(%s) for %q. This should trigger a scan for the %s %s RRset",
			dns.TypeToString[ntype], qname, qname, dns.TypeToString[ntype])
		scannerq <- ScanRequest{
			Cmd:       "SCAN",
			ChildZone: qname,
			ZoneData:  zd,
			RRtype:    ntype,
		}

	default:
		log.Printf("NotifyResponder: Unknown type of notification: NOTIFY(%s)",
			dns.TypeToString[ntype])
	}

	m.SetRcode(dhr.Msg, dns.RcodeSuccess)
	m.MsgHdr.Authoritative = true
	dhr.ResponseWriter.WriteMsg(m)
	return nil
}

// This is a minimal DNS server that only handles NOTIFYs. It is (only?) used in the tdns-reporter.

func CreateNotifyOnlyDNSServer(conf *Config) (stop func(context.Context) error, err error) {
	addr := viper.GetString("reporter.dns.listen")
	if addr == "" {
		addr = ":53"
	}

	// Set up a dedicated ServeMux to avoid global handlers
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if r == nil || r.Opcode != dns.OpcodeNotify {
			// Optionally reply REFUSED, or silently drop. Here we refuse.
			resp := new(dns.Msg)
			resp.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(resp)
			return
		}

		// At this point we have a NOTIFY. Minimal ACK:
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.MsgHdr.Authoritative = true

		// Optional: do any lightweight logging or enqueue a side-effect here.
		// e.g., record the notify, update metrics, etc.
		if edns0.HasReporterOption(r.IsEdns0()) {
			ro, found := edns0.ExtractReporterOption(r.IsEdns0())
			if found {
				edetxt := edns0.EDECodeToString[ro.EDECode]
				if ro.Details == "" {
					ro.Details = "No details provided"
				}
				fmt.Printf("NotifyReport: Zone: %s Sender: %s Error: %s (%d) Details: %s\n", 
				    ro.ZoneName, ro.Sender, edetxt, ro.EDECode, ro.Details)
			} else {
				fmt.Printf("NotifyReporter: Received a NOTIFY for %s (has EDNS(0) OPT RR, but no Reporter option found)\n", r.Question[0].Name)
				edns0.AttachEDEToResponse(resp, edns0.EDEReporterOptionNotFound)
			}
		} else {
			fmt.Printf("NotifyReporter: Received a NOTIFY for %s (no EDNS(0) options at all)\n", r.Question[0].Name)
			edns0.AttachEDEToResponse(resp, edns0.EDEReporterOptionNotFound)
		}
		_ = w.WriteMsg(resp)
	})

	udpSrv := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	tcpSrv := &dns.Server{Addr: addr, Net: "tcp", Handler: mux}

	// Start both listeners
	go func() { _ = udpSrv.ListenAndServe() }()
	go func() { _ = tcpSrv.ListenAndServe() }()

	// Return a unified stopper
	return func(ctx context.Context) error {
		_ = udpSrv.ShutdownContext(ctx)
		_ = tcpSrv.ShutdownContext(ctx)
		return nil
	}, nil
}