/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * IMR counters for evaluating large-KSK direct-TCP DNSKEY fetching.
 */

package tdns

import (
	"sync/atomic"

	"github.com/miekg/dns"
)

var (
	imrDSEncounteredTotal    atomic.Uint64
	imrDSEncounteredLarge    atomic.Uint64
	imrDNSKEYLookupTotal     atomic.Uint64
	imrDNSKEYLookupForcedTCP atomic.Uint64
)

// LargeKskImrMetrics is a snapshot of IMR large-KSK telemetry counters.
// Percentages: DSEncounteredLarge/DSEncounteredTotal,
// DNSKEYLookupForcedTCP/DNSKEYLookupTotal.
type LargeKskImrMetrics struct {
	DSEncounteredTotal    uint64
	DSEncounteredLarge    uint64
	DNSKEYLookupTotal     uint64
	DNSKEYLookupForcedTCP uint64
}

func LargeKskImrMetricsSnapshot() LargeKskImrMetrics {
	return LargeKskImrMetrics{
		DSEncounteredTotal:    imrDSEncounteredTotal.Load(),
		DSEncounteredLarge:    imrDSEncounteredLarge.Load(),
		DNSKEYLookupTotal:     imrDNSKEYLookupTotal.Load(),
		DNSKEYLookupForcedTCP: imrDNSKEYLookupForcedTCP.Load(),
	}
}

func (imr *Imr) noteDSEncountered(dsRRs []dns.RR) {
	if len(dsRRs) == 0 {
		return
	}
	imrDSEncounteredTotal.Add(1)
	if imr.dsRRsHaveLargeAlg(dsRRs) {
		imrDSEncounteredLarge.Add(1)
	}
}

func (imr *Imr) noteDNSKEYLookup(forceTCP bool) {
	imrDNSKEYLookupTotal.Add(1)
	if forceTCP {
		imrDNSKEYLookupForcedTCP.Add(1)
	}
}

func (imr *Imr) dsRRsHaveLargeAlg(rrs []dns.RR) bool {
	for _, rr := range rrs {
		d, ok := rr.(*dns.DS)
		if ok && imr.isLargeAlgorithm(d.Algorithm) {
			return true
		}
	}
	return false
}

// dnskeyQueryForceTCP returns true when a cached parent DS RRset signals a large
// child KSK algorithm and the IMR should fetch the child DNSKEY over TCP.
func (imr *Imr) dnskeyQueryForceTCP(qname string, qtype uint16) bool {
	if imr == nil || imr.Cache == nil || qtype != dns.TypeDNSKEY {
		return false
	}
	ds := imr.Cache.Get(qname, dns.TypeDS)
	if ds == nil || ds.RRset == nil {
		return false
	}
	for _, rr := range ds.RRset.RRs {
		d, ok := rr.(*dns.DS)
		if !ok || !imr.isLargeAlgorithm(d.Algorithm) {
			continue
		}
		lgDns.Info("large-alg DS observed; will query child DNSKEY over TCP",
			"zone", qname, "alg", d.Algorithm)
		return true
	}
	return false
}
