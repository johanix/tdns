/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * IMR counters for evaluating large-KSK direct-TCP DNSKEY fetching.
 */

package tdns

import (
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/miekg/dns"
)

var (
	imrDSEncounteredTotal    atomic.Uint64
	imrDSEncounteredLarge    atomic.Uint64
	imrDSDLargeRRByAlg       [256]atomic.Uint64
	imrDNSKEYLookupTotal     atomic.Uint64
	imrDNSKEYLookupForcedTCP atomic.Uint64
)

// LargeKskDSAlgCount holds the number of individual DS RRs seen for one
// large algorithm (dnssec.large_algorithms).
type LargeKskDSAlgCount struct {
	Algorithm uint8
	Count     uint64
}

// LargeKskImrMetrics is a snapshot of IMR large-KSK telemetry counters.
type LargeKskImrMetrics struct {
	DSEncounteredTotal    uint64
	DSEncounteredLarge    uint64
	DSDLargeRRByAlgorithm []LargeKskDSAlgCount
	DNSKEYLookupTotal     uint64
	DNSKEYLookupForcedTCP uint64
}

// DNSSECAlgorithmLabel returns a human-readable algorithm name with number.
func DNSSECAlgorithmLabel(alg uint8) string {
	if name := dns.AlgorithmToString[alg]; name != "" {
		return fmt.Sprintf("%s (%d)", name, alg)
	}
	return fmt.Sprintf("(%d)", alg)
}

func LargeKskImrMetricsSnapshot() LargeKskImrMetrics {
	m := LargeKskImrMetrics{
		DSEncounteredTotal:    imrDSEncounteredTotal.Load(),
		DSEncounteredLarge:    imrDSEncounteredLarge.Load(),
		DNSKEYLookupTotal:     imrDNSKEYLookupTotal.Load(),
		DNSKEYLookupForcedTCP: imrDNSKEYLookupForcedTCP.Load(),
	}
	for alg := range imrDSDLargeRRByAlg {
		if c := imrDSDLargeRRByAlg[alg].Load(); c > 0 {
			m.DSDLargeRRByAlgorithm = append(m.DSDLargeRRByAlgorithm, LargeKskDSAlgCount{
				Algorithm: uint8(alg),
				Count:     c,
			})
		}
	}
	sort.Slice(m.DSDLargeRRByAlgorithm, func(i, j int) bool {
		return m.DSDLargeRRByAlgorithm[i].Algorithm < m.DSDLargeRRByAlgorithm[j].Algorithm
	})
	return m
}

func (imr *Imr) noteDSEncountered(dsRRs []dns.RR) {
	if len(dsRRs) == 0 {
		return
	}
	imrDSEncounteredTotal.Add(1)
	hasLarge := false
	for _, rr := range dsRRs {
		d, ok := rr.(*dns.DS)
		if !ok || !imr.isLargeAlgorithm(d.Algorithm) {
			continue
		}
		hasLarge = true
		imrDSDLargeRRByAlg[d.Algorithm].Add(1)
	}
	if hasLarge {
		imrDSEncounteredLarge.Add(1)
	}
}

func (imr *Imr) noteDNSKEYLookup(forceTCP bool) {
	imrDNSKEYLookupTotal.Add(1)
	if forceTCP {
		imrDNSKEYLookupForcedTCP.Add(1)
	}
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
