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

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var (
	imrDSEncounteredTotal   atomic.Uint64
	imrDSEncounteredLarge   atomic.Uint64
	imrDSDLargeRRByAlg      [256]atomic.Uint64
	imrDNSKEYLookupTotal    atomic.Uint64
	imrDNSKEYLookupBypassed atomic.Uint64
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
	// DNSKEYLookupBypassed counts DNSKEY lookups that bypassed the server's
	// probabilistic transport selection per the dnskey_query_transport policy.
	// The transport actually chosen may be do53-tcp OR an encrypted transport
	// (DoQ/DoT/DoH) depending on the server's advertised capabilities.
	DNSKEYLookupBypassed uint64
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
		DSEncounteredTotal:   imrDSEncounteredTotal.Load(),
		DSEncounteredLarge:   imrDSEncounteredLarge.Load(),
		DNSKEYLookupTotal:    imrDNSKEYLookupTotal.Load(),
		DNSKEYLookupBypassed: imrDNSKEYLookupBypassed.Load(),
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

// resetLargeKskImrMetricsForTest zeroes all package-global counters. Test-only.
func resetLargeKskImrMetricsForTest() {
	imrDSEncounteredTotal.Store(0)
	imrDSEncounteredLarge.Store(0)
	imrDNSKEYLookupTotal.Store(0)
	imrDNSKEYLookupBypassed.Store(0)
	for i := range imrDSDLargeRRByAlg {
		imrDSDLargeRRByAlg[i].Store(0)
	}
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

func (imr *Imr) noteDNSKEYLookup(bypassed bool) {
	imrDNSKEYLookupTotal.Add(1)
	if bypassed {
		imrDNSKEYLookupBypassed.Add(1)
	}
}

// dnskeyPolicy returns the effective DNSKEY transport policy, treating the
// empty zero value as the default (use_ds_signal).
func (imr *Imr) dnskeyPolicy() DNSKEYTransportPolicy {
	if imr == nil || imr.dnskeyTransport == "" {
		return DNSKEYTransportUseDSSignal
	}
	return imr.dnskeyTransport
}

// dnskeyTransportBypass reports whether this DNSKEY query should bypass the
// server's probabilistic transport-weight selection and instead use the best
// available transport (resolved per-server by preferredDNSKEYTransport).
//
// DNSKEY queries are ~0.1% of traffic, so forcing them off the probabilistic
// distribution does not meaningfully disturb a server's load shape.
//
//   - force_udp:       never bypass.
//   - use_ds_signal:   bypass only when the cached parent DS uses a large alg.
//   - try/force_encrypted: always bypass.
func (imr *Imr) dnskeyTransportBypass(qname string, qtype uint16) bool {
	if imr == nil || qtype != dns.TypeDNSKEY {
		return false
	}
	switch imr.dnskeyPolicy() {
	case DNSKEYTransportForceUDP:
		return false
	case DNSKEYTransportTryEncrypted, DNSKEYTransportForceEncrypted:
		return true
	case DNSKEYTransportUseDSSignal:
		return imr.dnskeyDSSignalsLarge(qname)
	}
	return false
}

// dnskeyDSSignalsLarge reports whether a cached parent DS RRset for qname uses
// a large child KSK algorithm.
func (imr *Imr) dnskeyDSSignalsLarge(qname string) bool {
	if imr == nil || imr.Cache == nil {
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
		lgDns.Info("large-alg DS observed; will bypass UDP for child DNSKEY",
			"zone", qname, "alg", d.Algorithm)
		return true
	}
	return false
}

// preferredDNSKEYTransport picks the transport for a DNSKEY query that has been
// selected to bypass probabilistic transport weights. It honors the server's
// advertised capabilities (server.Transports) but ignores the weights. The
// preference order is DoQ > DoT > DoH > TCP.
//
// Returns 0 (no transport) when the policy is force_encrypted and the server
// advertises no encrypted transport; the caller must fail the query in that
// case rather than fall back to cleartext.
func (imr *Imr) preferredDNSKEYTransport(server *cache.AuthServer) core.Transport {
	order := []core.Transport{core.TransportDoQ, core.TransportDoT, core.TransportDoH}
	for _, pref := range order {
		if serverAdvertises(server, pref) {
			return pref
		}
	}

	if imr.dnskeyPolicy() == DNSKEYTransportForceEncrypted {
		// No encrypted transport available: signal failure (no fallback).
		return 0
	}

	// Non-encrypted fallback: plain TCP, never UDP.
	return core.TransportDo53TCP
}

// serverAdvertises reports whether the server lists transport t in its
// advertised Transports.
func serverAdvertises(server *cache.AuthServer, t core.Transport) bool {
	if server == nil {
		return false
	}
	for _, a := range server.Transports {
		if a == t {
			return true
		}
	}
	return false
}
