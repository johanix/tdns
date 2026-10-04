/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * What handleNegative makes of a denial whose proof the validator reads: the
 * records that count, and the rcode the proof supports.
 */
package tdns

import (
	"testing"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// denialReply is an authoritative negative answer to <qname, qtype> with rcode
// and the authority section ns.
func denialReply(qname string, qtype uint16, rcode int, ns []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.Response = true
	m.Authoritative = true
	m.Rcode = rcode
	m.Ns = ns
	return m
}

// denialOutcome is what handleNegative did with a denial: whether it was used,
// and what the cache then holds for the question.
type denialOutcome struct {
	used   bool
	cached *cache.CachedRRset
}

func handleDenial(t *testing.T, imr *Imr, qname string, qtype uint16, r *dns.Msg, serversZone string) denialOutcome {
	t.Helper()
	_, _, used := imr.handleNegative(qname, qtype, r, core.TransportDo53, serversZone)
	return denialOutcome{used: used, cached: imr.Cache.Get(qname, qtype)}
}

// notSecure fails unless the denial was refused, or cached with a verdict
// other than Secure.
func (o denialOutcome) notSecure(t *testing.T, what string) {
	t.Helper()
	if o.used && o.cached != nil && o.cached.State == cache.ValidationStateSecure {
		t.Errorf("%s: cached as a Secure %s", what, dns.RcodeToString[int(o.cached.Rcode)])
	}
}

// secure fails unless the denial was cached Secure with rcode.
func (o denialOutcome) secure(t *testing.T, what string, rcode int) {
	t.Helper()
	switch {
	case !o.used || o.cached == nil:
		t.Errorf("%s: not used", what)
	case o.cached.State != cache.ValidationStateSecure || int(o.cached.Rcode) != rcode:
		t.Errorf("%s: cached %s %s, want secure %s", what, cache.ValidationStateToString[o.cached.State],
			dns.RcodeToString[int(o.cached.Rcode)], dns.RcodeToString[rcode])
	}
}

// A denial is read from records of the zone whose SOA it carries. An NSEC of
// another signed zone, beside that SOA, proves nothing about the names of the
// zone that denies.
func TestHandleNegativeReadsOnlyTheDenyingZonesNSEC(t *testing.T) {
	const zone = "signed.example."
	const other = "other.test."
	_, imr, sign := validatorScanner(t, zone, other)
	soa := rrs(t, zone+" 300 IN SOA ns."+zone+" h."+zone+" 7 3600 600 604800 300")
	stranger := signedSet(sign, other, rrs(t, other+" 300 IN NSEC "+other+" A RRSIG NSEC"))
	ns := append(signedSet(sign, zone, soa), stranger...)

	for _, c := range []struct {
		qname string
		rcode int
	}{
		{"www." + zone, dns.RcodeNameError},
		{"ftp." + zone, dns.RcodeSuccess},
	} {
		handleDenial(t, imr, c.qname, dns.TypeA, denialReply(c.qname, dns.TypeA, c.rcode, ns), zone).
			notSecure(t, c.qname+" "+dns.RcodeToString[c.rcode]+" with another zone's NSEC")
	}

	// The zone's own proof beside it still holds.
	own := signedSet(sign, zone, rrs(t, zone+" 300 IN NSEC zzz."+zone+" SOA NS RRSIG NSEC DNSKEY"))
	q := "nope." + zone
	handleDenial(t, imr, q, dns.TypeA, denialReply(q, dns.TypeA, dns.RcodeNameError, append(append(ns[:0:0], ns...), own...)), zone).
		secure(t, q+" with the zone's own NSEC beside another's", dns.RcodeNameError)
}
