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

// The zone above's NSEC at a cut is no proof about the names below it, nor
// about any type at the cut but the DS: with a DS at the cut the denial is
// Bogus, without one Insecure. The DS question at the cut is still answered
// by it.
func TestHandleNegativeReadsNothingBelowAZoneCut(t *testing.T) {
	const parent = "example."
	const child = "child." + parent
	soa := func(t *testing.T) []dns.RR {
		return rrs(t, parent+" 300 IN SOA ns."+parent+" h."+parent+" 1 3600 600 604800 300")
	}
	for _, c := range []struct {
		name  string
		types string
		qname string
		qtype uint16
		rcode int
		state cache.ValidationState
	}{
		{"below a signed cut, no data", "NS DS RRSIG NSEC", "ns1." + child, dns.TypeA, dns.RcodeSuccess, cache.ValidationStateBogus},
		{"below a signed cut, name error", "NS DS RRSIG NSEC", "www." + child, dns.TypeA, dns.RcodeNameError, cache.ValidationStateBogus},
		{"at a signed cut, another type", "NS DS RRSIG NSEC", child, dns.TypeMX, dns.RcodeSuccess, cache.ValidationStateBogus},
		{"below an unsigned cut, no data", "NS RRSIG NSEC", "ns1." + child, dns.TypeA, dns.RcodeSuccess, cache.ValidationStateInsecure},
		{"at an unsigned cut, no DS", "NS RRSIG NSEC", child, dns.TypeDS, dns.RcodeSuccess, cache.ValidationStateSecure},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, imr, sign := validatorScanner(t, parent)
			cut := rrs(t, child+" 300 IN NSEC other."+parent+" "+c.types)
			ns := append(signedSet(sign, parent, soa(t)), signedSet(sign, parent, cut)...)
			// Asked of the zone above's servers: what the SOA says matches them.
			o := handleDenial(t, imr, c.qname, c.qtype, denialReply(c.qname, c.qtype, c.rcode, ns), parent)
			if o.cached == nil {
				t.Fatalf("not cached")
			}
			if o.cached.State != c.state {
				t.Errorf("cached %s, want %s", cache.ValidationStateToString[o.cached.State], cache.ValidationStateToString[c.state])
			}
		})
	}
}
