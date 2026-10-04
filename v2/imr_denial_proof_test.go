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

// The rcode a denial is cached with is the one its proof supports. An NSEC
// at the name shows that it exists: no name error. And the RFC 9824 compact
// denial reading, made from the shape of the section before validation, does
// not set the rcode of a proof that validated: an NXNAME NSEC that did not
// count, here an unsigned one whose owner differs in case from the zone's
// signed NSEC at the name, leaves the denial unused.
func TestHandleNegativeCachesTheRcodeTheProofSupports(t *testing.T) {
	const zone = "signed.example."
	const www = "www." + zone
	_, imr, sign := validatorScanner(t, zone)
	soa := signedSet(sign, zone, rrs(t, zone+" 300 IN SOA ns."+zone+" h."+zone+" 7 3600 600 604800 300"))
	noData := signedSet(sign, zone, rrs(t, www+" 300 IN NSEC zzz."+zone+" A RRSIG NSEC"))
	join := func(sets ...[]dns.RR) []dns.RR {
		var out []dns.RR
		for _, s := range sets {
			out = append(out, s...)
		}
		return out
	}

	handleDenial(t, imr, www, dns.TypeAAAA, denialReply(www, dns.TypeAAAA, dns.RcodeNameError, join(soa, noData)), zone).
		notSecure(t, "a name error proven by the NSEC at the name")

	stray := rrs(t, "WWW."+zone+" 300 IN NSEC \\000.www."+zone+" RRSIG NSEC NXNAME")
	o := handleDenial(t, imr, www, dns.TypeMX, denialReply(www, dns.TypeMX, dns.RcodeSuccess, join(soa, noData, stray)), zone)
	if o.used {
		state := "nothing cached"
		if o.cached != nil {
			state = cache.ValidationStateToString[o.cached.State] + " " + dns.RcodeToString[int(o.cached.Rcode)]
		}
		t.Errorf("a proof of no data beside an NXNAME NSEC that does not count: used (%s), want not used", state)
	}

	// A compact denial the zone signed is a name error, as before.
	const nope = "nope." + zone
	compact := signedSet(sign, zone, rrs(t, nope+" 300 IN NSEC \\000."+nope+" RRSIG NSEC NXNAME"))
	handleDenial(t, imr, nope, dns.TypeA, denialReply(nope, dns.TypeA, dns.RcodeSuccess, join(soa, compact)), zone).
		secure(t, "a compact denial", dns.RcodeNameError)

	// And a proof of no data is one, under NOERROR.
	handleDenial(t, imr, www, dns.TypeTXT, denialReply(www, dns.TypeTXT, dns.RcodeSuccess, join(soa, noData)), zone).
		secure(t, "no data at the name", dns.RcodeSuccess)
}

// A denial carries the SOA of the zone that denies, and the servers of a zone
// answer for it and for the zones below it they serve. A denial from the
// servers of child.example. with the SOA of example. is not theirs: it is not
// used, and the next server is asked. The same denial from the servers of
// example. is read as any other. Servers of a configured stub zone are the
// operator's, and the rule does not apply to them.
func TestHandleNegativeRefusesAnSOAFromAboveTheServersZone(t *testing.T) {
	const parent = "example."
	const child = "child." + parent
	const nope = "nope." + parent
	soa := rrs(t, parent+" 300 IN SOA ns."+parent+" h."+parent+" 1 3600 600 604800 300")
	apex := rrs(t, parent+" 300 IN NSEC zzz."+parent+" SOA NS RRSIG NSEC DNSKEY")

	for _, c := range []struct {
		name        string
		qname       string
		serversZone string
		stub        bool
		used        bool
	}{
		{"the zone above's SOA, from the child's servers", "www." + child, child, false, false},
		{"the zone above's SOA, from its own servers", nope, parent, false, true},
		{"servers of an unknown zone", nope, "", false, true},
		{"the zone above's SOA, from a stub zone's servers", "www." + child, child, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, imr, sign := validatorScanner(t, parent)
			if c.stub {
				imr.setZoneTable(imr.ForwardZones(), []string{child}, nil)
			}
			ns := append(signedSet(sign, parent, soa), signedSet(sign, parent, apex)...)
			o := handleDenial(t, imr, c.qname, dns.TypeA, denialReply(c.qname, dns.TypeA, dns.RcodeNameError, ns), c.serversZone)
			if o.used != c.used {
				t.Errorf("used %v, want %v", o.used, c.used)
			}
			if !c.used && o.cached != nil {
				t.Errorf("cached %s, want nothing", cache.ValidationStateToString[o.cached.State])
			}
		})
	}
}

func TestSOAAboveServersZone(t *testing.T) {
	for _, c := range []struct {
		soa, zone string
		want      bool
	}{
		{"example.", "child.example.", true},
		{".", "example.", true},
		{"example.", "example.", false},
		{"Example.", "example.", false},
		{"child.example.", "example.", false},
		{"example.", "", false},
		{"", "example.", false},
	} {
		if got := soaAboveServersZone(c.soa, c.zone); got != c.want {
			t.Errorf("soaAboveServersZone(%q, %q) = %v, want %v", c.soa, c.zone, got, c.want)
		}
	}
}
