/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"net"
	"strconv"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// An authoritative NXDOMAIN or NODATA without an SOA is served, and not cached
// (#830; RFC 2308 sections 2.1, 2.2 and 5).

const (
	negZone   = "neg830.test."
	negOther  = "other830.test."
	negNX     = "nx.neg830.test."
	negNoData = "nodata.neg830.test."
	negApexNS = "apexns.neg830.test."
	negCNAME  = "cname.neg830.test."
	negTarget = "gone.other830.test."
)

// negReply is how the test server answers one name.
type negReply struct {
	rcode int
	aa    bool
	ns    bool // authority carries the zone's NS RRset
}

// negImr is a resolver with negZone as a stub on 127.0.0.1 and negOther as a
// stub on ::1. Both servers answer per name from replies; negCNAME is a CNAME
// to negTarget. secure holds negZone Secure in the zone map.
func negImr(t *testing.T, replies map[string]negReply, secure bool) *Imr {
	t.Helper()
	cname := mustRR(t, negCNAME+" 300 IN CNAME "+negTarget)
	handler := func(zone string) dns.HandlerFunc {
		zoneNS := mustRR(t, zone+" 300 IN NS ns."+zone)
		return func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			name := dns.CanonicalName(r.Question[0].Name)
			if name == negCNAME {
				m.Answer = append(m.Answer, cname)
				_ = w.WriteMsg(m)
				return
			}
			if rep, ok := replies[name]; ok {
				m.Rcode, m.Authoritative = rep.rcode, rep.aa
				if rep.ns {
					m.Ns = append(m.Ns, zoneNS)
				}
			} else {
				m.Rcode = dns.RcodeRefused
			}
			_ = w.WriteMsg(m)
		}
	}
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, handler(negZone))
	startRefDouble(t, net.IPv6loopback, port, handler(negOther))

	imr := verdictImr(t, false)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	for zone, addr := range map[string]string{negZone: "127.0.0.1", negOther: "::1"} {
		if err := imr.Cache.AddStub(zone, []cache.AuthServer{
			{Name: "ns." + zone, Addrs: []string{addr}, Alpn: []string{"do53"}},
		}); err != nil {
			t.Fatalf("AddStub %s: %v", zone, err)
		}
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})
	if secure {
		imr.Cache.ZoneMap.Set(negZone, &cache.Zone{ZoneName: negZone, State: cache.ValidationStateSecure})
	}
	return imr
}

// notCached reports a denial that a later query could still read.
func notCached(t *testing.T, imr *Imr, name string, qtype uint16) {
	t.Helper()
	if c := imr.Cache.Get(name, qtype); c != nil {
		t.Errorf("the denial of %s %s was cached (context %s), want it served only",
			name, dns.TypeToString[qtype], cache.CacheContextToString[c.Context])
	}
}

func TestAuthoritativeDenialWithoutSOAIsServed(t *testing.T) {
	imr := negImr(t, map[string]negReply{
		negNX:     {rcode: dns.RcodeNameError, aa: true},
		negNoData: {rcode: dns.RcodeSuccess, aa: true},
		negApexNS: {rcode: dns.RcodeSuccess, aa: true, ns: true},
	}, false)
	for _, tc := range []struct {
		name  string
		rcode int
	}{
		{negNX, dns.RcodeNameError},   // NXDOMAIN, empty authority (type 3)
		{negNoData, dns.RcodeSuccess}, // NODATA, empty authority
		{negApexNS, dns.RcodeSuccess}, // NODATA carrying the zone's NS RRset
	} {
		got := askReferralImr(t, imr, tc.name)
		if got.Rcode != tc.rcode || len(got.Answer) != 0 {
			t.Errorf("%s: got %s with %d answers, want %s and none:\n%s", tc.name,
				dns.RcodeToString[got.Rcode], len(got.Answer), dns.RcodeToString[tc.rcode], got)
		}
		notCached(t, imr, tc.name, dns.TypeA)
	}
}

// Without AA an NXDOMAIN without an SOA says nothing, and with no other server
// the answer is SERVFAIL.
func TestNonAuthoritativeDenialWithoutSOAIsNotUsed(t *testing.T) {
	imr := negImr(t, map[string]negReply{negNX: {rcode: dns.RcodeNameError}}, false)
	if got := askReferralImr(t, imr, negNX); got.Rcode != dns.RcodeServerFailure {
		t.Errorf("got %s, want SERVFAIL:\n%s", dns.RcodeToString[got.Rcode], got)
	}
}

// A CNAME chain that ends in an authoritative NXDOMAIN without an SOA is
// answered NXDOMAIN, with the CNAME in the answer section.
func TestCNAMEChainEndingInDenialWithoutSOA(t *testing.T) {
	imr := negImr(t, map[string]negReply{negTarget: {rcode: dns.RcodeNameError, aa: true}}, false)
	got := askReferralImr(t, imr, negCNAME)
	if got.Rcode != dns.RcodeNameError {
		t.Fatalf("got %s, want NXDOMAIN:\n%s", dns.RcodeToString[got.Rcode], got)
	}
	if len(got.Answer) != 1 || got.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("answer section %v, want the CNAME alone", got.Answer)
	}
	notCached(t, imr, negTarget, dns.TypeA)
}

// Below a zone held Secure, a denial with nothing to validate is a stripped
// one: it is not used, and the answer is SERVFAIL.
func TestDenialWithoutSOAFromASecureZoneIsNotUsed(t *testing.T) {
	imr := negImr(t, map[string]negReply{negNX: {rcode: dns.RcodeNameError, aa: true}}, true)
	if got := askReferralImr(t, imr, negNX); got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("got %s, want SERVFAIL:\n%s", dns.RcodeToString[got.Rcode], got)
	}
}

// Only the zone's own NS RRset makes an authoritative empty reply a NODATA.
// Some servers set AA on a genuine referral: an NS RRset below the zone is
// still followed (Deckard's iter_ns_badaa). An NS RRset above the zone is an
// upward referral from a lame server, AA or not (iter_lame_aaaa).
func TestAuthoritativeNSRRsetOutsideTheZoneIsNotNoData(t *testing.T) {
	const (
		zone    = "aa830.test."
		child   = "child.aa830.test."
		childNS = "ns.child.aa830.test."
		below   = "www.child.aa830.test."
		upward  = "up.aa830.test."
	)
	delegation := mustRR(t, child+" 300 IN NS "+childNS)
	glue := mustRR(t, childNS+" 300 IN AAAA ::1")
	rootNS := mustRR(t, ". 300 IN NS a.root.test.")
	answer := mustRR(t, below+" 300 IN A 192.0.2.9")
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true // on everything, referrals included
		if name := dns.CanonicalName(r.Question[0].Name); dns.IsSubDomain(child, name) {
			m.Ns = append(m.Ns, delegation)
			m.Extra = append(m.Extra, glue)
		} else {
			m.Ns = append(m.Ns, rootNS)
		}
		_ = w.WriteMsg(m)
	})
	startRefDouble(t, net.IPv6loopback, port, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if dns.CanonicalName(r.Question[0].Name) == below && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, answer)
		}
		_ = w.WriteMsg(m)
	})
	imr := verdictImr(t, false)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	if err := imr.Cache.AddStub(zone, []cache.AuthServer{
		{Name: "ns." + zone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})

	got := askReferralImr(t, imr, below)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Errorf("AA referral below the zone: got %s with %d answers, want the child's answer:\n%s",
			dns.RcodeToString[got.Rcode], len(got.Answer), got)
	}
	if got := askReferralImr(t, imr, upward); got.Rcode != dns.RcodeServerFailure {
		t.Errorf("AA upward referral: got %s, want SERVFAIL from the only, lame, server:\n%s",
			dns.RcodeToString[got.Rcode], got)
	}
}
