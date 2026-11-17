/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// An NS RRset for the zone being queried is not a referral (#829). A lame
// server that answers with it is passed over, and the lookup goes on to the
// zone's other servers instead of aborting on the referral-loop check.

func TestReferralLeavesZone(t *testing.T) {
	for _, tc := range []struct {
		ref, zone string
		want      bool
	}{
		{"child.example.", "example.", true},
		{"a.b.example.", "example.", true},
		{"example.", "example.", false},
		{"EXAMPLE.", "example.", false},
		{".", "example.", false},
		{"other.", "example.", false},
		{"child.example.", "", true},
		{"", "example.", true},
	} {
		if got := referralLeavesZone(tc.ref, tc.zone); got != tc.want {
			t.Errorf("referralLeavesZone(%q, %q) = %v, want %v", tc.ref, tc.zone, got, tc.want)
		}
	}
}

const (
	lameParent = "p829.test."
	lameZone   = "lame.p829.test."
	lameNS1    = "ns1.lame.p829.test."
	lameOther  = "o829.test."
	lameNS2    = "ns2.o829.test."
	lameWWW    = "www.lame.p829.test."
)

// lameImr: the parent of lameZone, reached as a stub on 127.0.0.1, delegates it
// to ns1 (glue 127.0.0.1) and ns2 in another zone (no glue). The same server
// answers every query under lameZone with that delegation, so as ns1 it is
// lame. ns2's zone, and the real answer, are on ::1 when good is set.
func lameImr(t *testing.T, good bool) *Imr {
	t.Helper()
	delegation := []dns.RR{mustRR(t, lameZone+" 300 IN NS "+lameNS1), mustRR(t, lameZone+" 300 IN NS "+lameNS2)}
	glue := mustRR(t, lameNS1+" 300 IN A 127.0.0.1")
	parentSOA := mustRR(t, lameParent+" 300 IN SOA ns."+lameParent+" hostmaster."+lameParent+" 1 7200 1800 604800 300")
	otherSOA := mustRR(t, lameOther+" 300 IN SOA ns."+lameOther+" hostmaster."+lameOther+" 1 7200 1800 604800 300")
	ns2AAAA := mustRR(t, lameNS2+" 300 IN AAAA ::1")
	answer := mustRR(t, lameWWW+" 300 IN A 192.0.2.80")

	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if dns.IsSubDomain(lameZone, dns.CanonicalName(q.Name)) {
			m.Ns = append(m.Ns, delegation...) // AA clear: a referral, or a lame answer
			m.Extra = append(m.Extra, glue)
		} else {
			m.Authoritative = true
			m.Ns = append(m.Ns, parentSOA)
		}
		_ = w.WriteMsg(m)
	})
	if good {
		startRefDouble(t, net.IPv6loopback, port, func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			q := r.Question[0]
			switch name := dns.CanonicalName(q.Name); {
			case name == lameNS2 && q.Qtype == dns.TypeAAAA:
				m.Answer = append(m.Answer, ns2AAAA)
			case name == lameWWW && q.Qtype == dns.TypeA:
				m.Answer = append(m.Answer, answer)
			default:
				m.Ns = append(m.Ns, otherSOA)
			}
			_ = w.WriteMsg(m)
		})
	}
	imr := verdictImr(t, false)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	if err := imr.Cache.AddStub(lameParent, []cache.AuthServer{
		{Name: "ns." + lameParent, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub %s: %v", lameParent, err)
	}
	otherAddr := "::1"
	if !good {
		// ns2's zone is then served by the lame double, which has no address
		// for ns2: it cannot be resolved.
		otherAddr = "127.0.0.1"
	}
	if err := imr.Cache.AddStub(lameOther, []cache.AuthServer{
		{Name: "ns." + lameOther, Addrs: []string{otherAddr}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub %s: %v", lameOther, err)
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})
	return imr
}

// ns1 is lame: it answers with the delegation it is named in. The lookup
// passes over it, resolves ns2, and gets the answer there. Before #829 the
// lame answer was followed as a referral, the loop check fired, and the client
// got SERVFAIL.
func TestLameReferralToTheSameZoneTriesTheOtherServer(t *testing.T) {
	imr := lameImr(t, true)
	got := askReferralImr(t, imr, lameWWW)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("got %s with %d answers, want the answer from ns2:\n%s",
			dns.RcodeToString[got.Rcode], len(got.Answer), got)
	}
	if a, ok := got.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.80" {
		t.Fatalf("answer %v, want 192.0.2.80", got.Answer[0])
	}
}

// With no usable server left the answer is SERVFAIL, and it comes without
// waiting on the lame server again and again.
func TestOnlyLameServersEndInServfail(t *testing.T) {
	imr := lameImr(t, false)
	start := time.Now()
	got := askReferralImr(t, imr, lameWWW)
	if got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("got %s, want SERVFAIL:\n%s", dns.RcodeToString[got.Rcode], got)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("SERVFAIL took %v", took)
	}
}

const (
	zsParent = "p836.test."
	zsKid    = "kid.p836.test."
	zsKidNS  = "ns.kid.p836.test."
	zsWWW    = "www.kid.p836.test."
)

// A referral is judged against the zone of the servers that were asked, not
// the closest zone the cache knows for the name. Here the cache knows the
// child already (an empty server map, as a lookup in progress leaves it), and
// the question goes to the parent's servers: their referral into the child is
// a referral, and the child's answer comes through. The same with AA set on
// the referral, as some servers do: it is not the child's NODATA either.
func TestReferralIsJudgedAgainstTheServersZone(t *testing.T) {
	for _, aa := range []bool{false, true} {
		t.Run("aa="+strconv.FormatBool(aa), func(t *testing.T) { referralJudgedAgainstServersZone(t, aa) })
	}
}

func referralJudgedAgainstServersZone(t *testing.T, aa bool) {
	delegation := mustRR(t, zsKid+" 300 IN NS "+zsKidNS)
	glue := mustRR(t, zsKidNS+" 300 IN AAAA ::1")
	answer := mustRR(t, zsWWW+" 300 IN A 192.0.2.36")
	kidSOA := mustRR(t, zsKid+" 300 IN SOA "+zsKidNS+" hostmaster."+zsKid+" 1 7200 1800 604800 300")
	parentSOA := mustRR(t, zsParent+" 300 IN SOA ns."+zsParent+" hostmaster."+zsParent+" 1 7200 1800 604800 300")

	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if name := dns.CanonicalName(q.Name); dns.IsSubDomain(zsKid, name) && !(name == zsKid && q.Qtype == dns.TypeDS) {
			m.Authoritative = aa
			m.Ns = append(m.Ns, delegation)
			m.Extra = append(m.Extra, glue)
		} else {
			m.Authoritative = true
			m.Ns = append(m.Ns, parentSOA)
		}
		_ = w.WriteMsg(m)
	})
	startRefDouble(t, net.IPv6loopback, port, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if q := r.Question[0]; dns.CanonicalName(q.Name) == zsWWW && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, answer)
		} else {
			m.Ns = append(m.Ns, kidSOA)
		}
		_ = w.WriteMsg(m)
	})

	imr := verdictImr(t, false)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	if err := imr.Cache.AddStub(zsParent, []cache.AuthServer{
		{Name: "ns." + zsParent, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub %s: %v", zsParent, err)
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})
	imr.Cache.ServerMap.Set(zsKid, map[string]*cache.AuthServer{})
	if closest, _, _ := imr.Cache.FindClosestKnownZoneFor(zsWWW, dns.TypeA); closest != zsKid {
		t.Fatalf("precondition: the closest known zone for %s is %q, want %s", zsWWW, closest, zsKid)
	}
	parentServers, _ := imr.Cache.ServerMapCopy(zsParent)

	rrset, rcode, _, _, err := imr.IterativeDNSQueryInZone(context.Background(), zsWWW, dns.TypeA,
		parentServers, zsParent, false, edns0.PrivacyNone)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("got rcode %s, rrset %v, err %v; want the child's answer", dns.RcodeToString[rcode], rrset, err)
	}
	if a, ok := rrset.RRs[0].(*dns.A); !ok || a.A.String() != "192.0.2.36" {
		t.Fatalf("answer %v, want 192.0.2.36", rrset.RRs[0])
	}
}

const (
	rfRootNS = "a.root836.test."
	rfTLD    = "tld836."
	rfTLDNS  = "ns.tld836."
	rfCut    = "cut.tld836."
	rfWWW    = "www.cut.tld836."
)

// rootFallbackImr: the root's server map holds a double on 127.0.0.1, which
// refers everything under rfTLD to rfTLDNS (glue ::1), a double that answers
// rfWWW. The cache knows rfCut with an empty server map, as a zone whose
// nameservers are all out of bailiwick has until their addresses are found.
func rootFallbackImr(t *testing.T) *Imr {
	t.Helper()
	delegation := mustRR(t, rfTLD+" 300 IN NS "+rfTLDNS)
	glue := mustRR(t, rfTLDNS+" 300 IN AAAA ::1")
	answer := mustRR(t, rfWWW+" 300 IN A 192.0.2.83")
	tldSOA := mustRR(t, rfTLD+" 300 IN SOA "+rfTLDNS+" hostmaster."+rfTLD+" 1 7200 1800 604800 300")
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Ns = append(m.Ns, delegation)
		m.Extra = append(m.Extra, glue)
		_ = w.WriteMsg(m)
	})
	startRefDouble(t, net.IPv6loopback, port, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if q := r.Question[0]; dns.CanonicalName(q.Name) == rfWWW && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, answer)
		} else {
			m.Ns = append(m.Ns, tldSOA)
		}
		_ = w.WriteMsg(m)
	})
	imr := verdictImr(t, false)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	root := imr.Cache.GetOrCreateAuthServer(rfRootNS)
	root.SetAddrs([]string{"127.0.0.1"})
	imr.Cache.ServerMap.Set(".", map[string]*cache.AuthServer{cache.ServerKey(rfRootNS): root})
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})
	imr.Cache.ServerMap.Set(rfCut, map[string]*cache.AuthServer{})
	return imr
}

func TestZoneOfServers(t *testing.T) {
	imr := rootFallbackImr(t)
	rootServers, _ := imr.Cache.ServerMapCopy(".")
	other := cache.NewAuthServer("ns.elsewhere836.test.")
	for _, tc := range []struct {
		name    string
		servers map[string]*cache.AuthServer
		want    string
	}{
		{"the root's servers, for a name below an empty cut", rootServers, "."},
		{"servers held by no zone", map[string]*cache.AuthServer{cache.ServerKey(other.Name): other}, ""},
		{"no servers", nil, rfCut},
	} {
		if got := imr.zoneOfServers(rfWWW, dns.TypeA, tc.servers); got != tc.want {
			t.Errorf("%s: zoneOfServers = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A proof or data fetch below a zone cut with no servers goes to the root's
// servers (ServersFor), with no zone named. Their referral towards the cut is
// a referral: judged against the empty cut, it looked lame, and the fetch
// failed.
func TestFetchThroughTheRootFallbackFollowsTheRootsReferral(t *testing.T) {
	imr := rootFallbackImr(t)
	if closest, _, _ := imr.Cache.FindClosestKnownZoneFor(rfWWW, dns.TypeA); closest != rfCut {
		t.Fatalf("precondition: the closest known zone for %s is %q, want %s", rfWWW, closest, rfCut)
	}
	rrset, err := imr.DefaultRRsetFetcher(context.Background(), rfWWW, dns.TypeA)
	if err != nil || rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("fetch: rrset %v, err %v; want the answer through the root's referral", rrset, err)
	}
	if a, ok := rrset.RRs[0].(*dns.A); !ok || a.A.String() != "192.0.2.83" {
		t.Fatalf("answer %v, want 192.0.2.83", rrset.RRs[0])
	}
}
