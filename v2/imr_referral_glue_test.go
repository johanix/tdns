/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A referral's glue and transport signals are used only for names within the
// referring zone (imr_referral_glue.go).

func TestWithinGlueZone(t *testing.T) {
	for _, tc := range []struct {
		owner, zone string
		want        bool
	}{
		{"ns.kid.p.test.", "p.test.", true},
		{"ns.sibling.p.test.", "p.test.", true},
		{"NS.Kid.P.TEST.", "p.test.", true},
		{"_dns.ns.kid.p.test.", "p.test.", true},
		{"p.test.", "p.test.", true},
		{"ns.other.test.", "p.test.", false},
		{"ns.example.test.", "ample.test.", false},
		{"ns.anything.", ".", true},
		{"ns.kid.p.test.", "", false},
		{"", "p.test.", false},
	} {
		if got := withinGlueZone(tc.owner, tc.zone); got != tc.want {
			t.Errorf("withinGlueZone(%q, %q) = %v, want %v", tc.owner, tc.zone, got, tc.want)
		}
	}
}

// glueReferral feeds a referral to zone, from servers of referringZone, through
// ParseAdditionalForNSAddrs. The referral names ns and carries the records in
// extra.
func glueReferral(t *testing.T, imr *Imr, zone, referringZone string, ns []string, extra ...string) map[string]*cache.AuthServer {
	t.Helper()
	r := new(dns.Msg)
	r.SetQuestion("www."+zone, dns.TypeA)
	r.Response = true
	nsMap := map[string]bool{}
	for _, n := range ns {
		r.Ns = append(r.Ns, mustRR(t, zone+" 3600 IN NS "+n))
		nsMap[n] = true
	}
	for _, x := range extra {
		r.Extra = append(r.Extra, mustRR(t, x))
	}
	nsrrset := &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: r.Ns}
	sm, err := imr.ParseAdditionalForNSAddrs(context.Background(), "authority", nsrrset, zone, referringZone, nsMap, r)
	if err != nil {
		t.Fatalf("ParseAdditionalForNSAddrs: %v", err)
	}
	return sm
}

// hasAddr reports whether the shared server for nsname has addr.
func hasAddr(imr *Imr, nsname, addr string) bool {
	return slices.Contains(imr.Cache.GetOrCreateAuthServer(nsname).GetAddrs(), addr)
}

// Glue is used for a nameserver at or below the delegated zone (in-domain) and
// for one elsewhere in the referring zone (sibling), and not for one outside
// the referring zone. With the referring zone not known, only in-domain glue is
// used.
func TestReferralGlueIsUsedWithinTheReferringZone(t *testing.T) {
	const zone = "kid.p.test."
	for _, tc := range []struct {
		name, referring, ns string
		used                bool
	}{
		{"in-domain", "p.test.", "ns.kid.p.test.", true},
		{"sibling", "p.test.", "ns.sibling.p.test.", true},
		{"outside the referring zone", "p.test.", "ns.other.test.", false},
		{"in-domain, referring zone not known", "", "ns.kid.p.test.", true},
		{"sibling, referring zone not known", "", "ns.sibling.p.test.", false},
		{"from the root", ".", "ns.other.test.", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := verdictImr(t, false)
			sm := glueReferral(t, imr, zone, tc.referring, []string{tc.ns},
				tc.ns+" 3600 IN A 192.0.2.7", tc.ns+" 3600 IN AAAA 2001:db8::7")
			_, inMap := sm[cache.ServerKey(tc.ns)]
			cachedA := imr.Cache.Get(tc.ns, dns.TypeA)
			cachedAAAA := imr.Cache.Get(tc.ns, dns.TypeAAAA)
			if tc.used {
				if !inMap || !hasAddr(imr, tc.ns, "192.0.2.7") || !hasAddr(imr, tc.ns, "2001:db8::7") {
					t.Errorf("the glue for %s was not used: in map %v, addresses %v", tc.ns, inMap,
						imr.Cache.GetOrCreateAuthServer(tc.ns).GetAddrs())
				}
				if cachedA == nil || cachedAAAA == nil {
					t.Errorf("the glue for %s was not cached", tc.ns)
				}
				return
			}
			if inMap {
				t.Errorf("%s is in %s's server map", tc.ns, zone)
			}
			if addrs := imr.Cache.GetOrCreateAuthServer(tc.ns).GetAddrs(); len(addrs) != 0 {
				t.Errorf("%s has the addresses %v from the referral", tc.ns, addrs)
			}
			if cachedA != nil || cachedAAAA != nil {
				t.Errorf("the glue for %s was cached", tc.ns)
			}
			if sm, ok := imr.Cache.ServerMapCopy(zone); ok {
				if _, in := sm[cache.ServerKey(tc.ns)]; in {
					t.Errorf("%s is in the cached server map of %s", tc.ns, zone)
				}
			}
		})
	}
}

// A nameserver's server entry is shared by every zone it serves. A referral
// from another zone that names it, with an address record for it, leaves the
// entry and the cached address as they were.
func TestGlueOutsideTheReferringZoneLeavesOtherZonesAlone(t *testing.T) {
	const ns = "ns1.served.test."
	imr := verdictImr(t, false)
	glueReferral(t, imr, "served.test.", "test.", []string{ns}, ns+" 3600 IN A 192.0.2.53")
	answer := &core.RRset{Name: ns, Class: dns.ClassINET, RRtype: dns.TypeA,
		RRs: []dns.RR{mustRR(t, ns+" 3600 IN A 192.0.2.53")}}
	imr.Cache.Set(ns, dns.TypeA, &cache.CachedRRset{Name: ns, RRtype: dns.TypeA, RRset: answer,
		Context: cache.ContextAnswer, State: cache.ValidationStateSecure})

	glueReferral(t, imr, "sub.other.test.", "other.test.", []string{ns}, ns+" 3600 IN A 203.0.113.66")

	sm, _ := imr.Cache.ServerMapCopy("served.test.")
	if got := sm[cache.ServerKey(ns)].GetAddrs(); !slices.Equal(got, []string{"192.0.2.53"}) {
		t.Errorf("served.test.'s %s has %v, want 192.0.2.53 alone", ns, got)
	}
	c := imr.Cache.Get(ns, dns.TypeA)
	if c == nil || c.Context != cache.ContextAnswer || c.State != cache.ValidationStateSecure ||
		len(c.RRset.RRs) != 1 || c.RRset.RRs[0].(*dns.A).A.String() != "192.0.2.53" {
		t.Errorf("the cached %s A is now %+v, want the answer as it was", ns, c)
	}
}

// expireEntry makes the cached <name, qtype> expired without reading it: Get
// drops an expired entry, and Set computes a new expiration.
func expireEntry(t *testing.T, imr *Imr, name string, qtype uint16) {
	t.Helper()
	for item := range imr.Cache.RRsets.IterBuffered() {
		if core.EqualNames(item.Val.Name, name) && item.Val.RRtype == qtype {
			e := item.Val
			e.Expiration = cache.Now().Add(-time.Minute)
			imr.Cache.RRsets.Set(item.Key, e)
			return
		}
	}
	t.Fatalf("precondition: no cached %s %s", name, dns.TypeToString[qtype])
}

// Glue does not replace a live authoritative answer for the name, positive or
// negative. It replaces an expired one, and earlier glue.
func TestGlueDoesNotReplaceACachedAnswer(t *testing.T) {
	const zone, ns = "kid.p.test.", "ns.kid.p.test."
	seed := func(imr *Imr, ctx cache.CacheContext) {
		cr := &cache.CachedRRset{Name: ns, RRtype: dns.TypeA, Context: ctx, State: cache.ValidationStateInsecure}
		switch ctx {
		case cache.ContextNoErrNoAns:
			cr.Ttl = 3600
		case cache.ContextNXDOMAIN:
			cr.Ttl, cr.Rcode = 3600, dns.RcodeNameError
		default:
			cr.RRset = &core.RRset{Name: ns, Class: dns.ClassINET, RRtype: dns.TypeA,
				RRs: []dns.RR{mustRR(t, ns+" 3600 IN A 192.0.2.1")}}
		}
		imr.Cache.Set(ns, dns.TypeA, cr)
	}
	for _, tc := range []struct {
		name     string
		existing cache.CacheContext
		expired  bool
		replaced bool
	}{
		{"live answer", cache.ContextAnswer, false, false},
		{"live negative answer", cache.ContextNoErrNoAns, false, false},
		{"live name error", cache.ContextNXDOMAIN, false, false},
		{"expired answer", cache.ContextAnswer, true, true},
		{"earlier glue", cache.ContextGlue, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := verdictImr(t, false)
			seed(imr, tc.existing)
			if tc.expired {
				expireEntry(t, imr, ns, dns.TypeA)
			}
			glueReferral(t, imr, zone, "p.test.", []string{ns}, ns+" 3600 IN A 192.0.2.99")
			c := imr.Cache.Peek(ns, dns.TypeA)
			replaced := c != nil && c.Context == cache.ContextGlue && c.RRset != nil &&
				len(c.RRset.RRs) == 1 && c.RRset.RRs[0].(*dns.A).A.String() == "192.0.2.99"
			if replaced != tc.replaced {
				t.Errorf("replaced = %v, want %v (entry now %+v)", replaced, tc.replaced, c)
			}
			// The glue is the referring zone's statement of where the
			// delegated zone's servers are, and is used for that either way.
			if !hasAddr(imr, ns, "192.0.2.99") {
				t.Errorf("%s does not have the glue address", ns)
			}
		})
	}
}

// A transport signal in a referral's additional section is used only when its
// owner lies within the referring zone.
func TestReferralTransportSignalIsUsedWithinTheReferringZone(t *testing.T) {
	const ns = "ns1.served.test."
	signal := "_dns." + ns + " 3600 IN SVCB 1 . alpn=dot"
	for _, tc := range []struct {
		name, zone, referring string
		used                  bool
	}{
		{"within the referring zone", "kid.served.test.", "served.test.", true},
		{"outside the referring zone", "sub.other.test.", "other.test.", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := verdictImr(t, false)
			glueReferral(t, imr, tc.zone, tc.referring, []string{ns}, signal)
			got := slices.Contains(imr.Cache.GetOrCreateAuthServer(ns).GetAlpn(), "dot")
			if got != tc.used {
				t.Errorf("the signal was used: %v, want %v (alpn %v)", got, tc.used,
					imr.Cache.GetOrCreateAuthServer(ns).GetAlpn())
			}
		})
	}
}

const (
	rgParent  = "p-glue.test."
	rgKid     = "kid.p-glue.test."
	rgWWW     = "www.kid.p-glue.test."
	rgOther   = "other-glue.test."
	rgNS      = "ns.other-glue.test."
	rgSibling = "ns.sib.p-glue.test."
)

// The parent of rgKid, a stub on 127.0.0.1, delegates it to one nameserver,
// with an address record for it. The server on ::1 answers for rgKid.
//
// A nameserver outside the parent's zone (rgNS): the record points back at the
// parent itself and is not used. The resolver looks rgNS up in its own zone, a
// stub on ::1, and the answer comes from ::1.
//
// A nameserver elsewhere in the parent's zone (rgSibling): the record says ::1
// and is used. Nothing else would give it: the parent has no address for it
// beyond the glue.
func TestReferralGlueInALookup(t *testing.T) {
	for _, tc := range []struct {
		name, ns, glue string
		glueUsed       bool
	}{
		{"outside the referring zone", rgNS, rgNS + " 300 IN A 127.0.0.1", false},
		{"sibling", rgSibling, rgSibling + " 300 IN AAAA ::1", true},
	} {
		t.Run(tc.name, func(t *testing.T) { referralGlueInALookup(t, tc.ns, tc.glue, tc.glueUsed) })
	}
}

func referralGlueInALookup(t *testing.T, ns, glue string, glueUsed bool) {
	delegation := mustRR(t, rgKid+" 300 IN NS "+ns)
	glueRR := mustRR(t, glue)
	parentSOA := mustRR(t, rgParent+" 300 IN SOA ns0."+rgParent+" h."+rgParent+" 1 7200 1800 604800 300")
	otherSOA := mustRR(t, rgOther+" 300 IN SOA ns0."+rgOther+" h."+rgOther+" 1 7200 1800 604800 300")
	kidSOA := mustRR(t, rgKid+" 300 IN SOA "+ns+" h."+rgKid+" 1 7200 1800 604800 300")
	nsAAAA := mustRR(t, rgNS+" 300 IN AAAA ::1")
	answer := mustRR(t, rgWWW+" 300 IN A 192.0.2.80")

	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if name := dns.CanonicalName(q.Name); dns.IsSubDomain(rgKid, name) && !(name == rgKid && q.Qtype == dns.TypeDS) {
			m.Ns = append(m.Ns, delegation)
			m.Extra = append(m.Extra, glueRR)
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
		q := r.Question[0]
		switch name := dns.CanonicalName(q.Name); {
		case name == rgNS && q.Qtype == dns.TypeAAAA:
			m.Answer = append(m.Answer, nsAAAA)
		case name == rgWWW && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, answer)
		case dns.IsSubDomain(rgKid, name):
			m.Ns = append(m.Ns, kidSOA)
		default:
			m.Ns = append(m.Ns, otherSOA)
		}
		_ = w.WriteMsg(m)
	})

	imr := verdictImr(t, false)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	for zone, addr := range map[string]string{rgParent: "127.0.0.1", rgOther: "::1"} {
		if err := imr.Cache.AddStub(zone, []cache.AuthServer{
			{Name: "ns0." + zone, Addrs: []string{addr}, Alpn: []string{"do53"}},
		}); err != nil {
			t.Fatalf("AddStub %s: %v", zone, err)
		}
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})

	got := askReferralImr(t, imr, rgWWW)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("got %s with %d answers, want the answer from %s:\n%s",
			dns.RcodeToString[got.Rcode], len(got.Answer), ns, got)
	}
	if a, ok := got.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.80" {
		t.Fatalf("answer %v, want 192.0.2.80", got.Answer[0])
	}
	glueAddr := "127.0.0.1"
	if glueUsed {
		glueAddr = "::1"
	}
	if hasAddr(imr, ns, glueAddr) != glueUsed {
		t.Errorf("%s has the addresses %v; the glue address %s used: %v, want %v", ns,
			imr.Cache.GetOrCreateAuthServer(ns).GetAddrs(), glueAddr, !glueUsed, glueUsed)
	}
}

// Two delegations whose nameservers lie in each other's zone, each referral
// carrying an address record for its nameserver, outside the referring zone.
// Neither record is used, the nameservers cannot be resolved, and the lookup
// ends in SERVFAIL at once. Using the records, the lookup sent its queries to
// those addresses, where nothing answers, and gave up only on the timeouts.
func TestNameserversInEachOthersZonesEndInServfail(t *testing.T) {
	const (
		one, kidOne, nsOne = "one-cyc.test.", "x.one-cyc.test.", "ns.x.one-cyc.test."
		two, kidTwo, nsTwo = "two-cyc.test.", "x.two-cyc.test.", "ns.x.two-cyc.test."
	)
	parent := func(zone, kid, ns, glue string) dns.HandlerFunc {
		delegation, glueRR := mustRR(t, kid+" 300 IN NS "+ns), mustRR(t, glue)
		soa := mustRR(t, zone+" 300 IN SOA ns0."+zone+" h."+zone+" 1 7200 1800 604800 300")
		return func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if dns.IsSubDomain(kid, dns.CanonicalName(r.Question[0].Name)) {
				m.Ns = append(m.Ns, delegation)
				m.Extra = append(m.Extra, glueRR)
			} else {
				m.Authoritative = true
				m.Ns = append(m.Ns, soa)
			}
			_ = w.WriteMsg(m)
		}
	}
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, parent(one, kidOne, nsTwo, nsTwo+" 300 IN A 192.0.2.1"))
	startRefDouble(t, net.IPv6loopback, port, parent(two, kidTwo, nsOne, nsOne+" 300 IN A 192.0.2.2"))

	imr := verdictImr(t, false)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	for zone, addr := range map[string]string{one: "127.0.0.1", two: "::1"} {
		if err := imr.Cache.AddStub(zone, []cache.AuthServer{
			{Name: "ns0." + zone, Addrs: []string{addr}, Alpn: []string{"do53"}},
		}); err != nil {
			t.Fatalf("AddStub %s: %v", zone, err)
		}
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})

	start := time.Now()
	got := askReferralImr(t, imr, "www."+kidOne)
	if got.Rcode != dns.RcodeServerFailure {
		t.Errorf("got %s, want SERVFAIL:\n%s", dns.RcodeToString[got.Rcode], got)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("SERVFAIL took %v", took)
	}
	for _, ns := range []string{nsOne, nsTwo} {
		if addrs := imr.Cache.GetOrCreateAuthServer(ns).GetAddrs(); len(addrs) != 0 {
			t.Errorf("%s has the addresses %v from a referral outside its zone", ns, addrs)
		}
	}
}
