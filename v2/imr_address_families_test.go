/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// imrengine.address-families: a family left out is neither looked up nor used.

func TestParseAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		list   []string
		v4, v6 bool
		ok     bool
	}{
		{nil, true, true, true},
		{[]string{}, true, true, true},
		{[]string{"ipv4", "ipv6"}, true, true, true},
		{[]string{"ipv4"}, true, false, true},
		{[]string{" IPv6 "}, false, true, true},
		{[]string{"ipv4", "ipv5"}, false, false, false},
		{[]string{"v4"}, false, false, false},
	} {
		v4, v6, err := ParseAddressFamilies(tc.list)
		if (err == nil) != tc.ok || (tc.ok && (v4 != tc.v4 || v6 != tc.v6)) {
			t.Errorf("ParseAddressFamilies(%q) = %v, %v, %v; want %v, %v, ok=%v", tc.list, v4, v6, err, tc.v4, tc.v6, tc.ok)
		}
	}
}

func TestAddressFamiliesChangeNeedsARestart(t *testing.T) {
	boot := ImrEngineConf{AddressFamilies: []string{"ipv4", "ipv6"}}
	for _, tc := range []struct {
		families []string
		restart  bool
	}{
		{nil, false},                      // both, as before
		{[]string{"ipv6", "ipv4"}, false}, // the same, in another order
		{[]string{"ipv4"}, true},
	} {
		current := boot
		current.AddressFamilies = tc.families
		got := slices.Contains(imrRestartRequiredKeys(boot, current), "imrengine.address-families")
		if got != tc.restart {
			t.Errorf("address-families %v: restart required %v, want %v", tc.families, got, tc.restart)
		}
	}
}

const (
	afZone = "af.test."
	afWWW  = "www.af.test."
	afNS   = "ns.af-other.test."
	afNSZ  = "af-other.test."
)

// afImr is a resolver using only the families given. afZone is a stub with one
// server on 127.0.0.1 and one on ::1, doubles that answer afWWW; the counters
// are the queries each got.
func afImr(t *testing.T, v4, v6 bool) (*Imr, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var q4, q6 atomic.Int32
	answer := func(n *atomic.Int32, addr string) dns.HandlerFunc {
		a := mustRR(t, afWWW+" 300 IN A "+addr)
		return func(w dns.ResponseWriter, r *dns.Msg) {
			n.Add(1)
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = append(m.Answer, a)
			_ = w.WriteMsg(m)
		}
	}
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, answer(&q4, "192.0.2.4"))
	startRefDouble(t, net.IPv6loopback, port, answer(&q6, "192.0.2.6"))
	imr := verdictImr(t, false)
	imr.Cache.SetAddressFamilies(v4, v6)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	if err := imr.Cache.AddStub(afZone, []cache.AuthServer{
		{Name: "ns4." + afZone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
		{Name: "ns6." + afZone, Addrs: []string{"::1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	// The server of the family not in use would be picked first, had it kept its
	// address.
	sm, _ := imr.Cache.ServerMap.Get(afZone)
	for name, addr := range map[string]string{"ns4." + afZone: "127.0.0.1", "ns6." + afZone: "::1"} {
		rtt := 150 * time.Millisecond
		if (addr == "127.0.0.1") != v4 {
			rtt = time.Millisecond
		}
		sm[cache.ServerKey(name)].RecordRTT(addr, core.TransportDo53, rtt)
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})
	return imr, &q4, &q6
}

// With one family only, the other family's servers get no query, although
// their RTT would put them first.
func TestOnlyTheFamiliesInUseAreQueried(t *testing.T) {
	for _, tc := range []struct {
		name   string
		v4, v6 bool
		want   string
	}{
		{"ipv4 only", true, false, "192.0.2.4"},
		{"ipv6 only", false, true, "192.0.2.6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr, q4, q6 := afImr(t, tc.v4, tc.v6)
			got := askReferralImr(t, imr, afWWW)
			if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
				t.Fatalf("got %s with %d answers, want an answer:\n%s", dns.RcodeToString[got.Rcode], len(got.Answer), got)
			}
			if a, ok := got.Answer[0].(*dns.A); !ok || a.A.String() != tc.want {
				t.Fatalf("answer %v, want %s from the server in use", got.Answer[0], tc.want)
			}
			if (!tc.v4 && q4.Load() != 0) || (!tc.v6 && q6.Load() != 0) {
				t.Errorf("the family not in use got queries: IPv4 %d, IPv6 %d", q4.Load(), q6.Load())
			}
		})
	}
}

// A nameserver's addresses are looked up only for the families in use.
func TestNameserverAddressLookupsAskOnlyTheFamiliesInUse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		v4, v6   bool
		stubAddr string
		asked    []uint16
		addrs    []string
	}{
		{"ipv4 only", true, false, "127.0.0.1", []uint16{dns.TypeA}, []string{"192.0.2.53"}},
		{"ipv6 only", false, true, "::1", []uint16{dns.TypeAAAA}, []string{"2001:db8::53"}},
		{"both", true, true, "127.0.0.1", []uint16{dns.TypeA, dns.TypeAAAA}, []string{"192.0.2.53", "2001:db8::53"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var asked []uint16
			handler := func(w dns.ResponseWriter, r *dns.Msg) {
				q := r.Question[0]
				m := new(dns.Msg)
				m.SetReply(r)
				m.Authoritative = true
				if dns.CanonicalName(q.Name) == afNS {
					mu.Lock()
					asked = append(asked, q.Qtype)
					mu.Unlock()
					switch q.Qtype {
					case dns.TypeA:
						m.Answer = append(m.Answer, mustRR(t, afNS+" 300 IN A 192.0.2.53"))
					case dns.TypeAAAA:
						m.Answer = append(m.Answer, mustRR(t, afNS+" 300 IN AAAA 2001:db8::53"))
					}
				}
				_ = w.WriteMsg(m)
			}
			port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, handler)
			startRefDouble(t, net.IPv6loopback, port, handler)
			imr := verdictImr(t, false)
			imr.Cache.SetAddressFamilies(tc.v4, tc.v6)
			p := strconv.Itoa(port)
			imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
			imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
			if err := imr.Cache.AddStub(afNSZ, []cache.AuthServer{
				{Name: "ns." + afNSZ, Addrs: []string{tc.stubAddr}, Alpn: []string{"do53"}},
			}); err != nil {
				t.Fatalf("AddStub: %v", err)
			}
			imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})

			srv := imr.Cache.GetOrCreateAuthServer(afNS)
			imr.lookupServerAddrs(context.Background(), srv, afNS)
			mu.Lock()
			got := slices.Clone(asked)
			mu.Unlock()
			slices.Sort(got)
			if !slices.Equal(got, tc.asked) {
				t.Errorf("asked for %v, want %v", got, tc.asked)
			}
			addrs := srv.GetAddrs()
			slices.Sort(addrs)
			if !slices.Equal(addrs, tc.addrs) {
				t.Errorf("addresses %v, want %v", addrs, tc.addrs)
			}
		})
	}
}

// Glue of a family not in use is left out. A nameserver whose glue is all of
// that family then has no address, and is looked up as a glue-less one is,
// rather than kept with an address it cannot use.
func TestGlueOfAFamilyNotInUseIsLeftOut(t *testing.T) {
	const zone, ns1, ns2 = "glue.af.test.", "ns1.glue.af.test.", "ns2.glue.af.test."
	imr := verdictImr(t, false)
	imr.Cache.SetAddressFamilies(true, false)
	r := new(dns.Msg)
	r.SetQuestion("www."+zone, dns.TypeA)
	r.Response = true
	r.Ns = []dns.RR{mustRR(t, zone+" 300 IN NS "+ns1), mustRR(t, zone+" 300 IN NS "+ns2)}
	r.Extra = []dns.RR{
		mustRR(t, ns1+" 300 IN A 192.0.2.1"), mustRR(t, ns1+" 300 IN AAAA 2001:db8::1"),
		mustRR(t, ns2+" 300 IN AAAA 2001:db8::2"),
	}
	nsrrset := &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: r.Ns}
	sm, err := imr.ParseAdditionalForNSAddrs(context.Background(), "authority", nsrrset, zone,
		map[string]bool{ns1: true, ns2: true}, r)
	if err != nil {
		t.Fatalf("ParseAdditionalForNSAddrs: %v", err)
	}
	if got := sm[cache.ServerKey(ns1)].GetAddrs(); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("%s has %v, want the IPv4 glue alone", ns1, got)
	}
	if srv := sm[cache.ServerKey(ns2)]; srv != nil && len(srv.GetAddrs()) != 0 {
		t.Errorf("%s has %v, want no address", ns2, srv.GetAddrs())
	}
}

// Glue revalidation (revalidate-ns) asks only for the families in use.
func TestGlueRevalidationAsksOnlyTheFamiliesInUse(t *testing.T) {
	const zone, ns = "reval.af.test.", "ns.reval.af.test."
	var mu sync.Mutex
	var asked []uint16
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if dns.CanonicalName(q.Name) == ns {
			mu.Lock()
			asked = append(asked, q.Qtype)
			mu.Unlock()
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, mustRR(t, ns+" 300 IN A 127.0.0.1"))
			}
		}
		_ = w.WriteMsg(m)
	})
	imr := verdictImr(t, false)
	imr.Options[ImrOptRevalidateNS] = "true"
	imr.Cache.SetAddressFamilies(true, false)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})
	srv := imr.Cache.GetOrCreateAuthServer(ns)
	srv.SetAddrs([]string{"127.0.0.1"})
	imr.revalidateInBailiwickGlue(context.Background(), zone, map[string]*cache.AuthServer{cache.ServerKey(ns): srv}, true)
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(asked, []uint16{dns.TypeA}) {
		t.Errorf("asked for %v, want A alone", asked)
	}
}

// An unknown address family stops the resolver from starting, before it has
// built anything.
func TestAnUnknownAddressFamilyStopsTheStart(t *testing.T) {
	conf := &Config{}
	conf.Imr.AddressFamilies = []string{"ipv4", "ipv5"}
	err := conf.InitImrEngine(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "imrengine.address-families") {
		t.Fatalf("InitImrEngine: %v, want an error naming imrengine.address-families", err)
	}
	if conf.Internal.ImrEngine != nil {
		t.Error("the resolver was built")
	}
}
