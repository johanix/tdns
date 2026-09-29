/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Iterative queries go to authoritative servers with RD=0 (#817). The
// forwarding paths keep RD=1; imr_forward_test.go checks that on the wire.

// The message every iterative query starts from: RD clear, EDNS with DO.
func TestAuthQueryMsgClearsRD(t *testing.T) {
	m := authQueryMsg("www.example.", dns.TypeA)
	if m.RecursionDesired {
		t.Error("authQueryMsg: RD=1, want RD=0")
	}
	if opt := m.IsEdns0(); opt == nil || !opt.Do() || opt.UDPSize() != 4096 {
		t.Errorf("authQueryMsg: EDNS %v, want udpsize 4096 with DO", opt)
	}
	for _, oots := range []bool{false, true} {
		b, err := buildQuery("www.example.", dns.TypeA, oots)
		if err != nil {
			t.Fatalf("buildQuery(oots=%v): %v", oots, err)
		}
		if b.RecursionDesired {
			t.Errorf("buildQuery(oots=%v): RD=1, want RD=0", oots)
		}
	}
}

// A resolution through a stub and a referral: every query that reaches either
// server has RD=0, whatever the resolver sends along the way.
func TestIterativeQueriesGoOutWithRDClear(t *testing.T) {
	const (
		parent = "rd817.example."
		kid    = "kid.rd817.example."
		kidNS  = "ns.kid.rd817.example."
		www    = "www.kid.rd817.example."
	)
	delegation := mustRR(t, kid+" 300 IN NS "+kidNS)
	glue := mustRR(t, kidNS+" 300 IN AAAA ::1")
	parentSOA := mustRR(t, parent+" 300 IN SOA ns."+parent+" hostmaster."+parent+" 1 7200 1800 604800 300")
	kidSOA := mustRR(t, kid+" 300 IN SOA "+kidNS+" hostmaster."+kid+" 1 7200 1800 604800 300")
	answer := mustRR(t, www+" 300 IN A 192.0.2.80")

	var mu sync.Mutex
	var seen, withRD []string
	record := func(server string, r *dns.Msg) {
		mu.Lock()
		defer mu.Unlock()
		q := r.Question[0]
		e := fmt.Sprintf("%s: %s %s", server, q.Name, dns.TypeToString[q.Qtype])
		seen = append(seen, e)
		if r.RecursionDesired {
			withRD = append(withRD, e)
		}
	}

	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		record("parent", r)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		name := dns.CanonicalName(q.Name)
		if dns.IsSubDomain(kid, name) && !(q.Qtype == dns.TypeDS && name == kid) {
			m.Authoritative = false
			m.Ns = append(m.Ns, delegation)
			m.Extra = append(m.Extra, glue)
		} else {
			m.Ns = append(m.Ns, parentSOA)
		}
		_ = w.WriteMsg(m)
	})
	startRefDouble(t, net.IPv6loopback, port, func(w dns.ResponseWriter, r *dns.Msg) {
		record("kid", r)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		if q.Qtype == dns.TypeA && dns.CanonicalName(q.Name) == www {
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
	if err := imr.Cache.AddStub(parent, []cache.AuthServer{
		{Name: "ns." + parent, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	// No trust anchor: every walk up the tree ends at an Indeterminate root.
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})

	got := askReferralImr(t, imr, www)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) == 0 {
		t.Fatalf("the resolution did not succeed, so this test proves nothing:\n%s", got)
	}

	mu.Lock()
	defer mu.Unlock()
	var toParent, toKid bool
	for _, e := range seen {
		toParent = toParent || e[:6] == "parent"
		toKid = toKid || e[:3] == "kid"
	}
	if !toParent || !toKid {
		t.Fatalf("precondition: queries reached parent=%v kid=%v, want both: %v", toParent, toKid, seen)
	}
	if len(withRD) > 0 {
		t.Errorf("%d of %d queries to authoritative servers went out with RD=1: %v", len(withRD), len(seen), withRD)
	}
}
