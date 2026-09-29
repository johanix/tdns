/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A nameserver address on the resolver's own host is not queried unless the
// operator configured it (a stub) or set allow-loopback-nameservers (#831).

func TestHostLocalAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1":        true,
		"127.0.0.2":        true,
		"127.255.255.255":  true,
		"::1":              true,
		"::1%lo0":          true,
		"::ffff:127.0.0.1": true,
		"0.0.0.0":          true,
		"::":               true,
		"192.0.2.1":        false,
		"2001:db8::1":      false,
		"fe80::1%eth0":     false,
		"":                 false,
		"ns.example.":      false,
	} {
		if got := hostLocalAddr(addr); got != want {
			t.Errorf("hostLocalAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestMayQueryAddr(t *testing.T) {
	glue := cache.NewAuthServer("ns.example.")
	glue.SetSrc("glue")
	stub := cache.NewAuthServer("ns.stub.example.")
	stub.ForceSetSrc("stub")
	for _, tc := range []struct {
		name   string
		server *cache.AuthServer
		addr   string
		allow  bool
		want   bool
	}{
		{"glue, loopback", glue, "127.0.0.1", false, false},
		{"glue, v6 loopback", glue, "::1", false, false},
		{"glue, unspecified", glue, "0.0.0.0", false, false},
		{"glue, elsewhere", glue, "192.0.2.1", false, true},
		{"stub, loopback", stub, "127.0.0.1", false, true},
		{"glue, loopback, allowed", glue, "127.0.0.1", true, true},
	} {
		if got := mayQueryAddr(tc.server, tc.addr, tc.allow); got != tc.want {
			t.Errorf("%s: mayQueryAddr = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAllowLoopbackNameserversOptionParses(t *testing.T) {
	conf := &Config{}
	conf.Imr.OptionsStrs = []string{"allow-loopback-nameservers"}
	conf.parseImrOptions()
	if conf.Imr.Options[ImrOptAllowLoopbackNameservers] != "true" {
		t.Fatalf("options %v, want allow-loopback-nameservers set", conf.Imr.Options)
	}
}

// NS revalidation sends its queries without prioritizeServers, and skips an
// address on this host the same way.
func TestRevalidationSkipsHostLocalAddresses(t *testing.T) {
	glue := cache.NewAuthServer("ns.example.")
	glue.SetSrc("glue")
	glue.SetAddrs([]string{"127.0.0.1", "192.0.2.1"})
	sm := map[string]*cache.AuthServer{"ns.example.": glue}
	if got := collectServerAddressesForRevalidation(sm, false); !slices.Equal(got, []string{"192.0.2.1:53"}) {
		t.Errorf("got %v, want only 192.0.2.1:53", got)
	}
	got := collectServerAddressesForRevalidation(sm, true)
	slices.Sort(got)
	if !slices.Equal(got, []string{"127.0.0.1:53", "192.0.2.1:53"}) {
		t.Errorf("allowed: got %v, want both addresses", got)
	}
}

// With no usable address left, the warning says the address is on this host.
func TestExplainNoTuplesCountsHostLocalAddresses(t *testing.T) {
	glue := cache.NewAuthServer("ns.example.")
	glue.SetSrc("glue")
	glue.SetAddrs([]string{"127.0.0.1"})
	got := explainNoTuples(map[string]*cache.AuthServer{"ns.example.": glue}, nil, nil, "www.example.", edns0.PrivacyNone, false)
	if !strings.Contains(got, "1 on this host") {
		t.Errorf("explanation %q does not count the address on this host", got)
	}
}

const (
	lbParent = "p831.test."
	lbKid    = "kid.p831.test."
	lbKidNS  = "ns.kid.p831.test."
	lbWWW    = "www.kid.p831.test."
)

// loopbackImr: the parent of lbKid is a stub on 127.0.0.1. It delegates lbKid
// to lbKidNS with glue ::1, where the child's server answers lbWWW. The counts
// are the queries each server got.
func loopbackImr(t *testing.T, allow bool) (imr *Imr, parentQueries, kidQueries *atomic.Int32) {
	t.Helper()
	parentQueries, kidQueries = new(atomic.Int32), new(atomic.Int32)
	delegation := mustRR(t, lbKid+" 300 IN NS "+lbKidNS)
	glue := mustRR(t, lbKidNS+" 300 IN AAAA ::1")
	parentSOA := mustRR(t, lbParent+" 300 IN SOA ns."+lbParent+" hostmaster."+lbParent+" 1 7200 1800 604800 300")
	kidSOA := mustRR(t, lbKid+" 300 IN SOA "+lbKidNS+" hostmaster."+lbKid+" 1 7200 1800 604800 300")
	answer := mustRR(t, lbWWW+" 300 IN A 192.0.2.31")

	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		parentQueries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		name := dns.CanonicalName(q.Name)
		if dns.IsSubDomain(lbKid, name) && !(name == lbKid && q.Qtype == dns.TypeDS) {
			m.Ns = append(m.Ns, delegation)
			m.Extra = append(m.Extra, glue)
		} else {
			m.Authoritative = true
			m.Ns = append(m.Ns, parentSOA)
		}
		_ = w.WriteMsg(m)
	})
	startRefDouble(t, net.IPv6loopback, port, func(w dns.ResponseWriter, r *dns.Msg) {
		kidQueries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if q := r.Question[0]; dns.CanonicalName(q.Name) == lbWWW && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, answer)
		} else {
			m.Ns = append(m.Ns, kidSOA)
		}
		_ = w.WriteMsg(m)
	})

	imr = verdictImr(t, false)
	if !allow {
		delete(imr.Options, ImrOptAllowLoopbackNameservers)
	}
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	if err := imr.Cache.AddStub(lbParent, []cache.AuthServer{
		{Name: "ns." + lbParent, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub %s: %v", lbParent, err)
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})
	return imr, parentQueries, kidQueries
}

// The stub on 127.0.0.1 is queried, the glue ::1 it hands out is not, and the
// client gets SERVFAIL.
func TestLoopbackGlueIsNotQueried(t *testing.T) {
	imr, parentQueries, kidQueries := loopbackImr(t, false)
	got := askReferralImr(t, imr, lbWWW)
	if got.Rcode != dns.RcodeServerFailure || len(got.Answer) != 0 {
		t.Errorf("got %s with %d answers, want SERVFAIL and none:\n%s",
			dns.RcodeToString[got.Rcode], len(got.Answer), got)
	}
	if n := parentQueries.Load(); n == 0 {
		t.Error("the stub on 127.0.0.1 was not queried")
	}
	if n := kidQueries.Load(); n != 0 {
		t.Errorf("the server at the glue address ::1 got %d queries, want none", n)
	}
}

// With allow-loopback-nameservers the glue is used.
func TestLoopbackGlueIsQueriedWhenAllowed(t *testing.T) {
	imr, _, kidQueries := loopbackImr(t, true)
	got := askReferralImr(t, imr, lbWWW)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("got %s with %d answers, want the child's answer:\n%s",
			dns.RcodeToString[got.Rcode], len(got.Answer), got)
	}
	if a, ok := got.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.31" {
		t.Fatalf("answer %v, want 192.0.2.31", got.Answer[0])
	}
	if kidQueries.Load() == 0 {
		t.Error("the server at the glue address ::1 was not queried")
	}
}
