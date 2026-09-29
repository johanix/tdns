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

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A configured stub's servers are configuration: glue, a referral's NS RRset
// and servers learned by a lookup do not change them.

const (
	sgZone   = "stubglue.test."
	sgNS     = "ns.stubglue.test."
	sgOOBNS  = "ns.oob.stubglue-other.test."
	sgWWW    = "www.stubglue.test."
	sgAnswer = "192.0.2.44"
)

// sgImr is a resolver with sgZone as a stub on 127.0.0.1 port 0 (no server
// there) or, with a handler, on a test double that answers with it.
func sgImr(t *testing.T, handler dns.HandlerFunc) *Imr {
	t.Helper()
	imr := verdictImr(t, false)
	if handler != nil {
		p := strconv.Itoa(startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, handler))
		imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
		imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	}
	if err := imr.Cache.AddStub(sgZone, []cache.AuthServer{
		{Name: sgNS, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})
	return imr
}

// stubUnchanged fails unless sgZone's server map is still the configured one:
// sgNS alone, the same instance, with 127.0.0.1 alone.
func stubUnchanged(t *testing.T, imr *Imr, configured *cache.AuthServer) {
	t.Helper()
	sm, ok := imr.Cache.ServerMap.Get(sgZone)
	if !ok {
		t.Fatal("the stub's server map is gone")
	}
	var names []string
	for name := range sm {
		names = append(names, name)
	}
	if len(sm) != 1 || sm[cache.ServerKey(sgNS)] != configured {
		t.Fatalf("the stub's servers are %v, want the configured %s alone", names, sgNS)
	}
	if addrs := configured.GetAddrs(); !slices.Equal(addrs, []string{"127.0.0.1"}) {
		t.Errorf("the stub server's addresses are %v, want the configured 127.0.0.1 alone", addrs)
	}
}

func configuredStubServer(t *testing.T, imr *Imr) *cache.AuthServer {
	t.Helper()
	sm, _ := imr.Cache.ServerMap.Get(sgZone)
	srv := sm[cache.ServerKey(sgNS)]
	if srv == nil {
		t.Fatal("precondition: no configured stub server")
	}
	return srv
}

// A referral to sgZone: its NS RRset names sgNS, with glue elsewhere, and an
// out-of-bailiwick server whose address is cached.
func sgReferral(t *testing.T) *dns.Msg {
	r := new(dns.Msg)
	r.SetQuestion(sgWWW, dns.TypeA)
	r.Response = true
	r.Ns = []dns.RR{mustRR(t, sgZone+" 300 IN NS "+sgNS), mustRR(t, sgZone+" 300 IN NS "+sgOOBNS)}
	r.Extra = []dns.RR{mustRR(t, sgNS+" 300 IN A 192.0.2.66"), mustRR(t, sgNS+" 300 IN AAAA 2001:db8::66")}
	return r
}

func TestAddServersLeavesAStubAlone(t *testing.T) {
	imr := sgImr(t, nil)
	configured := configuredStubServer(t, imr)
	learned := imr.Cache.GetOrCreateAuthServer(sgNS)
	learned.AddAddr("192.0.2.66")
	other := imr.Cache.GetOrCreateAuthServer(sgOOBNS)
	other.AddAddr("192.0.2.77")
	if err := imr.Cache.AddServers(sgZone, map[string]*cache.AuthServer{sgNS: learned, sgOOBNS: other}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}
	stubUnchanged(t, imr, configured)
}

func TestGlueLeavesAStubAlone(t *testing.T) {
	imr := sgImr(t, nil)
	configured := configuredStubServer(t, imr)
	r := sgReferral(t)
	nsrrset := &core.RRset{Name: sgZone, Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: r.Ns}
	got, err := imr.ParseAdditionalForNSAddrs(context.Background(), "authority", nsrrset, sgZone,
		map[string]bool{sgNS: true, sgOOBNS: true}, r)
	if err != nil {
		t.Fatalf("ParseAdditionalForNSAddrs: %v", err)
	}
	if len(got) != 1 || got[cache.ServerKey(sgNS)] != configured {
		t.Errorf("the lookup goes on to %v, want the configured server", got)
	}
	stubUnchanged(t, imr, configured)
}

// A referral into a stub zone is followed to the configured servers, and
// leaves them as they were.
func TestReferralToAStubZoneUsesTheConfiguredServers(t *testing.T) {
	answer := mustRR(t, sgWWW+" 300 IN A "+sgAnswer)
	imr := sgImr(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if q := r.Question[0]; dns.CanonicalName(q.Name) == sgWWW && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, answer)
		} else {
			m.Ns = append(m.Ns, mustRR(t, sgZone+" 300 IN SOA "+sgNS+" hostmaster."+sgZone+" 1 7200 1800 604800 300"))
		}
		_ = w.WriteMsg(m)
	})
	configured := configuredStubServer(t, imr)
	// The out-of-bailiwick server's address is known, as the referral path
	// would otherwise add it.
	imr.Cache.Set(sgOOBNS, dns.TypeA, &cache.CachedRRset{
		Name: sgOOBNS, RRtype: dns.TypeA, Rcode: uint8(dns.RcodeSuccess), Context: cache.ContextAnswer,
		RRset: &core.RRset{Name: sgOOBNS, Class: dns.ClassINET, RRtype: dns.TypeA,
			RRs: []dns.RR{mustRR(t, sgOOBNS+" 300 IN A 192.0.2.77")}},
		Expiration: time.Now().Add(time.Hour),
	})

	rrset, rcode, _, _, err := imr.handleReferral(context.Background(), sgWWW, dns.TypeA, sgReferral(t),
		false, map[string]bool{}, core.TransportDo53, edns0.PrivacyNone)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("handleReferral: rcode %s, rrset %v, err %v; want the stub's answer",
			dns.RcodeToString[rcode], rrset, err)
	}
	if a, ok := rrset.RRs[0].(*dns.A); !ok || a.A.String() != sgAnswer {
		t.Fatalf("answer %v, want %s", rrset.RRs[0], sgAnswer)
	}
	stubUnchanged(t, imr, configured)
	// The out-of-bailiwick server named by the referral did not join this
	// lookup either: nothing created a server for it.
	if _, ok := imr.Cache.AuthServerMap.Get(sgOOBNS); ok {
		t.Errorf("the referral's %s was added to the lookup", sgOOBNS)
	}
}
