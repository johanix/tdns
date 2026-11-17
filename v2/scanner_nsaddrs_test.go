/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #925 review: a child's nameserver was asked at its first address only, and the
// A records are read before the AAAA records. A nameserver whose IPv4 address
// does not answer and whose IPv6 address does was recorded as one that gave no
// copy, and a DS withdrawal is refused as unverifiable while any nameserver gave
// none.

func TestNameserverAddressOrder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		v4, v6 []string
		want   []string
	}{
		{"none", nil, nil, nil},
		{"one of each: IPv4 first", []string{"a1"}, []string{"b1"}, []string{"a1", "b1"}},
		{"IPv4 only", []string{"a1", "a2"}, nil, []string{"a1", "a2"}},
		{"IPv6 only", nil, []string{"b1", "b2"}, []string{"b1", "b2"}},
		{"both families before either twice", []string{"a1", "a2", "a3"}, []string{"b1"}, []string{"a1", "b1", "a2", "a3"}},
		{"bounded", []string{"a1", "a2", "a3"}, []string{"b1", "b2", "b3"}, []string{"a1", "b1", "a2", "b2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nameserverAddressOrder(tc.v4, tc.v6); !slices.Equal(got, tc.want) {
				t.Errorf("order %v, want %v", got, tc.want)
			}
		})
	}
	if maxNameserverAddresses != 4 {
		t.Errorf("maxNameserverAddresses is %d: the test above and the cost stated at the constant assume 4", maxNameserverAddresses)
	}
}

// serveNameserverAddresses primes imr with the addresses of nsName.
func serveNameserverAddresses(t *testing.T, imr *Imr, nsName string, v4, v6 string) {
	t.Helper()
	exp := time.Now().Add(time.Hour)
	if v4 != "" {
		imr.Cache.Set(nsName, dns.TypeA, &cache.CachedRRset{Name: nsName, RRtype: dns.TypeA, Context: cache.ContextAnswer,
			State: cache.ValidationStateInsecure, Expiration: exp,
			RRset: &core.RRset{Name: nsName, Class: dns.ClassINET, RRtype: dns.TypeA,
				RRs: []dns.RR{mustRR(t, nsName+" 300 IN A "+v4)}}})
	}
	if v6 != "" {
		imr.Cache.Set(nsName, dns.TypeAAAA, &cache.CachedRRset{Name: nsName, RRtype: dns.TypeAAAA, Context: cache.ContextAnswer,
			State: cache.ValidationStateInsecure, Expiration: exp,
			RRset: &core.RRset{Name: nsName, Class: dns.ClassINET, RRtype: dns.TypeAAAA,
				RRs: []dns.RR{mustRR(t, nsName+" 300 IN AAAA "+v6)}}})
	}
}

// ipv6Server starts a test DNS server on [::1], answering with answer, and
// returns the port. The test is skipped where the host has no IPv6 loopback.
func ipv6Server(t *testing.T, answer ...string) string {
	t.Helper()
	probe, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = probe.Close()
	_, port, err := net.SplitHostPort(testAuthServerAt(t, "[::1]:0", true, answer, nil))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// The nameserver's IPv4 address answers nothing (nothing listens on it at the
// port its IPv6 address does): its IPv6 address is asked next, and its answer is
// the nameserver's.
func TestQueryAllNSAsksTheNextAddressWhenTheFirstDoesNotAnswer(t *testing.T) {
	const (
		child  = "child.example."
		nsName = "ns1.provider.example."
	)
	port := ipv6Server(t, child+" 300 IN A 192.0.2.7")
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second); err == nil {
		_ = c.Close()
		t.Skipf("something listens on 127.0.0.1:%s", port)
	}
	imr := newTestImr(t)
	serveNameserverAddresses(t, imr, nsName, "127.0.0.1", "::1")
	sc := NewScanner(startAuthQueryEngine(t), false, false)
	sc.childPort = port
	ns := &core.RRset{Name: child, RRtype: dns.TypeNS, RRs: []dns.RR{mustRR(t, child+" 300 IN NS "+nsName)}}

	answers, queryErrors, err := sc.queryAllNS(context.Background(), child, dns.TypeA, ns, imr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(queryErrors) != 0 {
		t.Errorf("the nameserver is recorded as silent: %v", queryErrors)
	}
	if len(answers) != 1 || answers[0].NS != nsName || len(answers[0].RRset.RRs) != 1 {
		t.Fatalf("answers %+v, want the one from %s at its IPv6 address", answers, nsName)
	}
}

// A nameserver none of whose addresses answers gave no copy, and the error says
// what each address said.
func TestQueryAllNSLeavesOutANameserverNoAddressOfWhichAnswers(t *testing.T) {
	const (
		child  = "child.example."
		nsName = "ns1.provider.example."
	)
	port := ipv6Server(t, child+" 300 IN A 192.0.2.7")
	imr := newTestImr(t)
	// Both addresses are IPv4 loopback, where nothing listens at this port.
	serveNameserverAddresses(t, imr, nsName, "127.0.0.1", "")
	sc := NewScanner(startAuthQueryEngine(t), false, false)
	sc.childPort = port
	ns := &core.RRset{Name: child, RRtype: dns.TypeNS, RRs: []dns.RR{mustRR(t, child+" 300 IN NS "+nsName)}}

	answers, queryErrors, err := sc.queryAllNS(context.Background(), child, dns.TypeA, ns, imr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 0 || len(queryErrors) != 1 || !strings.Contains(queryErrors[0], "no answer at any address") ||
		!strings.Contains(queryErrors[0], "127.0.0.1:"+port) {
		t.Errorf("answers %+v, errors %v; want the nameserver left out, with the address it tried", answers, queryErrors)
	}
}

// Once the budget is spent no further address is tried.
func TestAskNameserverAddressesStopsWhenTheContextIsDone(t *testing.T) {
	port := ipv6Server(t, "child.example. 300 IN A 192.0.2.7")
	sc := NewScanner(startAuthQueryEngine(t), false, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// The first address is always asked; the second would answer, and is not.
	_, _, err := sc.askNameserverAddresses(ctx, "child.example.", dns.TypeA,
		[]string{net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("::1", port)})
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("got %v, want no answer, the context being done", err)
	}
}

// The DS withdrawal that was refused as unverifiable for a nameserver that is
// reachable: the child's only nameserver has an IPv4 address that does not
// answer and an IPv6 address that serves the copy signed by the remaining
// signer. The check asks the nameserver as the server does, through the
// scanner, and the withdrawal passes.
func TestCoherenceAsksAnIPv6AddressWhenTheIPv4OneDoesNotAnswer(t *testing.T) {
	const nsName = "ns1.provider-a.example."
	p := newSignerPair(t, cohChild)
	copyB := p.signedBy(t, p.b)
	answer := []string{p.a.dnskey.String(), p.b.dnskey.String(), copyB.RRSIGs[0].String()}
	port := ipv6Server(t, answer...)
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second); err == nil {
		_ = c.Close()
		t.Skipf("something listens on 127.0.0.1:%s", port)
	}

	imr := newTestImr(t)
	serveNameserverAddresses(t, imr, nsName, "127.0.0.1", "::1")
	conf := &Config{}
	conf.Internal.ImrEngine = imr
	conf.Internal.ImrReady = NewImrReadiness()
	conf.Internal.ImrReady.Publish()
	sc := NewScanner(startAuthQueryEngine(t), false, false)
	sc.conf = conf
	sc.childPort = port

	err := CheckDelegationCoherence(cohChild, []dns.RR{mustRR(t, cohChild+" 3600 IN NS "+nsName)},
		[]dns.RR{p.dsA, p.dsB}, []dns.RR{delOneDS(p.dsA)}, nameserversDnskeyFetcher(sc))
	if err != nil {
		t.Fatalf("withdrawing A's DS, with the one nameserver serving B's copy at its IPv6 address: %v", err)
	}
}
