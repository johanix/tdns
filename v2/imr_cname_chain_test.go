/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// CNAME chains, asked through the responder (#717). The auth double serves an
// unsigned zone and answers one CNAME per response, as the servers of a
// CDN-style chain do, so the resolver follows every link itself:
//
//	a  -> b -> c        c has an A, and no TXT
//	nx -> gone          gone does not exist
//	loop1 -> loop2 -> loop1
//	m0 -> m1 -> ... -> m11      11 CNAMEs, m11 has an A
//	x0 -> x1 -> ... -> x12      12 CNAMEs, x12 has an A
//	z0 -> z1                    both with TTL 0, z1 has an A
const chainZone = "chain.test."

type chainDouble struct {
	mu      sync.Mutex
	queries map[string]int // "name/TYPE" -> queries received
}

func (d *chainDouble) count(name string, qtype uint16) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.queries[core.CanonicalizeName(name)+"/"+dns.TypeToString[qtype]]
}

func startChainDouble(t *testing.T) (*chainDouble, string) {
	t.Helper()
	cnames := map[string]string{
		"a." + chainZone:     "b." + chainZone,
		"b." + chainZone:     "c." + chainZone,
		"nx." + chainZone:    "gone." + chainZone,
		"loop1." + chainZone: "loop2." + chainZone,
		"loop2." + chainZone: "loop1." + chainZone,
	}
	addrs := map[string]net.IP{"c." + chainZone: net.IPv4(192, 0, 2, 1)}
	// z0 -> z1, and z1's A, carry TTL 0: usable for the answer at hand, and
	// not to be kept.
	cnames["z0."+chainZone] = "z1." + chainZone
	addrs["z1."+chainZone] = net.IPv4(192, 0, 2, 10)
	zeroTTL := map[string]bool{"z0." + chainZone: true, "z1." + chainZone: true}
	for i := 0; i < 11; i++ {
		cnames[fmt.Sprintf("m%d.%s", i, chainZone)] = fmt.Sprintf("m%d.%s", i+1, chainZone)
	}
	addrs["m11."+chainZone] = net.IPv4(192, 0, 2, 11)
	for i := 0; i < 12; i++ {
		cnames[fmt.Sprintf("x%d.%s", i, chainZone)] = fmt.Sprintf("x%d.%s", i+1, chainZone)
	}
	addrs["x12."+chainZone] = net.IPv4(192, 0, 2, 12)

	d := &chainDouble{queries: map[string]int{}}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: chainZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns." + chainZone, Mbox: "hostmaster." + chainZone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(chainZone, func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := core.CanonicalizeName(q.Name)
		d.mu.Lock()
		d.queries[name+"/"+dns.TypeToString[q.Qtype]]++
		d.mu.Unlock()

		ttl := uint32(60)
		if zeroTTL[name] {
			ttl = 0
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		switch {
		case cnames[name] != "":
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: cnames[name],
			})
		case addrs[name] != nil && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   addrs[name],
			})
		case addrs[name] != nil || name == chainZone:
			m.Ns = append(m.Ns, soa) // NODATA
		default:
			m.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, soa)
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	started := make(chan struct{})
	served := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { served <- srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("auth double did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("auth double shutdown: %v", err)
		}
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("auth double serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("auth double serve goroutine did not exit")
		}
	})
	return d, strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
}

// chainImr is a resolver with no trust anchor that reaches chainZone through a
// stub pointing at the double.
func chainImr(t *testing.T) (*Imr, *chainDouble) {
	t.Helper()
	d, port := startChainDouble(t)
	imr := verdictImr(t, false)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	if err := imr.Cache.AddStub(chainZone, []cache.AuthServer{
		{Name: "ns." + chainZone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	return imr, d
}

// askChain sends <qname, qtype> to the responder and returns what the client
// gets, and how long it took.
func askChain(t *testing.T, imr *Imr, qname string, qtype uint16) (*dns.Msg, time.Duration) {
	t.Helper()
	r, opts := verdictQuery{do: true}.msgFor(qname, qtype)
	cw := &captureWriter{}
	start := time.Now()
	imr.ImrResponder(context.Background(), cw, r, qname, qtype, opts)
	took := time.Since(start)
	if cw.got == nil {
		t.Fatalf("%s %s: responder wrote nothing", qname, dns.TypeToString[qtype])
	}
	return cw.got, took
}

func answerHas(m *dns.Msg, owner string, rrtype uint16) bool {
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == rrtype && core.EqualNames(rr.Header().Name, owner) {
			return true
		}
	}
	return false
}

// A chain that ends in data answers with the data, and the resolver asks the
// auth server for each link once.
func TestCNAMEChainEndingInData(t *testing.T) {
	imr, d := chainImr(t)
	m, _ := askChain(t, imr, "a."+chainZone, dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || !answerHas(m, "c."+chainZone, dns.TypeA) {
		t.Fatalf("a A: rcode %s, answer %v; want NOERROR with c's A", dns.RcodeToString[m.Rcode], m.Answer)
	}
	for _, name := range []string{"a", "b", "c"} {
		if n := d.count(name+"."+chainZone, dns.TypeA); n != 1 {
			t.Errorf("%s.%s A was queried %d times, want 1", name, chainZone, n)
		}
	}
}

// A chain whose last name has no data of the type asked for is NODATA:
// NOERROR, not SERVFAIL. The chase used to ask the last name again until its
// iteration count ran out.
func TestCNAMEChainEndingInNODATA(t *testing.T) {
	imr, d := chainImr(t)
	m, _ := askChain(t, imr, "a."+chainZone, dns.TypeTXT)
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("a TXT: rcode %s, want NOERROR (NODATA at the end of the chain)", dns.RcodeToString[m.Rcode])
	}
	if !answerHas(m, "a."+chainZone, dns.TypeCNAME) {
		t.Errorf("a TXT: answer %v lacks a's CNAME", m.Answer)
	}
	if n := d.count("c."+chainZone, dns.TypeTXT); n != 1 {
		t.Errorf("c.%s TXT was queried %d times, want 1", chainZone, n)
	}
}

// A chain whose last name does not exist is NXDOMAIN, with the CNAME in the
// answer (RFC 6604).
func TestCNAMEChainEndingInNXDOMAIN(t *testing.T) {
	imr, _ := chainImr(t)
	m, _ := askChain(t, imr, "nx."+chainZone, dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("nx A: rcode %s, want NXDOMAIN (the chain's last name does not exist)", dns.RcodeToString[m.Rcode])
	}
	if !answerHas(m, "nx."+chainZone, dns.TypeCNAME) {
		t.Errorf("nx A: answer %v lacks nx's CNAME", m.Answer)
	}
}

// A CNAME loop fails, and fails at once. It used to take the process down:
// every link was answered from the cache, the nested chase never stopped, and
// the stack overflowed.
func TestCNAMELoopFails(t *testing.T) {
	imr, _ := chainImr(t)
	m, took := askChain(t, imr, "loop1."+chainZone, dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("loop1 A: rcode %s, want SERVFAIL", dns.RcodeToString[m.Rcode])
	}
	if took > 2*time.Second {
		t.Errorf("loop1 A took %v: the loop was not detected", took)
	}
}

// At most 11 CNAMEs are followed: a chain of 11 resolves, one of 12 fails.
func TestCNAMEChainLimit(t *testing.T) {
	imr, _ := chainImr(t)
	m, _ := askChain(t, imr, "m0."+chainZone, dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || !answerHas(m, "m11."+chainZone, dns.TypeA) {
		t.Errorf("m0 A (11 CNAMEs): rcode %s, answer %v; want NOERROR with m11's A", dns.RcodeToString[m.Rcode], m.Answer)
	}
	m, _ = askChain(t, imr, "x0."+chainZone, dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("x0 A (12 CNAMEs): rcode %s, want SERVFAIL", dns.RcodeToString[m.Rcode])
	}
}

// The chain on the context belongs to the chase whose last name owns the next
// CNAME. Any other chase nested inside it -- the address of a nameserver met
// while resolving a link -- is a chain of its own: it neither counts toward
// the outer chain's limit nor loops on its names.
func TestCNAMEChainIsPerChase(t *testing.T) {
	ctx := context.WithValue(context.Background(), cnameChainKey{}, []string{"a.test.", "b.test."})

	got, err := extendCNAMEChain(ctx, "B.test.", "c.test.")
	if err != nil || len(got) != 3 || got[2] != "c.test." {
		t.Errorf("continuing from b: chain %v, err %v; want a, b, c", got, err)
	}
	if _, err := extendCNAMEChain(ctx, "b.test.", "A.test."); err == nil {
		t.Error("b -> a: no error, want a loop")
	}
	got, err = extendCNAMEChain(ctx, "ns.other.test.", "a.test.")
	if err != nil || len(got) != 2 || got[0] != "ns.other.test." {
		t.Errorf("an unrelated chase: chain %v, err %v; want a fresh chain ns.other, a", got, err)
	}
}
