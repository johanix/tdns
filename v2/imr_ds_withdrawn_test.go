/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A zone whose DS its parent has withdrawn is Insecure once the DS has expired.
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

// dsWithdrawnServer is an authoritative double for a parent and its child on
// one address, as when one server serves both sides of the cut: it answers
// from a table of responses keyed by "qname qtype", which the test changes.
type dsWithdrawnServer struct {
	mu    sync.Mutex
	table map[string]*dns.Msg
	asked []string
}

func (s *dsWithdrawnServer) set(key string, m *dns.Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.table[key] = m
}

func (s *dsWithdrawnServer) questions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.asked...)
}

func (s *dsWithdrawnServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	key := dns.CanonicalName(q.Name) + " " + dns.TypeToString[q.Qtype]
	s.mu.Lock()
	s.asked = append(s.asked, key)
	tmpl := s.table[key]
	s.mu.Unlock()
	m := new(dns.Msg)
	m.SetReply(r)
	if tmpl == nil {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	m.Authoritative = true
	m.Answer = append(m.Answer, tmpl.Answer...)
	m.Ns = append(m.Ns, tmpl.Ns...)
	_ = w.WriteMsg(m)
}

// The parent withdraws a child's DS, and says so in a signed denial. Once the
// DS has expired from the cache and the child's DNSKEY RRset is fetched again,
// the child is Insecure and its data is no longer validated: the child's Secure
// standing in the ZoneMap does not outlive the DS it rests on. How long that
// takes is up to the DS's TTL, which is the parent's to keep short
// (ttls.max-served; see update_ttl_clamp_test.go).
func TestAWithdrawnDSMakesTheChildInsecure(t *testing.T) {
	const parent, child = "dsw.example.", "kid.dsw.example."
	const owner = "www." + child
	start := time.Now().Truncate(time.Second)
	path := startTestDataClock(t, start)
	from, until := start.Add(-time.Hour), start.Add(7*24*time.Hour)

	pk, ck := newFwdSecKey(t, parent), newFwdSecKey(t, child)
	rr := func(s string) dns.RR { return fwdSecRR(t, s) }
	answer := func(rrs ...dns.RR) *dns.Msg { return &dns.Msg{Answer: rrs} }
	denial := func(rrs ...dns.RR) *dns.Msg { return &dns.Msg{Ns: rrs} }

	ds := ck.dnskey.ToDS(dns.SHA256)
	ds.Hdr.Ttl = 120
	parentSOA := pk.signAt(t, from, until, rr(parent+" 60 IN SOA ns."+parent+" h."+parent+" 2 60 900 604800 60"))
	srv := &dsWithdrawnServer{table: map[string]*dns.Msg{
		parent + " DNSKEY": answer(pk.signAt(t, from, until, dns.Copy(pk.dnskey))...),
		child + " DS":      answer(pk.signAt(t, from, until, ds)...),
		child + " DNSKEY":  answer(ck.signAt(t, from, until, dns.Copy(ck.dnskey))...),
		owner + " TXT":     answer(ck.signAt(t, from, until, rr(owner+` 300 IN TXT "hello"`))...),
	}}

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	dsrv := &dns.Server{PacketConn: pc, Handler: srv}
	started := make(chan struct{})
	dsrv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = dsrv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = dsrv.Shutdown() })
	port := strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)

	imr := newTestImr(t)
	imr.Cache.DnskeyCache = cache.NewDnskeyCache()
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	if err := imr.Cache.AddStub(parent, []cache.AuthServer{
		{Name: "ns." + parent, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.Cache.DnskeyCache.Set(parent, pk.dnskey.KeyTag(), &cache.CachedDnskeyRRset{
		Name: parent, Keyid: pk.dnskey.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure,
		Dnskey: *pk.dnskey, Expiration: cache.Now().Add(30 * 24 * time.Hour)})
	imr.Cache.ZoneMap.Set(parent, &cache.Zone{ZoneName: parent, State: cache.ValidationStateSecure})

	childState := func() string {
		z, ok := imr.Cache.ZoneMap.Get(child)
		if !ok {
			return "none"
		}
		return cache.ValidationStateToString[z.GetState()]
	}
	ask := func(when string) *ImrResponse {
		t.Helper()
		resp, err := imr.ImrQuery(context.Background(), owner, dns.TypeTXT, dns.ClassINET, nil)
		if err != nil {
			t.Fatalf("%s: ImrQuery: %v (asked %v)", when, err, srv.questions())
		}
		return resp
	}

	if resp := ask("with the DS"); !resp.Validated {
		t.Fatalf("with the DS: validated=false (state %s, child %s); want validated. Asked: %v",
			cache.ValidationStateToString[resp.ValidationState], childState(), srv.questions())
	}

	// The parent withdraws the DS: a signed NSEC at the cut, NS and no DS.
	srv.set(child+" DS", denial(append(parentSOA,
		pk.signAt(t, from, until, rr(child+" 60 IN NSEC zzz."+parent+" NS RRSIG NSEC"))...)...))

	// Past the DS's TTL, the DNSKEY RRset's and the TXT's.
	for i, after := range []time.Duration{301 * time.Second, 602 * time.Second, 903 * time.Second} {
		writeFaketimeFile(t, path, start.Add(after))
		resp := ask(fmt.Sprintf("round %d", i))
		if resp.Error || resp.RRset == nil || resp.ValidationState != cache.ValidationStateInsecure {
			t.Errorf("%s after the DS was withdrawn: error=%v (%s), answer=%v, state %s, child %s; want an insecure answer",
				after, resp.Error, resp.ErrorMsg, resp.RRset != nil, cache.ValidationStateToString[resp.ValidationState], childState())
		}
	}
	if st := childState(); st != cache.ValidationStateToString[cache.ValidationStateInsecure] {
		t.Errorf("the child is held %s; want insecure", st)
	}
}
