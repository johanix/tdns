/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

// Copies of the resolver's test helpers (github.com/johanix/tdns/v2/imr) that
// tdns's own tests use: fake upstreams and authoritative servers, signing
// keys, and resolvers built for a test. A test package cannot import another
// test package's helpers. A resolver a root test builds is the daemon's Imr
// around the module's, from exported fields or through NewImr.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	imrcore "github.com/johanix/tdns/v2/imr"
	"github.com/miekg/dns"
)

// From the resolver's dnslookup_prioritize_test.go.
// newTestImr returns a minimal Imr suitable for prioritizeServers tests.
// The cache is populated but no network clients are exercised. FamilyTracker
// uses sensible defaults; tests that need to drive specific suspect/probe
// behaviour replace the field after construction.
func newTestImr(t *testing.T) *Imr {
	t.Helper()
	lg := log.New(os.Stderr, "test", log.LstdFlags)
	c := cache.NewRRsetCache(lg, false, false)
	ft := cache.NewFamilyTracker(
		10*time.Minute, // window
		10*time.Minute, // suspect duration
		30*time.Second, // probe interval
		5,              // failure threshold
	)
	return &Imr{Imr: &imrcore.Imr{Cache: c, FamilyTracker: ft, Options: loopbackTestOptions()}}
}

// loopbackTestOptions sets allow-loopback-nameservers: the test doubles listen
// on 127.0.0.1 and ::1, and many are reached through glue or an address lookup
// rather than a stub. imr_loopback_ns_test.go tests the default.
func loopbackTestOptions() map[ImrOption]string {
	return map[ImrOption]string{ImrOptAllowLoopbackNameservers: "true"}
}

// From the resolver's imr_answer_verdict_test.go.
const verdictName = "www.verdict.example."

// verdictImr is a resolver with its own DNSKEY cache (the default one is
// process-wide), optionally holding a trust anchor.
func verdictImr(t *testing.T, anchored bool) *Imr {
	t.Helper()
	imr := newTestImr(t)
	imr.Cache.DnskeyCache = cache.NewDnskeyCache()
	if anchored {
		imr.Cache.DnskeyCache.Set(".", 1, &cache.CachedDnskeyRRset{Name: ".", Keyid: 1, TrustAnchor: true,
			State: cache.ValidationStateSecure, Expiration: time.Now().Add(time.Hour)})
	}
	return imr
}

type verdictQuery struct{ do, cd, ad bool }

func (q verdictQuery) msg() (*dns.Msg, *edns0.MsgOptions) {
	r := new(dns.Msg)
	r.SetQuestion(verdictName, dns.TypeA)
	r.RecursionDesired = true
	r.AuthenticatedData = q.ad
	r.CheckingDisabled = q.cd
	r.SetEdns0(4096, q.do)
	return r, &edns0.MsgOptions{RD: true, DO: q.do, CD: q.cd}
}

func edeOf(m *dns.Msg) uint16 {
	opt := m.IsEdns0()
	if opt == nil {
		return 0
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok {
			return e.InfoCode
		}
	}
	return 0
}

func (q verdictQuery) msgFor(qname string, qtype uint16) (*dns.Msg, *edns0.MsgOptions) {
	r := new(dns.Msg)
	r.SetQuestion(qname, qtype)
	r.RecursionDesired = true
	r.AuthenticatedData = q.ad
	r.CheckingDisabled = q.cd
	r.SetEdns0(4096, q.do)
	return r, &edns0.MsgOptions{RD: true, DO: q.do, CD: q.cd}
}

// From the resolver's imr_cache_ttl_test.go.
// nearTTL allows the one-second slack that comes from RemainingTTL rounding a
// sub-second remainder down: an entry given 600s and read back a moment later
// legitimately has 599.
func nearTTL(got, want uint32) bool { return got == want || got+1 == want }

// seedAnswer caches a positive answer with `left` of its `ttl`-second lifetime
// still to run, as though it had been fetched (ttl-left) seconds ago.
func seedAnswer(t *testing.T, imr *Imr, rrstr string, left time.Duration) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(rrstr)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	h := rr.Header()
	imr.Cache.Set(h.Name, h.Rrtype, &cache.CachedRRset{
		Name:       h.Name,
		RRtype:     h.Rrtype,
		Rcode:      uint8(dns.RcodeSuccess),
		RRset:      &core.RRset{Name: h.Name, Class: dns.ClassINET, RRtype: h.Rrtype, RRs: []dns.RR{rr}},
		Context:    cache.ContextAnswer,
		State:      cache.ValidationStateSecure,
		Expiration: time.Now().Add(left),
		Transport:  core.TransportDo53,
	})
	return rr
}

// From the resolver's imr_cname_chain.go.
// synthesizeFromDNAME returns the target of the CNAME that a DNAME at owner,
// pointing at target, synthesizes for qname (RFC 6672 §2.2): qname's labels
// below owner, followed by target. qname must be strictly below owner.
func synthesizeFromDNAME(qname, owner, target string) string {
	ql := dns.SplitDomainName(qname)
	prefix := strings.Join(ql[:len(ql)-dns.CountLabel(owner)], ".")
	if t := dns.Fqdn(target); t != "." {
		return prefix + "." + t
	}
	return prefix + "."
}

// From the resolver's imr_cname_chain_answer_test.go.
// The signed zone for the tests below, and an unsigned stub zone on the same
// server:
//
//	s1 -> s2 -> s3 A                 every RRset signed
//	bad -> s3                        the CNAME's RRSIG stripped on the way
//	out -> www.plain.test. A         into an unsigned zone
//	sub  DNAME tgt; www.tgt A        the server synthesizes www.sub -> www.tgt
//	lie  DNAME tgt                   the server's CNAME for www.lie says evil
//	s3 also has a DS, as though it were a delegation, for the DS test;
//	asked for any other type, s3 is NODATA, proved by a signed NSEC
//
// and, for the DS and DNSKEY questions at a CNAME owner (#875):
//
//	top -> the zone's apex, which has its DNSKEY
//	self -> s3                       signed by a key named self, its own owner
//	kid                              a signed child: its DS signed by the
//	                                 parent, its DNSKEY by itself
//	www.kid -> kid                   signed by kid; the response carries kid's
//	                                 own NODATA for kid DS in AUTHORITY, as the
//	                                 servers of a zone answering for its www do
//
// The double counts the questions it is asked.
const (
	sigChainZone = "sigchain.example."
	plainZone    = "plain.test."
)

func startSigChainDouble(t *testing.T, s *zoneSigner) (string, *chainDouble) {
	t.Helper()
	z := sigChainZone
	d := &chainDouble{queries: map[string]int{}}
	s3NSEC := mustRR(t, "s3."+z+" 300 IN NSEC sub."+z+" A RRSIG NSEC")
	soa := mustRR(t, z+" 300 IN SOA ns."+z+" hostmaster."+z+" 1 7200 1800 604800 300")
	plainSOA := mustRR(t, plainZone+" 300 IN SOA ns."+plainZone+" hostmaster."+plainZone+" 1 7200 1800 604800 300")
	cnames := map[string]string{
		"s1." + z:  "s2." + z,
		"s2." + z:  "s3." + z,
		"bad." + z: "s3." + z,
		"out." + z: "www." + plainZone,
		"top." + z: z,
	}
	kid := "kid." + z
	kidSigner := newZoneSigner(t, kid)
	selfSigner := newZoneSigner(t, "self."+z)
	kidDS := kidSigner.key.ToDS(dns.SHA256)
	kidDS.Hdr.Ttl = 300
	kidSOA := mustRR(t, kid+" 300 IN SOA ns."+kid+" hostmaster."+kid+" 1 7200 1800 604800 300")
	kidApexNSEC := mustRR(t, kid+" 300 IN NSEC www."+kid+" NS SOA RRSIG NSEC DNSKEY")
	addrs := map[string]string{
		"s3." + z:      "192.0.2.3",
		"www.tgt." + z: "192.0.2.4",
		"evil." + z:    "192.0.2.66",
	}
	dnames := map[string]string{"sub." + z: "tgt." + z, "lie." + z: "tgt." + z}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		name := core.CanonicalizeName(q.Name)
		d.mu.Lock()
		d.queries[name+"/"+dns.TypeToString[q.Qtype]]++
		d.mu.Unlock()
		var dnameOwner string
		for owner := range dnames {
			if dns.IsSubDomain(owner, name) && name != owner {
				dnameOwner = owner
			}
		}
		switch {
		case dns.IsSubDomain(plainZone, name):
			if name == "www."+plainZone && q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, mustRR(t, q.Name+" 300 IN A 192.0.2.80"))
			} else {
				m.Ns = append(m.Ns, plainSOA)
			}
		case dnameOwner != "":
			dname := mustRR(t, dnameOwner+" 300 IN DNAME "+dnames[dnameOwner])
			target := synthesizeFromDNAME(name, dnameOwner, dnames[dnameOwner])
			if dnameOwner == "lie."+z {
				target = "evil." + z
			}
			m.Answer = append(s.sign(t, dname), mustRR(t, q.Name+" 300 IN CNAME "+target))
		case name == "self."+z:
			m.Answer = selfSigner.sign(t, mustRR(t, q.Name+" 300 IN CNAME s3."+z))
		case name == "www."+kid:
			m.Answer = kidSigner.sign(t, mustRR(t, q.Name+" 300 IN CNAME "+kid))
			if q.Qtype == dns.TypeDS {
				m.Ns = append(kidSigner.sign(t, kidSOA), kidSigner.sign(t, kidApexNSEC)...)
			}
		case name == kid && q.Qtype == dns.TypeDS:
			m.Answer = s.sign(t, kidDS)
		case name == kid && q.Qtype == dns.TypeDNSKEY:
			m.Answer = kidSigner.sign(t, kidSigner.key)
		case name == z && q.Qtype == dns.TypeDNSKEY:
			m.Answer = s.sign(t, s.key)
		case cnames[name] != "":
			cn := mustRR(t, q.Name+" 300 IN CNAME "+cnames[name])
			if name == "bad."+z {
				m.Answer = append(m.Answer, cn)
			} else {
				m.Answer = s.sign(t, cn)
			}
		case name == "s3."+z && q.Qtype == dns.TypeDS:
			m.Answer = s.sign(t, mustRR(t, q.Name+" 300 IN DS 12345 15 2 "+strings.Repeat("AB", 32)))
		case addrs[name] != "" && q.Qtype == dns.TypeA:
			m.Answer = s.sign(t, mustRR(t, q.Name+" 300 IN A "+addrs[name]))
		case name == "s3."+z:
			m.Ns = append(s.sign(t, soa), s.sign(t, s3NSEC)...)
		case q.Qtype == dns.TypeSOA && name == z:
			m.Answer = s.sign(t, soa)
		default:
			m.Ns = s.sign(t, soa)
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1: %v", err)
	}
	started := make(chan struct{})
	served := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
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
	return strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port), d
}

// sigChainImr holds sigChainZone as Secure, under a trust anchor for its key,
// and reaches both zones through stubs pointing at the double, which it
// returns too.
func sigChainImr(t *testing.T) (*Imr, *chainDouble) {
	t.Helper()
	s := newZoneSigner(t, sigChainZone)
	port, d := startSigChainDouble(t, s)
	imr := verdictImr(t, true)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	for _, zone := range []string{sigChainZone, plainZone} {
		if err := imr.Cache.AddStub(zone, []cache.AuthServer{
			{Name: "ns." + zone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
		}); err != nil {
			t.Fatalf("AddStub(%s): %v", zone, err)
		}
	}
	imr.Cache.DnskeyCache.Set(sigChainZone, s.key.KeyTag(), &cache.CachedDnskeyRRset{Name: sigChainZone,
		Keyid: s.key.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure, Dnskey: *s.key, Expiration: time.Now().Add(time.Hour)})
	imr.Cache.ZoneMap.Set(sigChainZone, &cache.Zone{ZoneName: sigChainZone, State: cache.ValidationStateSecure})
	return imr, d
}

// From the resolver's imr_cname_chain_test.go.
type chainDouble struct {
	mu      sync.Mutex
	queries map[string]int // "name/TYPE" -> queries received
}

func (d *chainDouble) count(name string, qtype uint16) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.queries[core.CanonicalizeName(name)+"/"+dns.TypeToString[qtype]]
}

// From the resolver's imr_default_anchor_test.go.
// The IANA root DS records, as an operator would paste them.
const (
	rootDS20326 = ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
	rootDS38696 = ". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
)

func dsKeyTags(dss []*dns.DS) []uint16 {
	tags := make([]uint16, 0, len(dss))
	for _, ds := range dss {
		tags = append(tags, ds.KeyTag)
	}
	slices.Sort(tags)
	return tags
}

// From the resolver's imr_denial_answer_test.go.
// startDenialAuthDouble is an authoritative double for zone on 127.0.0.1 that
// has no data: NXDOMAIN for nxname, NODATA for any other name, both with the
// zone SOA in AUTHORITY, its TTL and MINIMUM both soaTTL. The counter records
// the queries for <qname, qtype>, so the validator's own lookups do not count.
func startDenialAuthDouble(t *testing.T, zone, nxname, qname string, qtype uint16, soaTTL uint32) (int, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1: %v", err)
	}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
		Ns:  "ns." + zone, Mbox: "hostmaster." + zone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: soaTTL,
	}
	var asked atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		if core.EqualNames(q.Name, qname) && q.Qtype == qtype {
			asked.Add(1)
		}
		if core.EqualNames(q.Name, nxname) {
			m.Rcode = dns.RcodeNameError
		}
		m.Ns = append(m.Ns, soa)
		_ = w.WriteMsg(m)
	})
	started := make(chan struct{})
	served := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() { served <- srv.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-served:
		t.Fatalf("denial double failed to serve: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("denial double did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("denial double shutdown: %v", err)
		}
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("denial double stopped serving with: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("denial double: serve goroutine did not exit")
		}
	})
	return pc.LocalAddr().(*net.UDPAddr).Port, &asked
}

// denialTestImr is a resolver that knows zone only as a stub pointing at the
// denial double on 127.0.0.1:port.
func denialTestImr(t *testing.T, zone string, port int) *Imr {
	t.Helper()
	imr := newTestImr(t)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	if err := imr.Cache.AddStub(zone, []cache.AuthServer{
		{Name: "ns." + zone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub(%s): %v", zone, err)
	}
	return imr
}

// From the resolver's imr_forward_first_test.go.
// rootForward is a forward of "." to the upstream at addr:port.
func rootForward(addr string, port uint16) []ImrForwardConf {
	return []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}}
}

// From the resolver's imr_forward_test.go.
type upstreamQuery struct {
	Qname string
	Qtype uint16
	RD    bool
	CD    bool
}

type upstreamLog struct {
	mu      sync.Mutex
	queries []upstreamQuery
}

func (l *upstreamLog) add(q upstreamQuery) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.queries = append(l.queries, q)
}

func (l *upstreamLog) find(qname string, qtype uint16) []upstreamQuery {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []upstreamQuery
	for _, q := range l.queries {
		if q.Qname == qname && q.Qtype == qtype {
			out = append(out, q)
		}
	}
	return out
}

// upstreamAnswer is the behaviour of the resolver double: a validating
// recursive that serves fwd.example. and a fake root. It REFUSES queries
// without RD, answers www.fwd.example. A with AD=1 and
// unsigned.fwd.example. A with AD=0, NXDOMAINs nx.fwd.example. (AD=1),
// answers ". NS" (so root priming works through a forward), and answers
// everything else NODATA+SOA (AD=1 under fwd.example.).
func upstreamAnswer(logr *upstreamLog, r *dns.Msg) *dns.Msg {
	q := r.Question[0]
	logr.add(upstreamQuery{Qname: q.Name, Qtype: q.Qtype, RD: r.RecursionDesired, CD: r.CheckingDisabled})

	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	if !r.RecursionDesired {
		// A forwarded query MUST carry RD; this is what separates
		// forwarding from iteration in these tests.
		m.Rcode = dns.RcodeRefused
		return m
	}

	fwdSOA := &dns.SOA{
		Hdr: dns.RR_Header{Name: "fwd.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns.fwd.example.", Mbox: "hostmaster.fwd.example.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}
	rootSOA := &dns.SOA{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns.fake-root.", Mbox: "hostmaster.fake-root.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}

	switch {
	case q.Name == "www.fwd.example." && q.Qtype == dns.TypeA:
		m.AuthenticatedData = true
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 77),
		})
	case q.Name == "unsigned.fwd.example." && q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 78),
		})
	case q.Name == "nx.fwd.example.":
		m.AuthenticatedData = true
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, fwdSOA)
	case q.Name == "." && q.Qtype == dns.TypeNS:
		m.Answer = append(m.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
			Ns:  "ns.fake-root.",
		})
	default:
		if dns.IsSubDomain("fwd.example.", q.Name) {
			m.AuthenticatedData = true
			m.Ns = append(m.Ns, fwdSOA)
		} else {
			m.Ns = append(m.Ns, rootSOA)
		}
	}
	return m
}

func upstreamDNSHandler(logr *upstreamLog) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(upstreamAnswer(logr, r))
	}
}

func splitHostPort(t *testing.T, hostport string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", hostport, err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, uint16(port)
}

// startTestUpstream starts the double on 127.0.0.1 UDP.
func startTestUpstream(t *testing.T) (string, uint16, *upstreamLog, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := splitHostPort(t, pc.LocalAddr().String())

	logr := &upstreamLog{}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: upstreamDNSHandler(logr), NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test upstream did not start")
	}
	return host, port, logr, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	}
}

// newUpstreamTestCert makes a self-signed certificate for
// "dns.test.example" and 127.0.0.1, and a pool trusting it.
func newUpstreamTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dns.test.example"},
		DNSNames:              []string{"dns.test.example"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// From the resolver's imr_forward_validation_test.go.
// A forwarding IMR that validates for itself (no trust-ad) sees no referrals:
// the DS of a zone is asked for on its own, by the validator, and a zone the
// parent delegates without a DS is known only by the parent's denial of it.
// These tests run that through the IMR's own forwarding, validation and
// responder, against a double of a validating recursive upstream that serves
// sec.example., signed, which the IMR holds a trust anchor for, and
// kid.sec.example., signed, delegated from it with or without a DS.
const (
	fwdSecParent = "sec.example."
	fwdSecKid    = "kid.sec.example."
	fwdSecWWW    = "www.kid.sec.example."
)

type fwdSecKey struct {
	dnskey *dns.DNSKEY
	priv   crypto.Signer
}

func newFwdSecKey(t *testing.T, zone string) *fwdSecKey {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	p, err := generateSigningKey(k, 256)
	if err != nil {
		t.Fatal(err)
	}
	return &fwdSecKey{dnskey: k, priv: p.(crypto.Signer)}
}

// sign returns rrs followed by their RRSIG, as a message section carries them.
func (k *fwdSecKey) sign(t *testing.T, rrs ...dns.RR) []dns.RR {
	t.Helper()
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Ttl: rrs[0].Header().Ttl}, Algorithm: dns.ED25519, KeyTag: k.dnskey.KeyTag(), SignerName: k.dnskey.Hdr.Name,
		Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(k.priv, rrs); err != nil {
		t.Fatal(err)
	}
	return append(append([]dns.RR{}, rrs...), sig)
}

func fwdSecRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

// startSignedForwardUpstream serves the answers in sections, keyed by
// "qname qtype", with RA set and the answer's rcode, and SERVFAIL to anything
// else. The records are
// built before the server starts: the handler runs outside the test goroutine.
func startSignedForwardUpstream(t *testing.T, answers map[string]*dns.Msg) (string, uint16) {
	t.Helper()
	return startLoggedSignedForwardUpstream(t, answers, nil)
}

// startLoggedSignedForwardUpstream is startSignedForwardUpstream that also
// records every question it is asked in logr, when logr is not nil.
func startLoggedSignedForwardUpstream(t *testing.T, answers map[string]*dns.Msg, logr *upstreamLog) (string, uint16) {
	t.Helper()
	h := func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if logr != nil {
			logr.add(upstreamQuery{Qname: q.Name, Qtype: q.Qtype, RD: r.RecursionDesired, CD: r.CheckingDisabled})
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		if a, ok := answers[strings.ToLower(q.Name)+" "+dns.TypeToString[q.Qtype]]; ok {
			m.Answer, m.Ns, m.Rcode = a.Answer, a.Ns, a.Rcode
		} else {
			m.Rcode = dns.RcodeServerFailure
		}
		_ = w.WriteMsg(m)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := splitHostPort(t, pc.LocalAddr().String())
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(h), NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test upstream did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	return host, port
}

// From the resolver's imr_forwarded_root_test.go.
// startGatedSignedForwardUpstream is startSignedForwardUpstream that answers
// only while open is set, and otherwise drops the query: an upstream that is
// down, and comes back.
func startGatedSignedForwardUpstream(t *testing.T, answers map[string]*dns.Msg, open *atomic.Bool) (string, uint16) {
	t.Helper()
	h := func(w dns.ResponseWriter, r *dns.Msg) {
		if !open.Load() {
			return
		}
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		if a, ok := answers[strings.ToLower(q.Name)+" "+dns.TypeToString[q.Qtype]]; ok {
			m.Answer, m.Ns = a.Answer, a.Ns
		} else {
			m.Rcode = dns.RcodeServerFailure
		}
		_ = w.WriteMsg(m)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := splitHostPort(t, pc.LocalAddr().String())
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(h), NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test upstream did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	return host, port
}

// From the resolver's imr_nsec3_test.go.
// n3RR is an NSEC3 in zone, with no salt and iterations, matching name, or,
// with cover, covering it with an interval that holds its hash and no other.
func n3RR(zone, name string, cover bool, flags uint8, iterations uint16, types ...uint16) *dns.NSEC3 {
	h := dns.HashName(name, dns.SHA1, iterations, "")
	owner := h
	if cover {
		owner = refHashStep(h, -1)
	}
	return &dns.NSEC3{Hdr: dns.RR_Header{Name: owner + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash: dns.SHA1, Flags: flags, Iterations: iterations, HashLength: 20, NextDomain: refHashStep(h, 1), TypeBitMap: types}
}

func countType(rrs []dns.RR, t uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			n++
		}
	}
	return n
}

// From the resolver's imr_referral_ds_proof_test.go.
const refHashDigits = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

// refHashStep is the base32hex hash one step after h, or before it for a
// negative step.
func refHashStep(h string, step int) string {
	b := []byte(h)
	for i := len(b) - 1; i >= 0; i-- {
		switch j := strings.IndexByte(refHashDigits, b[i]) + step; {
		case j >= len(refHashDigits):
			b[i] = refHashDigits[0]
		case j < 0:
			b[i] = refHashDigits[len(refHashDigits)-1]
		default:
			b[i] = refHashDigits[j]
			return string(b)
		}
	}
	return string(b)
}

// From the resolver's imr_reload_test.go.
func fwdConf(zone, addr string, port uint16) ImrForwardConf {
	return ImrForwardConf{
		Zone:      zone,
		Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}},
	}
}

func stubConf(zone, ns, addr string) ImrStubConf {
	return ImrStubConf{
		Zone:    zone,
		Servers: []cache.AuthServer{{Name: ns, Addrs: []string{addr}, Alpn: []string{"do53"}}},
	}
}

// From the resolver's imr_stripped_rrsig_test.go.
// zoneSigner signs with a key the resolver holds as Secure for its zone, so what
// it signs validates for real.
type zoneSigner struct {
	zone string
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newZoneSigner(t *testing.T, zone string) *zoneSigner {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 256, Protocol: 3, Algorithm: dns.ED25519}
	p, err := generateSigningKey(k, 256)
	if err != nil {
		t.Fatal(err)
	}
	return &zoneSigner{zone: zone, key: k, priv: p.(crypto.Signer)}
}

// sign returns rrs followed by their RRSIG.
func (s *zoneSigner) sign(t *testing.T, rrs ...dns.RR) []dns.RR {
	t.Helper()
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Ttl: rrs[0].Header().Ttl}, Algorithm: dns.ED25519, KeyTag: s.key.KeyTag(), SignerName: s.zone,
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(s.priv, rrs); err != nil {
		t.Fatal(err)
	}
	return append(append([]dns.RR{}, rrs...), sig)
}

// From the resolver's imr_stub_resolution_test.go.
// startStubAuthServer is an authoritative-server double for stub-zone tests:
// AA=1 answers for SOA/NS/A, REFUSED for DS (a child-auth server does not hold
// its own DS), NODATA for everything else.
func startStubAuthServer(t *testing.T, zone string) (string, string, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(pc.LocalAddr().String())

	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns." + zone, Mbox: "hostmaster." + zone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeDS:
			m.Rcode = dns.RcodeRefused
		case dns.TypeSOA:
			m.Answer = append(m.Answer, soa)
		case dns.TypeNS:
			m.Answer = append(m.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  "ns." + zone,
			})
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 55),
			})
		default:
			m.Ns = append(m.Ns, soa)
		}
		_ = w.WriteMsg(m)
	})

	started := make(chan struct{})
	served := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { served <- srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("stub auth double did not start")
	}
	return host, port, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("stub auth double shutdown: %v", err)
		}
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Error("stub auth double serve goroutine did not exit")
		}
	}
}

// From the resolver's imr_wildcard_answer_test.go.
// rrSigner signs records for a zone, returning them followed by their RRSIG.
type rrSigner interface {
	sign(t *testing.T, rrs ...dns.RR) []dns.RR
}

// wildcardSigned signs the record in text, owned by a wildcard, then serves it
// and its RRSIG owned by owner: an answer synthesized from the wildcard.
func wildcardSigned(t *testing.T, s rrSigner, text, owner string) []dns.RR {
	t.Helper()
	rrs := s.sign(t, fwdSecRR(t, text))
	for _, rr := range rrs {
		rr.Header().Name = owner
	}
	return rrs
}

// askWith asks imr for qname and qtype, with DO as given.
func askWith(t *testing.T, imr *Imr, qname string, qtype uint16, do bool) *dns.Msg {
	t.Helper()
	r, opts := verdictQuery{do: do}.msgFor(qname, qtype)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, qtype, opts)
	if cw.got == nil {
		t.Fatalf("%s %s: responder wrote nothing", qname, dns.TypeToString[qtype])
	}
	return cw.got
}

// From the resolver's oots_endpoints_test.go.
const dotTarget = "dot-ns." + stateZone

// From the resolver's oots_resolver_test.go.
const pathNS = "ns.kid.p.test."

const pathOwner = "_dns." + pathNS

// signalOnEachPath runs one nameserver's SVCB RRs through each path a signal
// arrives by and returns the server each path left behind: the Additional
// section of a response from that server, the Additional section of a
// referral, and an answer to a direct query for the _dns name.
func signalOnEachPath(t *testing.T, texts []string) map[string]*cache.AuthServer {
	t.Helper()
	rrs := func() []dns.RR {
		out := make([]dns.RR, len(texts))
		for i, text := range texts {
			out[i] = mustRR(t, text)
		}
		return out
	}
	ctx := context.Background()
	out := map[string]*cache.AuthServer{}

	imr := newTestImr(t)
	server := cache.NewAuthServer(pathNS)
	r := new(dns.Msg)
	r.SetQuestion("www.kid.p.test.", dns.TypeA)
	r.Extra = rrs()
	imr.TransportSignalFromAdditional(ctx, server, r)
	out["additional"] = server

	imr = newTestImr(t)
	ref := new(dns.Msg)
	ref.SetQuestion("www.kid.p.test.", dns.TypeA)
	ref.Response = true
	ref.Ns = []dns.RR{mustRR(t, "kid.p.test. 3600 IN NS "+pathNS)}
	ref.Extra = rrs()
	nsrrset := &core.RRset{Name: "kid.p.test.", Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: ref.Ns}
	if _, err := imr.ParseAdditionalForNSAddrs(ctx, "authority", nsrrset, "kid.p.test.", "p.test.",
		map[string]bool{pathNS: true}, ref); err != nil {
		t.Fatalf("ParseAdditionalForNSAddrs: %v", err)
	}
	out["referral"] = imr.Cache.GetOrCreateAuthServer(pathNS)

	imr = newTestImr(t)
	server = cache.NewAuthServer(pathNS)
	imr.Cache.ServerMap.Set("kid.p.test.", map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})
	imr.TransportSignalFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB, RRs: rrs()},
		cache.ValidationStateIndeterminate)
	out["answer"] = server
	return out
}

// signalSnapshot renders what a server took from its signal: the source, the
// weights as received and the dial ports, by oots token (do53 read as udp and
// tcp). "none" when it has no signal.
func signalSnapshot(server *cache.AuthServer) string {
	rec := server.GetReceivedSignal()
	if rec == nil {
		return "none"
	}
	var w, p []string
	for tr, v := range rec.Weights {
		w = append(w, fmt.Sprintf("%s:%d", core.TransportToSignalToken[tr], v))
	}
	for tr, v := range server.GetTransportPorts() {
		p = append(p, fmt.Sprintf("%s:%d", core.TransportToSignalToken[tr], v))
	}
	sort.Strings(w)
	sort.Strings(p)
	return fmt.Sprintf("%s w=%s p=%s", rec.Source, strings.Join(w, ","), strings.Join(p, ","))
}

// checkEveryPathBothOrders runs the RRs in the order given and reversed, on
// each path, and wants the same snapshot every time.
func checkEveryPathBothOrders(t *testing.T, texts []string, want string) {
	t.Helper()
	reversed := slices.Clone(texts)
	slices.Reverse(reversed)
	for _, order := range [][]string{texts, reversed} {
		for path, server := range signalOnEachPath(t, order) {
			if got := signalSnapshot(server); got != want {
				t.Errorf("%s path, order %q:\n got  %s\n want %s", path, order, got, want)
			}
		}
	}
}

// From the resolver's oots_signal_filter_test.go.
// signalState is what selection holds for a server after a signal: the set of
// transports, their weights, and the signal as received. Transports are
// sorted: applyTransportMapToServer builds them from a map.
type signalState struct {
	Transports []core.Transport
	Weights    map[core.Transport]uint8
	Received   map[core.Transport]uint8
	Source     string
}

func stateOf(s *cache.AuthServer) signalState {
	ts, ws := s.GetTransportSignal()
	ts = append([]core.Transport(nil), ts...)
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	st := signalState{Transports: ts, Weights: ws}
	if r := s.GetReceivedSignal(); r != nil {
		st.Received, st.Source = r.Weights, r.Source
	}
	return st
}

// assertTCPNotChosen fails when Do53TCP is among the transports selection
// draws from. A tcp weight may be held, as a cap, but tdns never chooses
// optional TCP.
func assertTCPNotChosen(t *testing.T, label string, st signalState) {
	t.Helper()
	for _, tr := range st.Transports {
		if tr == core.TransportDo53TCP {
			t.Errorf("%s: transports %v hold Do53TCP", label, st.Transports)
		}
	}
}

// From the resolver's oots_signal_state_test.go.
const (
	stateZone     = "kid.p.test."
	providerZone  = "provider.example."
	providerOwner = "_dns.ns." + providerZone
)
