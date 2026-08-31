/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// The forward form documented in cmdv2/imr/tdns-imr.sample.yaml must decode,
// including the hyphenated keys.
func TestImrForwardConfigDecodes(t *testing.T) {
	const documented = `
forward:
   - zone: foo.bar.
     upstreams:
        - addr:      192.0.2.1
          port:      8853
          transport: doq
          tls-server-name: dns.example.com
   - zone: company.com.
     trust-ad: true
     upstreams:
        - addr:      192.0.2.2
          transport: dot
          tls-server-name: resolver.company.com
   - zone: lab.example.
     upstreams:
        - addr:      192.0.2.4
          transport: tcp
        - addr:      2001:db8::53
          transport: dot
          insecure:  true
   - zone: .
     upstreams:
        - addr: 192.0.2.3
`
	var conf struct {
		Forward []ImrForwardConf `yaml:"forward"`
	}
	if err := yaml.Unmarshal([]byte(documented), &conf); err != nil {
		t.Fatalf("the documented forward form does not decode: %v", err)
	}
	if len(conf.Forward) != 4 {
		t.Fatalf("want 4 forward zones, got %d", len(conf.Forward))
	}
	f0 := conf.Forward[0]
	if f0.Zone != "foo.bar." || f0.TrustAD {
		t.Errorf("forward[0] = %+v", f0)
	}
	if f0.Upstreams[0].Port != 8853 || f0.Upstreams[0].Transport != "doq" ||
		f0.Upstreams[0].TLSServerName != "dns.example.com" {
		t.Errorf("forward[0].upstreams[0] = %+v", f0.Upstreams[0])
	}
	f1 := conf.Forward[1]
	if !f1.TrustAD || len(f1.Upstreams) != 1 || f1.Upstreams[0].TLSServerName != "resolver.company.com" {
		t.Errorf("forward[1] = %+v", f1)
	}
	f2 := conf.Forward[2]
	if f2.TrustAD || len(f2.Upstreams) != 2 || !f2.Upstreams[1].Insecure {
		t.Errorf("forward[2] = %+v", f2)
	}
}

func TestBuildImrForwardsDefaultsAndOrder(t *testing.T) {
	forwards, err := BuildImrForwards([]ImrForwardConf{
		{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.3"}}},
		{Zone: "Foo.Bar", Upstreams: []ImrUpstreamConf{
			{Addr: "192.0.2.1", Transport: "doq"},
			{Addr: "192.0.2.4", Transport: "doh"},
			{Addr: "192.0.2.5", Transport: "udp"},
			{Addr: "192.0.2.6", Transport: "tcp"},
		}},
		{Zone: "bar.", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.2", Transport: "dot", Port: 8853}}},
	})
	if err != nil {
		t.Fatalf("BuildImrForwards: %v", err)
	}
	// Most-specific first: foo.bar. (2 labels), bar. (1), . (0).
	if forwards[0].Zone != "foo.bar." || forwards[1].Zone != "bar." || forwards[2].Zone != "." {
		t.Fatalf("order = %s, %s, %s", forwards[0].Zone, forwards[1].Zone, forwards[2].Zone)
	}
	// Default ports per transport, configured port wins.
	wantPorts := []struct {
		up   *ForwardUpstream
		port string
		xp   core.Transport
	}{
		{forwards[2].Upstreams[0], "53", core.TransportDo53},
		{forwards[0].Upstreams[0], "853", core.TransportDoQ},
		{forwards[0].Upstreams[1], "443", core.TransportDoH},
		{forwards[0].Upstreams[2], "53", core.TransportDo53},
		{forwards[0].Upstreams[3], "53", core.TransportDo53TCP},
		{forwards[1].Upstreams[0], "8853", core.TransportDoT},
	}
	for i, w := range wantPorts {
		if w.up.Port != w.port || w.up.Transport != w.xp {
			t.Errorf("upstream %d: port=%s transport=%s, want %s/%s",
				i, w.up.Port, core.TransportToString[w.up.Transport], w.port, core.TransportToString[w.xp])
		}
	}

	// trust-ad demands an authenticated channel and must be accepted on one.
	if _, err := BuildImrForwards([]ImrForwardConf{
		{Zone: "ok.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{
			{Addr: "192.0.2.1", Transport: "dot", TLSServerName: "dns.example.com"},
			{Addr: "192.0.2.2", Transport: "doq"},
		}},
	}); err != nil {
		t.Errorf("trust-ad with verified encrypted upstreams rejected: %v", err)
	}

	bad := []struct {
		name string
		conf []ImrForwardConf
	}{
		{"hostname addr", []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: "dns.example.com"}}}}},
		{"unknown transport", []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1", Transport: "smtp"}}}}},
		{"tls options on do53", []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1", TLSServerName: "x.example."}}}}},
		{"duplicate zone", []ImrForwardConf{
			{Zone: "foo.bar.", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1"}}},
			{Zone: "Foo.bar", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.2"}}},
		}},
		{"no upstreams", []ImrForwardConf{{Zone: "foo.bar."}}},
		{"no zone", []ImrForwardConf{{Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1"}}}}},
		// A spoofable AD bit must not be a Secure-cache oracle: trust-ad
		// over plaintext or unverified TLS is refused at build time.
		{"trust-ad on do53", []ImrForwardConf{{Zone: ".", TrustAD: true, Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1"}}}}},
		{"trust-ad on tcp", []ImrForwardConf{{Zone: ".", TrustAD: true, Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1", Transport: "tcp"}}}}},
		{"trust-ad with insecure dot", []ImrForwardConf{{Zone: ".", TrustAD: true, Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1", Transport: "dot", Insecure: true}}}}},
		{"trust-ad with one plaintext upstream", []ImrForwardConf{{Zone: ".", TrustAD: true, Upstreams: []ImrUpstreamConf{
			{Addr: "192.0.2.1", Transport: "dot"},
			{Addr: "192.0.2.2"},
		}}}},
	}
	for _, b := range bad {
		if _, err := BuildImrForwards(b.conf); err == nil {
			t.Errorf("%s: config accepted, want error", b.name)
		}
	}
}

// The TLS settings of an encrypted upstream must reach the DNS client.
func TestForwardUpstreamTLSConfig(t *testing.T) {
	forwards, err := BuildImrForwards([]ImrForwardConf{
		{Zone: "a.example.", Upstreams: []ImrUpstreamConf{
			{Addr: "192.0.2.1", Transport: "doq", TLSServerName: "dns.example.com"},
			{Addr: "192.0.2.2", Transport: "dot", Insecure: true},
		}},
	})
	if err != nil {
		t.Fatalf("BuildImrForwards: %v", err)
	}
	doq := forwards[0].Upstreams[0].Client.(*core.DNSClient)
	if doq.TLSConfig.ServerName != "dns.example.com" {
		t.Errorf("doq ServerName = %q", doq.TLSConfig.ServerName)
	}
	if doq.TLSConfig.InsecureSkipVerify {
		t.Error("doq upstream must verify by default")
	}
	if doq.TLSConfig.MinVersion < tls.VersionTLS13 {
		t.Errorf("doq MinVersion = %x, want TLS 1.3", doq.TLSConfig.MinVersion)
	}
	if len(doq.TLSConfig.NextProtos) != 1 || doq.TLSConfig.NextProtos[0] != "doq" {
		t.Errorf("doq NextProtos = %v", doq.TLSConfig.NextProtos)
	}
	dot := forwards[0].Upstreams[1].Client.(*core.DNSClient)
	if !dot.TLSConfig.InsecureSkipVerify {
		t.Error("insecure: true did not reach the DoT client")
	}
}

func TestForwardZoneFor(t *testing.T) {
	forwards, err := BuildImrForwards([]ImrForwardConf{
		{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1"}}},
		{Zone: "sub.foo.bar.", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.2"}}},
		{Zone: "foo.bar.", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.3"}}},
	})
	if err != nil {
		t.Fatalf("BuildImrForwards: %v", err)
	}
	// foo.bar. is deliberately BOTH a stub and a forward zone: equal
	// specificity means the forward wins — a stub overrides only when it is
	// strictly more specific.
	imr := &Imr{Forwards: forwards, stubZones: []string{"internal.example.", "deep.sub.foo.bar.", "foo.bar."}}

	cases := []struct {
		qname string
		want  string // matched forward zone, "" for iterate
	}{
		{"www.example.com.", "."},          // root forward catches everything...
		{"WWW.Foo.Bar.", "foo.bar."},       // ...unless something more specific matches (case-insensitively)
		{"foo.bar.", "foo.bar."},           // same-zone stub + forward: forward wins
		{"x.sub.foo.bar.", "sub.foo.bar."}, // longest forward match wins
		{"host.internal.example.", ""},     // stub more specific than "." wins
		{"a.deep.sub.foo.bar.", ""},        // stub more specific than sub.foo.bar. wins
		{"internal.example.", ""},          // the stub apex itself
	}
	for _, c := range cases {
		fz := imr.forwardZoneFor(c.qname)
		got := ""
		if fz != nil {
			got = fz.Zone
		}
		if got != c.want {
			t.Errorf("forwardZoneFor(%q) = %q, want %q", c.qname, got, c.want)
		}
	}

	// Without forward zones, no allocation-visible work and no match.
	if fz := (&Imr{}).forwardZoneFor("www.example.com."); fz != nil {
		t.Errorf("empty forward table matched %s", fz.Zone)
	}
}

// ----- upstream resolver double, shared by the Do53/DoT/DoH/DoQ servers -----

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

// trustUpstreamCert points every encrypted upstream client of fz at the test
// pool, keeping certificate verification ON — this is the test's stand-in
// for the host trust store, not a verification bypass.
func trustUpstreamCert(t *testing.T, fz *ForwardZone, pool *x509.CertPool) {
	t.Helper()
	for _, up := range fz.Upstreams {
		if c, ok := up.Client.(*core.DNSClient); ok && c.TLSConfig != nil {
			c.TLSConfig.RootCAs = pool
		}
	}
}

// startTestUpstreamDoT starts the double behind a TLS listener.
func startTestUpstreamDoT(t *testing.T, cert tls.Certificate) (string, uint16, *upstreamLog, func()) {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	host, port := splitHostPort(t, l.Addr().String())

	logr := &upstreamLog{}
	started := make(chan struct{})
	srv := &dns.Server{Listener: l, Handler: upstreamDNSHandler(logr), NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("DoT upstream double did not start")
	}
	return host, port, logr, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	}
}

// startTestUpstreamDoH starts the double behind an HTTPS /dns-query endpoint.
// No ready-wait is needed: tls.Listen has already bound and is accepting (the
// kernel backlog queues connections until Serve picks them up); http.Server
// offers no NotifyStartedFunc equivalent. The DoQ double is in the same
// position with quic.ListenAddr.
func startTestUpstreamDoH(t *testing.T, cert tls.Certificate) (string, uint16, *upstreamLog, func()) {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	host, port := splitHostPort(t, l.Addr().String())

	logr := &upstreamLog{}
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "unpack", http.StatusBadRequest)
			return
		}
		packed, err := upstreamAnswer(logr, q).Pack()
		if err != nil {
			http.Error(w, "pack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	return host, port, logr, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// startTestUpstreamDoQ starts the double behind a DoQ (RFC 9250) listener.
func startTestUpstreamDoQ(t *testing.T, cert tls.Certificate) (string, uint16, *upstreamLog, func()) {
	t.Helper()
	l, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
		MinVersion:   tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	host, port := splitHostPort(t, l.Addr().String())

	logr := &upstreamLog{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := l.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() {
						defer stream.Close()
						var lenBuf [2]byte
						if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
							return
						}
						buf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
						if _, err := io.ReadFull(stream, buf); err != nil {
							return
						}
						q := new(dns.Msg)
						if err := q.Unpack(buf); err != nil {
							return
						}
						packed, err := upstreamAnswer(logr, q).Pack()
						if err != nil {
							return
						}
						binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))
						_, _ = stream.Write(lenBuf[:])
						_, _ = stream.Write(packed)
					}()
				}
			}()
		}
	}()
	return host, port, logr, func() {
		cancel()
		_ = l.Close()
	}
}

func newForwardTestImr(t *testing.T, conf []ImrForwardConf) *Imr {
	t.Helper()
	forwards, err := BuildImrForwards(conf)
	if err != nil {
		t.Fatalf("BuildImrForwards: %v", err)
	}
	lg := log.New(os.Stderr, "test", log.LstdFlags)
	return &Imr{
		Cache:    cache.NewRRsetCache(lg, false, false),
		Quiet:    true,
		Forwards: forwards,
	}
}

// ----- end-to-end tests -----

// trust-ad over DoT with real certificate verification: the query must reach
// the upstream with RD=1 and CD=0, the upstream's AD bit must map onto the
// cache validation state for positives AND negatives, and AD=0 must map to
// Insecure. Also the DoT wire e2e.
func TestForwardQueryTrustAD(t *testing.T) {
	cert, pool := newUpstreamTestCert(t)
	addr, port, logr, stop := startTestUpstreamDoT(t, cert)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{
			{Addr: addr, Port: port, Transport: "dot", TLSServerName: "dns.test.example"},
		}},
	})
	trustUpstreamCert(t, imr.Forwards[0], pool)
	ctx := context.Background()

	// Positive answer, via the real entry point so the forward hook in
	// IterativeDNSQueryWithLoopDetection is exercised, not forwardQuery
	// directly. The empty serverMap must be irrelevant.
	rrset, rcode, cctx, transport, err := imr.IterativeDNSQuery(ctx, "www.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("forwarded query over DoT: %v", err)
	}
	if rcode != dns.RcodeSuccess || cctx != cache.ContextAnswer || len(rrset.RRs) != 1 {
		t.Fatalf("rcode=%d context=%s rrs=%v", rcode, cache.CacheContextToString[cctx], rrset)
	}
	if transport != core.TransportDoT {
		t.Errorf("transport = %s", core.TransportToString[transport])
	}
	if a, ok := rrset.RRs[0].(*dns.A); !ok || a.A.String() != "192.0.2.77" {
		t.Errorf("answer = %v", rrset.RRs[0])
	}
	seen := logr.find("www.fwd.example.", dns.TypeA)
	if len(seen) == 0 {
		t.Fatal("upstream never saw the query")
	}
	if !seen[0].RD || seen[0].CD {
		t.Errorf("trust-ad query on the wire: RD=%v CD=%v, want RD=true CD=false", seen[0].RD, seen[0].CD)
	}
	crrset := imr.Cache.Get("www.fwd.example.", dns.TypeA)
	if crrset == nil || crrset.State != cache.ValidationStateSecure {
		t.Fatalf("trust-ad with upstream AD=1: cached = %+v, want state secure", crrset)
	}

	// AD=0 from the upstream must map to Insecure, never borrow Secure.
	if _, _, _, _, err := imr.IterativeDNSQuery(ctx, "unsigned.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false); err != nil {
		t.Fatalf("AD=0 query: %v", err)
	}
	if crrset := imr.Cache.Get("unsigned.fwd.example.", dns.TypeA); crrset == nil || crrset.State != cache.ValidationStateInsecure {
		t.Errorf("trust-ad with upstream AD=0: cached = %+v, want state insecure", crrset)
	}

	// Negatives: the upstream authenticated the denial (AD=1), so the
	// cached negative must be Secure too — trust-ad is not positives-only.
	rrset, rcode, cctx, _, err = imr.IterativeDNSQuery(ctx, "nx.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("forwarded NXDOMAIN query: %v", err)
	}
	if rrset != nil || rcode != dns.RcodeNameError || cctx != cache.ContextNXDOMAIN {
		t.Fatalf("NXDOMAIN: rrset=%v rcode=%d context=%s", rrset, rcode, cache.CacheContextToString[cctx])
	}
	if crrset := imr.Cache.Get("nx.fwd.example.", dns.TypeA); crrset == nil || crrset.State != cache.ValidationStateSecure {
		t.Errorf("trust-ad NXDOMAIN with upstream AD=1: cached = %+v, want state secure", crrset)
	}

	rrset, rcode, cctx, _, err = imr.IterativeDNSQuery(ctx, "www.fwd.example.", dns.TypeMX, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("forwarded NODATA query: %v", err)
	}
	if rrset != nil || rcode != dns.RcodeSuccess || cctx != cache.ContextNoErrNoAns {
		t.Fatalf("NODATA: rrset=%v rcode=%d context=%s", rrset, rcode, cache.CacheContextToString[cctx])
	}
	if crrset := imr.Cache.Get("www.fwd.example.", dns.TypeMX); crrset == nil || crrset.State != cache.ValidationStateSecure {
		t.Errorf("trust-ad NODATA with upstream AD=1: cached = %+v, want state secure", crrset)
	}
}

// Without trust-ad, a forwarded answer goes through the normal local
// validation path: the query must carry CD=1 on the wire (local validation
// must see data the upstream's validator would filter), and neither the
// positive nor the negative cache entry may borrow the upstream's AD bit.
func TestForwardQueryValidatesLocally(t *testing.T) {
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}},
	})
	ctx := context.Background()

	rrset, rcode, cctx, _, err := imr.IterativeDNSQuery(ctx, "www.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("forwarded query: %v", err)
	}
	if rcode != dns.RcodeSuccess || cctx != cache.ContextAnswer || rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("rcode=%d context=%s rrset=%v", rcode, cache.CacheContextToString[cctx], rrset)
	}
	seen := logr.find("www.fwd.example.", dns.TypeA)
	if len(seen) == 0 {
		t.Fatal("upstream never saw the query")
	}
	if !seen[0].RD || !seen[0].CD {
		t.Errorf("local-validation query on the wire: RD=%v CD=%v, want RD=true CD=true", seen[0].RD, seen[0].CD)
	}
	crrset := imr.Cache.Get("www.fwd.example.", dns.TypeA)
	if crrset == nil {
		t.Fatal("answer not cached")
	}
	if crrset.State == cache.ValidationStateSecure {
		t.Error("unsigned forwarded answer cached as secure: the upstream AD bit leaked through without trust-ad")
	}

	// The upstream marks its NODATA AD=1 too; without trust-ad that must
	// not become a Secure negative.
	if _, _, _, _, err := imr.IterativeDNSQuery(ctx, "www.fwd.example.", dns.TypeMX, map[string]*cache.AuthServer{}, false, false); err != nil {
		t.Fatalf("forwarded NODATA query: %v", err)
	}
	if crrset := imr.Cache.Get("www.fwd.example.", dns.TypeMX); crrset != nil && crrset.State == cache.ValidationStateSecure {
		t.Error("negative cached as secure from the upstream AD bit without trust-ad")
	}
}

// Forwarding over DoH: the wire is HTTPS POST /dns-query with certificate
// verification against the upstream's IP SAN.
func TestForwardQueryDoH(t *testing.T) {
	cert, pool := newUpstreamTestCert(t)
	addr, port, logr, stop := startTestUpstreamDoH(t, cert)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{
			{Addr: addr, Port: port, Transport: "doh"},
		}},
	})
	trustUpstreamCert(t, imr.Forwards[0], pool)

	rrset, rcode, _, transport, err := imr.IterativeDNSQuery(context.Background(), "www.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("forwarded query over DoH: %v", err)
	}
	if rcode != dns.RcodeSuccess || rrset == nil || len(rrset.RRs) != 1 || transport != core.TransportDoH {
		t.Fatalf("DoH: rcode=%d transport=%s rrset=%v", rcode, core.TransportToString[transport], rrset)
	}
	if len(logr.find("www.fwd.example.", dns.TypeA)) == 0 {
		t.Fatal("DoH upstream never saw the query")
	}
}

// Forwarding over DoQ (RFC 9250): TLS 1.3, ALPN "doq", certificate verified
// against the configured tls-server-name.
func TestForwardQueryDoQ(t *testing.T) {
	cert, pool := newUpstreamTestCert(t)
	addr, port, logr, stop := startTestUpstreamDoQ(t, cert)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{
			{Addr: addr, Port: port, Transport: "doq", TLSServerName: "dns.test.example"},
		}},
	})
	trustUpstreamCert(t, imr.Forwards[0], pool)

	rrset, rcode, _, transport, err := imr.IterativeDNSQuery(context.Background(), "www.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("forwarded query over DoQ: %v", err)
	}
	if rcode != dns.RcodeSuccess || rrset == nil || len(rrset.RRs) != 1 || transport != core.TransportDoQ {
		t.Fatalf("DoQ: rcode=%d transport=%s rrset=%v", rcode, core.TransportToString[transport], rrset)
	}
	if len(logr.find("www.fwd.example.", dns.TypeA)) == 0 {
		t.Fatal("DoQ upstream never saw the query")
	}
}

// A dead first upstream must not take the query down: the second upstream
// answers. And when every upstream is dead, the query must fail with an error
// naming the forward zone (forward-only, no fallback to iteration).
func TestForwardQueryFailover(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	// 192.0.2.9 is TEST-NET: nothing answers. Use a sub-second timeout so
	// the failover test doesn't sit out the full 5s default.
	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{
			{Addr: "192.0.2.9", Port: 1},
			{Addr: addr, Port: port},
		}},
	})
	for _, up := range imr.Forwards[0].Upstreams {
		c := up.Client.(*core.DNSClient)
		c.Timeout = 500 * time.Millisecond
		c.DNSClientUDP.Timeout = c.Timeout
		c.DNSClientTCP.Timeout = c.Timeout
	}

	rrset, rcode, _, _, err := imr.IterativeDNSQuery(context.Background(), "www.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("failover query: %v", err)
	}
	if rcode != dns.RcodeSuccess || rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("failover: rcode=%d rrset=%v", rcode, rrset)
	}

	dead := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.9", Port: 1}}},
	})
	c := dead.Forwards[0].Upstreams[0].Client.(*core.DNSClient)
	c.Timeout = 500 * time.Millisecond
	c.DNSClientUDP.Timeout = c.Timeout
	c.DNSClientTCP.Timeout = c.Timeout
	_, rcode, cctx, _, err := dead.IterativeDNSQuery(context.Background(), "www.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err == nil {
		t.Fatal("all upstreams dead: want an error, got none")
	}
	if rcode != dns.RcodeServerFailure || cctx != cache.ContextFailure {
		t.Errorf("all upstreams dead: rcode=%d context=%s", rcode, cache.CacheContextToString[cctx])
	}
}

// With a "zone: ." forward, priming must not depend on the network at all:
// PrimeFromHintsOnly seeds the hints and marks the cache primed without the
// live ". NS" fetch, so a forward-all resolver starts (and serves) even when
// its upstream is down at boot. The upstream double must see NO query during
// priming, and ordinary queries must forward afterwards.
func TestForwardRootPrimingSkipsFetch(t *testing.T) {
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}},
	})

	if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("PrimeFromHintsOnly: %v", err)
	}
	if !imr.Cache.IsPrimed() {
		t.Fatal("cache not primed")
	}
	if seen := logr.find(".", dns.TypeNS); len(seen) != 0 {
		t.Fatalf("hints-only priming sent a query to the upstream: %+v", seen)
	}
	// The hint-seeded root server map exists (FindClosestKnownZone stays
	// well-behaved) even though forwarding will outrank it.
	bestmatch, servers, err := imr.Cache.FindClosestKnownZone("www.example.com.")
	if err != nil || bestmatch != "." || len(servers) == 0 {
		t.Fatalf("root serverMap not seeded: match=%q servers=%d err=%v", bestmatch, len(servers), err)
	}

	rrset, rcode, _, _, err := imr.IterativeDNSQuery(context.Background(), "www.fwd.example.", dns.TypeA, servers, false, false)
	if err != nil {
		t.Fatalf("forwarded query after hints-only priming: %v", err)
	}
	if rcode != dns.RcodeSuccess || rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("rcode=%d rrset=%v", rcode, rrset)
	}
}

// The startup probe: a dead upstream is WARNed and aggregated into the
// Upstream/ImrForward server error (config status DEGRADED), a live one is
// recorded reachable — and the resolver keeps serving either way. A later
// successful exchange against a failing upstream clears the error.
func TestProbeForwardUpstreams(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{
			{Addr: "192.0.2.9", Port: 1},
			{Addr: addr, Port: port},
		}},
	})
	imr.errorRegistry = NewServerErrorRegistry()
	for _, up := range imr.Forwards[0].Upstreams {
		c := up.Client.(*core.DNSClient)
		c.Timeout = 500 * time.Millisecond
		c.DNSClientUDP.Timeout = c.Timeout
		c.DNSClientTCP.Timeout = c.Timeout
	}

	imr.ProbeForwardUpstreams()

	st := imr.StatusReport()
	if len(st.ForwardZones) != 1 || len(st.ForwardZones[0].Upstreams) != 2 {
		t.Fatalf("status report shape: %+v", st)
	}
	deadUp, liveUp := st.ForwardZones[0].Upstreams[0], st.ForwardZones[0].Upstreams[1]
	if !deadUp.Unreachable || deadUp.Failures == 0 || deadUp.LastError == "" {
		t.Errorf("dead upstream not reported unreachable: %+v", deadUp)
	}
	if liveUp.Unreachable || liveUp.Queries == 0 || liveUp.LastSuccess.IsZero() {
		t.Errorf("live upstream not reported reachable: %+v", liveUp)
	}

	errs := imr.errorRegistry.List()
	if len(errs) != 1 || errs[0].Subtype != ErrSubImrForward {
		t.Fatalf("registry after probe = %+v, want one Upstream/ImrForward entry", errs)
	}
	if !strings.Contains(errs[0].Message, "192.0.2.9") {
		t.Errorf("aggregate error does not name the dead upstream: %s", errs[0].Message)
	}

	// The resolver still serves through the live upstream despite the error.
	rrset, rcode, _, _, err := imr.IterativeDNSQuery(context.Background(), "www.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil {
		t.Fatalf("query while DEGRADED: rcode=%d rrset=%v err=%v", rcode, rrset, err)
	}

	// Recovery: a successful exchange against a failing upstream clears the
	// aggregate. Simulate by marking the live upstream failing, then letting
	// a real forwarded query (cache bypassed via force) succeed against it.
	imr.Forwards[0].Upstreams[0], imr.Forwards[0].Upstreams[1] =
		imr.Forwards[0].Upstreams[1], imr.Forwards[0].Upstreams[0]
	live := imr.Forwards[0].Upstreams[0]
	live.recordFailure(time.Now(), fmt.Errorf("synthetic"))
	imr.Forwards[0].Upstreams = imr.Forwards[0].Upstreams[:1] // drop the dead one
	imr.updateForwardUpstreamError()

	if _, _, _, _, err := imr.IterativeDNSQuery(context.Background(), "www.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, true, false); err != nil {
		t.Fatalf("recovery query: %v", err)
	}
	if errs := imr.errorRegistry.List(); len(errs) != 0 {
		t.Errorf("registry not cleared after recovery: %+v", errs)
	}
}
