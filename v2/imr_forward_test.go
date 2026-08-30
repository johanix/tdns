/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
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
          transport: tcp
        - addr:      2001:db8::53
          insecure:  true
          transport: dot
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
	if len(conf.Forward) != 3 {
		t.Fatalf("want 3 forward zones, got %d", len(conf.Forward))
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
	if !f1.TrustAD || len(f1.Upstreams) != 2 || !f1.Upstreams[1].Insecure {
		t.Errorf("forward[1] = %+v", f1)
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
	imr := &Imr{Forwards: forwards, stubZones: []string{"internal.example.", "deep.sub.foo.bar."}}

	cases := []struct {
		qname string
		want  string // matched forward zone, "" for iterate
	}{
		{"www.example.com.", "."},          // root forward catches everything...
		{"WWW.Foo.Bar.", "foo.bar."},       // ...unless something more specific matches (case-insensitively)
		{"x.sub.foo.bar.", "sub.foo.bar."}, // longest forward match wins
		{"host.internal.example.", ""},     // stub more specific than "." wins
		{"a.deep.sub.foo.bar.", ""},        // stub more specific than sub.foo.bar. wins
		{"internal.example.", ""},          // the stub apex itself
		{"foo.bar.", "foo.bar."},           // the forward apex itself
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

// startTestUpstream starts a UDP resolver double on 127.0.0.1 that answers
// like a recursive: it REFUSES queries without RD, answers www.fwd.example. A
// with an A record (AD=1), nx.fwd.example. with NXDOMAIN+SOA, and everything
// else with NODATA+SOA.
func startTestUpstream(t *testing.T) (string, uint16, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)

	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: "fwd.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns.fwd.example.", Mbox: "hostmaster.fwd.example.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		if !r.RecursionDesired {
			// A forwarded query MUST carry RD; this is what separates
			// forwarding from iteration in this test.
			m.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		switch {
		case q.Name == "www.fwd.example." && q.Qtype == dns.TypeA:
			m.AuthenticatedData = true
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(192, 0, 2, 77),
			})
		case q.Name == "nx.fwd.example.":
			m.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, soa)
		default:
			m.Ns = append(m.Ns, soa)
		}
		_ = w.WriteMsg(m)
	})

	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test upstream did not start")
	}
	return host, uint16(port), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
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

// End to end over Do53 on a non-standard port: the query must reach the
// upstream with RD=1, the answer must be cached, the upstream's AD bit must
// map to the validation state (trust-ad), and negatives must cache as
// negatives. Also proves the per-upstream port plumbing, since the upstream
// listens on an ephemeral port.
func TestForwardQueryTrustAD(t *testing.T) {
	addr, port, stop := startTestUpstream(t)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}},
	})
	ctx := context.Background()

	// Positive answer, via the real entry point so the forward hook in
	// IterativeDNSQueryWithLoopDetection is exercised, not forwardQuery
	// directly. The empty serverMap must be irrelevant.
	rrset, rcode, cctx, transport, err := imr.IterativeDNSQuery(ctx, "www.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("forwarded query: %v", err)
	}
	if rcode != dns.RcodeSuccess || cctx != cache.ContextAnswer || len(rrset.RRs) != 1 {
		t.Fatalf("rcode=%d context=%s rrs=%v", rcode, cache.CacheContextToString[cctx], rrset)
	}
	if transport != core.TransportDo53 {
		t.Errorf("transport = %s", core.TransportToString[transport])
	}
	if a, ok := rrset.RRs[0].(*dns.A); !ok || a.A.String() != "192.0.2.77" {
		t.Errorf("answer = %v", rrset.RRs[0])
	}
	crrset := imr.Cache.Get("www.fwd.example.", dns.TypeA)
	if crrset == nil || crrset.Context != cache.ContextAnswer {
		t.Fatalf("answer not cached: %+v", crrset)
	}
	if crrset.State != cache.ValidationStateSecure {
		t.Errorf("trust-ad with upstream AD=1: state = %s, want secure", cache.ValidationStateToString[crrset.State])
	}

	// NXDOMAIN caches as a negative.
	rrset, rcode, cctx, _, err = imr.IterativeDNSQuery(ctx, "nx.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("forwarded NXDOMAIN query: %v", err)
	}
	if rrset != nil || rcode != dns.RcodeNameError || cctx != cache.ContextNXDOMAIN {
		t.Fatalf("NXDOMAIN: rrset=%v rcode=%d context=%s", rrset, rcode, cache.CacheContextToString[cctx])
	}

	// NODATA caches as a negative.
	rrset, rcode, cctx, _, err = imr.IterativeDNSQuery(ctx, "www.fwd.example.", dns.TypeMX, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("forwarded NODATA query: %v", err)
	}
	if rrset != nil || rcode != dns.RcodeSuccess || cctx != cache.ContextNoErrNoAns {
		t.Fatalf("NODATA: rrset=%v rcode=%d context=%s", rrset, rcode, cache.CacheContextToString[cctx])
	}
}

// A dead first upstream must not take the query down: the second upstream
// answers. And when every upstream is dead, the query must fail with an error
// naming the forward zone (forward-only, no fallback to iteration).
func TestForwardQueryFailover(t *testing.T) {
	addr, port, stop := startTestUpstream(t)
	defer stop()

	// 192.0.2.9 is TEST-NET: nothing answers. Use a sub-second timeout so
	// the failover test doesn't sit out the full 5s default.
	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{
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

// Without trust-ad, a forwarded answer goes through the normal local
// validation path. The upstream serves an unsigned answer and NODATA for the
// validator's chain queries, so the outcome must be a cached, NON-secure
// answer — never a borrowed AD bit.
func TestForwardQueryValidatesLocally(t *testing.T) {
	addr, port, stop := startTestUpstream(t)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}},
	})

	rrset, rcode, cctx, _, err := imr.IterativeDNSQuery(context.Background(), "www.fwd.example.", dns.TypeA, map[string]*cache.AuthServer{}, false, false)
	if err != nil {
		t.Fatalf("forwarded query: %v", err)
	}
	if rcode != dns.RcodeSuccess || cctx != cache.ContextAnswer || rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("rcode=%d context=%s rrset=%v", rcode, cache.CacheContextToString[cctx], rrset)
	}
	crrset := imr.Cache.Get("www.fwd.example.", dns.TypeA)
	if crrset == nil {
		t.Fatal("answer not cached")
	}
	if crrset.State == cache.ValidationStateSecure {
		t.Error("unsigned forwarded answer cached as secure: the upstream AD bit leaked through without trust-ad")
	}
}
