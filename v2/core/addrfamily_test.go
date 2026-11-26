/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAddrFamilyNetwork(t *testing.T) {
	for _, tc := range []struct {
		f    AddrFamily
		base string
		want string
	}{
		{FamilyAny, "udp", "udp"},
		{FamilyAny, "tcp-tls", "tcp-tls"},
		{FamilyIPv4, "udp", "udp4"},
		{FamilyIPv4, "tcp", "tcp4"},
		{FamilyIPv6, "udp", "udp6"},
		{FamilyIPv6, "tcp", "tcp6"},
		// DoT: the family goes BEFORE the -tls that miekg strips itself.
		{FamilyIPv4, "tcp-tls", "tcp4-tls"},
		{FamilyIPv6, "tcp-tls", "tcp6-tls"},
		// Applied twice, or over the other family, it replaces rather than stacks.
		{FamilyIPv6, "tcp4", "tcp6"},
		{FamilyIPv4, "tcp6-tls", "tcp4-tls"},
		{FamilyIPv6, "tcp6", "tcp6"},
	} {
		if got := tc.f.Network(tc.base); got != tc.want {
			t.Errorf("%v.Network(%q) = %q, want %q", tc.f, tc.base, got, tc.want)
		}
	}
}

func TestParseAddrFamily(t *testing.T) {
	for in, want := range map[string]AddrFamily{"": FamilyAny, "4": FamilyIPv4, "6": FamilyIPv6} {
		got, err := ParseAddrFamily(in)
		if err != nil || got != want {
			t.Errorf("ParseAddrFamily(%q) = %v, %v; want %v", in, got, err, want)
		}
		if got.Suffix() != in {
			t.Errorf("%v.Suffix() = %q, want %q (round trip)", got, got.Suffix(), in)
		}
	}
	// A typo must not quietly become dual-stack.
	for _, bad := range []string{"46", "v4", "ipv6", "-4", "5"} {
		if _, err := ParseAddrFamily(bad); err == nil {
			t.Errorf("ParseAddrFamily(%q) accepted", bad)
		}
	}
	if FamilyIPv4.Flag() != "-4" || FamilyIPv6.Flag() != "-6" || FamilyAny.Flag() != "" {
		t.Errorf("Flag() = %q %q %q", FamilyIPv4.Flag(), FamilyIPv6.Flag(), FamilyAny.Flag())
	}
}

func TestAddrFamilyAllows(t *testing.T) {
	for _, tc := range []struct {
		f       AddrFamily
		host    string
		allowed bool
		literal bool
	}{
		{FamilyIPv4, "192.0.2.1", true, true},
		{FamilyIPv4, "2001:db8::1", false, true},
		{FamilyIPv6, "2001:db8::1", true, true},
		{FamilyIPv6, "192.0.2.1", false, true},
		{FamilyIPv6, "::1", true, true},
		// A scoped link-local address is still an IPv6 literal.
		{FamilyIPv6, "fe80::1%en0", true, true},
		{FamilyIPv4, "fe80::1%en0", false, true},
		// ::ffff:a.b.c.d is dialled over IPv4, so it is an IPv4 address here.
		{FamilyIPv4, "::ffff:192.0.2.1", true, true},
		{FamilyIPv6, "::ffff:192.0.2.1", false, true},
		// A name says nothing until it is resolved.
		{FamilyIPv4, "ns1.example.com", true, false},
		{FamilyIPv6, "ns1.example.com", true, false},
		{FamilyAny, "2001:db8::1", true, true},
	} {
		allowed, literal := tc.f.Allows(tc.host)
		if allowed != tc.allowed || literal != tc.literal {
			t.Errorf("%v.Allows(%q) = (%v, %v), want (%v, %v)",
				tc.f, tc.host, allowed, literal, tc.allowed, tc.literal)
		}
	}
}

// WithAddrFamily(FamilyAny) must leave the client exactly as NewDNSClient built
// it, because dog passes the option only when -4 or -6 was given but library
// callers may pass the zero value through unconditionally.
func TestWithAddrFamilyAnyIsANoop(t *testing.T) {
	c := NewDNSClient(TransportDo53, "53", nil, WithAddrFamily(FamilyAny))
	if c.DNSClientUDP.Net != "udp" || c.DNSClientTCP.Net != "tcp" {
		t.Errorf("nets %q/%q changed by FamilyAny", c.DNSClientUDP.Net, c.DNSClientTCP.Net)
	}
	c = NewDNSClient(TransportDoT, "853", nil, WithAddrFamily(FamilyAny))
	if c.DNSClientTLS.Net != "tcp-tls" {
		t.Errorf("DoT net %q changed by FamilyAny", c.DNSClientTLS.Net)
	}
}

func TestWithAddrFamilyRewritesEveryDNSClient(t *testing.T) {
	c := NewDNSClient(TransportDo53, "53", nil, WithAddrFamily(FamilyIPv6))
	if c.DNSClientUDP.Net != "udp6" || c.DNSClientTCP.Net != "tcp6" {
		t.Errorf("Do53 nets %q/%q, want udp6/tcp6 (the TCP fallback must stay on the family too)",
			c.DNSClientUDP.Net, c.DNSClientTCP.Net)
	}
	c = NewDNSClient(TransportDoT, "853", nil, WithAddrFamily(FamilyIPv4))
	if c.DNSClientTLS.Net != "tcp4-tls" {
		t.Errorf("DoT net %q, want tcp4-tls", c.DNSClientTLS.Net)
	}
	if c.AddrFamily != FamilyIPv4 {
		t.Errorf("AddrFamily = %v, want IPv4", c.AddrFamily)
	}
}

// --- loopback servers --------------------------------------------------------

const (
	answerV4 = "192.0.2.4"
	answerV6 = "192.0.2.6"
)

// loopbackFor is the literal host of the family's loopback address.
func loopbackFor(f AddrFamily) string {
	if f == FamilyIPv6 {
		return "[::1]"
	}
	return "127.0.0.1"
}

func answerWith(ip string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		if len(q.Question) > 0 {
			r.Answer = append(r.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			})
		}
		_ = w.WriteMsg(r)
	}
}

func familyAnswer(f AddrFamily) string {
	if f == FamilyIPv6 {
		return answerV6
	}
	return answerV4
}

// skipWithoutIPv6 skips a test on a host with no IPv6 loopback, which is a
// property of the machine and not of the code under test.
func skipWithoutIPv6(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = l.Close()
}

func selfSignedTLS(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "addrfamily-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func serve(t *testing.T, srv *dns.Server) {
	t.Helper()
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("test DNS server did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
}

// startServer starts a server for transport on f's loopback address and
// returns its host:port. It answers A queries with familyAnswer(f), so a
// response also says which server produced it.
func startServer(t *testing.T, tr Transport, f AddrFamily) string {
	t.Helper()
	if f == FamilyIPv6 {
		skipWithoutIPv6(t)
	}
	listen := loopbackFor(f) + ":0"
	h := answerWith(familyAnswer(f))
	switch tr {
	case TransportDo53:
		pc, err := net.ListenPacket(f.Network("udp"), listen)
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		serve(t, &dns.Server{PacketConn: pc, Handler: h})
		return pc.LocalAddr().String()
	case TransportDo53TCP:
		l, err := net.Listen(f.Network("tcp"), listen)
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		serve(t, &dns.Server{Listener: l, Handler: h})
		return l.Addr().String()
	case TransportDoT:
		l, err := net.Listen(f.Network("tcp"), listen)
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{selfSignedTLS(t)}, MinVersion: tls.VersionTLS12}
		serve(t, &dns.Server{Listener: tls.NewListener(l, cfg), Handler: h})
		return l.Addr().String()
	case TransportDoH:
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			q := new(dns.Msg)
			if err := q.Unpack(body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			r := new(dns.Msg)
			r.SetReply(q)
			r.Answer = append(r.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(familyAnswer(f)),
			})
			packed, _ := r.Pack()
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(packed)
		}))
		l, err := net.Listen(f.Network("tcp"), listen)
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		_ = ts.Listener.Close()
		ts.Listener = l
		ts.StartTLS()
		t.Cleanup(ts.Close)
		return l.Addr().String()
	case TransportDoQ:
		addr, stop := startStrictDoQServerOn(t, listen)
		t.Cleanup(stop)
		return addr
	}
	t.Fatalf("no test server for transport %v", tr)
	return ""
}

func queryAOnce(c *DNSClient, server string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion("test.example.", dns.TypeA)
	r, _, err := c.Exchange(m, server, false)
	if err != nil {
		return "", err
	}
	if len(r.Answer) == 0 {
		return "", io.ErrUnexpectedEOF
	}
	a, ok := r.Answer[0].(*dns.A)
	if !ok {
		return "", io.ErrUnexpectedEOF
	}
	return a.A.String(), nil
}

// A client restricted to one family reaches a server of that family and
// cannot reach one of the other, on every transport. The second half is the
// point: -6 that still lets a query out over IPv4 is worse than no -6.
func TestAddrFamilyRestrictsEveryTransport(t *testing.T) {
	for _, tc := range []struct {
		name string
		tr   Transport
	}{
		{"Do53-UDP", TransportDo53},
		{"Do53-TCP", TransportDo53TCP},
		{"DoT", TransportDoT},
		{"DoH", TransportDoH},
		{"DoQ", TransportDoQ},
	} {
		t.Run(tc.name, func(t *testing.T) {
			skipWithoutIPv6(t)
			v4 := startServer(t, tc.tr, FamilyIPv4)
			v6 := startServer(t, tc.tr, FamilyIPv6)
			// Port "" because both are given as host:port, which dialAddr uses as is.
			for _, f := range []AddrFamily{FamilyIPv4, FamilyIPv6} {
				same, other := v4, v6
				if f == FamilyIPv6 {
					same, other = v6, v4
				}
				mk := func() *DNSClient {
					return NewDNSClient(tc.tr, "", nil, WithTimeout(2*time.Second), WithAddrFamily(f))
				}
				if _, err := queryAOnce(mk(), same); err != nil {
					t.Errorf("%v client to a %v server (%s): %v", f, f, same, err)
				}
				if got, err := queryAOnce(mk(), other); err == nil {
					t.Errorf("%v client reached %s, a server of the other family (answer %s)", f, other, got)
				}
			}
			// Unrestricted still reaches both: the option is what restricts,
			// and its absence must not.
			for _, addr := range []string{v4, v6} {
				c := NewDNSClient(tc.tr, "", nil, WithTimeout(2*time.Second))
				if _, err := queryAOnce(c, addr); err != nil {
					t.Errorf("unrestricted client to %s: %v", addr, err)
				}
			}
		})
	}
}

// startPair starts a UDP and a TCP server on the SAME port on both loopbacks,
// answering with the family's own address. With one name resolving to both, a
// restricted client picking its family is then visible in the answer, which a
// literal address cannot show.
func startPair(t *testing.T) string {
	t.Helper()
	skipWithoutIPv6(t)
	for attempt := 0; attempt < 30; attempt++ {
		pc4, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp4: %v", err)
		}
		_, port, _ := net.SplitHostPort(pc4.LocalAddr().String())
		pc6, err6 := net.ListenPacket("udp6", "[::1]:"+port)
		l4, err4t := net.Listen("tcp4", "127.0.0.1:"+port)
		l6, err6t := net.Listen("tcp6", "[::1]:"+port)
		if err6 != nil || err4t != nil || err6t != nil {
			// The port was free for UDP/v4 but not for the rest: try another.
			pc4.Close()
			if pc6 != nil {
				pc6.Close()
			}
			if l4 != nil {
				l4.Close()
			}
			if l6 != nil {
				l6.Close()
			}
			continue
		}
		serve(t, &dns.Server{PacketConn: pc4, Handler: answerWith(answerV4)})
		serve(t, &dns.Server{PacketConn: pc6, Handler: answerWith(answerV6)})
		serve(t, &dns.Server{Listener: l4, Handler: answerWith(answerV4)})
		serve(t, &dns.Server{Listener: l6, Handler: answerWith(answerV6)})
		return port
	}
	t.Skip("could not find a port free on both IPv4 and IPv6 loopback")
	return ""
}

// The case the flags exist for: ONE name with both an A and an AAAA address,
// where -4 and -6 choose which the query goes to. localhost is the one name a
// test can rely on having both.
func TestAddrFamilyPicksTheAddressOfAName(t *testing.T) {
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", "localhost")
	if err != nil {
		t.Skipf("cannot resolve localhost: %v", err)
	}
	var has4, has6 bool
	for _, ip := range ips {
		if ip.Unmap() == netip.MustParseAddr("127.0.0.1") {
			has4 = true
		}
		if ip == netip.MustParseAddr("::1") {
			has6 = true
		}
	}
	if !has4 || !has6 {
		t.Skipf("localhost does not resolve to both 127.0.0.1 and ::1 (%v)", ips)
	}
	port := startPair(t)
	server := net.JoinHostPort("localhost", port)

	for _, tc := range []struct {
		name string
		tr   Transport
	}{{"UDP", TransportDo53}, {"TCP", TransportDo53TCP}} {
		for _, f := range []AddrFamily{FamilyIPv4, FamilyIPv6} {
			c := NewDNSClient(tc.tr, "", nil, WithTimeout(2*time.Second), WithAddrFamily(f))
			got, err := queryAOnce(c, server)
			if err != nil {
				t.Errorf("%s %v to %s: %v", tc.name, f, server, err)
				continue
			}
			if want := familyAnswer(f); got != want {
				t.Errorf("%s %v to %s was answered by the %s server (%s), want %s",
					tc.name, f, server, map[string]string{answerV4: "IPv4", answerV6: "IPv6"}[got], got, want)
			}
		}
	}
}
