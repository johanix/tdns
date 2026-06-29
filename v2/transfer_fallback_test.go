package tdns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startTestSOAServer starts a UDP DNS responder on 127.0.0.1 that answers SOA
// queries for zone with the given serial and rcode. Returns its addr:port and a
// shutdown func.
func startTestSOAServer(t *testing.T, zone string, serial uint32, rcode int) (string, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.LocalAddr().String()

	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = rcode
		if rcode == dns.RcodeSuccess {
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:      "ns." + zone,
				Mbox:    "hostmaster." + zone,
				Serial:  serial,
				Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
			})
		}
		_ = w.WriteMsg(m)
	})

	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test DNS server did not start")
	}
	return addr, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	}
}

// startTestSOAServerTSIG starts a UDP SOA responder that REQUIRES a valid TSIG
// under keyName and signs its response with the same key.
func startTestSOAServerTSIG(t *testing.T, zone string, serial uint32, keyName, secret string) (string, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.LocalAddr().String()

	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		ts := r.IsTsig()
		if ts == nil || w.TsigStatus() != nil { // require a valid TSIG
			m.Rcode = dns.RcodeNotAuth
			_ = w.WriteMsg(m)
			return
		}
		m.Answer = append(m.Answer, &dns.SOA{
			Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:      "ns." + zone,
			Mbox:    "hostmaster." + zone,
			Serial:  serial,
			Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
		})
		// Sign the response with the same key (RFC 8945); the server fills the MAC.
		m.SetTsig(ts.Hdr.Name, dns.HmacSHA256, 300, time.Now().Unix())
		_ = w.WriteMsg(m)
	})

	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn:        pc,
		Handler:           mux,
		TsigSecret:        map[string]string{dns.CanonicalName(keyName): secret},
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test DNS server did not start")
	}
	return addr, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	}
}

// A keyed upstream: the SOA probe must be TSIG-signed (server accepts), and a
// wrong secret must fail.
func TestDoTransfer_SignsWithKey(t *testing.T) {
	zone := "example.test."
	const secret = "MTIzNDU2Nzg5MDEyMzQ1Ng=="
	good, stop := startTestSOAServerTSIG(t, zone, 42, "tkey", secret)
	defer stop()

	conf := &Config{}
	conf.Keys.Tsig = []TsigDetails{{Name: "tkey", Algorithm: "hmac-sha256", Secret: secret}}
	if err := conf.LoadTsigKeys(); err != nil {
		t.Fatalf("LoadTsigKeys: %v", err)
	}
	zd := &ZoneData{ZoneName: zone, Upstreams: []PeerConf{{Addr: good, Key: "tkey"}}}
	if _, serial, err := zd.DoTransfer(conf); err != nil || serial != 42 {
		t.Fatalf("signed SOA probe: serial=%d err=%v, want 42/nil", serial, err)
	}

	bad := &Config{}
	bad.Keys.Tsig = []TsigDetails{{Name: "tkey", Algorithm: "hmac-sha256", Secret: "YWJjZGVmZ2hpamtsbW5vcA=="}}
	if err := bad.LoadTsigKeys(); err != nil {
		t.Fatalf("LoadTsigKeys(bad): %v", err)
	}
	zd2 := &ZoneData{ZoneName: zone, Upstreams: []PeerConf{{Addr: good, Key: "tkey"}}}
	// Wrong secret -> the server rejects with NOTAUTH, so the probe gets no usable
	// SOA: it must back off quietly (no error) without warranting a transfer and
	// crucially without ever reading the upstream's real serial.
	xfr, serial, err := zd2.DoTransfer(bad)
	if err != nil {
		t.Fatalf("wrong secret should back off without accepting data, got err=%v", err)
	}
	if xfr || serial == 42 {
		t.Fatalf("wrong secret must not yield a usable transfer: xfr=%v serial=%d", xfr, serial)
	}
}

func TestDoTransfer_NoUpstreams(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.test."}
	if _, _, err := zd.DoTransfer(&Config{}); err == nil {
		t.Fatal("expected an error when no upstreams are configured")
	}
}

// A REFUSED from the first primary must NOT terminate the probe: a sibling
// primary may have a different allow-transfer/query ACL. We must advance.
func TestDoTransfer_RefusedAdvancesToNextPrimary(t *testing.T) {
	zone := "example.test."
	refusing, stop1 := startTestSOAServer(t, zone, 0, dns.RcodeRefused)
	defer stop1()
	good, stop2 := startTestSOAServer(t, zone, 99, dns.RcodeSuccess)
	defer stop2()

	zd := &ZoneData{ZoneName: zone, Upstreams: []PeerConf{{Addr: refusing}, {Addr: good}}}
	xfr, serial, err := zd.DoTransfer(&Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if serial != 99 {
		t.Fatalf("serial: got %d, want 99 (should have retried past REFUSED)", serial)
	}
	if !xfr {
		t.Fatal("expected a transfer to be warranted (serial 99 > incoming 0)")
	}
}

// A transport failure (nothing listening) on the first address advances to a
// working sibling.
func TestDoTransfer_TransportErrorAdvancesToNextPrimary(t *testing.T) {
	zone := "example.test."
	good, stop := startTestSOAServer(t, zone, 7, dns.RcodeSuccess)
	defer stop()

	// 127.0.0.1:1 has no listener -> connection refused / timeout (transport).
	zd := &ZoneData{ZoneName: zone, Upstreams: []PeerConf{{Addr: "127.0.0.1:1"}, {Addr: good}}}
	_, serial, err := zd.DoTransfer(&Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if serial != 7 {
		t.Fatalf("serial: got %d, want 7 (should have skipped the dead address)", serial)
	}
}

// When every primary answers but none gives a usable SOA (all REFUSED), back
// off quietly: no transfer, no error.
func TestDoTransfer_AllRefusedQuietBackoff(t *testing.T) {
	zone := "example.test."
	r1, s1 := startTestSOAServer(t, zone, 0, dns.RcodeRefused)
	defer s1()
	r2, s2 := startTestSOAServer(t, zone, 0, dns.RcodeRefused)
	defer s2()

	zd := &ZoneData{ZoneName: zone, Upstreams: []PeerConf{{Addr: r1}, {Addr: r2}}}
	xfr, _, err := zd.DoTransfer(&Config{})
	if err != nil {
		t.Fatalf("all-REFUSED should back off quietly, got error: %v", err)
	}
	if xfr {
		t.Fatal("no transfer expected when every primary refused")
	}
}

// When no primary is reachable at all, surface a hard error.
func TestDoTransfer_AllUnreachableIsError(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.test.", Upstreams: []PeerConf{{Addr: "127.0.0.1:1"}, {Addr: "127.0.0.1:2"}}}
	if _, _, err := zd.DoTransfer(&Config{}); err == nil {
		t.Fatal("expected an error when every upstream is unreachable")
	}
}

func TestFetchFromUpstream_NoUpstreams(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.test."}
	if _, err := zd.FetchFromUpstream(false, false, nil, &Config{}); err == nil {
		t.Fatal("expected an error when no upstreams are configured")
	}
}
