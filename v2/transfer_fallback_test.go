package tdns

import (
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
	return addr, func() { _ = srv.Shutdown() }
}

func TestDoTransfer_NoUpstreams(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.test."}
	if _, _, err := zd.DoTransfer(); err == nil {
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
	xfr, serial, err := zd.DoTransfer()
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
	_, serial, err := zd.DoTransfer()
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
	xfr, _, err := zd.DoTransfer()
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
	if _, _, err := zd.DoTransfer(); err == nil {
		t.Fatal("expected an error when every upstream is unreachable")
	}
}

func TestFetchFromUpstream_NoUpstreams(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.test."}
	if _, err := zd.FetchFromUpstream(false, false, nil); err == nil {
		t.Fatal("expected an error when no upstreams are configured")
	}
}
