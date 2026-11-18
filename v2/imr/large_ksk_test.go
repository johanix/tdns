package imr

import (
	"log"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func TestLargeKskImrMetrics(t *testing.T) {
	resetLargeKskImrMetricsForTest()
	t.Cleanup(resetLargeKskImrMetricsForTest)

	imr := &Imr{largeAlgs: map[uint8]bool{dns.RSASHA512: true}}

	smallDS := &dns.DS{
		Hdr:       dns.RR_Header{Name: "small.example.", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		Algorithm: dns.ED25519,
	}
	imr.noteDSEncountered([]dns.RR{smallDS})

	largeDS := &dns.DS{
		Hdr:       dns.RR_Header{Name: "large.example.", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		Algorithm: dns.RSASHA512,
	}
	imr.noteDSEncountered([]dns.RR{largeDS, largeDS})

	imr.noteDNSKEYLookup(false)
	imr.noteDNSKEYLookup(true)

	m := LargeKskImrMetricsSnapshot()
	if m.DSEncounteredTotal != 2 || m.DSEncounteredLarge != 1 {
		t.Fatalf("DS metrics = %+v, want total=2 large RRsets=1", m)
	}
	if len(m.DSDLargeRRByAlgorithm) != 1 || m.DSDLargeRRByAlgorithm[0].Algorithm != dns.RSASHA512 ||
		m.DSDLargeRRByAlgorithm[0].Count != 2 {
		t.Fatalf("per-alg DS RR metrics = %+v, want RSASHA512 x2", m.DSDLargeRRByAlgorithm)
	}
	if LargeAlgDSMetrics() != 2 {
		t.Fatalf("LargeAlgDSMetrics = %d, want 2 large DS RRs", LargeAlgDSMetrics())
	}
	if m.DNSKEYLookupTotal != 2 || m.DNSKEYLookupBypassed != 1 {
		t.Fatalf("DNSKEY metrics = %+v, want total=2 bypassed=1", m)
	}
}

// cacheWithLargeDS returns an RRset cache seeded with a large-algorithm parent
// DS for qname.
func cacheWithLargeDS(t *testing.T, qname string) *cache.RRsetCacheT {
	t.Helper()
	logger := log.New(os.Stderr, "", 0)
	rrcache := cache.NewRRsetCache(logger, false, false)
	ds := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Algorithm: dns.RSASHA512,
	}
	rrcache.Set(qname, dns.TypeDS, &cache.CachedRRset{
		Name:       qname,
		RRtype:     dns.TypeDS,
		Expiration: time.Now().Add(time.Hour),
		RRset: &core.RRset{
			Name:   qname,
			RRtype: dns.TypeDS,
			Class:  dns.ClassINET,
			RRs:    []dns.RR{ds},
		},
	})
	return rrcache
}

func TestDnskeyTransportBypass(t *testing.T) {
	qname := "example.com."

	// use_ds_signal: bypass only when cached DS is large.
	imr := &Imr{largeAlgs: map[uint8]bool{dns.RSASHA512: true}}
	if imr.dnskeyTransportBypass(qname, dns.TypeA, edns0.PrivacyNone) {
		t.Fatal("non-DNSKEY query must never bypass")
	}
	if imr.dnskeyTransportBypass(qname, dns.TypeDNSKEY, edns0.PrivacyNone) {
		t.Fatal("use_ds_signal with no cached DS must not bypass")
	}
	imr.Cache = cacheWithLargeDS(t, qname)
	if !imr.dnskeyTransportBypass(qname, dns.TypeDNSKEY, edns0.PrivacyNone) {
		t.Fatal("use_ds_signal with large cached DS must bypass")
	}

	// force_udp: never bypass, even with a large DS.
	imrUDP := &Imr{
		largeAlgs:       map[uint8]bool{dns.RSASHA512: true},
		dnskeyTransport: DNSKEYTransportForceUDP,
		Cache:           cacheWithLargeDS(t, qname),
	}
	if imrUDP.dnskeyTransportBypass(qname, dns.TypeDNSKEY, edns0.PrivacyNone) {
		t.Fatal("force_udp must never bypass")
	}

	// try_encrypted / force_encrypted: always bypass DNSKEY, DS irrelevant.
	for _, pol := range []DNSKEYTransportPolicy{DNSKEYTransportTryEncrypted, DNSKEYTransportForceEncrypted} {
		i := &Imr{dnskeyTransport: pol} // no cache, no large algs
		if !i.dnskeyTransportBypass(qname, dns.TypeDNSKEY, edns0.PrivacyNone) {
			t.Fatalf("%s must bypass for DNSKEY regardless of DS", pol)
		}
		if i.dnskeyTransportBypass(qname, dns.TypeA, edns0.PrivacyNone) {
			t.Fatalf("%s must not bypass non-DNSKEY", pol)
		}
	}
}

// Strict privacy suppresses the bypass whatever the policy says.
//
// preferredDNSKEYTransport resolves against server.Transports alone and falls
// back to Do53TCP, so on a server whose encrypted transport is known only from
// TransportWeights -- which candidateTransports accepts, and which is what let
// the query past the strict precheck in the first place -- the bypass would
// put a client's strict DNSKEY query on the wire in cleartext. Nothing is lost
// by suppressing it: strict privacy already restricts the query to DoT/DoQ/DoH,
// every one a stream transport, which is what the bypass exists to reach.
func TestDnskeyTransportBypassSuppressedByStrictPrivacy(t *testing.T) {
	qname := "example.com."

	for _, pol := range []DNSKEYTransportPolicy{
		DNSKEYTransportTryEncrypted,
		DNSKEYTransportForceEncrypted,
		DNSKEYTransportUseDSSignal,
	} {
		i := &Imr{
			dnskeyTransport: pol,
			largeAlgs:       map[uint8]bool{dns.RSASHA512: true},
			Cache:           cacheWithLargeDS(t, qname),
		}
		// Sanity: without the privacy signal this policy DOES bypass, so the
		// assertion below is about privacy and not about the policy.
		if !i.dnskeyTransportBypass(qname, dns.TypeDNSKEY, edns0.PrivacyNone) {
			t.Fatalf("setup: %s should bypass with no privacy signal", pol)
		}
		if i.dnskeyTransportBypass(qname, dns.TypeDNSKEY, edns0.PrivacyStrict) {
			t.Errorf("%s bypassed under strict privacy; the preferred transport may be cleartext", pol)
		}
		// Opportunistic accepted cleartext, so the bypass still applies.
		if !i.dnskeyTransportBypass(qname, dns.TypeDNSKEY, edns0.PrivacyOpportunistic) {
			t.Errorf("%s stopped bypassing under opportunistic privacy", pol)
		}
	}
}

func TestPreferredDNSKEYTransport(t *testing.T) {
	mkServer := func(ts ...core.Transport) *cache.AuthServer {
		s := cache.NewAuthServer("ns.example.")
		s.Transports = ts
		return s
	}

	// Prefers DoQ over DoT over DoH.
	imr := &Imr{dnskeyTransport: DNSKEYTransportTryEncrypted}
	if got := imr.preferredDNSKEYTransport(mkServer(core.TransportDo53, core.TransportDoT, core.TransportDoQ)); got != core.TransportDoQ {
		t.Fatalf("want DoQ, got %v", got)
	}
	if got := imr.preferredDNSKEYTransport(mkServer(core.TransportDo53, core.TransportDoT)); got != core.TransportDoT {
		t.Fatalf("want DoT, got %v", got)
	}

	// try_encrypted with no encrypted transport falls back to TCP.
	if got := imr.preferredDNSKEYTransport(mkServer(core.TransportDo53)); got != core.TransportDo53TCP {
		t.Fatalf("try_encrypted no-encrypted want TCP, got %v", got)
	}

	// force_encrypted with no encrypted transport returns 0 (fail).
	imrForce := &Imr{dnskeyTransport: DNSKEYTransportForceEncrypted}
	if got := imrForce.preferredDNSKEYTransport(mkServer(core.TransportDo53)); got != 0 {
		t.Fatalf("force_encrypted no-encrypted want 0, got %v", got)
	}
	if got := imrForce.preferredDNSKEYTransport(mkServer(core.TransportDo53, core.TransportDoT)); got != core.TransportDoT {
		t.Fatalf("force_encrypted with DoT want DoT, got %v", got)
	}
}

// A signal installed the production way has dot, doh and doq at weight 0
// when it leaves them out (the absence defaults), and they sit in
// server.Transports. Weight 0 means "send none": the DNSKEY bypass must not
// pick them. Before the fix it picked DoQ for every signalled server.
func TestPreferredDNSKEYTransportSkipsZeroWeight(t *testing.T) {
	imr := &Imr{dnskeyTransport: DNSKEYTransportTryEncrypted}
	imrForce := &Imr{dnskeyTransport: DNSKEYTransportForceEncrypted}

	cleartext := cache.NewAuthServer("ns1.example.")
	applyTransportMapToServer(cleartext, map[string]uint8{"udp": 100, "tcp": 100})
	if !slices.Contains(cleartext.GetTransports(), core.TransportDoQ) {
		t.Fatalf("setup: DoQ at weight 0 is not in Transports (%v); the test no longer reaches the case", cleartext.GetTransports())
	}
	if got := imr.preferredDNSKEYTransport(cleartext); got != core.TransportDo53TCP {
		t.Errorf("cleartext-only signal: got %v, want Do53TCP", got)
	}
	if got := imrForce.preferredDNSKEYTransport(cleartext); got != 0 {
		t.Errorf("cleartext-only signal, force_encrypted: got %v, want 0 (fail)", got)
	}

	// doq:0 named explicitly is the same; a non-zero dot is picked.
	dot := cache.NewAuthServer("ns2.example.")
	applyTransportMapToServer(dot, map[string]uint8{"doq": 0, "dot": 20})
	if got := imr.preferredDNSKEYTransport(dot); got != core.TransportDoT {
		t.Errorf("doq:0,dot:20: got %v, want DoT", got)
	}

	// An ALPN-only server lists its transports at weight 100: offered.
	alpn := cache.NewAuthServer("ns3.example.")
	applyAlpnSignalToServer(alpn, "doq")
	if got := imr.preferredDNSKEYTransport(alpn); got != core.TransportDoQ {
		t.Errorf("alpn doq: got %v, want DoQ", got)
	}
}

// RefreshDnssecPolicy must update the singleton Imr's cached knobs after a
// config reload, and must be safe against concurrent query-path readers
// (regression: reload previously left the init-time values in place forever;
// a bare field assignment here would be a data race under -race).
func TestRefreshDnssecPolicy(t *testing.T) {
	imr := &Imr{
		largeAlgs:       map[uint8]bool{dns.RSASHA512: true},
		dnskeyTransport: DNSKEYTransportForceUDP,
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = imr.isLargeAlgorithm(dns.RSASHA512)
					_ = imr.dnskeyPolicy()
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		imr.RefreshDnssecPolicy(map[uint8]bool{dns.ED25519: true}, DNSKEYTransportTryEncrypted)
	}
	close(stop)
	wg.Wait()

	if imr.isLargeAlgorithm(dns.RSASHA512) || !imr.isLargeAlgorithm(dns.ED25519) {
		t.Fatalf("largeAlgs not refreshed: RSASHA512=%v ED25519=%v",
			imr.isLargeAlgorithm(dns.RSASHA512), imr.isLargeAlgorithm(dns.ED25519))
	}
	if got := imr.dnskeyPolicy(); got != DNSKEYTransportTryEncrypted {
		t.Fatalf("dnskeyTransport not refreshed: got %v", got)
	}

	// nil receiver must be a no-op, not a panic (auth daemons without an IMR).
	var nilImr *Imr
	nilImr.RefreshDnssecPolicy(map[uint8]bool{dns.ED25519: true}, DNSKEYTransportForceUDP)
}
