/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * cache-max-ttl / cache-min-ttl (#610): from the config file to the TTL a
 * client is served.
 */
package tdns

import (
	"context"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The join, not the arm: the limits come from the config through
// InitImrEngine, the data from a real upstream through the forward path, and
// the TTL is read off the response the responder writes -- fresh and from
// cache. The upstream's A record has TTL 300 and its NXDOMAIN proof TTL 60, so
// a ceiling of 120 and a floor of 90 each move one of them.
func TestCacheTTLLimitsReachTheWire(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	savedImr := Globals.ImrEngine
	savedLimits := cache.GetTTLLimits()
	t.Cleanup(func() {
		Globals.ImrEngine = savedImr
		cache.SetTTLLimits(savedLimits)
	})

	conf := &Config{}
	conf.Imr.Forward = []ImrForwardConf{
		{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}},
	}
	conf.Imr.Tuning.CacheMaxTTL = 120
	conf.Imr.Tuning.CacheMinTTL = 90
	if err := conf.InitImrEngine(context.Background(), true); err != nil {
		t.Fatalf("InitImrEngine: %v", err)
	}
	imr := conf.Internal.ImrEngine

	ask := func(qname string) *dns.Msg {
		t.Helper()
		r := new(dns.Msg)
		r.SetQuestion(qname, dns.TypeA)
		cw := &captureWriter{}
		imr.ImrResponder(context.Background(), cw, r, qname, dns.TypeA, &edns0.MsgOptions{RD: true})
		if cw.got == nil {
			t.Fatalf("%s: responder wrote no response", qname)
		}
		return cw.got
	}

	for _, when := range []string{"fresh", "cached"} {
		m := ask("www.fwd.example.")
		if len(m.Answer) != 1 {
			t.Fatalf("%s: www.fwd.example. A answered with %v", when, m.Answer)
		}
		if got := m.Answer[0].Header().Ttl; !nearTTL(got, 120) {
			t.Errorf("%s answer served with TTL %d, want 120: cache-max-ttl caps the upstream's 300", when, got)
		}

		m = ask("nx.fwd.example.")
		if m.Rcode != dns.RcodeNameError {
			t.Fatalf("%s: nx.fwd.example. rcode %s, want NXDOMAIN", when, dns.RcodeToString[m.Rcode])
		}
		var soa dns.RR
		for _, rr := range m.Ns {
			if rr.Header().Rrtype == dns.TypeSOA {
				soa = rr
			}
		}
		if soa == nil {
			t.Fatalf("%s: NXDOMAIN carried no SOA: %v", when, m.Ns)
		}
		if got := soa.Header().Ttl; !nearTTL(got, 90) {
			t.Errorf("%s NXDOMAIN proof served with TTL %d, want 90: cache-min-ttl floors the upstream's 60", when, got)
		}
	}
}

func TestCacheTTLTuningDefaults(t *testing.T) {
	var tc ImrTuningConf
	LoadImrTuningDefaults(&tc)
	if tc.CacheMaxTTL != 86400 || tc.CacheMinTTL != 0 {
		t.Errorf("defaults: max %d min %d, want Unbound's 86400 and 0", tc.CacheMaxTTL, tc.CacheMinTTL)
	}

	tc = ImrTuningConf{CacheMinTTL: 7200, CacheMaxTTL: 3600}
	LoadImrTuningDefaults(&tc)
	if tc.CacheMinTTL != 3600 || tc.CacheMaxTTL != 3600 {
		t.Errorf("min above max: got min %d max %d, want both 3600 (max wins)", tc.CacheMinTTL, tc.CacheMaxTTL)
	}
}

// The keys decode from the integer seconds an operator copies out of
// unbound.conf, and a changed value is reported as needing a restart like every
// other tuning key: the limits are installed once, at init.
func TestCacheTTLKnobsDecodeAndNeedRestart(t *testing.T) {
	boot := ImrEngineConf{Tuning: ImrTuningConf{CacheMaxTTL: DefaultCacheMaxTTL}}
	imr := runningImr(t, boot)
	conf := writeImrConfig(t, `imrengine:
   tuning:
      cache-max-ttl: 3600
      cache-min-ttl: 60
   forward:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
`)
	block, err := conf.reloadImrEngineFromFile()
	if err != nil {
		t.Fatalf("reloadImrEngineFromFile: %v", err)
	}
	if block.Tuning.CacheMaxTTL != 3600 || block.Tuning.CacheMinTTL != 60 {
		t.Fatalf("decoded max %d min %d, want 3600 and 60", block.Tuning.CacheMaxTTL, block.Tuning.CacheMinTTL)
	}

	conf.Internal.ImrEngine = imr
	conf.Imr = boot
	res, err := conf.applyImrEngineReload()
	if err != nil {
		t.Fatalf("applyImrEngineReload: %v", err)
	}
	if len(res.RestartRequired) != 1 || res.RestartRequired[0] != "imrengine.tuning" {
		t.Errorf("RestartRequired = %v, want [imrengine.tuning]", res.RestartRequired)
	}
}
