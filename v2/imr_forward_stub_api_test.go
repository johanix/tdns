/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func TestForwardZoneList(t *testing.T) {
	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "foo.bar.", TrustAD: true, Upstreams: []ImrUpstreamConf{
			{Addr: "192.0.2.1", Port: 8853, Transport: "doq", TLSServerName: "dns.example.net"},
		}},
		{Zone: ".", Upstreams: []ImrUpstreamConf{
			{Addr: "192.0.2.2", Transport: "dot", Insecure: true},
		}},
	})
	list := imr.ForwardZoneList()
	if len(list) != 2 {
		t.Fatalf("want 2 zones, got %d", len(list))
	}
	// Table order is most-specific first.
	if list[0].Zone != "foo.bar." || !list[0].TrustAD ||
		list[0].Upstreams[0].Upstream != "192.0.2.1:8853/doq" ||
		list[0].Upstreams[0].TLSServerName != "dns.example.net" {
		t.Errorf("list[0] = %+v", list[0])
	}
	if list[1].Zone != "." || !list[1].Upstreams[0].Insecure {
		t.Errorf("list[1] = %+v", list[1])
	}
}

// The on-demand forward probe reports per upstream AND records into the live
// reachability state, exactly like the startup probe — so probing refreshes
// (or clears) the DEGRADED aggregate.
func TestProbeForwardUpstreamsReport(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{
			{Addr: addr, Port: port},
			{Addr: "192.0.2.9", Port: 1},
		}},
		{Zone: "other.example.", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}},
	})
	imr.errorRegistry = NewServerErrorRegistry()
	for _, fz := range imr.Forwards {
		for _, up := range fz.Upstreams {
			c := up.Client.(*core.DNSClient)
			c.Timeout = 500 * time.Millisecond
			c.DNSClientUDP.Timeout = c.Timeout
			c.DNSClientTCP.Timeout = c.Timeout
		}
	}

	// Zone-scoped probe touches only that zone's upstreams.
	results, err := imr.ProbeForwardUpstreamsReport(context.Background(), "other.example.")
	if err != nil {
		t.Fatalf("scoped probe: %v", err)
	}
	if len(results) != 1 || !results[0].OK || results[0].Zone != "other.example." {
		t.Fatalf("scoped probe results = %+v", results)
	}

	// Full probe: one ok, one failed, and the failure is recorded.
	results, err = imr.ProbeForwardUpstreamsReport(context.Background(), "")
	if err != nil {
		t.Fatalf("full probe: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("want 3 results, got %d: %+v", len(results), results)
	}
	var okCount, failCount int
	for _, res := range results {
		if res.OK {
			okCount++
			if res.RTT == "" {
				t.Errorf("ok result without rtt: %+v", res)
			}
		} else {
			failCount++
			if res.Error == "" {
				t.Errorf("failed result without error: %+v", res)
			}
		}
	}
	if okCount != 2 || failCount != 1 {
		t.Errorf("ok=%d fail=%d, want 2/1", okCount, failCount)
	}
	if errs := imr.errorRegistry.List(); len(errs) != 1 || !strings.Contains(errs[0].Message, "192.0.2.9") {
		t.Errorf("aggregate error after probe = %+v", errs)
	}

	if _, err := imr.ProbeForwardUpstreamsReport(context.Background(), "nosuch.zone."); err == nil {
		t.Error("probe of unknown forward zone accepted, want error")
	}
}

// A cancelled context stops probes before their exchanges start: nothing
// reaches the upstream, nothing is recorded as upstream failure, and the
// call returns promptly instead of waiting out client timeouts.
func TestProbeCancellation(t *testing.T) {
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}},
	})
	imr.errorRegistry = NewServerErrorRegistry()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		imr.ProbeForwardUpstreams(ctx)
		if results, err := imr.ProbeForwardUpstreamsReport(ctx, ""); err != nil {
			t.Errorf("cancelled report probe errored: %v", err)
		} else {
			for _, res := range results {
				if res.OK {
					t.Errorf("cancelled probe reported success: %+v", res)
				}
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled probes did not return promptly")
	}

	logr.mu.Lock()
	n := len(logr.queries)
	logr.mu.Unlock()
	if n != 0 {
		t.Errorf("cancelled probe sent %d query(ies) upstream", n)
	}
	up := imr.Forwards[0].Upstreams[0]
	up.mu.Lock()
	failing, failures := up.failing, up.failures
	up.mu.Unlock()
	if failing || failures != 0 {
		t.Errorf("cancellation recorded as upstream failure: failing=%v failures=%d", failing, failures)
	}
	if errs := imr.errorRegistry.List(); len(errs) != 0 {
		t.Errorf("cancellation raised a server error: %+v", errs)
	}
}

// Stub list/status/probe against a live authoritative double, plus the
// design's central safety property: the stub probe is report-only — probing
// a dead address must NOT put it into backoff.
func TestStubListStatusProbe(t *testing.T) {
	const zone = "stubtest.example."
	addr, port, stop := startStubAuthServer(t, zone)
	defer stop()

	lg := log.New(os.Stderr, "test", log.LstdFlags)
	c := cache.NewRRsetCache(lg, false, false)
	do53 := core.NewDNSClient(core.TransportDo53, port, nil)
	do53.Timeout = 500 * time.Millisecond
	do53.DNSClientUDP.Timeout = do53.Timeout
	do53.DNSClientTCP.Timeout = do53.Timeout
	c.DNSClient[core.TransportDo53] = do53
	c.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	if err := c.AddStub(zone, []cache.AuthServer{
		{Name: "ns." + zone, Addrs: []string{addr, "192.0.2.9"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr := &Imr{
		Cache:     c,
		Quiet:     true,
		stubZones: []string{zone},
		FamilyTracker: cache.NewFamilyTracker(
			10*time.Minute, 10*time.Minute, 30*time.Second, 5),
	}

	// list: config view.
	list := imr.StubZoneList()
	if len(list) != 1 || list[0].Zone != zone || len(list[0].Servers) != 1 {
		t.Fatalf("StubZoneList = %+v", list)
	}
	if list[0].Servers[0].Name != "ns."+zone || len(list[0].Servers[0].Addrs) != 2 {
		t.Errorf("stub server info = %+v", list[0].Servers[0])
	}

	// probe: live addr answers authoritatively, dead addr fails — and
	// neither outcome may leave a trace in the server's backoff state.
	results, err := imr.ProbeStubServers(context.Background(), zone)
	if err != nil {
		t.Fatalf("ProbeStubServers: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 probe results (2 addrs x 1 transport), got %d: %+v", len(results), results)
	}
	byAddr := map[string]ImrStubProbeResult{}
	for _, res := range results {
		byAddr[res.Addr] = res
	}
	if res := byAddr[addr]; !res.OK || !res.AA || res.Rcode != "NOERROR" {
		t.Errorf("live stub probe = %+v, want OK/AA/NOERROR", res)
	}
	if res := byAddr["192.0.2.9"]; res.OK || res.Error == "" {
		t.Errorf("dead stub probe = %+v, want failure with error", res)
	}

	st := imr.StubZoneStatus()
	if len(st) != 1 || len(st[0].Servers) != 1 {
		t.Fatalf("StubZoneStatus = %+v", st)
	}
	server := st[0].Servers[0]
	if len(server.Backoffs) != 0 {
		t.Fatalf("stub probe recorded a backoff — a diagnostic poisoned resolution: %v", server.Backoffs)
	}
	if len(server.Attempted) != 0 {
		t.Errorf("stub probe recorded transport counters, want report-only: %+v", server.Attempted)
	}

	// A real query through the stub DOES move the counters, and status
	// shows them.
	sm, ok := c.ServerMapCopy(zone)
	if !ok {
		t.Fatal("no serverMap for stub zone")
	}
	if _, _, _, _, err := imr.IterativeDNSQuery(context.Background(), zone, dns.TypeSOA, sm, false, false); err != nil {
		t.Fatalf("query through stub: %v", err)
	}
	server = imr.StubZoneStatus()[0].Servers[0]
	total := uint64(0)
	for _, n := range server.Attempted {
		total += n
	}
	if total == 0 {
		t.Errorf("no attempted counters after a real query: %+v", server)
	}

	if _, err := imr.ProbeStubServers(context.Background(), "nosuch.zone."); err == nil {
		t.Error("probe of unknown stub zone accepted, want error")
	}
}
