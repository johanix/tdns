/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Forward-table quarantine (#475). What these pin down is the behaviour the
 * old build-fails-whole path could not have: the daemon STARTS with a broken
 * forward zone, the broken part is inert rather than absent, and the parts
 * that still work still work.
 */

package tdns

import (
	"context"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The headline of #475: one misconfigured forward zone must not stop the
// resolver. With the quarantine removed and the old `return err` restored,
// InitImrEngine fails here and every assertion below is unreachable.
func TestInitImrEngineStartsWithABadForwardZone(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	savedImr := Globals.ImrEngine
	defer func() { Globals.ImrEngine = savedImr }()

	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	conf.Imr.Forward = []ImrForwardConf{
		{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}},
		// trust-ad over plaintext: used to abort the whole daemon.
		{Zone: "bad.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.9"}}},
	}
	if err := conf.InitImrEngine(context.Background(), true); err != nil {
		t.Fatalf("InitImrEngine refused to start over one bad forward zone: %v", err)
	}
	imr := conf.Internal.ImrEngine
	if imr == nil {
		t.Fatal("no engine after InitImrEngine")
	}

	bad := imr.forwardZoneFor("www.bad.example.")
	if bad == nil {
		t.Fatal("quarantined zone left the table: names under it would fall back to iteration")
	}
	if !bad.isQuarantined() {
		t.Error("bad.example. is serving; want quarantined")
	}
	good := imr.forwardZoneFor("www.other.example.")
	if good == nil || good.Zone != "." || good.isQuarantined() {
		t.Errorf("the healthy root forward did not survive: %+v", good)
	}

	// And the operator can see it, service-impacting half separated from the
	// still-serving half.
	var sawZone bool
	for _, e := range conf.Internal.ServerErrors.List() {
		if e.Category == ErrCatConfig && e.Subtype == ErrSubImrForwardZone {
			sawZone = true
			if !strings.Contains(e.Message, "bad.example.") {
				t.Errorf("zone-quarantine error does not name the zone: %s", e.Message)
			}
		}
	}
	if !sawZone {
		t.Error("no Config/ImrForwardZone error for a quarantined forward zone")
	}
}

// A quarantined zone answers SERVFAIL without an exchange, and without
// falling back to iteration. The nil Client on the placeholder upstream is
// the proof that nothing dialled: forwardQuery would panic if it tried.
func TestForwardQuarantinedZoneServfailsWithoutDialling(t *testing.T) {
	imr := newReloadTestImr(t)
	forwards, diags := BuildImrForwards([]ImrForwardConf{
		{Zone: "bad.example.", Upstreams: []ImrUpstreamConf{{Addr: "not-an-ip.example.com"}}},
	})
	if len(diags) == 0 {
		t.Fatal("unparseable upstream accepted silently")
	}
	fz := forwards[0]
	if !fz.isQuarantined() {
		t.Fatal("zone with no usable upstream is not quarantined")
	}
	if fz.Upstreams[0].Client != nil {
		t.Fatal("placeholder upstream has a client; this test cannot prove no dial")
	}
	_, rcode, _, _, err := imr.forwardQuery(context.Background(), "www.bad.example.", 1, fz, false, edns0.PrivacyNone)
	if rcode != 2 { // dns.RcodeServerFailure
		t.Errorf("rcode = %d, want SERVFAIL", rcode)
	}
	if err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Errorf("error does not say why the query failed: %v", err)
	}
}

// Reduced redundancy: when one upstream of a trust-ad zone authenticates and
// another does not, the zone keeps serving on the one that does.
func TestForwardQuarantineKeepsTheAuthenticatedUpstream(t *testing.T) {
	forwards, diags := BuildImrForwards([]ImrForwardConf{
		{Zone: "mix.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{
			{Addr: "192.0.2.1", Transport: "dot"},
			{Addr: "192.0.2.2"}, // plaintext: quarantined
		}},
	})
	if len(diags) != 1 {
		t.Fatalf("want exactly one diag, got %v", diags)
	}
	fz := forwards[0]
	if fz.isQuarantined() {
		t.Fatal("zone quarantined although one upstream authenticates")
	}
	live := fz.liveUpstreams()
	if len(live) != 1 || live[0].Transport != core.TransportDoT {
		t.Fatalf("live upstreams = %v, want just the dot one", live)
	}
	// The PRIVACY precheck must not count the quarantined plaintext upstream
	// as encrypted, nor be fooled into thinking there is none.
	if !fz.hasEncryptedUpstream() {
		t.Error("hasEncryptedUpstream false although the live upstream is dot")
	}
}

// The carry across a reload keeps reachability and drops the config verdict.
// upstreamKey has no TrustAD in it, so without adoptQuarantineFrom the
// upstream below keeps a quarantine the new config no longer earns — and the
// zone stays dead after the operator fixed it.
func TestForwardQuarantineNotCarriedAcrossTrustADRemoval(t *testing.T) {
	imr := newReloadTestImr(t)
	withTrustAD := []ImrForwardConf{{
		Zone: "a.example.", TrustAD: true,
		Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1"}},
	}}
	// Startup-shaped: build and publish directly, since ReloadZones refuses
	// this config whole (that asymmetry is TestReloadZonesRejectedConfig...).
	forwards, diags := BuildImrForwards(withTrustAD)
	if len(diags) != 1 || !forwards[0].isQuarantined() {
		t.Fatalf("setup: want a quarantined zone, got diags=%v", diags)
	}
	imr.setZoneTable(forwards, nil, map[string]string{})

	// The operator drops `trust-ad:` and reloads. Same upstream, same key.
	if _, err := imr.ReloadZones(nil, []ImrForwardConf{
		{Zone: "a.example.", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1"}}},
	}); err != nil {
		t.Fatalf("ReloadZones of a fixed config: %v", err)
	}
	fz := imr.forwardZoneFor("www.a.example.")
	if fz == nil {
		t.Fatal("zone gone after the reload")
	}
	if fz.isQuarantined() {
		q, why := fz.quarantineState()
		t.Errorf("stale quarantine carried across the reload: %v (%s)", q, why)
	}
	if len(fz.liveUpstreams()) != 1 {
		t.Errorf("live upstreams = %d, want 1", len(fz.liveUpstreams()))
	}
}

// Quarantine and unreachability are disjoint: a quarantined upstream is never
// dialled, so it must not also be counted into the reachability aggregate —
// even when it was carried across a reload with a stale failing flag.
func TestForwardQuarantinedUpstreamIsNotAlsoUnreachable(t *testing.T) {
	imr := newReloadTestImr(t)
	imr.errorRegistry = NewServerErrorRegistry()
	forwards, _ := BuildImrForwards([]ImrForwardConf{
		{Zone: "mix.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{
			{Addr: "192.0.2.1", Transport: "dot"},
			{Addr: "192.0.2.2"},
		}},
	})
	// Pretend the plaintext upstream had been failing before the config that
	// quarantined it landed.
	forwards[0].Upstreams[1].failing = true
	imr.setZoneTable(forwards, nil, map[string]string{})
	imr.updateForwardUpstreamError()
	imr.updateForwardQuarantineError()

	for _, e := range imr.errorRegistry.List() {
		if e.Category == ErrCatUpstream && e.Subtype == ErrSubImrForward {
			t.Errorf("quarantined upstream reported as unreachable too: %s", e.Message)
		}
	}
	var sawUpstreamCfg bool
	for _, e := range imr.errorRegistry.List() {
		if e.Category == ErrCatConfig && e.Subtype == ErrSubImrForwardUpstream {
			sawUpstreamCfg = true
			if !strings.Contains(e.Message, "reduced redundancy") {
				t.Errorf("still-serving quarantine does not read as non-fatal: %s", e.Message)
			}
		}
	}
	if !sawUpstreamCfg {
		t.Error("no Config/ImrForwardUpstream error for a quarantined upstream on a serving zone")
	}
}

// A reload that fixes the config clears the aggregate the startup path set.
func TestForwardQuarantineAggregateClears(t *testing.T) {
	imr := newReloadTestImr(t)
	imr.errorRegistry = NewServerErrorRegistry()
	forwards, _ := BuildImrForwards([]ImrForwardConf{
		{Zone: "a.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1"}}},
	})
	imr.setZoneTable(forwards, nil, map[string]string{})
	imr.updateForwardQuarantineError()
	if len(imr.errorRegistry.List()) == 0 {
		t.Fatal("setup: no aggregate for a quarantined zone")
	}
	if _, err := imr.ReloadZones(nil, []ImrForwardConf{
		{Zone: "a.example.", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.1"}}},
	}); err != nil {
		t.Fatalf("ReloadZones: %v", err)
	}
	if got := imr.errorRegistry.List(); len(got) != 0 {
		t.Errorf("aggregate survived the reload that fixed the config: %v", got)
	}
}

// `imr forward probe` must report a quarantined upstream instead of dialling
// it. Without the guard this panics: a placeholder upstream has no client.
func TestForwardProbeReportsQuarantinedWithoutDialling(t *testing.T) {
	imr := newReloadTestImr(t)
	forwards, _ := BuildImrForwards([]ImrForwardConf{
		{Zone: "bad.example.", Upstreams: []ImrUpstreamConf{
			{Addr: "not-an-ip.example.com", Transport: "dot"},
		}},
	})
	imr.setZoneTable(forwards, nil, map[string]string{})
	imr.errorRegistry = NewServerErrorRegistry()

	results, err := imr.ProbeForwardUpstreamsReport(context.Background(), "")
	if err != nil {
		t.Fatalf("ProbeForwardUpstreamsReport: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d result(s), want the quarantined upstream reported: %+v", len(results), results)
	}
	if results[0].OK || !strings.Contains(results[0].Error, "quarantined") {
		t.Errorf("quarantined upstream not reported as such: %+v", results[0])
	}
}

// The PRIVACY path must not count a quarantined upstream as available. This
// is the guard for the #474 merge: that branch rewrites hasEncryptedUpstream
// and adds forwardUpstreamsForPrivacy, both of which range fz.Upstreams
// directly. Whichever lands second, the selection has to go through
// liveUpstreams() — otherwise the resolver promises encryption on the
// strength of an upstream it will never dial, and a placeholder's nil Client
// can reach the query loop.
func TestForwardQuarantineExcludedFromPrivacySelection(t *testing.T) {
	forwards, diags := BuildImrForwards([]ImrForwardConf{
		// The only ENCRYPTED upstream is unbuildable; the plaintext one is
		// fine. A zone like this can serve, but never privately.
		{Zone: "half.example.", Upstreams: []ImrUpstreamConf{
			{Addr: "not-an-ip.example.com", Transport: "dot"},
			{Addr: "192.0.2.2"},
		}},
	})
	if len(diags) != 1 {
		t.Fatalf("want one diag for the unbuildable dot upstream, got %v", diags)
	}
	fz := forwards[0]
	if fz.isQuarantined() {
		t.Fatal("zone quarantined although the plaintext upstream is usable")
	}
	if fz.hasEncryptedUpstream() {
		t.Error("hasEncryptedUpstream true on the strength of a quarantined upstream: " +
			"a PRIVACY query would be accepted and then fail")
	}
	// And nothing selectable carries a nil client into the query loop.
	for _, up := range fz.liveUpstreams() {
		if up.Client == nil {
			t.Errorf("liveUpstreams returned %s with a nil client", up.Label)
		}
	}
}

// placeholderUpstream is quarantined at construction, not by its caller:
// an unquarantined placeholder is a nil client on the query path.
func TestPlaceholderUpstreamIsBornQuarantined(t *testing.T) {
	up := placeholderUpstream(ImrUpstreamConf{Addr: "nope.example.com", Transport: "dot"}, "unbuildable")
	q, why := up.quarantineState()
	if !q || why != "unbuildable" {
		t.Errorf("placeholder not quarantined at construction: q=%v why=%q", q, why)
	}
	if up.Client != nil {
		t.Error("placeholder carries a client")
	}
	// The transport survives so `forward status` does not call a broken dot
	// upstream do53.
	if up.Transport != core.TransportDoT {
		t.Errorf("transport = %v, want dot", up.Transport)
	}
}

// R1: pin the DIAL LIST, not just the helpers.
//
// TestForwardQuarantineExcludedFromPrivacySelection pins hasEncryptedUpstream
// and liveUpstreams, but a #474 merge could keep both and still take that
// branch's forwardUpstreamsForPrivacy / PrivacyNone dial list, which is built
// from fz.Upstreams. That merge passes the other test and still hands a
// placeholder's nil Client to the exchange. This test fails on it: the
// quarantined upstream is FIRST in configured order, so anything that dials
// fz.Upstreams reaches it before the usable one.
func TestForwardQueryNeverDialsAQuarantinedUpstream(t *testing.T) {
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()

	forwards, diags := BuildImrForwards([]ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{
			{Addr: "not-an-ip.example.com"}, // unbuildable: placeholder, nil Client
			{Addr: addr, Port: port},        // usable
		}},
	})
	if len(diags) != 1 {
		t.Fatalf("want one diag for the unbuildable upstream, got %v", diags)
	}
	fz := forwards[0]
	if fz.Upstreams[0].Client != nil {
		t.Fatal("first upstream is not the nil-client placeholder; test cannot detect a bad dial list")
	}
	// Deliberately NOT guarded by a nil-Client check in forwardQuery's loop.
	// A guard there would turn this into a silent skip and let a merge ship
	// with quarantined upstreams still in the selection list — where they
	// would keep distorting PrivacyStrict ordering and the "N usable
	// upstreams" the SERVFAIL reports, symptom hidden. The contract is that
	// the dial list comes from liveUpstreams(); breaking it should be loud.
	// (probeForwardUpstream keeps its guard: separate function, separate
	// filter, operator-triggered rather than the query hot path.)
	imr := newReloadTestImr(t)
	imr.setZoneTable(forwards, nil, nil)

	_, _, _, _, err := imr.forwardQuery(context.Background(), "www.fwd.example.", dns.TypeA, fz, false, edns0.PrivacyNone)
	if err != nil {
		t.Fatalf("forwardQuery did not fall through to the usable upstream: %v", err)
	}
	logr.mu.Lock()
	n := len(logr.queries)
	logr.mu.Unlock()
	if n != 1 {
		t.Errorf("live upstream saw %d query(ies), want exactly 1", n)
	}
}
