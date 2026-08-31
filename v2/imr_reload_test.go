/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Reloading stub and forward zones (#436). What these pin down is not just
 * "the new config took effect" but the two properties that make a live
 * reload worth having: an untouched zone keeps its live state, and a rejected
 * config changes nothing at all.
 */

package tdns

import (
	"log"
	"os"
	"sync"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
)

func newReloadTestImr(t *testing.T) *Imr {
	t.Helper()
	lg := log.New(os.Stderr, "test", log.LstdFlags)
	imr := &Imr{
		Cache: cache.NewRRsetCache(lg, false, false),
		Quiet: true,
	}
	imr.setZoneTable(nil, nil, map[string]string{})
	return imr
}

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

func findZone(imr *Imr, zone string) *ForwardZone {
	for _, fz := range imr.ForwardZones() {
		if fz.Zone == zone {
			return fz
		}
	}
	return nil
}

// TestReloadZonesForwardDiff: adding one forward zone must not disturb the
// other, and the diff must name what actually changed.
func TestReloadZonesForwardDiff(t *testing.T) {
	imr := newReloadTestImr(t)
	if _, err := imr.ReloadZones(nil, []ImrForwardConf{
		fwdConf("a.example.", "192.0.2.1", 0),
		fwdConf("b.example.", "192.0.2.2", 0),
	}); err != nil {
		t.Fatalf("initial ReloadZones: %v", err)
	}

	// The live object for a.example.'s upstream, with some accumulated state.
	before := findZone(imr, "a.example.").Upstreams[0]
	before.recordSuccess()

	res, err := imr.ReloadZones(nil, []ImrForwardConf{
		fwdConf("a.example.", "192.0.2.1", 0),    // untouched
		fwdConf("b.example.", "192.0.2.2", 5353), // edited: different port
		fwdConf("c.example.", "192.0.2.3", 0),    // added
	})
	if err != nil {
		t.Fatalf("ReloadZones: %v", err)
	}

	if got := res.ForwardsAdded; len(got) != 1 || got[0] != "c.example." {
		t.Errorf("ForwardsAdded = %v, want [c.example.]", got)
	}
	if got := res.ForwardsChanged; len(got) != 1 || got[0] != "b.example." {
		t.Errorf("ForwardsChanged = %v, want [b.example.]", got)
	}
	if len(res.ForwardsRemoved) != 0 {
		t.Errorf("ForwardsRemoved = %v, want none", res.ForwardsRemoved)
	}

	// The untouched upstream must be the SAME object: its reachability
	// counters and its DNS client survive a reload of its neighbours.
	after := findZone(imr, "a.example.").Upstreams[0]
	if after != before {
		t.Errorf("untouched upstream was rebuilt; its counters and client were lost")
	}
	if after.queries == 0 {
		t.Errorf("untouched upstream lost its query counter across the reload")
	}
	// The edited one must NOT be, or it would keep a client dialling the old port.
	if findZone(imr, "b.example.").Upstreams[0].Port != "5353" {
		t.Errorf("edited upstream kept its old port")
	}

	// Removal.
	res, err = imr.ReloadZones(nil, []ImrForwardConf{fwdConf("a.example.", "192.0.2.1", 0)})
	if err != nil {
		t.Fatalf("ReloadZones (removal): %v", err)
	}
	if got := res.ForwardsRemoved; len(got) != 2 || got[0] != "b.example." || got[1] != "c.example." {
		t.Errorf("ForwardsRemoved = %v, want [b.example. c.example.]", got)
	}
	if len(imr.ForwardZones()) != 1 {
		t.Errorf("forward table has %d zones after removal, want 1", len(imr.ForwardZones()))
	}
}

// TestReloadZonesRejectedConfigChangesNothing: a forward table that fails
// validation must leave the running one exactly as it was.
func TestReloadZonesRejectedConfigChangesNothing(t *testing.T) {
	imr := newReloadTestImr(t)
	if _, err := imr.ReloadZones(nil, []ImrForwardConf{fwdConf("a.example.", "192.0.2.1", 0)}); err != nil {
		t.Fatalf("initial ReloadZones: %v", err)
	}
	before := imr.ForwardZones()

	// trust-ad over a plaintext upstream: refused by BuildImrForwards.
	_, err := imr.ReloadZones(nil, []ImrForwardConf{
		fwdConf("a.example.", "192.0.2.1", 0),
		{Zone: "bad.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.9"}}},
	})
	if err == nil {
		t.Fatalf("ReloadZones accepted trust-ad over a plaintext upstream")
	}
	if len(imr.ForwardZones()) != 1 || imr.ForwardZones()[0] != before[0] {
		t.Errorf("a refused reload changed the running forward table")
	}
}

// TestReloadZonesStubs: added, edited, untouched and removed stubs, and what
// each does to the cache's server map.
func TestReloadZonesStubs(t *testing.T) {
	imr := newReloadTestImr(t)
	res, err := imr.ReloadZones([]ImrStubConf{
		stubConf("keep.example.", "ns.keep.example.", "192.0.2.1"),
		stubConf("edit.example.", "ns.edit.example.", "192.0.2.2"),
		stubConf("drop.example.", "ns.drop.example.", "192.0.2.3"),
	}, nil)
	if err != nil {
		t.Fatalf("initial ReloadZones: %v", err)
	}
	if len(res.StubsAdded) != 3 {
		t.Fatalf("StubsAdded = %v, want three zones", res.StubsAdded)
	}

	// Live state on the untouched stub's server: a reload must not reset it.
	keep, ok := imr.Cache.ServerMapCopy("keep.example.")
	if !ok {
		t.Fatalf("stub keep.example. did not reach the server map")
	}
	keepServer := keep[cache.ServerKey("ns.keep.example.")]
	if keepServer == nil {
		t.Fatalf("stub server missing from the server map")
	}
	keepServer.IncrementTransportCounter(core.TransportDo53)

	res, err = imr.ReloadZones([]ImrStubConf{
		stubConf("keep.example.", "ns.keep.example.", "192.0.2.1"),
		stubConf("edit.example.", "ns.edit.example.", "192.0.2.99"), // new address
		stubConf("new.example.", "ns.new.example.", "192.0.2.4"),
	}, nil)
	if err != nil {
		t.Fatalf("ReloadZones: %v", err)
	}
	if got := res.StubsAdded; len(got) != 1 || got[0] != "new.example." {
		t.Errorf("StubsAdded = %v, want [new.example.]", got)
	}
	if got := res.StubsChanged; len(got) != 1 || got[0] != "edit.example." {
		t.Errorf("StubsChanged = %v, want [edit.example.]", got)
	}
	if got := res.StubsRemoved; len(got) != 1 || got[0] != "drop.example." {
		t.Errorf("StubsRemoved = %v, want [drop.example.]", got)
	}

	// Untouched: same AuthServer instance, counter intact.
	keep2, _ := imr.Cache.ServerMapCopy("keep.example.")
	if keep2[cache.ServerKey("ns.keep.example.")] != keepServer {
		t.Errorf("untouched stub was rebuilt; its counters and backoffs were lost")
	}
	// Edited: the new address is live.
	edited, _ := imr.Cache.ServerMapCopy("edit.example.")
	if srv := edited[cache.ServerKey("ns.edit.example.")]; srv == nil || len(srv.Addrs) != 1 || srv.Addrs[0] != "192.0.2.99" {
		t.Errorf("edited stub did not pick up its new address: %+v", srv)
	}
	// Removed: gone from both the table and the server map.
	if _, still := imr.Cache.ServerMapCopy("drop.example."); still {
		t.Errorf("removed stub is still in the server map")
	}
	for _, z := range imr.StubZones() {
		if z == "drop.example." {
			t.Errorf("removed stub is still in the stub table")
		}
	}
}

// TestReloadZonesStubBeatsForward: the reloaded stub list must feed the
// forward decision, not just the status output.
func TestReloadZonesStubBeatsForward(t *testing.T) {
	imr := newReloadTestImr(t)
	if _, err := imr.ReloadZones(nil, []ImrForwardConf{fwdConf(".", "192.0.2.1", 0)}); err != nil {
		t.Fatalf("ReloadZones: %v", err)
	}
	if fz := imr.forwardZoneFor("host.internal.example."); fz == nil {
		t.Fatalf("root forward did not catch host.internal.example.")
	}
	if _, err := imr.ReloadZones(
		[]ImrStubConf{stubConf("internal.example.", "ns.internal.example.", "192.0.2.5")},
		[]ImrForwardConf{fwdConf(".", "192.0.2.1", 0)},
	); err != nil {
		t.Fatalf("ReloadZones: %v", err)
	}
	if fz := imr.forwardZoneFor("host.internal.example."); fz != nil {
		t.Errorf("newly stubbed name is still forwarded to %s", fz.Zone)
	}
}

// TestImrRestartRequiredKeys: an edit the reload cannot apply must be
// reported, not silently ignored.
func TestImrRestartRequiredKeys(t *testing.T) {
	boot := ImrEngineConf{
		RootHints:       "/etc/tdns/root.hints",
		TrustAnchorFile: "/etc/tdns/anchors",
		Tuning:          ImrTuningConf{QueryBudget: 10 * time.Second},
	}

	// Stubs and forwards are reloadable: changing them requires no restart.
	reloadable := boot
	reloadable.Stubs = []ImrStubConf{stubConf("a.example.", "ns.a.example.", "192.0.2.1")}
	reloadable.Forward = []ImrForwardConf{fwdConf("b.example.", "192.0.2.2", 0)}
	if keys := imrRestartRequiredKeys(boot, reloadable); len(keys) != 0 {
		t.Errorf("stub/forward edits reported as needing a restart: %v", keys)
	}

	changed := boot
	changed.TrustAnchorFile = "/etc/tdns/anchors.new"
	changed.Tuning.QueryBudget = 30 * time.Second
	keys := imrRestartRequiredKeys(boot, changed)
	want := map[string]bool{"imrengine.trust-anchor-file": true, "imrengine.tuning": true}
	if len(keys) != len(want) {
		t.Fatalf("RestartRequired = %v, want %v", keys, want)
	}
	for _, k := range keys {
		if !want[k] {
			t.Errorf("unexpected key %q", k)
		}
	}
}

// TestReloadZonesConcurrentWithReaders is the claim the whole design rests
// on: a reload swaps a table that readers hold snapshots of, so a query
// choosing a route while a reload lands must never observe a torn table.
// Meaningful under -race.
func TestReloadZonesConcurrentWithReaders(t *testing.T) {
	imr := newReloadTestImr(t)
	if _, err := imr.ReloadZones(nil, []ImrForwardConf{fwdConf(".", "192.0.2.1", 0)}); err != nil {
		t.Fatalf("initial ReloadZones: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Both halves of the decision: the forward table and the
				// stub list that can veto it.
				_ = imr.forwardZoneFor("host.internal.example.")
				_ = imr.StubZones()
				_ = imr.StatusReport()
			}
		}()
	}

	for i := 0; i < 50; i++ {
		stubs := []ImrStubConf{stubConf("internal.example.", "ns.internal.example.", "192.0.2.5")}
		if i%2 == 0 {
			stubs = nil
		}
		if _, err := imr.ReloadZones(stubs, []ImrForwardConf{
			fwdConf(".", "192.0.2.1", uint16(1000+i)),
		}); err != nil {
			t.Errorf("ReloadZones: %v", err)
			break
		}
	}
	close(stop)
	wg.Wait()
}

// TestStubZoneWithoutTrailingDot: a stub configured as "internal.example"
// must work exactly like "internal.example.".
//
// It did not. ServerMap canonicalises case but NOT absoluteness — a relative
// name and its FQDN are different keys — and AddStub used to be handed the
// raw config string. So the servers went in under "internal.example" while
// every lookup asks for "internal.example.", and the stub resolved nothing.
// The stub list, which HAS always been FQDN-ified, meanwhile still let that
// stub veto a forward zone covering the same names: the one thing the dead
// stub could still do was break forwarding.
func TestStubZoneWithoutTrailingDot(t *testing.T) {
	imr := newReloadTestImr(t)
	relative := ImrStubConf{
		Zone:    "internal.example", // no trailing dot, as a config file may well say
		Servers: []cache.AuthServer{{Name: "ns.internal.example.", Addrs: []string{"192.0.2.5"}, Alpn: []string{"do53"}}},
	}
	if _, err := imr.ReloadZones([]ImrStubConf{relative}, nil); err != nil {
		t.Fatalf("ReloadZones: %v", err)
	}
	sm, ok := imr.Cache.ServerMapCopy("internal.example.")
	if !ok || len(sm) != 1 {
		t.Fatalf("stub servers are not reachable under the FQDN: found=%v n=%d", ok, len(sm))
	}
	if zones := imr.StubZones(); len(zones) != 1 || zones[0] != "internal.example." {
		t.Errorf("StubZones = %v, want [internal.example.]", zones)
	}
}
