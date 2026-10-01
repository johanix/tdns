/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"log"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Step 3, after the reviews of #884: what follows a deferred publish is
// registered with the stage, under the same lock; the resolver's view of a
// changed delegation is dropped after the publish, not at the stage; a refresh
// does not take a staged change the zone could not publish; the management API
// waits the one bound.

// The follow-up of a deferred update is registered with the stage, under the
// lock the stage ran under, so that no publish can come between the two. It
// runs once, after the publish that carries the change.
func TestTheFollowUpIsRegisteredWithTheStage(t *testing.T) {
	const zone = "followup.gate.example."
	zd, kdb := busyZone(t, zone, 700*time.Millisecond)
	var ran atomic.Bool
	ur := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: zone, InternalUpdate: true,
		Actions: []dns.RR{mustRR(t, "a."+zone+" 300 IN TXT \"one\"")}}
	updated, deferred, err := zd.applyZoneUpdate(ur, kdb, func() { ran.Store(true) })
	if err != nil || !updated || !deferred {
		t.Fatalf("applyZoneUpdate on a busy zone: updated=%v deferred=%v err=%v", updated, deferred, err)
	}
	zd.mu.Lock()
	registered := len(zd.afterPublish)
	zd.mu.Unlock()
	if registered == 0 {
		t.Fatal("the follow-up was not registered by the time the stage returned")
	}
	if ran.Load() {
		t.Fatal("the follow-up ran before the publish")
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool { return served(zd, "a."+zone, dns.TypeTXT) })
	waitFor(t, 3*time.Second, "the follow-up after the publish", func() bool { return ran.Load() })
}

// The resolver's view of a delegation the update changed is dropped after the
// publish that carries the change (#694 under the gate): dropped at the stage,
// a lookup in the window before the publish would cache the old delegation
// again, for its TTL.
func TestTheResolverViewIsDroppedAfterTheDeferredPublish(t *testing.T) {
	const zone = "parent.gate.example."
	const child = "kid." + zone
	rrcache := cache.NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)
	saved := Globals.ImrEngine
	Globals.ImrEngine = &Imr{Cache: rrcache}
	t.Cleanup(func() { Globals.ImrEngine = saved })
	soa := &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeSOA,
		RRs: []dns.RR{mustRR(t, zone+" 900 IN SOA ns."+zone+" h."+zone+" 1 1800 900 604800 900")}}
	rrcache.Set(child, dns.TypeDS, &cache.CachedRRset{Name: child, RRtype: dns.TypeDS, RRset: soa,
		Context: cache.ContextNoErrNoAns, State: cache.ValidationStateSecure, Expiration: time.Now().Add(15 * time.Minute)})

	zd, kdb := busyZone(t, zone, 700*time.Millisecond)
	ur := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: zone, InternalUpdate: true,
		Actions: []dns.RR{mustRR(t, child+" 3600 IN DS 12345 15 2 8BE06F4F1E2DE81BD1A9D0A29C7C79C3E43D83C1C1A6E1E6CA0A77F6CD8D0B0E")}}
	updated, deferred, err := zd.applyZoneUpdate(ur, kdb, nil)
	if err != nil || !updated || !deferred {
		t.Fatalf("applyZoneUpdate on a busy zone: updated=%v deferred=%v err=%v", updated, deferred, err)
	}
	if rrcache.Get(child, dns.TypeDS) == nil {
		t.Fatal("the resolver's pre-DS denial was dropped at the stage, before the DS is served")
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool { return served(zd, child, dns.TypeDS) })
	waitFor(t, 3*time.Second, "the resolver's view to be dropped after the publish", func() bool {
		return rrcache.Get(child, dns.TypeDS) == nil
	})
}

// A local change the zone could not publish (signing refused it) stays staged
// for the pass that can; a transfer meanwhile is refused and retried shortly,
// rather than taking that change with the replacement.
func TestARefreshDoesNotTakeAStagedChangeItCannotPublish(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	withCompleteness(t, CompletenessStrict)
	srSigning(t, zd, false)
	local := ovCDS(t, 5)
	_ = ovUpdate(t, zd, local) // refused at the publish: the change stays staged
	zd.mu.Lock()
	staged := zd.workingSet != nil && !zd.wsFromReplacement
	zd.mu.Unlock()
	if !staged {
		t.Fatal("precondition: the change was not left staged by the refused publish")
	}
	if ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), local) {
		t.Fatal("precondition: the change was published")
	}
	served := ovServedSerial(t, zd)

	_, addr, stop := ixfrTestPrimary(t, ovUpstreamZone(20, srFresh))
	defer stop()
	zd.mu.Lock()
	zd.Upstreams = []PeerConf{{Addr: addr}}
	zd.mu.Unlock()
	_, err := zd.FetchFromUpstream(context.Background(), false, false, true, zd.CollectDynamicRRs(&Config{}), &Config{})
	if !errors.Is(err, ErrRefreshStaged) {
		t.Fatalf("a refresh over a staged change the zone cannot publish: err=%v, want ErrRefreshStaged", err)
	}
	if got := ovServedSerial(t, zd); got != served {
		t.Errorf("the refused refresh changed the served serial %d -> %d", served, got)
	}
	zd.mu.Lock()
	staged = zd.workingSet != nil && !zd.wsFromReplacement
	zd.mu.Unlock()
	if !staged {
		t.Fatal("the refused refresh took the staged change")
	}
	if got := nextRefreshAfterFailure(&RefreshCounter{Name: zd.ZoneName, SOARefresh: 3600, SOARetry: 900}, err); got != refreshHeldRetrySeconds {
		t.Errorf("the next attempt is in %d s, want %d", got, refreshHeldRetrySeconds)
	}

	// Signing works again: the retried refresh publishes the change first,
	// then lands; the overlay keeps the change.
	srSigning(t, zd, true)
	ovTransferFrom(t, zd, addr, true)
	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), local) {
		t.Error("the local change is not served after the retried refresh")
	}
	if !ovHas(ovServed(t, zd, "fresh.example.", dns.TypeA), mustRR(t, srFresh)) {
		t.Error("the retried refresh did not land")
	}
	if deltas := ovJournal(t, zd); len(deltas) != 1 {
		t.Errorf("journal has %d delta(s), want 1 (the local change):%s", len(deltas), ovJournalString(deltas))
	}
}

// The management API waits the one bound, max(UpdateApplyTimeout, 2 x cadence):
// on a zone whose cadence is longer than UpdateApplyTimeout the answer comes
// after UpdateApplyTimeout, and the API must still be there to take it. This
// test waits one such cadence.
func TestTheApiWaitsTheOneBound(t *testing.T) {
	const zone = "apibound.gate.example."
	zd, kdb := busyZone(t, zone, UpdateApplyTimeout+time.Second)
	startTxUpdater(t, kdb)
	ur := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: zone, InternalUpdate: true,
		Actions: []dns.RR{mustRR(t, "a."+zone+" 300 IN TXT \"one\"")}}
	start := time.Now()
	res, err := zd.queueApiZoneUpdate(context.Background(), ur, "addrr")
	took := time.Since(start)
	if err != nil {
		t.Fatalf("after %v: %v", took, err)
	}
	if !res.Applied || res.Err != nil {
		t.Fatalf("after %v: applied=%v err=%v", took, res.Applied, res.Err)
	}
	if took < UpdateApplyTimeout {
		t.Errorf("answered after %v: the zone was not busy for the whole cadence", took)
	}
	if !served(zd, "a."+zone, dns.TypeTXT) {
		t.Error("answered, but the change is not served")
	}
}
