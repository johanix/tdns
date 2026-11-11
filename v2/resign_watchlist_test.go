/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// watchedTestZone is a zone signed here, published and in Zones, and not on the
// renewal watchlist: what a first load leaves before its OnFirstLoad callbacks
// run.
func watchedTestZone(t *testing.T, name string) *ZoneData {
	t.Helper()
	zd, _ := signedTestZone(t, name, fmt.Sprintf(`%[1]s	3600	IN	SOA	ns.%[1]s hostmaster.%[1]s 1 7200 1800 604800 300
%[1]s	3600	IN	NS	ns.%[1]s
ns.%[1]s	3600	IN	A	10.0.0.1
`, name), false)
	// Never walked by a renewal pass, so renewed() means this test's pass.
	zd.setResignSchedule(time.Time{}, 0)
	return zd
}

// renewed reports whether a renewal pass has walked zd: RenewZoneSignatures
// records when the zone is next due, and nothing else does.
func renewed(zd *ZoneData) bool {
	_, ok := zd.resignDue()
	return ok
}

// emptyResignWake empties the wake slot, which any registration fills, before
// the test and after it.
func emptyResignWake(t *testing.T) {
	t.Helper()
	drain := func() {
		select {
		case <-resignWake:
		default:
		}
	}
	drain()
	t.Cleanup(drain)
}

// TestRegistrationDoesNotWaitForABusyResigner is #1033. The resigner is one
// goroutine, and while it replaces a zone's signatures or sweeps, nothing reads
// its queue. Registration used to be a send on that queue, bounded at two
// seconds, so a zone that loaded during a long pass timed out, was never put on
// the watchlist, and had its signatures expire.
//
// Here a pass is stuck on a zone whose lock is held, and twenty zones register
// meanwhile.
func TestRegistrationDoesNotWaitForABusyResigner(t *testing.T) {
	emptyResignWake(t)
	busy := watchedTestZone(t, "busy.example.")
	busy.KeepRenewed()
	var zones []*ZoneData
	for i := 0; i < 20; i++ {
		zones = append(zones, watchedTestZone(t, fmt.Sprintf("z%02d.example.", i)))
	}

	busy.mu.Lock()
	passDone := make(chan struct{})
	go func() {
		defer close(passDone)
		resignPass(context.Background(), map[string]*ZoneData{busy.ZoneName: busy})
	}()

	start := time.Now()
	for _, zd := range zones {
		zd.registerForPeriodicResign()
	}
	elapsed := time.Since(start)
	busy.mu.Unlock()
	<-passDone

	if elapsed > time.Second {
		t.Errorf("20 registrations took %s while the resigner was busy; registration must not wait for it", elapsed)
	}
	if !renewed(busy) {
		t.Error("the pass that was held up never renewed the zone it was waiting for")
	}

	candidates := resignCandidates(Zones.Items())
	mine := make(map[string]*ZoneData)
	for _, zd := range zones {
		if candidates[zd.ZoneName] != zd {
			t.Errorf("%s registered while the resigner was busy and is not on the watchlist;"+
				" nothing would renew its signatures", zd.ZoneName)
			continue
		}
		mine[zd.ZoneName] = zd
	}
	resignPass(context.Background(), mine)
	for _, zd := range zones {
		if !renewed(zd) {
			t.Errorf("%s was not renewed by the pass after it registered", zd.ZoneName)
		}
	}
}

// A zone removed from Zones leaves the watchlist with it. The list this replaced
// kept every ZoneData it was ever handed, and renewed (and published) a removed
// zone for the life of the process.
func TestARemovedZoneLeavesTheWatchlist(t *testing.T) {
	zd := watchedTestZone(t, "removed.example.")
	zd.KeepRenewed()
	if resignCandidates(Zones.Items())[zd.ZoneName] != zd {
		t.Fatal("test setup: the zone is not on the watchlist")
	}

	Zones.Remove(zd.ZoneName)

	if _, ok := resignCandidates(Zones.Items())[zd.ZoneName]; ok {
		t.Error("a zone removed from Zones is still on the watchlist")
	}
}

// A zone replaced by a new ZoneData, as ModifyDynamicZone does, is renewed as the
// live copy and only once that copy registers. The old one stops being renewed
// at the replacement, and comes back if the replacement is rolled back.
func TestAReplacedZoneIsRenewedAsTheLiveCopy(t *testing.T) {
	const name = "replaced.example."
	old := watchedTestZone(t, name)
	old.KeepRenewed()
	repl := watchedTestZone(t, name) // now the live copy, not registered

	if got, ok := resignCandidates(Zones.Items())[name]; ok {
		t.Errorf("after the replacement the watchlist renews %p (old %p, new %p): the old copy"+
			" is no longer served, and the new one has not registered", got, old, repl)
	}

	repl.KeepRenewed()
	if got := resignCandidates(Zones.Items())[name]; got != repl {
		t.Errorf("the registered replacement is not what the watchlist renews: got %p, want %p", got, repl)
	}

	Zones.Set(name, old) // ModifyDynamicZone's rollback
	if got := resignCandidates(Zones.Items())[name]; got != old {
		t.Errorf("after a rollback the watchlist does not renew the restored zone: got %p, want %p", got, old)
	}
}

// A key-state request that was dropped is honoured on a zone that never
// registered. On main such a zone was owed a replace that no pass looked for,
// because the pass only walked the watchlist.
func TestADroppedTriggerOnAnUnregisteredZoneIsStillHonoured(t *testing.T) {
	zd, _, oldTag := rolledZone(t)
	conf := triggerResignConf(t, zd, 0) // nobody can take the request

	triggerResign(conf, zd.ZoneName)

	if resignCandidates(Zones.Items())[zd.ZoneName] != zd {
		t.Fatal("a zone owed a replace is not picked up by the resigner's pass")
	}
	resignPass(context.Background(), map[string]*ZoneData{zd.ZoneName: zd})
	if hasKeytag(zd.mustRRSIGKeytags(t, signedName, dns.TypeA), oldTag) {
		t.Errorf("a signature by the retired key %d survived the pass", oldTag)
	}
}

// Registering a zone wakes the resigner, since a new zone has no renewal
// estimate and the resigner may be asleep for up to resignSafetyTick. The wake
// never blocks: a full slot already means a wake is owed.
func TestRegistrationWakesTheResignerWithoutWaiting(t *testing.T) {
	emptyResignWake(t)
	a := watchedTestZone(t, "wake-a.example.")
	b := watchedTestZone(t, "wake-b.example.")

	a.KeepRenewed()
	if len(resignWake) != 1 {
		t.Fatal("registering a zone did not wake the resigner")
	}

	done := make(chan struct{})
	go func() {
		b.KeepRenewed()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a registration waited on a full wake slot")
	}
	if !b.keepSigned.Load() {
		t.Error("the registration that found the wake slot full did not put the zone on the watchlist")
	}

	<-resignWake
	a.KeepRenewed()
	if len(resignWake) != 0 {
		t.Error("registering a zone already on the watchlist woke the resigner again")
	}
}

// A zone is not renewed because its options say it signs. A relayed copy can
// arrive from upstream with inline-signing on (#995), and renewing it would
// re-sign an upstream's zone that this server has not been told to sign.
func TestAZoneIsNotRenewedOnItsOptionsAlone(t *testing.T) {
	zd := watchedTestZone(t, "relayed.example.")
	if !zd.Options[OptInlineSigning] {
		t.Fatal("test setup: the zone does not carry inline-signing")
	}
	if _, ok := resignCandidates(Zones.Items())[zd.ZoneName]; ok {
		t.Error("a zone that never registered and owes nothing is on the watchlist")
	}
}
