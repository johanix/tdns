/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// triggerResignConf wires just enough Config for triggerResign, with a ResignQ
// of the given depth. Depth 0 is a queue that can never accept a non-blocking
// send -- the "full queue" case.
func triggerResignConf(t *testing.T, zd *ZoneData, depth int) *Config {
	t.Helper()
	conf := &Config{}
	conf.Internal.ResignQ = make(chan ResignRequest, depth)
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
	return conf
}

// TestRenewalCannotStandInForAKeyStateResign is the premise everything below
// rests on: after a rollover the published signatures are VALID and merely made
// by the wrong key, so the renewal pass -- which only looks at how soon a
// signature expires -- finds nothing to do and leaves them there.
//
// If this ever stops holding, the pending-replace machinery is unnecessary.
func TestRenewalCannotStandInForAKeyStateResign(t *testing.T) {
	zd, kdb, oldTag := rolledZone(t)

	if _, err := zd.RenewZoneSignatures(context.Background(), kdb); err != nil {
		t.Fatalf("RenewZoneSignatures: %v", err)
	}

	if !hasKeytag(zd.mustRRSIGKeytags(t, signedName, dns.TypeA), oldTag) {
		t.Skip("renewal now replaces signatures by a retired key; the pending-replace" +
			" flag exists because it did not, and that decision should be revisited")
	}
}

// TestADroppedResignTriggerIsNotLost. triggerResign's send is non-blocking --
// it has sixteen call sites, several inside rollover state machines, and none
// of them can afford to wait on a busy resigner. The drop used to lose the
// request outright, under a log line promising the next cycle would handle it.
// It would not: see TestRenewalCannotStandInForAKeyStateResign.
func TestADroppedResignTriggerIsNotLost(t *testing.T) {
	zd, _, _ := rolledZone(t)
	conf := triggerResignConf(t, zd, 0) // nobody can take it

	triggerResign(conf, zd.ZoneName)

	if len(conf.Internal.ResignQ) != 0 {
		t.Fatal("test setup: the request was queued, so nothing was dropped")
	}
	if !zd.resignPendingSet() {
		t.Error("the trigger was dropped and left no trace; the zone keeps serving" +
			" signatures by a key that is no longer active, and renewal will not notice")
	}
}

// The next resigner pass is where a dropped trigger gets picked up, so the
// sweep has to act on the flag rather than only renew.
func TestTheResignerSweepPicksUpADroppedTrigger(t *testing.T) {
	zd, _, oldTag := rolledZone(t)
	conf := triggerResignConf(t, zd, 0)

	triggerResign(conf, zd.ZoneName)
	resignSweepZone(context.Background(), zd)

	tags := zd.mustRRSIGKeytags(t, signedName, dns.TypeA)
	if len(tags) == 0 {
		t.Fatal("the RRset came out unsigned")
	}
	if hasKeytag(tags, oldTag) {
		t.Errorf("a signature by the retired key %d survived the sweep that was supposed"+
			" to pick up the dropped trigger: %v", oldTag, tags)
	}
	if zd.resignPendingSet() {
		t.Error("the replace succeeded but the zone is still marked as owing one;" +
			" every later sweep would redo it")
	}
}

// A delivered trigger that then FAILS inside the resigner is the other half.
// Clearing the flag on entry and walking away would lose the request just as
// thoroughly as the dropped send did.
func TestAFailedReplaceStaysOwed(t *testing.T) {
	zd, _, _ := rolledZone(t)
	zd.markResignPending()

	// A zone in DnssecError is the realistic shape: ResignZone refuses outright
	// rather than signing with something it does not trust.
	zd.SetError(DnssecError, "injected: signing is broken for this zone")
	zd.replaceSignaturesNow(context.Background())

	if !zd.resignPendingSet() {
		t.Error("a failed replace cleared the flag; the zone would go on serving" +
			" signatures by a retired key with nothing left to retry it")
	}
}

// A zone that does not sign its own content can never satisfy the flag, so
// holding it would make every sweep for the rest of the process retry it.
func TestAZoneThatDoesNotSignDropsTheClaim(t *testing.T) {
	zd, _, _ := rolledZone(t)
	zd.Options[OptOnlineSigning] = false
	zd.Options[OptInlineSigning] = false
	zd.markResignPending()

	zd.replaceSignaturesNow(context.Background())

	if zd.resignPendingSet() {
		t.Error("a non-signing zone stayed marked; nothing will ever clear it")
	}
}

// An owed replace must not be slept through. The renewal estimate says when a
// signature next AGES, which after a rollover can be a fortnight away -- and
// resignSafetyTick would still put the engine to sleep for an hour.
func TestTheSchedulerDoesNotSleepOnAnOwedReplace(t *testing.T) {
	const floor = 60 * time.Second

	zd := &ZoneData{
		ZoneName: "owed.example.",
		Options:  map[ZoneOption]bool{OptInlineSigning: true},
	}
	snap := &zoneSnapshot{Serial: 7}
	zd.snapshot.Store(snap)
	zd.setResignSchedule(time.Now().Add(14*24*time.Hour), snap.Serial)
	zones := map[string]*ZoneData{"owed": zd}

	if got := nextResignWake(zones, floor); got != resignSafetyTick {
		t.Fatalf("test setup: wake is %s, expected the safety tick with nothing owed", got)
	}

	zd.markResignPending()

	if got := nextResignWake(zones, floor); got != floor {
		t.Errorf("slept %s with a replace owed, want the floor %s: the zone is serving"+
			" signatures by a key that is no longer active", got, floor)
	}
}

// countStagedZsks returns how many ZSKs the maintainer has minted. A generated
// key is staged as PUBLISHED, not standby -- it has to propagate before it can
// become one -- so PUBLISHED is where the loop's output lands.
func countStagedZsks(t *testing.T, kdb *KeyDB, zoneName string) int {
	t.Helper()
	keys, err := GetDnssecKeysByState(kdb, zoneName, DnskeyStatePublished)
	if err != nil {
		t.Fatalf("GetDnssecKeysByState: %v", err)
	}
	return countKeysForMaintain(keys, 256, dns.ED25519, false)
}

// TestStandbyKeyGenerationStopsOnCancellation. Generating a keypair is
// unbounded work -- seconds each for a large RSA key, worse for the PQ
// algorithms -- and this loop mints one per missing standby key, for every
// signing zone on the server. Without a context check it went on minting them
// right through shutdown.
//
// Cancelled before the call rather than mid-flight: the contract is that the
// check is consulted at all, and a timing race would make the test flaky
// without making it stronger.
func TestStandbyKeyGenerationStopsOnCancellation(t *testing.T) {
	zd, kdb, _ := rolledZone(t)
	conf := triggerResignConf(t, zd, 4)

	before := countStagedZsks(t, kdb, zd.ZoneName)
	if before != 0 {
		t.Fatalf("test setup: %d ZSKs already in the pipeline, so the maintainer would"+
			" return before it reached the generation loop", before)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	maintainStandbyKeysForType(ctx, conf, kdb, zd.ZoneName, dns.ED25519, "ZSK", 256, 2, false)

	if got := countStagedZsks(t, kdb, zd.ZoneName); got != before {
		t.Errorf("generated %d keys after cancellation; shutdown waits out every one of them",
			got-before)
	}
}

// The other half: the check must stop generation on cancellation and nothing
// else. A guard that never lets the loop run would pass the test above.
func TestStandbyKeyGenerationStillRunsWhenLive(t *testing.T) {
	zd, kdb, _ := rolledZone(t)
	conf := triggerResignConf(t, zd, 4)

	before := countStagedZsks(t, kdb, zd.ZoneName)
	maintainStandbyKeysForType(context.Background(), conf, kdb, zd.ZoneName, dns.ED25519, "ZSK", 256, 1, false)

	if got := countStagedZsks(t, kdb, zd.ZoneName); got <= before {
		t.Errorf("standby ZSKs went %d -> %d; the zone is short of the configured count", before, got)
	}
}

// The per-zone walk takes the same check, and it is not made redundant by the
// one inside the generator: the rest of the loop body still runs. In relaxed
// mode that includes capStandbyZsksByCount, which DELETES surplus standby ZSKs.
// A shutdown should not get halfway through a deletion sweep across every zone
// on the server.
func TestStandbyMaintenanceStopsBetweenZonesOnCancellation(t *testing.T) {
	zd, kdb, _ := rolledZone(t)
	conf := triggerResignConf(t, zd, 4)
	zd.DnssecPolicy.ZSKAlgorithm = dns.ED25519

	prev := Conf.Internal.Completeness
	Conf.Internal.Completeness = CompletenessRelaxed
	t.Cleanup(func() { Conf.Internal.Completeness = prev })

	// Two standby ZSKs against a cap of one: the surplus is what the cap
	// deletes, and what a cancelled walk must leave alone.
	for i := 0; i < 2; i++ {
		if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateStandby,
			dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
			t.Fatalf("generate standby ZSK: %v", err)
		}
	}
	before := countStandbyZsks(t, kdb, zd.ZoneName)
	if before != 2 {
		t.Fatalf("test setup: %d standby ZSKs, want 2", before)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	maintainStandbyKeys(ctx, conf, kdb, 1, 0)

	if got := countStandbyZsks(t, kdb, zd.ZoneName); got != before {
		t.Errorf("standby ZSKs went %d -> %d after cancellation; the walk carried on"+
			" into the relaxed-mode deletion sweep", before, got)
	}
}

// countStandbyZsks returns how many standby ZSKs the zone has, any algorithm --
// which is what the relaxed-mode cap counts.
func countStandbyZsks(t *testing.T, kdb *KeyDB, zoneName string) int {
	t.Helper()
	keys, err := GetDnssecKeysByState(kdb, zoneName, DnskeyStateStandby)
	if err != nil {
		t.Fatalf("GetDnssecKeysByState: %v", err)
	}
	n := 0
	for _, k := range keys {
		if k.Flags == 256 {
			n++
		}
	}
	return n
}

// TestTheResignerPassesRefuseToStartOnACancelledContext.
//
// ResignZone and RenewZoneSignatures both walk a zone and can sign a share of
// it while holding zd.mu. Neither took a context, so a root cancellation could
// not stop a pass and shutdown waited for work proportional to the zone.
//
// Refusing rather than truncating, for the same reason the signing walk does:
// a pass abandoned half way has staged signatures that must not be published,
// and the error is what refuses the publish.
func TestTheResignerPassesRefuseToStartOnACancelledContext(t *testing.T) {
	zd, kdb, _ := rolledZone(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := zd.RenewZoneSignatures(ctx, kdb); err == nil {
		t.Error("RenewZoneSignatures started a pass on a cancelled context")
	} else if !errors.Is(err, context.Canceled) {
		t.Errorf("RenewZoneSignatures: %v does not match context.Canceled, so a caller"+
			" cannot tell a shutdown from a signing failure", err)
	}

	if _, err := zd.ResignZone(ctx, kdb); err == nil {
		t.Error("ResignZone started a replacement pass on a cancelled context")
	}
}

// The engine's own sweep must stop too, and must not mark a zone as having had
// its replacement done when it did not.
func TestACancelledSweepLeavesTheReplaceStillOwed(t *testing.T) {
	zd, _, oldTag := rolledZone(t)
	zd.markResignPending()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resignSweepZone(ctx, zd)

	if !zd.resignPendingSet() {
		t.Error("a sweep abandoned at shutdown cleared the pending replace; the zone would" +
			" go on serving signatures by a retired key with nothing left to retry it")
	}
	if !hasKeytag(zd.mustRRSIGKeytags(t, signedName, dns.TypeA), oldTag) {
		t.Log("the retired key's signature is gone, so the pass ran despite cancellation")
	}
}

// TestAStreamOfRequestsCannotPostponeTheRenewalSweep.
//
// Every request used to reset the resigner's timer to a full floor, so each one
// that arrived before the timer fired pushed the sweep out again. Requests are
// steady-state traffic -- one per zone load, one per key-state change -- and on
// a busy server they can come more often than once a floor. The sweep then
// never runs, and nothing on the watchlist is renewed.
//
// Simulates exactly that: a request every 20s against a 60s floor, for ten
// minutes. The sweep must still come due at the first deadline.
func TestAStreamOfRequestsCannotPostponeTheRenewalSweep(t *testing.T) {
	const floor = 60 * time.Second
	start := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	nextWake := start.Add(floor)
	deadline := nextWake

	for tick := 1; tick <= 30; tick++ {
		now := start.Add(time.Duration(tick) * 20 * time.Second)
		if !now.Before(deadline) {
			break // the timer would have fired by now
		}
		nextWake, _ = earlierResignWake(nextWake, now, floor)
		if nextWake.After(deadline) {
			t.Fatalf("a request at %s moved the sweep from %s to %s; repeated requests"+
				" would postpone renewal indefinitely", now.Sub(start), deadline.Sub(start), nextWake.Sub(start))
		}
	}
}

// And the case it still has to handle: a long sleep (up to resignSafetyTick) is
// cut short by a new zone, which has no estimate and wants a pass within one
// floor.
func TestANewZoneStillShortensALongSleep(t *testing.T) {
	const floor = 60 * time.Second
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	longSleep := now.Add(resignSafetyTick)

	at, sooner := earlierResignWake(longSleep, now, floor)
	if !sooner {
		t.Fatal("a new zone did not shorten an hour-long sleep; it would wait the full hour" +
			" for its first renewal pass with no estimate to justify it")
	}
	if want := now.Add(floor); !at.Equal(want) {
		t.Errorf("woke at %s, want one floor from now (%s)", at, want)
	}
}
