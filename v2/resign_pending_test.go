/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
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

	if _, err := zd.RenewZoneSignatures(kdb); err != nil {
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
	resignSweepZone(zd)

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
	zd.replaceSignaturesNow()

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

	zd.replaceSignaturesNow()

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
