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

// A reload that turns signing on for a zone that is already loaded signs it
// through a policy apply, and no first load runs to register it. The apply
// registers it.
func TestAReloadThatTurnsOnSigningPutsTheZoneOnTheWatchlist(t *testing.T) {
	withAppType(t, AppTypeAuth)
	kdb := newTestKeyDB(t)
	withLivePolicies(t, map[string]DnssecPolicy{"base": kskzsk(dns.ED25519, dns.ED25519)})
	zone := algZone + "\t3600\tIN\tSOA\tns." + algZone + " hostmaster." + algZone + " 1 7200 1800 604800 7200\n" +
		algZone + "\t3600\tIN\tNS\tns." + algZone + "\n"
	zd := testZone(t, algZone, zone) // loaded, unsigned, not on the watchlist
	zd.ZoneType = Primary
	zd.KeyDB = kdb
	registerZones(t, zd)

	// The reload: signing on in the zone's options, then the policy sync the
	// config-bearing refresh of an existing zone runs (refreshengine.go).
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	if err := syncZoneDnssecPolicyFromConfig(context.Background(), zd, kdb, &Config{}, "base"); err != nil {
		t.Fatalf("policy sync: %v", err)
	}
	if zd.DnssecPolicyName != "base" {
		t.Fatal("test setup: the policy did not bind")
	}
	if resignCandidates(Zones.Items())[zd.ZoneName] != zd {
		t.Error("the reload signed the zone and left it off the watchlist; nothing would renew its signatures")
	}
}

// ModifyDynamicZone leaves a new ZoneData that has no first load of its own.
// When a later policy apply signs it, the apply registers it; nothing else
// does.
func TestAPolicyApplyPutsAModifiedZoneOnTheWatchlist(t *testing.T) {
	withAppType(t, AppTypeAuth)
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	conf, ch := newTestConfigForCores(t)
	const name = "modsig.example."
	in := DynamicZoneInput{Name: name, Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		Options:   map[ZoneOption]bool{OptInlineSigning: true}}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("add: %v", err)
	}
	<-ch
	mod := in
	mod.Primaries = []PeerConf{{Addr: "192.0.2.9:53", Key: NOKEY}}
	if _, err := conf.ModifyDynamicZone(context.Background(), mod); err != nil {
		t.Fatalf("modify: %v", err)
	}
	<-ch
	repl, _ := Zones.Get(name)
	if !repl.Options[OptInlineSigning] {
		t.Fatal("test setup: the replacement does not carry inline-signing")
	}
	if _, ok := resignCandidates(Zones.Items())[name]; ok {
		t.Fatal("test setup: the replacement is on the watchlist before anything signed it")
	}

	loadAsTransferred(t, repl) // what the forced refresh after the modify transfers
	kdb := newTestKeyDB(t)
	repl.KeyDB = kdb

	pol := kskzsk(dns.ED25519, dns.ED25519)
	if _, err := applyZonePolicyTransactional(context.Background(), repl, kdb, &pol, "base", PolicyApplySourceCommand); err != nil {
		t.Fatalf("policy apply: %v", err)
	}
	if resignCandidates(Zones.Items())[name] != repl {
		t.Error("a policy apply signed the modified zone and left it off the watchlist; nothing would renew its signatures")
	}
}

// loadAsTransferred gives a dynamic secondary the content its first transfer
// would: an unsigned SOA and NS, published.
func loadAsTransferred(t *testing.T, zd *ZoneData) {
	t.Helper()
	name := zd.ZoneName
	zone := name + "\t3600\tIN\tSOA\tns." + name + " hostmaster." + name + " 1 7200 1800 604800 7200\n" +
		name + "\t3600\tIN\tNS\tns." + name + "\n"
	if _, _, err := zd.ReadZoneData(zone, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.Ready = true
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.stopPublisher)
}

// A ModifyDynamicZone replacement keeps the zone's applied-policy row, which is
// keyed by name. The next config-bearing sync finds it matching intent and only
// rebinds the policy onto the new ZoneData (Branch 1): no re-sign, and no first
// load to register the zone. The publish after it signs, so the rebind has to
// register it.
func TestASyncThatRebindsAModifiedZonePutsItOnTheWatchlist(t *testing.T) {
	withAppType(t, AppTypeAuth)
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	kdb := newTestKeyDB(t)
	withLivePolicies(t, map[string]DnssecPolicy{"base": kskzsk(dns.ED25519, dns.ED25519)})
	conf, ch := newTestConfigForCores(t)
	const name = "rebind.example."
	in := DynamicZoneInput{Name: name, Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		Options:   map[ZoneOption]bool{OptInlineSigning: true}}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("add: %v", err)
	}
	<-ch
	old, _ := Zones.Get(name)
	loadAsTransferred(t, old)
	old.KeyDB = kdb
	// Signed under "base" before the modify, which writes the applied row.
	if err := syncZoneDnssecPolicyFromConfig(context.Background(), old, kdb, conf, "base"); err != nil {
		t.Fatalf("policy sync before the modify: %v", err)
	}

	mod := in
	mod.Primaries = []PeerConf{{Addr: "192.0.2.9:53", Key: NOKEY}}
	if _, err := conf.ModifyDynamicZone(context.Background(), mod); err != nil {
		t.Fatalf("modify: %v", err)
	}
	<-ch
	repl, _ := Zones.Get(name)
	if repl == old {
		t.Fatal("test setup: the modify did not replace the ZoneData")
	}
	if _, ok := resignCandidates(Zones.Items())[name]; ok {
		t.Fatal("test setup: the replacement is on the watchlist before its policy sync")
	}
	loadAsTransferred(t, repl)
	repl.KeyDB = kdb

	if err := syncZoneDnssecPolicyFromConfig(context.Background(), repl, kdb, conf, "base"); err != nil {
		t.Fatalf("policy sync after the modify: %v", err)
	}
	if repl.DnssecPolicyName != "base" {
		t.Fatal("test setup: the sync did not bind the policy")
	}
	if soa := getRRsetFrom(repl.publishedSnapshot(), name, dns.TypeSOA); soa != nil && len(soa.RRSIGs) > 0 {
		t.Fatal("test setup: the sync signed the replacement; this test is for the rebind that does not")
	}
	if resignCandidates(Zones.Items())[name] != repl {
		t.Error("the sync bound a policy to the modified zone, whose next publish signs it, and left it off the watchlist")
	}
}

// A reload that finds a zone already signed under intent, with no applied row,
// backfills: it binds without a re-sign. At a first load OnFirstLoad registers
// the zone afterwards. A reload has no first load, so the backfill must.
func TestAReloadThatBackfillsPutsTheZoneOnTheWatchlist(t *testing.T) {
	withAppType(t, AppTypeAuth)
	kdb := newTestKeyDB(t)
	withLivePolicies(t, map[string]DnssecPolicy{"base": kskzsk(dns.ED25519, dns.ED25519)})
	zd := readySignedApexZone(t, algZone, dns.ED25519)
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	zd.ZoneType = Primary
	zd.KeyDB = kdb
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	registerZones(t, zd)

	if err := syncZoneDnssecPolicyFromConfig(context.Background(), zd, kdb, &Config{}, "base"); err != nil {
		t.Fatalf("policy sync: %v", err)
	}
	if name, _, ok, err := GetZoneAppliedPolicy(kdb, algZone); err != nil || !ok || name != "base" {
		t.Fatalf("test setup: applied (%q,%v,%v), want a backfill of base", name, ok, err)
	}
	if resignCandidates(Zones.Items())[algZone] != zd {
		t.Error("the reload backfilled a zone that signs here and left it off the watchlist")
	}
}
