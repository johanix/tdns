/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The CDS follows the keys, not the history of the zone (#752, #736; design
// docs/2026-09-24-cds-publication-and-rfc-conformance.md §1). Test numbers in
// the comments are the design's §1.3 numbers.

// signingRig is the DS engine rig for a zone that is signed here, with real
// keys, under a policy with rollover method none: the zones whose CDS the DS
// engine now publishes on its own (§1.2 (a)). kskA is active; a ZSK signs.
type signingRig struct {
	*dsEngineRig
	kskA *dns.DNSKEY
}

func newSigningRig(t *testing.T, startEngine bool) *signingRig {
	t.Helper()
	r := buildDSEngineRig(t, 0, false)
	pol := kskzsk(dns.ED25519, dns.ED25519)
	pol.Name = "test"
	r.zd.DnssecPolicy = &pol
	r.zd.Options[OptOnlineSigning] = true
	sr := &signingRig{dsEngineRig: r}
	sr.kskA = sr.genKey(t, DnskeyStateActive, "KSK")
	sr.genKey(t, DnskeyStateActive, "ZSK")
	sr.serveKeys(t)
	if startEngine {
		startDSEngine(t, r.kdb)
	}
	return sr
}

// genKey mints a key the way the keystore does, with the row columns the
// zone's DS model gives it.
func (r *signingRig) genKey(t *testing.T, state, keytype string) *dns.DNSKEY {
	t.Helper()
	pkc, _, err := r.kdb.GenerateKeypair(r.zd.ZoneName, "test", state, dns.TypeDNSKEY, dns.ED25519, keytype, nil)
	if err != nil {
		t.Fatalf("generate %s (%s): %v", keytype, state, err)
	}
	k := pkc.DnskeyRR
	return &k
}

// serveKeys republishes the DNSKEY RRset from the keystore and signs the zone,
// as a signing pass does.
func (r *signingRig) serveKeys(t *testing.T) {
	t.Helper()
	dak, err := r.kdb.GetDnssecKeys(r.zd.ZoneName, DnskeyStateActive)
	if err != nil {
		t.Fatalf("active keys: %v", err)
	}
	if err := r.zd.PublishDnskeyRRs(dak); err != nil {
		t.Fatalf("PublishDnskeyRRs: %v", err)
	}
	r.zd.mu.Lock()
	r.zd.publishLocked(r.zd.generation.Load())
	r.zd.mu.Unlock()
	if !servesApexType(r.zd, dns.TypeDNSKEY) {
		t.Fatal("the rig zone serves no DNSKEY RRset")
	}
}

// cdsOfKeys is the CDS RRset asking for the DS of these KSKs.
func cdsOfKeys(zone string, keys ...*dns.DNSKEY) []dns.RR {
	var ds []dns.RR
	for _, k := range keys {
		ds = append(ds, k.ToDS(dns.SHA256))
	}
	return cdsFromDS(zone, ds)
}

func keyTags(keys ...*dns.DNSKEY) []uint16 {
	var out []uint16
	for _, k := range keys {
		out = append(out, k.KeyTag())
	}
	return out
}

// waitForCDS waits until the zone serves the CDS for exactly these keys.
func waitForCDS(t *testing.T, zd *ZoneData, keys ...*dns.DNSKEY) {
	t.Helper()
	want := cdsTuplesOf(cdsOfKeys(zd.ZoneName, keys...))
	deadline := time.Now().Add(2 * time.Second)
	for !cdsTupleSetsEqual(servedCDS(t, zd), want) {
		if time.Now().After(deadline) {
			t.Fatalf("served CDS keyids %v after two seconds, want %v",
				tupleKeyids(servedCDS(t, zd)), keyTags(keys...))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func assertServedCDS(t *testing.T, zd *ZoneData, keys ...*dns.DNSKEY) {
	t.Helper()
	want := cdsTuplesOf(cdsOfKeys(zd.ZoneName, keys...))
	if got := servedCDS(t, zd); !cdsTupleSetsEqual(got, want) {
		t.Errorf("served CDS keyids %v, want %v", tupleKeyids(got), keyTags(keys...))
	}
}

// Test 1. A signed zone whose keys tdns manages gets the CDS its keys call for
// on the engine's first run, although nothing asked for one and it has no
// parentsync: a downstream parentsync-proxy agent acts only on what it
// transfers, and a parent that polls reads only what is served.
func TestFirstSigningPublishesTheCds(t *testing.T) {
	r := newSigningRig(t, false)

	r.kdb.followKeysWithCDS(context.Background(), r.zd)

	assertServedCDS(t, r.zd, r.kskA)
}

// Test 2. A restart that finds the CDS already served, and right, publishes
// nothing: no serial, no journal row.
func TestARestartWithTheCdsServedPublishesNothing(t *testing.T) {
	r := newSigningRig(t, false)
	stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))

	r.kdb.followKeysWithCDS(context.Background(), r.zd)

	if events := r.log.snapshot(); len(events) != 0 {
		t.Errorf("a CDS already in step was republished: %v", events)
	}
	assertServedCDS(t, r.zd, r.kskA)
}

// Tests 5 and 6. The two transitions that change what the keys call for without
// changing the served DNSKEY set: published -> standby, and a manual KSK roll,
// which retires the old key but keeps it published. Both used to leave the CDS
// as it was, and a parent following it after the roll kept a DS for a key that
// no longer signs.
func TestStandbyAndAManualRollReachTheCds(t *testing.T) {
	r := newSigningRig(t, true)
	kskB := r.genKey(t, DnskeyStatePublished, "KSK")
	r.serveKeys(t)
	stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))

	if err := UpdateDnssecKeyState(r.kdb, "example.", kskB.KeyTag(), DnskeyStateStandby); err != nil {
		t.Fatalf("published -> standby: %v", err)
	}
	waitForCDS(t, r.zd, r.kskA, kskB)

	if _, _, err := r.kdb.RolloverKey("example.", "KSK", nil); err != nil {
		t.Fatalf("manual KSK roll: %v", err)
	}
	waitForCDS(t, r.zd, kskB)
}

// Test 8. A run with nothing changed publishes nothing.
func TestAFollowWithNothingChangedPublishesNothing(t *testing.T) {
	r := newSigningRig(t, false)

	r.kdb.followKeysWithCDS(context.Background(), r.zd)
	before := len(r.log.snapshot())
	serial := r.zd.CurrentSerial

	r.kdb.followKeysWithCDS(context.Background(), r.zd)

	if after := len(r.log.snapshot()); after != before {
		t.Errorf("a second run with nothing changed published again: %v", r.log.snapshot())
	}
	if r.zd.CurrentSerial != serial {
		t.Errorf("serial moved from %d to %d with nothing changed", serial, r.zd.CurrentSerial)
	}
}

// Test 3. What (a) does not cover: a zone signed elsewhere, although the
// keystore holds keys for it, and a multi-DS zone, whose CDS is the rollover
// engine's.
func TestZonesTheEngineDoesNotPublishACdsFor(t *testing.T) {
	t.Run("signed elsewhere", func(t *testing.T) {
		r := buildDSEngineRig(t, 0, false)
		r.zd.DnssecPolicy = &DnssecPolicy{Name: "test"}
		seedKey(t, r.kdb, "example.", DnskeyStateActive, 257, pubA)
		stageApexRRset(t, r.zd, dns.TypeDNSKEY, []dns.RR{testKSK("example.", pubA)}, nil)

		r.kdb.followKeysWithCDS(context.Background(), r.zd)

		if got := servedCDS(t, r.zd); len(got) != 0 {
			t.Errorf("a zone this server does not sign got a CDS: keyids %v", tupleKeyids(got))
		}
	})
	t.Run("multi-DS", func(t *testing.T) {
		r := newSigningRig(t, false)
		r.zd.DnssecPolicy.Rollover.Method = RolloverMethodMultiDS

		r.kdb.followKeysWithCDS(context.Background(), r.zd)

		if got := servedCDS(t, r.zd); len(got) != 0 {
			t.Errorf("a multi-DS zone got a CDS from the follow path: keyids %v", tupleKeyids(got))
		}
	})
}

// Test 4. cds: false stops the first publish only. A CDS the zone serves is
// still followed through a manual roll, and a parentsync zone publishes anyway.
func TestCdsFalseOnlyStopsTheFirstPublish(t *testing.T) {
	t.Run("no CDS of its own", func(t *testing.T) {
		r := newSigningRig(t, false)
		r.zd.DnssecPolicy.SuppressCDS = true

		r.kdb.followKeysWithCDS(context.Background(), r.zd)

		if got := servedCDS(t, r.zd); len(got) != 0 {
			t.Errorf("cds: false, and the zone got a CDS: keyids %v", tupleKeyids(got))
		}
	})
	t.Run("a served CDS still follows a manual roll", func(t *testing.T) {
		r := newSigningRig(t, false)
		r.zd.DnssecPolicy.SuppressCDS = true
		kskB := r.genKey(t, DnskeyStateStandby, "KSK")
		r.serveKeys(t)
		stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA, kskB))
		startDSEngine(t, r.kdb)

		if _, _, err := r.kdb.RolloverKey("example.", "KSK", nil); err != nil {
			t.Fatalf("manual KSK roll: %v", err)
		}
		waitForCDS(t, r.zd, kskB)
	})
	t.Run("ignored for a parentsync zone", func(t *testing.T) {
		r := newChildSyncRig(t, 4)
		r.zd.DnssecPolicy.SuppressCDS = true

		r.kdb.followKeysWithCDS(context.Background(), r.zd)

		assertServedCDS(t, r.zd, r.kskA)
	})
}

// Test 7. A change to a key row that no hint reports -- here an edit made
// straight in the database -- reaches the CDS through the key state worker's
// backstop.
func TestTheBackstopCatchesAnUnreportedKeyChange(t *testing.T) {
	r := newSigningRig(t, false)
	kskB := r.genKey(t, DnskeyStatePublished, "KSK")
	r.serveKeys(t)
	stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))
	r.kdb.takeDSDirty() // the setup's own marks, so only the backstop can wake the engine
	startDSEngine(t, r.kdb)

	if _, err := r.kdb.DB.Exec(`UPDATE DnssecKeyStore SET ds = 1 WHERE zonename = ? AND keyid = ?`,
		"example.", int(kskB.KeyTag())); err != nil {
		t.Fatalf("edit the ds column: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	assertServedCDS(t, r.zd, r.kskA) // nothing reported it

	// Through the key state worker's tick, not the backstop alone: the tick
	// is what runs it.
	conf := &Config{}
	conf.Internal.KeyDB = r.kdb
	checkAndTransitionKeys(context.Background(), conf, r.kdb, time.Hour, 0, 0)

	waitForCDS(t, r.zd, r.kskA, kskB)
}

// newChildSyncRig is newSigningRig for a zone in child delegation-sync mode,
// with a DelegationSyncQ of the given size that nothing reads.
func newChildSyncRig(t *testing.T, queue int) *signingRig {
	t.Helper()
	prev := Globals.App.Type
	t.Cleanup(func() { Globals.App.Type = prev })
	Globals.App.Type = AppTypeAuth
	r := newSigningRig(t, false)
	r.zd.Options[OptParentSync] = true
	r.zd.DelegationSyncQ = make(chan DelegationSyncRequest, queue)
	return r
}

// queuedSyncs drains the zone's DelegationSyncQ and counts the explicit syncs.
func queuedSyncs(t *testing.T, zd *ZoneData) int {
	t.Helper()
	n := 0
	for {
		select {
		case req := <-zd.DelegationSyncQ:
			if req.Command != "EXPLICIT-SYNC-DELEGATION" || req.ZoneData != zd {
				t.Errorf("queued %s for %s, want EXPLICIT-SYNC-DELEGATION for this zone", req.Command, req.ZoneName)
			}
			n++
		default:
			return n
		}
	}
}

// Tests 9 and 10. A follow-keys change on a child-sync zone queues one explicit
// sync. When that sync takes the NOTIFY scheme, ensureCDS finds the CDS already
// served and publishes nothing, and one NOTIFY(CDS) goes out.
func TestAFollowKeysChangeTellsTheParentOnce(t *testing.T) {
	r := newChildSyncRig(t, 4)
	// This test is about the change, not the first run; and the rig's own key
	// generation has marked the zone already, so the engine starts only once
	// the CDS is in step.
	r.zd.dsFirstRunDone.Store(true)
	stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))
	startDSEngine(t, r.kdb)
	kskB := r.genKey(t, DnskeyStateStandby, "KSK")

	r.kdb.KeysChanged(r.zd)
	waitForCDS(t, r.zd, r.kskA, kskB)
	deadline := time.Now().Add(2 * time.Second)
	for len(r.zd.DelegationSyncQ) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := queuedSyncs(t, r.zd); n != 1 {
		t.Fatalf("%d explicit syncs queued after one follow-keys change, want 1", n)
	}

	cdsPublishes := func() int {
		n := 0
		for _, e := range r.log.snapshot() {
			if e == "published CDS" {
				n++
			}
		}
		return n
	}
	before := cdsPublishes()
	_, rcode, err := r.zd.SyncZoneDelegationViaNotify(context.Background(), r.kdb, r.notifyq,
		DelegationSyncStatus{DSAdds: []dns.RR{kskB.ToDS(dns.SHA256)}}, testDsyncTarget)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("SyncZoneDelegationViaNotify: rcode %s, err %v", dns.RcodeToString[int(rcode)], err)
	}
	if after := cdsPublishes(); after != before {
		t.Errorf("the explicit sync published the CDS again (%d publishes, was %d)", after, before)
	}
	notifies := 0
	for len(r.notifyq) > 0 {
		if req := <-r.notifyq; req.RRtype == dns.TypeCDS {
			notifies++
		}
	}
	if notifies != 1 {
		t.Errorf("%d NOTIFY(CDS) sent, want 1", notifies)
	}
}

// Test 11. An intent that goes empty withdraws the CDS and tells the parent
// nothing: going insecure stays an operator's action.
func TestAWithdrawalTellsTheParentNothing(t *testing.T) {
	r := newChildSyncRig(t, 4)
	r.zd.dsFirstRunDone.Store(true)
	stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))
	if _, err := r.kdb.DB.Exec(`UPDATE DnssecKeyStore SET ds = 0 WHERE zonename = ?`, "example."); err != nil {
		t.Fatalf("clear ds: %v", err)
	}

	r.kdb.followKeysWithCDS(context.Background(), r.zd)

	if got := servedCDS(t, r.zd); len(got) != 0 {
		t.Errorf("the CDS was not withdrawn: keyids %v", tupleKeyids(got))
	}
	if n := queuedSyncs(t, r.zd); n != 0 {
		t.Errorf("%d explicit syncs queued for a withdrawal, want none", n)
	}
}

// Test 12. A full DelegationSyncQ does not block the engine, and the send is
// not lost: the next run, with the CDS unchanged, makes it, and the one after
// that makes none.
func TestAFullSyncQueueIsRetriedOnTheNextRun(t *testing.T) {
	r := newChildSyncRig(t, 1)
	r.zd.dsFirstRunDone.Store(true)
	r.zd.DelegationSyncQ <- DelegationSyncRequest{Command: "FILLER"}
	kskB := r.genKey(t, DnskeyStateStandby, "KSK")
	stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.kdb.followKeysWithCDS(context.Background(), r.zd)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("followKeysWithCDS blocked on a full DelegationSyncQ")
	}
	assertServedCDS(t, r.zd, r.kskA, kskB)
	if filler := <-r.zd.DelegationSyncQ; filler.Command != "FILLER" {
		t.Fatalf("the queue held %s, want the filler", filler.Command)
	}

	r.kdb.followKeysWithCDS(context.Background(), r.zd)
	if n := queuedSyncs(t, r.zd); n != 1 {
		t.Fatalf("%d explicit syncs queued on the retry, want 1", n)
	}
	r.kdb.followKeysWithCDS(context.Background(), r.zd)
	if n := queuedSyncs(t, r.zd); n != 0 {
		t.Errorf("%d explicit syncs queued after the retry went through, want none", n)
	}
}

// Tests 13 and 15. The first run for a child-sync zone compares with the
// parent once, although its CDS is already in step: the parent may have missed
// a KSK change while the server was down. Per ZoneData, not per process, so a
// zone loaded later gets its compare too.
func TestTheFirstRunForAZoneComparesWithTheParentOnce(t *testing.T) {
	r := newChildSyncRig(t, 4)
	stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))

	r.kdb.followKeysWithCDS(context.Background(), r.zd)
	if n := queuedSyncs(t, r.zd); n != 1 {
		t.Fatalf("%d explicit syncs queued on the first run, want 1", n)
	}
	r.kdb.followKeysWithCDS(context.Background(), r.zd)
	if n := queuedSyncs(t, r.zd); n != 0 {
		t.Errorf("%d explicit syncs queued on the second run, want none", n)
	}
	if events := r.log.snapshot(); len(events) != 0 {
		t.Errorf("a CDS already in step was republished: %v", events)
	}

	later := newChildSyncRig(t, 4) // another ZoneData, loaded after the first ran
	stageCDS(t, later.zd, cdsOfKeys("example.", later.kskA))
	later.kdb.followKeysWithCDS(context.Background(), later.zd)
	if n := queuedSyncs(t, later.zd); n != 1 {
		t.Errorf("%d explicit syncs queued on a later zone's first run, want 1", n)
	}
}

// Test 16. A first run that also publishes the zone's first CDS queues one
// sync, not one for the publish and one for the first run.
func TestAFirstRunThatPublishesQueuesOneSync(t *testing.T) {
	r := newChildSyncRig(t, 4)

	r.kdb.followKeysWithCDS(context.Background(), r.zd)

	assertServedCDS(t, r.zd, r.kskA)
	if n := queuedSyncs(t, r.zd); n != 1 {
		t.Errorf("%d explicit syncs queued, want 1", n)
	}
}

// Test 17. An explicit sync nobody waits on waits for the IMR, and runs once
// it is up; one an operator waits on runs at once and is answered; a process
// with no readiness signal never waits.
func TestExplicitSyncWaitsForTheImrOnlyWhenNobodyIsWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runs := 0
	run := func() DelegationSyncStatus { runs++; return DelegationSyncStatus{Msg: "ran"} }
	q := make(chan DelegationSyncRequest, 1)
	internal := DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: "example."}

	ready := NewImrReadiness()
	done := handleExplicitSyncWith(ctx, ready, q, internal, run)
	if done == nil || runs != 0 {
		t.Fatalf("with the IMR not up: deferred %v, runs %d; want deferred and not run", done != nil, runs)
	}
	ready.Publish()
	select {
	case again := <-q:
		if handleExplicitSyncWith(ctx, ready, q, again, run) != nil || runs != 1 {
			t.Errorf("once the IMR is up: runs %d, want 1", runs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the deferred explicit sync never came back")
	}
	<-done

	operator := DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", Response: make(chan DelegationSyncStatus, 1)}
	if handleExplicitSyncWith(ctx, NewImrReadiness(), q, operator, run) != nil || runs != 2 {
		t.Errorf("an operator's request with the IMR not up: runs %d, want it run at once", runs)
	}
	if got := <-operator.Response; got.Msg != "ran" {
		t.Errorf("the operator was answered %+v", got)
	}

	if handleExplicitSyncWith(ctx, nil, q, internal, run) != nil || runs != 3 {
		t.Errorf("no readiness signal: runs %d, want it run at once", runs)
	}
}

// Test 26 at the syncher's arm: a SIGNALS-EDITED for a held zone is not run.
func TestTheSignalsEditedArmDoesNothingUnderAHold(t *testing.T) {
	prev := txHoldPollInterval
	txHoldPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { txHoldPollInterval = prev })
	r := buildDSEngineRig(t, 0, false)
	ready := NewImrReadiness()
	ready.Publish()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := make(chan DelegationSyncRequest, 1)
	ds := DelegationSyncRequest{Command: "SIGNALS-EDITED", ZoneName: r.zd.ZoneName, ZoneData: r.zd}
	runs := 0

	id, err := r.zd.BeginTx(0)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	done := handleSignalsEditedArm(ctx, ready, q, r.zd, ds, func() { runs++ })
	if done == nil || runs != 0 {
		t.Fatalf("under a hold: deferred %v, runs %d; want deferred and not run", done != nil, runs)
	}
	if err := r.zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	again := <-q
	<-done
	if handleSignalsEditedArm(ctx, ready, q, r.zd, again, func() { runs++ }) != nil || runs != 1 {
		t.Errorf("after the commit: runs %d, want 1", runs)
	}
}

// triggerResign, which every key state transition and every owner
// (TriggerResign) calls, tells the DS engine too.
func TestTriggerResignTellsTheDSEngine(t *testing.T) {
	r := buildDSEngineRig(t, 0, false)
	conf := &Config{}
	conf.Internal.KeyDB = r.kdb

	TriggerResign(conf, r.zd.ZoneName)

	if got := dirtyZoneNames(r.kdb); len(got) != 1 || got[0] != r.zd.ZoneName {
		t.Errorf("marked zones = %v, want [%s]", got, r.zd.ZoneName)
	}
}

// Test 18. Without parentsync the CDS is published and the parent is told
// nothing; the same for a parentsync-proxy zone, whose agent talks to the
// parent itself.
func TestOnlyAChildSyncZoneTellsTheParent(t *testing.T) {
	for _, opt := range []ZoneOption{OptAllowUpdates, OptParentSyncProxy} {
		t.Run(ZoneOptionToString[opt], func(t *testing.T) {
			r := newChildSyncRig(t, 4)
			r.zd.Options[OptParentSync] = false
			r.zd.Options[opt] = true

			r.kdb.followKeysWithCDS(context.Background(), r.zd)

			assertServedCDS(t, r.zd, r.kskA)
			if n := queuedSyncs(t, r.zd); n != 0 {
				t.Errorf("%d explicit syncs queued for a zone without child delegation sync", n)
			}
		})
	}
}

// Tests 13 and 14, the analysis half. The first run's explicit sync compares
// first: against a parent still holding a KSK the zone no longer uses it finds
// the DS out of step, and against a parent already holding the zone's DS it
// finds nothing to send. Sending through the parent's scheme needs the parent's
// DSYNC, which needs an IMR; that half is a lab test.
func TestTheFirstRunsCompareFindsTheParentBehindOrInStep(t *testing.T) {
	old := testKSK("example.", pubB) // a KSK the zone no longer has
	cases := []struct {
		name     string
		parentDS func(r *signingRig) *dns.DS
		inSync   bool
	}{
		{"behind", func(r *signingRig) *dns.DS { return old.ToDS(dns.SHA256) }, false},
		{"in step", func(r *signingRig) *dns.DS { return r.kskA.ToDS(dns.SHA256) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newChildSyncRig(t, 4)
			stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))
			fakeParent(t, r.zd, []string{"example. 3600 IN NS ns.example.", "ns.example. 3600 IN A 192.0.2.1",
				tc.parentDS(r).String()})

			r.kdb.followKeysWithCDS(context.Background(), r.zd)
			if n := queuedSyncs(t, r.zd); n != 1 {
				t.Fatalf("%d explicit syncs queued on the first run, want 1", n)
			}

			resp, err := r.zd.AnalyseZoneDelegation(nil)
			if err != nil {
				t.Fatalf("AnalyseZoneDelegation: %v", err)
			}
			if resp.InSync != tc.inSync {
				t.Fatalf("in sync = %v, want %v (adds %v, removes %v)", resp.InSync, tc.inSync, resp.DSAdds, resp.DSRemoves)
			}
			if tc.inSync {
				return
			}
			if !sameRecords(resp.DSAdds, []dns.RR{r.kskA.ToDS(dns.SHA256)}) ||
				!sameRecords(resp.DSRemoves, []dns.RR{old.ToDS(dns.SHA256)}) {
				t.Errorf("adds %v, removes %v; want +the zone's KSK -the old one", resp.DSAdds, resp.DSRemoves)
			}
		})
	}
}

// fromText is rrs printed and parsed back, as a journal replay or a zone file
// load gives them: the DNS library prints a DS digest in upper case, and ToDS
// and wire unpacking give lower case.
func fromText(t *testing.T, rrs []dns.RR) []dns.RR {
	t.Helper()
	var out []dns.RR
	for _, rr := range rrs {
		out = append(out, mustRR(t, rr.String()))
	}
	return out
}

// Test 2, as the lab found it: after a restart the CDS comes back from the
// journal, parsed from text, with its digest in upper case. That is the same
// CDS, and neither the follow-keys run nor ensureCDS may publish it again.
func TestACdsReadBackFromTextIsTheSameCds(t *testing.T) {
	r := newSigningRig(t, false)
	served := fromText(t, cdsOfKeys("example.", r.kskA))
	if c := served[0].(*dns.CDS); c.Digest == cdsOfKeys("example.", r.kskA)[0].(*dns.CDS).Digest {
		t.Fatal("the round trip kept the digest's case; this test needs it changed")
	}
	stageCDS(t, r.zd, served)

	r.kdb.followKeysWithCDS(context.Background(), r.zd)
	if res := r.kdb.ensureCDS(context.Background(), r.zd); res.err != nil {
		t.Fatalf("ensureCDS: %v", res.err)
	}

	if events := r.log.snapshot(); len(events) != 0 {
		t.Errorf("a CDS read back from text was republished: %v", events)
	}
}
