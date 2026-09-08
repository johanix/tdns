/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A parent zone that already carries the whole DSYNC advertisement for the
// all-schemes configuration -- everything but the receiver KEY, which each
// test adds as it needs.
const fullyAdvertisedParent = `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.1
_dsync.example. 7200 IN DSYNC ANY UPDATE 5302 updates.example.
_dsync.example. 7200 IN DSYNC CDS NOTIFY 5302 notifications.example.
_dsync.example. 7200 IN DSYNC CSYNC NOTIFY 5302 notifications.example.
_dsync.example. 7200 IN DSYNC CDS API 8443 api.example.
_dsync.example. 7200 IN DSYNC CSYNC API 8443 api.example.
api.example. 7200 IN URI 1 1 "https://api.example:8443/dsync/v1"
api.example. 7200 IN TXT "tdns-child-api-v1.0"
updates.example. 7200 IN SVCB 1 . key65282="at-apex,at-ns"
updates.example. 7200 IN A 192.0.2.53
notifications.example. 7200 IN A 192.0.2.53
notifications.example. 7200 IN AAAA 2001:db8::53
api.example. 7200 IN A 192.0.2.80
`

// proxyAdvertZone is a childsync-proxy agent's view of example.: the served
// copy, a real keystore, and a queue that would catch any local publication.
func proxyAdvertZone(t *testing.T, zoneText string) *ZoneData {
	t.Helper()
	prevApp := Globals.App.Type
	t.Cleanup(func() { Globals.App.Type = prevApp })
	Globals.App.Type = AppTypeAgent
	allSchemesChildSync(t)

	zd := testZone(t, "example.", zoneText)
	registerZones(t, zd)
	zd.ZoneType = Secondary
	zd.KeyDB = newTestKeyDB(t)
	zd.KeyDB.UpdateQ = make(chan UpdateRequest, 4)
	zd.Options = map[ZoneOption]bool{OptChildSyncProxy: true, OptChildSync: true}
	p := DefaultDelegationPolicy()
	zd.DelegationPolicy = &p
	return zd
}

func withManualBackend(zd *ZoneData) *DBDelegationBackend {
	store := &DBDelegationBackend{kdb: zd.KeyDB}
	zd.DelegationBackend = &composedDelegationBackend{name: "manual", store: store, zd: zd}
	return store
}

func withPushBackend(t *testing.T, zd *ZoneData, sink *updateSink) *DBDelegationBackend {
	t.Helper()
	store := &DBDelegationBackend{kdb: zd.KeyDB}
	writer := &ddnsParentZoneWriter{
		zd: zd, store: store, targets: []string{sink.addr}, keyName: testAgentTsigKey,
		retryInterval: 20 * time.Millisecond, maxAttempts: 2,
	}
	zd.DelegationBackend = &composedDelegationBackend{name: "push", store: store, writer: writer, async: true, zd: zd}
	return store
}

func receiverKeyRR(t *testing.T, kdb *KeyDB) string {
	t.Helper()
	if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
		Command: "sig0-mgmt", SubCommand: "generate", Zone: "example.", Keyname: "updates.example.",
		Algorithm: dns.ED25519, State: Sig0StateActive, Creator: "test",
	}); err != nil {
		t.Fatalf("generating the receiver key: %v", err)
	}
	sak, err := kdb.GetSig0Keys("updates.example.", Sig0StateActive)
	if err != nil || sak == nil || len(sak.Keys) == 0 {
		t.Fatalf("no receiver key after generating one: %v", err)
	}
	rr := sak.Keys[0].KeyRR
	rr.Hdr.Name = "updates.example."
	rr.Hdr.Ttl = 7200
	return rr.String()
}

// With nothing to deliver the advertisement, the reconciler waits: an
// nsupdate block for the operator, a warning on the zone, the receiver key
// generated in the keystore -- and nothing published into the agent's own
// copy of the zone.
func TestProxyAdvertisementWaitsWithoutAWriter(t *testing.T) {
	zd := proxyAdvertZone(t, partiallyAdvertisedParent)
	withManualBackend(zd)

	if st := zd.ReconcileChildSyncAdvertisement(); st != ChildSyncProxyWaiting {
		t.Fatalf("state = %s, want waiting-for-publication", st)
	}
	status := zd.ChildSyncProxyStatus()
	if status.Delta != 11 {
		t.Errorf("delta = %d, want the 10 DSYNC-side records plus the receiver KEY", status.Delta)
	}
	for _, want := range []string{"zone example.\n", "update add _dsync.example.", "\tKEY\t", "send\n"} {
		if !strings.Contains(status.Instruction, want) {
			t.Errorf("instruction lacks %q:\n%s", want, status.Instruction)
		}
	}
	ze, ok := zd.Errors[DelegationSyncWarning]
	if !ok || !strings.HasPrefix(ze.Msg, childSyncProxyWarningPrefix) {
		t.Fatalf("expected the advertisement warning, got %+v", zd.Errors)
	}
	if sak, err := zd.KeyDB.GetSig0Keys("updates.example.", Sig0StateActive); err != nil || sak == nil || len(sak.Keys) == 0 {
		t.Fatal("the receiver key was not generated in the keystore")
	}
	if len(zd.KeyDB.UpdateQ) != 0 {
		t.Fatal("the reconciler published into the agent's own copy of the zone")
	}
}

// With a writer that speaks to the network, the reconciler enqueues and the
// engine delivers the whole advertisement, receiver KEY included, to the
// parent primary as one signed UPDATE.
func TestProxyAdvertisementPublishesThroughTheEngine(t *testing.T) {
	withAgentTsigKey(t)
	withParentPushQueue(t, 16)
	sink := startUpdateSink(t, dns.RcodeSuccess)
	zd := proxyAdvertZone(t, partiallyAdvertisedParent)
	withPushBackend(t, zd, sink)
	runParentPushEngine(t)

	if st := zd.ReconcileChildSyncAdvertisement(); st != ChildSyncProxyPublishing {
		t.Fatalf("state = %s, want publishing", st)
	}
	m := sink.wait(t, 3*time.Second)
	s := strings.Join(actionStrings(m.Ns), "\n")
	for _, want := range []string{
		"IN _dsync.example.\t7200\tIN\tDSYNC\tCDS\tNOTIFY 5302 notifications.example.",
		"IN api.example.\t7200\tIN\tURI\t1 1 \"https://api.example:8443/dsync/v1\"",
		"IN updates.example.\t7200\tIN\tSVCB\t1 . key65282=\"at-apex,at-ns\"",
		"IN updates.example.\t7200\tIN\tKEY\t",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the primary did not receive %q:\n%s", want, s)
		}
	}
	waitFor(t, 2*time.Second, "the push to be recorded", func() bool {
		st := zd.ParentPushStatus()
		return !st.LastOK.IsZero() && len(st.Failures) == 0
	})
	if zd.HasError(DelegationSyncWarning) {
		t.Fatalf("a publishing advertisement left a warning: %+v", zd.Errors)
	}
	if len(zd.KeyDB.UpdateQ) != 0 {
		t.Fatal("the reconciler published into the agent's own copy of the zone")
	}
}

// A zone that carries everything, our KEY included, is ready and clears the
// warning: the loop has closed.
func TestProxyAdvertisementIsReadyWhenTheZoneCarriesIt(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyRR := receiverKeyRR(t, kdb)
	zd := proxyAdvertZone(t, fullyAdvertisedParent+keyRR+"\n")
	zd.KeyDB = kdb
	withManualBackend(zd)
	zd.SetError(DelegationSyncWarning, "%sleft over from an earlier reconcile", childSyncProxyWarningPrefix)

	if st := zd.ReconcileChildSyncAdvertisement(); st != ChildSyncProxyReady {
		t.Fatalf("state = %s, want ready (delta %d: %s)", st, zd.ChildSyncProxyStatus().Delta, zd.ChildSyncProxyStatus().Instruction)
	}
	if zd.HasError(DelegationSyncWarning) {
		t.Fatalf("ready did not clear the warning: %+v", zd.Errors)
	}
}

// A KEY this agent does not hold at the UPDATE target is a foreign key: no
// competing key is minted, the rest of the advertisement still counts, and
// the zone carries a warning that says what to do.
func TestProxyAdvertisementFlagsAForeignKey(t *testing.T) {
	const foreign = "updates.example. 7200 IN KEY 512 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=\n"
	zd := proxyAdvertZone(t, partiallyAdvertisedParent+foreign)
	withManualBackend(zd)

	if st := zd.ReconcileChildSyncAdvertisement(); st != ChildSyncProxyForeignKey {
		t.Fatalf("state = %s, want foreign-key", st)
	}
	status := zd.ChildSyncProxyStatus()
	if status.Delta != 10 || strings.Contains(status.Instruction, "\tKEY\t") {
		t.Errorf("the delta must carry the DSYNC-side records and no KEY: delta=%d\n%s", status.Delta, status.Instruction)
	}
	if sak, _ := zd.KeyDB.GetSig0Keys("updates.example.", Sig0StateActive); sak != nil && len(sak.Keys) > 0 {
		t.Fatal("a competing receiver key was minted beside the foreign one")
	}
	ze, ok := zd.Errors[DelegationSyncWarning]
	if !ok || !strings.Contains(ze.Msg, "does not hold") {
		t.Fatalf("expected the foreign-key warning, got %+v", zd.Errors)
	}
}

func TestProxyAdvertisementWithNoZoneData(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.", ZoneType: Secondary, Options: map[ZoneOption]bool{OptChildSyncProxy: true, OptChildSync: true}}
	if st := zd.ReconcileChildSyncAdvertisement(); st != ChildSyncProxyNoZone {
		t.Fatalf("state = %s, want no-zone-data", st)
	}
	if zd.HasError(DelegationSyncWarning) {
		t.Fatal("a zone that is still loading must not carry a warning")
	}
}

// The hook is registered for every zone and gates on the option at run time.
func TestProxyHookIsRegisteredAndSelfGates(t *testing.T) {
	zd := proxyAdvertZone(t, partiallyAdvertisedParent)
	withManualBackend(zd)
	zd.Options = map[ZoneOption]bool{}
	zd.registerStandardRefreshHooks(nil)

	for _, cb := range zd.OnZonePostRefresh {
		cb(zd)
	}
	if !zd.ChildSyncProxyStatus().LastReconcile.IsZero() {
		t.Fatal("the hook reconciled a zone without the option")
	}

	zd.Options = map[ZoneOption]bool{OptChildSyncProxy: true, OptChildSync: true}
	for _, cb := range zd.OnZonePostRefresh {
		cb(zd)
	}
	if st := zd.ChildSyncProxyStatus(); st.LastReconcile.IsZero() || st.State != ChildSyncProxyWaiting {
		t.Fatalf("the hook did not reconcile once the option was set: %+v", st)
	}
}

// §6.4 and D-3's non-goal in one: the refresh reconcile pushes the delta for
// every child the store knows, and never deletes anything for a child it
// does not. An empty store must never be able to empty a parent zone.
func TestProxyRefreshReconcileIsAdditiveForUnknownChildren(t *testing.T) {
	withAgentTsigKey(t)
	withParentPushQueue(t, 16)
	sink := startUpdateSink(t, dns.RcodeSuccess)
	const delegated = fullyAdvertisedParent +
		"alpha.example. 3600 IN NS ns.alpha.example.\n" +
		"ns.alpha.example. 3600 IN A 192.0.2.51\n" +
		"bravo.example. 3600 IN NS ns.bravo.example.\n"
	kdb := newTestKeyDB(t)
	keyRR := receiverKeyRR(t, kdb)
	zd := proxyAdvertZone(t, delegated+keyRR+"\n")
	zd.KeyDB = kdb
	store := withPushBackend(t, zd, sink)
	runParentPushEngine(t)

	// Empty store, two served delegations: nothing may be pushed.
	zd.ChildSyncProxyPostRefresh()
	waitFor(t, time.Second, "the reconcile to run", func() bool {
		st := zd.ParentPushStatus()
		return !st.Running && len(st.Pending) == 0
	})
	time.Sleep(50 * time.Millisecond)
	if n := sink.count(); n != 0 {
		t.Fatalf("an empty store produced %d push(es):\n%s", n, strings.Join(actionStrings(sink.last().Ns), "\n"))
	}

	// Seed the store, then change alpha's intent behind the engine's back
	// (straight into the store, so nothing enqueues) -- the refresh
	// reconcile must find and push exactly that difference.
	if _, _, err := zd.AdoptServedDelegations(); err != nil {
		t.Fatal(err)
	}
	ur := childUpdate(t, "alpha.example. 3600 IN NS ns2.alpha.example.")
	ur.ZoneName = "example."
	if err := store.ApplyChildUpdate("example.", ur); err != nil {
		t.Fatal(err)
	}
	zd.ChildSyncProxyPostRefresh()
	m := sink.wait(t, 3*time.Second)
	got := actionStrings(m.Ns)
	if strings.Join(got, "\n") != "IN alpha.example.\t3600\tIN\tNS\tns2.alpha.example." {
		t.Fatalf("the reconcile pushed:\n%s\nwant exactly alpha's added NS", strings.Join(got, "\n"))
	}
}
