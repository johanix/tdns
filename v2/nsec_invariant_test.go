package tdns

import (
	"fmt"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// assertChainInvariant checks the two properties that make an NSEC chain
// usable, against the zone as PUBLISHED -- which is what a secondary receives
// and what it will answer denial from.
//
//  1. it covers exactly the authoritative names: every name that owns data has
//     an NSEC, and nothing else does;
//  2. it is a single cycle in canonical order, closing on the apex.
//
// Querying this server proves none of that: denial is synthesised per query and
// never reads the chain.
func assertChainInvariant(t *testing.T, zd *ZoneData, context string) {
	t.Helper()

	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatalf("%s: nothing published", context)
	}

	// What the chain SHOULD cover.
	zd.mu.Lock()
	zd.ensureWorkingSet()
	want := map[string]bool{}
	for _, n := range zd.chainNamesLocked(zd.workingOwnerNamesLocked()) {
		want[n] = true
	}
	zd.mu.Unlock()

	next := map[string]string{}
	for name := range snap.Data {
		od := getOwnerFrom(snap, name)
		if od == nil {
			continue
		}
		has := len(od.NSEC.RRs) > 0
		if has && !want[name] {
			t.Errorf("%s: %q has an NSEC but is not an authoritative name of the zone"+
				" (a deleted name that kept its own proof of existence, or data below a delegation)",
				context, name)
		}
		if !has && want[name] {
			t.Errorf("%s: %q owns data but has no NSEC, so its existence cannot be proven"+
				" and a denial will wrongly cover it", context, name)
		}
		if !has {
			continue
		}
		nsec, ok := od.NSEC.RRs[0].(*dns.NSEC)
		if !ok {
			t.Fatalf("%s: %q NSEC property holds a %T", context, name, od.NSEC.RRs[0])
		}
		next[name] = nsec.NextDomain
		if len(od.NSEC.RRSIGs) == 0 {
			t.Errorf("%s: %q has an unsigned NSEC; a validator rejects the proof outright",
				context, name)
		}
	}

	if len(next) == 0 {
		t.Fatalf("%s: the zone has no chain at all", context)
	}

	// A single cycle, in canonical order, closing on the apex.
	apex := zd.ZoneName
	if _, ok := next[apex]; !ok {
		t.Fatalf("%s: the apex is not in the chain", context)
	}
	seen := map[string]bool{}
	cur := apex
	for range next {
		if seen[cur] {
			t.Fatalf("%s: the chain revisits %q before closing", context, cur)
		}
		seen[cur] = true
		nxt, ok := next[cur]
		if !ok {
			t.Fatalf("%s: %q points at %q, which has no NSEC -- the chain is broken",
				context, cur, nxt)
		}
		// Canonical order: every link goes forward, except the single wrap
		// back to the apex at the end.
		if nxt != apex && !canonicalOwnerLess(cur, nxt) {
			t.Errorf("%s: %q -> %q goes backwards in canonical order", context, cur, nxt)
		}
		cur = nxt
	}
	if cur != apex {
		t.Fatalf("%s: the chain does not close on the apex; ended at %q", context, cur)
	}
	if len(seen) != len(next) {
		t.Fatalf("%s: the chain covers %d names but %d have NSECs -- it is not one cycle",
			context, len(seen), len(next))
	}
}

func signingTestZone(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()
	const zone = `inv.example.	3600	IN	SOA	ns.inv.example. hostmaster.inv.example. 1 7200 1800 604800 7200
inv.example.	3600	IN	NS	ns.inv.example.
ns.inv.example.	3600	IN	A	127.0.0.1
alpha.inv.example.	3600	IN	A	10.0.0.1
charlie.inv.example.	3600	IN	A	10.0.0.3
`
	zd := testZone(t, "inv.example.", zone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true, OptAllowUpdates: true, OptAllowApiUpdates: true}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
	}
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT)
	zd.InstallInitialSnapshot()

	// Sign the zone, which builds the chain and signs it in one pass -- the
	// only way a chain is produced.
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("initial SignZone: %v", err)
	}
	return zd
}

func applyRR(t *testing.T, zd *ZoneData, kdb *KeyDB, verb string, rr string) {
	t.Helper()
	actions, err := BuildZoneUpdateActions(zd.ZoneName, ZoneUpdateSpec{Verb: verb, RRs: []string{rr}})
	if err != nil {
		t.Fatalf("building %v %s: %v", verb, rr, err)
	}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, Actions: actions,
	}, kdb); err != nil {
		t.Fatalf("applying %v %s: %v", verb, rr, err)
	}
}

// The chain must hold after every publish, not after a later repair pass.
func TestChainInvariantHoldsAcrossUpdates(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)
	assertChainInvariant(t, zd, "initial")

	steps := []struct {
		verb string
		rr   string
		why  string
	}{
		{VerbAddRR, "bravo.inv.example. 3600 IN A 10.0.0.2", "insert between two existing names"},
		{VerbAddRR, "zulu.inv.example. 3600 IN A 10.0.0.9", "insert at the end, before the wrap"},
		{VerbAddRR, "aaa.inv.example. 3600 IN A 10.0.0.8", "insert immediately after the apex"},
		{VerbDelRR, "bravo.inv.example. 3600 IN A 10.0.0.2", "remove a middle name entirely"},
		{VerbAddRR, "alpha.inv.example. 3600 IN TXT \"x\"", "change an existing name's type bitmap"},
		{VerbDelRR, "zulu.inv.example. 3600 IN A 10.0.0.9", "remove the last name, moving the wrap"},
	}
	for i, s := range steps {
		applyRR(t, zd, kdb, s.verb, s.rr)
		assertChainInvariant(t, zd, fmt.Sprintf("step %d (%s)", i+1, s.why))
	}

	// The removed names must be gone completely, not lingering as data-less
	// owners that prove their own existence.
	snap := zd.publishedSnapshot()
	for _, gone := range []string{"bravo.inv.example.", "zulu.inv.example."} {
		if od := getOwnerFrom(snap, gone); od != nil && (od.RRtypes.Count() > 0 || len(od.NSEC.RRs) > 0) {
			t.Errorf("%s survived its deletion: %d rrtypes, %d NSEC records",
				gone, od.RRtypes.Count(), len(od.NSEC.RRs))
		}
	}
}

// The restitch runs with zd.mu held and signs what it rewrites. Signing
// re-enters key handling, which re-locks zd.mu unless the keys are resolved
// with zdLocked=true -- the same trap the SOA re-sign had.
func TestRestitchUnderLockNoSelfDeadlock(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)

	// A staged change, or restitchNsecLocked returns at its "nothing changed"
	// guard and the test proves nothing: the deadlock is in the signing path,
	// which is only reached when there is something to re-sign.
	rr, err := dns.NewRR("newname.inv.example. 3600 IN A 10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		zd.mu.Lock()
		defer zd.mu.Unlock()
		zd.ensureWorkingSet()
		zd.stageRRsetLocked("newname.inv.example.",
			core.RRset{Name: "newname.inv.example.", RRtype: dns.TypeA, RRs: []dns.RR{rr}})
		if changed := changedChainNames(zd.snapshot.Load(), zd.workingSet); len(changed) == 0 {
			panic("test setup: no staged change, so the signing path is never reached")
		}
		zd.restitchNsecLocked()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("restitchNsecLocked deadlocked while zd.mu was held" +
			" (re-entrant zd.mu via EnsureActiveDnssecKeys -> PublishDnskeyRRs)")
	}

	// And it got far enough to sign: an unsigned or missing NSEC here would
	// mean the run completed without exercising the path the test is about.
	zd.mu.Lock()
	od := zd.stagedOwner("newname.inv.example.")
	zd.mu.Unlock()
	if od == nil || len(od.NSEC.RRs) == 0 {
		t.Fatal("the restitch did not give the new name an NSEC, so it never reached signing")
	}
	if len(od.NSEC.RRSIGs) == 0 {
		t.Fatal("the restitch left the new name's NSEC unsigned")
	}
}

// A delegation appearing or disappearing moves OTHER names into or out of the
// chain without changing those names at all. Reconciling only the names whose
// own data changed leaves the rest behind: glue keeps the NSEC it was given
// while it was still ours, and the chain stops being a single cycle.
func TestDelegationChangesReconcileChainMembership(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)

	// A name that will become glue once the delegation appears.
	applyRR(t, zd, kdb, VerbAddRR, "ns1.sub.inv.example. 3600 IN A 10.5.5.5")
	assertChainInvariant(t, zd, "before the delegation")

	stageNS := func(present bool) {
		zd.mu.Lock()
		zd.ensureWorkingSet()
		if present {
			rr, err := dns.NewRR("sub.inv.example. 3600 IN NS ns1.sub.inv.example.")
			if err != nil {
				t.Fatal(err)
			}
			zd.stageRRsetLocked("sub.inv.example.",
				core.RRset{Name: "sub.inv.example.", RRtype: dns.TypeNS, RRs: []dns.RR{rr}})
		} else {
			zd.stageDeleteLocked("sub.inv.example.", dns.TypeNS)
		}
		zd.mu.Unlock()
		zd.requestPublish(true)
	}

	// Delegation ADDED: ns1.sub is now the child's data and must leave the chain.
	stageNS(true)
	snap := zd.publishedSnapshot()
	if od := getOwnerFrom(snap, "ns1.sub.inv.example."); od != nil && len(od.NSEC.RRs) > 0 {
		t.Error("glue below a new delegation kept its NSEC, so the chain still claims it")
	}
	assertChainInvariant(t, zd, "after the delegation was added")

	// Delegation REMOVED: the name is ours again and needs an NSEC.
	stageNS(false)
	snap = zd.publishedSnapshot()
	od := getOwnerFrom(snap, "ns1.sub.inv.example.")
	if od == nil || len(od.NSEC.RRs) == 0 {
		t.Error("a name that re-entered the chain when its delegation went away got no NSEC," +
			" so its existence cannot be proven")
	}
	assertChainInvariant(t, zd, "after the delegation was removed")
}

// The refusal path runs with zd.mu HELD, and the obvious way to report the
// failure -- zd.SetError -- takes zd.mu itself. Getting that wrong deadlocks
// the publish at exactly the moment it is trying to tell someone the zone
// could not be published, which is the worst possible time to hang.
//
// It also has to put the serial back. The bump happens before the repair runs,
// so a refusal that leaves it advanced makes publishSync report a serial that
// no snapshot carries.
//
// Driven directly rather than through an injected signing failure. Clearing
// the KeyDB does not work as a lever: zoneMaintainsItsOwnChain skips the
// restitch entirely when it is nil, and the publish then panics further along
// (johanix/tdns#368). A policy naming an unsupported algorithm DOES make the
// restitch fail cleanly, but it exercises the same path this drives directly
// while depending on key generation to keep rejecting that algorithm.
func TestRefusingAnUnrepairableChainDoesNotDeadlockOrKeepTheSerial(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)

	const prevSerial = 41
	zd.mu.Lock()
	zd.CurrentSerial = 42 // as if the publish had already bumped it
	zd.mu.Unlock()

	done := make(chan struct{})
	go func() {
		zd.mu.Lock() // the publishWorkingSetLocked context
		defer zd.mu.Unlock()
		zd.refuseUnrepairableChainLocked(prevSerial, fmt.Errorf("no keys"))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("refusing the publish deadlocked while zd.mu was held" +
			" (re-entrant zd.mu via SetError)")
	}

	zd.mu.Lock()
	got := zd.CurrentSerial
	zd.mu.Unlock()
	if got != prevSerial {
		t.Fatalf("the serial was left at %d after a refused publish, want %d rolled back;"+
			" publishSync would report a serial no snapshot carries", got, prevSerial)
	}

	var found bool
	for _, e := range zd.ErrorList() {
		if e.Type == DnssecPolicyWarning {
			found = true
		}
	}
	if !found {
		t.Error("a refused publish recorded no error against the zone")
	}
}
