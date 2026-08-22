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

	// Sign the zone, which builds the chain AND signs it -- the path a real
	// zone takes. GenerateNsecChain alone leaves the NSECs unsigned.
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
