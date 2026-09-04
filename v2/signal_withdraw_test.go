/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// The child's apex KEY and the copy of it that a previous run left at the
// signal name. Same content, so the publish half is change-gated to a no-op
// and every update these tests see is a withdrawal.
const (
	sigKeyRdata   = "256 3 15 dGVzdGtleQ=="
	sigOwnerFoo   = "_sig0key.example._signal.ns.foobar.com."
	dsbootOwnFoo  = "_dsboot.example._signal.ns.foobar.com."
	sigOwnerInBai = "_sig0key.child.example._signal.ns.child.example."
)

// withdrawFixture is the shape all four withdrawal cases share: a customer
// zone whose apex asks for republication, and a local primary holding both the
// resulting signal RRset and (via the first reconcile) its ledger row.
type withdrawFixture struct {
	child  *ZoneData
	target *ZoneData
	q      chan UpdateRequest
	kdb    *KeyDB
}

// newWithdrawFixture wires child + target against a real keystore and runs one
// reconcile with everything in order. That first pass must write nothing (the
// signal RRset already matches) and record the publication, which is also the
// assertion that the ledger is populated by the change-gated path -- a restart
// against an already-published zone has no other chance to record it.
func newWithdrawFixture(t *testing.T, childOwners map[string][]dns.RR, childOpts map[ZoneOption]bool, targetOwners map[string][]dns.RR) *withdrawFixture {
	t.Helper()
	kdb := newTestKeyDB(t)

	target, q := signalTarget("foobar.com.", targetOwners)
	target.KeyDB = kdb
	kdb.UpdateQ = q

	child := newMapZone("example.", Secondary, childOwners)
	child.Options = childOpts
	child.KeyDB = kdb
	registerZones(t, child, target)

	child.ReconcileSignalPublications()
	if urs := drainUpdateQ(q); len(urs) != 0 {
		t.Fatalf("fixture setup wrote %d updates; it must be a change-gated no-op: %+v", len(urs), urs)
	}
	rows, err := kdb.SignalPublicationsForZone("example.")
	if err != nil {
		t.Fatalf("SignalPublicationsForZone: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("the change-gated publish recorded nothing; there would be nothing to withdraw")
	}
	return &withdrawFixture{child: child, target: target, q: q, kdb: kdb}
}

// pubkeyFixture: one customer zone, one nameserver, published and recorded.
func pubkeyFixture(t *testing.T) *withdrawFixture {
	t.Helper()
	return newWithdrawFixture(t,
		map[string][]dns.RR{
			"example.": {
				mustRR(t, "example. 3600 IN HSYNCPARAM pubkey"),
				mustRR(t, "example. 3600 IN NS ns.foobar.com."),
				mustRR(t, "example. 3600 IN KEY "+sigKeyRdata),
			},
		},
		map[ZoneOption]bool{OptUseHsyncparam: true},
		map[string][]dns.RR{sigOwnerFoo: {mustRR(t, sigOwnerFoo+" 3600 IN KEY "+sigKeyRdata)}},
	)
}

// reloadChild replaces the customer zone with new content, the way an incoming
// transfer does, keeping its identity, options and keystore.
func reloadChild(t *testing.T, f *withdrawFixture, owners map[string][]dns.RR) {
	t.Helper()
	child := newMapZone("example.", Secondary, owners)
	child.Options = f.child.Options
	child.KeyDB = f.kdb
	Zones.Set(child.ZoneName, child)
	f.child = child
}

// assertWithdrawn checks that exactly one update was enqueued, that it deletes
// the given RRtypes at owner and adds nothing, and that the ledger has
// forgotten the name.
func assertWithdrawn(t *testing.T, f *withdrawFixture, owner string, rrtypes ...uint16) {
	t.Helper()
	urs := drainUpdateQ(f.q)
	if len(urs) != 1 {
		t.Fatalf("expected exactly 1 withdrawal update, got %d: %+v", len(urs), urs)
	}
	ur := urs[0]
	if ur.Cmd != "ZONE-UPDATE" || ur.ZoneName != "foobar.com." || !ur.InternalUpdate {
		t.Fatalf("unexpected UpdateRequest: %+v", ur)
	}
	deleted := map[uint16]bool{}
	for _, rr := range ur.Actions {
		if rr.Header().Name != owner {
			t.Errorf("action owner = %q, want %q", rr.Header().Name, owner)
		}
		if rr.Header().Class != dns.ClassANY {
			t.Errorf("a withdrawal must be deletes only; got %s", rr)
			continue
		}
		deleted[rr.Header().Rrtype] = true
	}
	for _, rrtype := range rrtypes {
		if !deleted[rrtype] {
			t.Errorf("no delete-RRset for %s", dns.TypeToString[rrtype])
		}
	}
	if len(deleted) != len(rrtypes) {
		t.Errorf("deleted %d RRtypes, want %d", len(deleted), len(rrtypes))
	}
	assertNoLedgerRow(t, f.kdb, "foobar.com.", owner)
}

func assertNoLedgerRow(t *testing.T, kdb *KeyDB, target, owner string) {
	t.Helper()
	rows, err := kdb.SignalPublicationsForTarget(target)
	if err != nil {
		t.Fatalf("SignalPublicationsForTarget: %v", err)
	}
	for _, p := range rows {
		if p.Owner == owner {
			t.Fatalf("ledger still claims %s is published in %s", owner, target)
		}
	}
}

func assertLedgerRow(t *testing.T, kdb *KeyDB, target, owner string) {
	t.Helper()
	rows, err := kdb.SignalPublicationsForTarget(target)
	if err != nil {
		t.Fatalf("SignalPublicationsForTarget: %v", err)
	}
	for _, p := range rows {
		if p.Owner == owner {
			return
		}
	}
	t.Fatalf("ledger has forgotten %s in %s; nothing can withdraw it now", owner, target)
}

// Case 1: use-hsyncparam removed from the zone's options. The option is read
// when the hook runs, so this is the same code path whether the operator
// reloaded the config or edited it with the daemon stopped.
func TestWithdraw_UseHsyncparamRemoved(t *testing.T) {
	f := pubkeyFixture(t)

	f.child.Options = map[ZoneOption]bool{}
	f.child.ReconcileSignalPublications()

	assertWithdrawn(t, f, sigOwnerFoo, dns.TypeKEY)
}

// Case 2: the pubkey flag dropped from the customer's apex HSYNCPARAM while
// the option stays on. Visible in the transfer, so the reconcile that follows
// it is the one that acts.
func TestWithdraw_HsyncparamFlagRemoved(t *testing.T) {
	f := pubkeyFixture(t)

	reloadChild(t, f, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubcds"), // pubkey gone
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			mustRR(t, "example. 3600 IN KEY "+sigKeyRdata),
		},
	})
	f.child.ReconcileSignalPublications()

	assertWithdrawn(t, f, sigOwnerFoo, dns.TypeKEY)
}

// The HSYNCPARAM disappearing entirely is the same withdrawal: the record was
// published on the strength of an instruction that is no longer there.
func TestWithdraw_HsyncparamRemovedEntirely(t *testing.T) {
	f := pubkeyFixture(t)

	reloadChild(t, f, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			mustRR(t, "example. 3600 IN KEY "+sigKeyRdata),
		},
	})
	f.child.ReconcileSignalPublications()

	assertWithdrawn(t, f, sigOwnerFoo, dns.TypeKEY)
}

// A flag that survives but whose apex RRset is gone asks us to mirror nothing.
// Leaving the record would advertise, to a parent verifying via at-ns, a key
// the child no longer publishes.
func TestWithdraw_ApexSourceRRsetEmptied(t *testing.T) {
	f := pubkeyFixture(t)

	reloadChild(t, f, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubkey"),
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			// no apex KEY
		},
	})
	f.child.ReconcileSignalPublications()

	assertWithdrawn(t, f, sigOwnerFoo, dns.TypeKEY)
}

// Case 3a: a nameserver removed from the customer's apex NS RRset. Its signal
// name is stale; the remaining nameservers' are not.
func TestWithdraw_NameserverRemovedFromApex(t *testing.T) {
	f := pubkeyFixture(t)

	reloadChild(t, f, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubkey"),
			mustRR(t, "example. 3600 IN NS ns.elsewhere.net."), // ns.foobar.com. gone
			mustRR(t, "example. 3600 IN KEY "+sigKeyRdata),
		},
	})
	f.child.ReconcileSignalPublications()

	assertWithdrawn(t, f, sigOwnerFoo, dns.TypeKEY)
}

// pubcds withdraws both RRtypes of its spec in one update, including the one
// the child never had -- the publication deleted both, so the withdrawal does.
func TestWithdraw_PubcdsWithdrawsBothTypes(t *testing.T) {
	f := newWithdrawFixture(t,
		map[string][]dns.RR{
			"example.": {
				mustRR(t, "example. 3600 IN HSYNCPARAM pubcds"),
				mustRR(t, "example. 3600 IN NS ns.foobar.com."),
				mustRR(t, "example. 3600 IN CDS 12345 15 2 ABCDEF"),
			},
		},
		map[ZoneOption]bool{OptUseHsyncparam: true},
		map[string][]dns.RR{dsbootOwnFoo: {mustRR(t, dsbootOwnFoo+" 3600 IN CDS 12345 15 2 ABCDEF")}},
	)

	f.child.Options = map[ZoneOption]bool{}
	f.child.ReconcileSignalPublications()

	assertWithdrawn(t, f, dsbootOwnFoo, dns.TypeCDS, dns.TypeCDNSKEY)
}

// Case 3b: the customer zone is no longer served here at all, so its own
// reconciler will never run again. The target zone withdraws on its behalf --
// but only once startup has finished registering zones, because before that a
// missing zone means "not loaded yet".
func TestWithdraw_ZoneNoLongerServed(t *testing.T) {
	f := pubkeyFixture(t)
	Zones.Remove("example.")

	t.Run("not armed: nothing happens", func(t *testing.T) {
		f.target.ReconcileSignalPublications()
		if urs := drainUpdateQ(f.q); len(urs) != 0 {
			t.Fatalf("orphan sweep ran before it was armed: %+v", urs)
		}
		assertLedgerRow(t, f.kdb, "foobar.com.", sigOwnerFoo)
	})

	t.Run("armed: withdrawn", func(t *testing.T) {
		armOrphanSweep(t)
		f.target.ReconcileSignalPublications()
		assertWithdrawn(t, f, sigOwnerFoo, dns.TypeKEY)
	})
}

// A zone being removed from the running server does not wait for the target's
// next refresh.
func TestWithdraw_ZoneRemovalIsPrompt(t *testing.T) {
	f := pubkeyFixture(t)

	WithdrawSignalPublicationsForZone(f.kdb, "example.")

	assertWithdrawn(t, f, sigOwnerFoo, dns.TypeKEY)
}

// Case 4: parentsync turned off for a zone whose at-ns bootstrap put a
// KEY at a signal name. Here the published-for zone and the target are the same
// zone -- the nameserver is in bailiwick, which is the case at-ns exists for.
func TestWithdraw_DelegationSyncTurnedOff(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd, q := signalTarget("child.example.", map[string][]dns.RR{
		"child.example.": {mustRR(t, "child.example. 3600 IN NS ns.child.example.")},
		sigOwnerInBai:    {mustRR(t, sigOwnerInBai+" 3600 IN KEY "+sigKeyRdata)},
	})
	zd.KeyDB = kdb
	kdb.UpdateQ = q
	zd.Options = map[ZoneOption]bool{OptDelSyncChild: true}
	registerZones(t, zd)

	if err := kdb.RecordSignalPublication(SignalPublication{
		Target: "child.example.", Owner: sigOwnerInBai, Zone: "child.example.",
		NS: "ns.child.example.", Prefix: signalPrefixSig0Key, Source: signalSourceAtNs,
	}); err != nil {
		t.Fatalf("RecordSignalPublication: %v", err)
	}

	// With parentsync on, the at-ns publication is retained untouched --
	// and in particular the reconciler does not start republishing it.
	zd.ReconcileSignalPublications()
	if urs := drainUpdateQ(q); len(urs) != 0 {
		t.Fatalf("an at-ns publication with parentsync on must be left alone: %+v", urs)
	}
	assertLedgerRow(t, kdb, "child.example.", sigOwnerInBai)

	zd.Options = map[ZoneOption]bool{}
	zd.ReconcileSignalPublications()

	urs := drainUpdateQ(q)
	if len(urs) != 1 {
		t.Fatalf("expected 1 withdrawal update, got %d: %+v", len(urs), urs)
	}
	for _, rr := range urs[0].Actions {
		if rr.Header().Name != sigOwnerInBai || rr.Header().Class != dns.ClassANY || rr.Header().Rrtype != dns.TypeKEY {
			t.Errorf("unexpected action %s (class %s)", rr, dns.ClassToString[rr.Header().Class])
		}
	}
	assertNoLedgerRow(t, kdb, "child.example.", sigOwnerInBai)
}

// The authority rule, stated as a test: a signal RRset this server did not
// publish is never touched, however little the current configuration wants it
// there. The zone here is set up exactly like TestWithdraw_UseHsyncparamRemoved
// -- option off, record present -- and the only difference is the missing
// ledger row.
func TestWithdraw_LeavesRecordsItDidNotPublish(t *testing.T) {
	kdb := newTestKeyDB(t)
	target, q := signalTarget("foobar.com.", map[string][]dns.RR{
		sigOwnerFoo: {mustRR(t, sigOwnerFoo+" 3600 IN KEY "+sigKeyRdata)},
	})
	target.KeyDB = kdb
	kdb.UpdateQ = q

	child := newMapZone("example.", Secondary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubkey"),
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			mustRR(t, "example. 3600 IN KEY "+sigKeyRdata),
		},
	})
	child.Options = map[ZoneOption]bool{} // no use-hsyncparam: nothing is wanted here
	child.KeyDB = kdb
	registerZones(t, child, target)

	armOrphanSweep(t)
	child.ReconcileSignalPublications()
	target.ReconcileSignalPublications()

	if urs := drainUpdateQ(q); len(urs) != 0 {
		t.Fatalf("a hand-published signal RRset was touched: %+v", urs)
	}
	if rrset, err := target.GetRRset(sigOwnerFoo, dns.TypeKEY); err != nil || rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("the operator's record should still be in the zone: %v %v", rrset, err)
	}
}

// A zone whose apex NS RRset is empty is a zone we cannot answer "which
// nameservers" for, and answering "none" would withdraw everything it has.
// Withdraw nothing and leave the rows for a pass that can read the zone.
func TestWithdraw_EmptyApexNSWithdrawsNothing(t *testing.T) {
	f := pubkeyFixture(t)

	reloadChild(t, f, map[string][]dns.RR{
		"example.": {mustRR(t, "example. 3600 IN HSYNCPARAM pubkey")}, // no NS at all
	})
	f.child.ReconcileSignalPublications()

	if urs := drainUpdateQ(f.q); len(urs) != 0 {
		t.Fatalf("a zone with no apex NS RRset must withdraw nothing: %+v", urs)
	}
	assertLedgerRow(t, f.kdb, "foobar.com.", sigOwnerFoo)
}

// A row whose target zone has not loaded yet reads as "nothing at that name"
// for every name. Forgetting the row on that answer would drop the only record
// of a publication that is still on disk, so the row is kept for a later pass.
func TestWithdraw_UnreadyTargetKeepsTheRow(t *testing.T) {
	f := pubkeyFixture(t)

	// A registry entry with no published snapshot: configured, not yet loaded.
	unready := &ZoneData{ZoneName: "foobar.com.", ZoneType: Primary, KeyDB: f.kdb}
	Zones.Set("foobar.com.", unready)

	f.child.Options = map[ZoneOption]bool{}
	f.child.ReconcileSignalPublications()

	if urs := drainUpdateQ(f.q); len(urs) != 0 {
		t.Fatalf("nothing may be enqueued against an unloaded target: %+v", urs)
	}
	assertLedgerRow(t, f.kdb, "foobar.com.", sigOwnerFoo)
}

// The warrant fails when the signal name's zone is no longer served here as
// primary -- signalPublishTargets skips a non-primary target, so the name drops
// out of the keep set. The withdrawal that follows must then NOT happen: we
// cannot write to a zone we do not control, and a demoted zone's content is
// upstream's. The row is kept rather than forgotten, because it is the only
// thing that would still authorize withdrawing the record if the zone is
// promoted back.
func TestWithdraw_TargetNoLongerPrimaryKeepsTheRow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(f *withdrawFixture)
	}{
		{"demoted to secondary", func(f *withdrawFixture) { f.target.ZoneType = Secondary }},
		{"no longer served here", func(f *withdrawFixture) { Zones.Remove("foobar.com.") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := pubkeyFixture(t)
			tc.break_(f)

			f.child.ReconcileSignalPublications()

			if urs := drainUpdateQ(f.q); len(urs) != 0 {
				t.Fatalf("nothing may be written to a zone we are not primary for: %+v", urs)
			}
			assertLedgerRow(t, f.kdb, "foobar.com.", sigOwnerFoo)
			if rrset, err := f.target.GetRRset(sigOwnerFoo, dns.TypeKEY); err != nil || rrset == nil || len(rrset.RRs) != 1 {
				t.Fatalf("the record must be left where it is: %v %v", rrset, err)
			}
		})
	}
}

// The mirror of TestWithdraw_UnreadyTargetKeepsTheRow, on the other zone: a
// PUBLISHED-FOR zone with no snapshot cannot be asked what it wants, and
// reading its empty apex as "wants nothing" would withdraw everything it has.
//
// This asserts the behaviour, not one guard: two checks enforce it (no
// snapshot, and no apex NS), and removing either alone leaves the other
// holding, so no mutation isolates them. Removing both fails this test.
func TestWithdraw_UnreadyPublishedForZoneKeepsRows(t *testing.T) {
	f := pubkeyFixture(t)

	// The registry entry a zone has before its first load completes: options
	// and keystore wired, no published data.
	unloaded := &ZoneData{ZoneName: "example.", ZoneType: Secondary, KeyDB: f.kdb,
		Options: map[ZoneOption]bool{OptUseHsyncparam: true}}
	Zones.Set("example.", unloaded)

	unloaded.ReconcileSignalPublications()

	if urs := drainUpdateQ(f.q); len(urs) != 0 {
		t.Fatalf("a zone that has not loaded must withdraw nothing: %+v", urs)
	}
	assertLedgerRow(t, f.kdb, "foobar.com.", sigOwnerFoo)
}

// A row written by a future build, whose source this one does not recognise,
// is not ours to reason about and therefore not ours to delete.
func TestWithdraw_UnknownSourceIsLeftAlone(t *testing.T) {
	f := pubkeyFixture(t)
	if err := f.kdb.RecordSignalPublication(SignalPublication{
		Target: "foobar.com.", Owner: sigOwnerFoo, Zone: "example.",
		NS: "ns.foobar.com.", Prefix: signalPrefixSig0Key, Source: "some-future-publisher",
	}); err != nil {
		t.Fatalf("RecordSignalPublication: %v", err)
	}

	f.child.Options = map[ZoneOption]bool{}
	f.child.ReconcileSignalPublications()

	if urs := drainUpdateQ(f.q); len(urs) != 0 {
		t.Fatalf("a publication with an unknown source was acted on: %+v", urs)
	}
	assertLedgerRow(t, f.kdb, "foobar.com.", sigOwnerFoo)
}

// armOrphanSweep turns on the target-side role for the duration of a test.
func armOrphanSweep(t *testing.T) {
	t.Helper()
	prev := signalOrphanSweepArmed.Load()
	signalOrphanSweepArmed.Store(true)
	t.Cleanup(func() { signalOrphanSweepArmed.Store(prev) })
}
