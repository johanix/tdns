package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

func rrsOf(t *testing.T, strs ...string) []dns.RR {
	t.Helper()
	out := make([]dns.RR, 0, len(strs))
	for _, s := range strs {
		out = append(out, mustRR(t, s))
	}
	return out
}

// #507: the DSYNC API scheme is declarative -- it sends what the delegation
// SHOULD be, built from NewNS/NewA/NewAAAA/NewDS. Only NewDS was ever filled
// in, so the payload carried the DS and silently dropped every NS and glue
// change, while both sides reported success and nothing converged.
func TestDeclarativePayloadCarriesNSAndGlueNotJustDS(t *testing.T) {
	child := "child.example."
	syncstate := DelegationSyncStatus{
		ZoneName: child,
		NewNS: rrsOf(t,
			"child.example. 3600 IN NS ns1.child.example.",
			"child.example. 3600 IN NS ns4.child.example."),
		NewA: rrsOf(t,
			"ns1.child.example. 3600 IN A 192.0.2.1",
			"ns4.child.example. 3600 IN A 192.0.2.4"),
		NewAAAA: rrsOf(t,
			"ns4.child.example. 3600 IN AAAA 2001:db8::4"),
		NewDS: rrsOf(t,
			"child.example. 3600 IN DS 12345 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		NewDSKnown: true,
	}

	got := DsyncApiRRsetsFromSyncStatus(child, syncstate)

	// One NS RRset, one DS RRset, and glue grouped per owner per family.
	want := map[string]int{
		"child.example./NS":       2,
		"child.example./DS":       1,
		"ns1.child.example./A":    1,
		"ns4.child.example./A":    1,
		"ns4.child.example./AAAA": 1,
	}
	seen := map[string]int{}
	for _, set := range got {
		seen[set.Owner+"/"+set.Type] = len(set.RRs)
	}
	for k, n := range want {
		if seen[k] != n {
			t.Errorf("%s: %d record(s), want %d -- a delegation sent without its NS and glue"+
				" never converges, and the parent reports success anyway", k, seen[k], n)
		}
	}
	if len(got) != len(want) {
		t.Errorf("sent %d RRsets, want %d: %v", len(got), len(want), seen)
	}
}

// The convergence check is what makes a repeat of #507 loud instead of silent:
// the parent's reply is its own account of the delegation it now holds.
func TestUnconvergedIsDetectedFromTheParentsOwnAnswer(t *testing.T) {
	sent := []DsyncApiRRset{
		{Owner: "child.example.", Type: "NS", RRs: []string{
			"child.example. 3600 IN NS ns1.child.example.",
			"child.example. 3600 IN NS ns4.child.example."}},
		{Owner: "child.example.", Type: "DS", RRs: []string{
			"child.example. 3600 IN DS 12345 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
	}

	t.Run("the parent applied everything", func(t *testing.T) {
		got := &DsyncApiDelegation{Child: "child.example.", RRsets: sent}
		diffs, comparable := dsyncApiUnconverged(sent, got)
		if !comparable {
			t.Fatal("a readable reply was reported as not comparable")
		}
		if len(diffs) != 0 {
			t.Errorf("reported %v for a delegation that matches", diffs)
		}
	})

	t.Run("the parent re-applied its own TTLs", func(t *testing.T) {
		reTTLd := []DsyncApiRRset{
			{Owner: "child.example.", Type: "NS", RRs: []string{
				"child.example. 86400 IN NS ns1.child.example.",
				"child.example. 86400 IN NS ns4.child.example."}},
			{Owner: "child.example.", Type: "DS", RRs: []string{
				"child.example. 86400 IN DS 12345 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
		}
		got := &DsyncApiDelegation{Child: "child.example.", RRsets: reTTLd}
		diffs, comparable := dsyncApiUnconverged(sent, got)
		if !comparable {
			t.Fatal("a readable reply was reported as not comparable")
		}
		if len(diffs) != 0 {
			t.Errorf("a differing TTL was reported as a difference: %v."+
				" The parent is entitled to its own TTLs", diffs)
		}
	})

	t.Run("the parent kept only the DS", func(t *testing.T) {
		// #507 exactly: the DS applied, the NS silently not.
		got := &DsyncApiDelegation{Child: "child.example.", RRsets: []DsyncApiRRset{sent[1]}}
		diffs, comparable := dsyncApiUnconverged(sent, got)
		if !comparable {
			t.Fatal("a readable reply was reported as not comparable")
		}
		if len(diffs) != 1 {
			t.Fatalf("reported %d differences, want 1: %v", len(diffs), diffs)
		}
	})

	// An unreadable or empty read-back leaves convergence UNKNOWN, and unknown
	// must not be reported as failure: the apply is the parent's 200, and both
	// sides of this exchange deliberately return success in exactly these two
	// cases so that a landed change is not retried.
	//
	// This test asserted the opposite before, which is how it shipped.
	t.Run("the parent returned no delegation", func(t *testing.T) {
		diffs, comparable := dsyncApiUnconverged(sent, nil)
		if comparable {
			t.Error("a missing delegation was treated as evidence")
		}
		if len(diffs) != 0 {
			t.Errorf("reported differences from a reply that says nothing: %v", diffs)
		}
	})

	t.Run("the parent returned an empty delegation", func(t *testing.T) {
		// What the endpoint answers when its own read-back fails, AFTER
		// applying the update.
		got := &DsyncApiDelegation{Child: "child.example."}
		diffs, comparable := dsyncApiUnconverged(sent, got)
		if comparable {
			t.Error("an empty read-back was treated as evidence that nothing applied;" +
				" that retries a change the parent has already applied and persisted")
		}
		if len(diffs) != 0 {
			t.Errorf("reported differences: %v", diffs)
		}
	})
}

// The half the payload test above cannot reach: the analyser is what fills the
// declarative fields, and leaving them unset is the actual defect in #507. A
// test that hands DsyncApiRRsetsFromSyncStatus a status built by hand passes
// happily while the analyser produces nothing.
func TestAnalyserDeclaresTheChildsOwnDelegation(t *testing.T) {
	const zone = `child.example.	3600	IN	SOA	ns1.child.example. hostmaster.child.example. 1 7200 1800 604800 7200
child.example.	3600	IN	NS	ns1.child.example.
child.example.	3600	IN	NS	ns4.child.example.
child.example.	3600	IN	NS	ns.elsewhere.net.
ns1.child.example.	3600	IN	A	192.0.2.1
ns4.child.example.	3600	IN	A	192.0.2.4
ns4.child.example.	3600	IN	AAAA	2001:db8::4
`
	zd := testZone(t, "child.example.", zone)

	var resp DelegationSyncStatus
	zd.declareDelegationFromChild(&resp)

	if len(resp.NewNS) != 3 {
		t.Errorf("NewNS has %d records, want the child's whole apex NS RRset (3)", len(resp.NewNS))
	}
	// Glue for the in-bailiwick nameservers only; ns.elsewhere.net. is not ours
	// to declare and has no address records here anyway.
	if len(resp.NewA) != 2 {
		t.Errorf("NewA has %d records, want 2 (ns1 and ns4)", len(resp.NewA))
	}
	if len(resp.NewAAAA) != 1 {
		t.Errorf("NewAAAA has %d records, want 1 (ns4)", len(resp.NewAAAA))
	}

	// And the payload built from it carries all of it, which is the property
	// that failed in the field: NS and glue present, not the DS alone.
	sets := DsyncApiRRsetsFromSyncStatus(zd.ZoneName, resp)
	seen := map[string]bool{}
	for _, s := range sets {
		seen[s.Owner+"/"+s.Type] = true
	}
	for _, want := range []string{
		"child.example./NS", "ns1.child.example./A",
		"ns4.child.example./A", "ns4.child.example./AAAA",
	} {
		if !seen[want] {
			t.Errorf("the declarative payload has no %s; the parent is never told about it"+
				" and the delegation cannot converge", want)
		}
	}
}

// The guard that makes #507 impossible to reintroduce through a THIRD producer
// of a sync status: edits to make, nothing declared to make them with.
func TestIncompleteDeclarativeStatusIsRefused(t *testing.T) {
	ns := rrsOf(t, "child.example. 3600 IN NS ns4.child.example.")
	glue := rrsOf(t, "ns4.child.example. 3600 IN A 192.0.2.4")
	glue6 := rrsOf(t, "ns4.child.example. 3600 IN AAAA 2001:db8::4")

	t.Run("exactly the shape that shipped", func(t *testing.T) {
		// What AnalyseZoneDelegation produced: deltas for NS and glue, and only
		// the DS declared.
		s := DelegationSyncStatus{
			NsAdds: ns, AAdds: glue, AAAAAdds: glue6,
			NewDSKnown: true,
		}
		gaps := dsyncApiIncoherentStatus(s)
		if len(gaps) != 3 {
			t.Errorf("reported %d gaps, want 3 (NS, A, AAAA): %v", len(gaps), gaps)
		}
	})

	t.Run("edits and a matching declaration", func(t *testing.T) {
		s := DelegationSyncStatus{
			NsAdds: ns, NewNS: ns,
			AAdds: glue, NewA: glue,
			AAAAAdds: glue6, NewAAAA: glue6,
		}
		if gaps := dsyncApiIncoherentStatus(s); len(gaps) != 0 {
			t.Errorf("a complete status was reported incoherent: %v", gaps)
		}
	})

	t.Run("nothing to change is not a gap", func(t *testing.T) {
		if gaps := dsyncApiIncoherentStatus(DelegationSyncStatus{}); len(gaps) != 0 {
			t.Errorf("an empty status was reported incoherent: %v", gaps)
		}
	})

	t.Run("an empty DS is a declaration when NewDSKnown says so", func(t *testing.T) {
		ds := rrsOf(t, "child.example. 3600 IN DS 12345 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		withdraw := DelegationSyncStatus{DSRemoves: ds, NewDS: nil, NewDSKnown: true}
		if gaps := dsyncApiIncoherentStatus(withdraw); len(gaps) != 0 {
			t.Errorf("withdrawing the DS was reported incoherent: %v", gaps)
		}
		silent := DelegationSyncStatus{DSRemoves: ds, NewDS: nil, NewDSKnown: false}
		if gaps := dsyncApiIncoherentStatus(silent); len(gaps) != 1 {
			t.Errorf("DS edits with no declaration reported %d gaps, want 1: %v", len(gaps), gaps)
		}
	})
}

// A withdrawal is a declaration too, and the endpoint spells one as an RRset
// with no records. Declaring nothing at all is not the same thing: the payload
// REPLACES what it names, so an owner left unmentioned keeps whatever stale
// records the parent still holds.
func TestWithdrawalsAreDeclaredNotOmitted(t *testing.T) {
	child := "child.example."

	t.Run("glue removed in full", func(t *testing.T) {
		syncstate := DelegationSyncStatus{
			ZoneName: child,
			NewNS:    rrsOf(t, "child.example. 3600 IN NS ns1.child.example."),
			// ns4's glue is going away entirely, so nothing is left to declare
			// for it and it appears only in the removes.
			ARemoves: rrsOf(t, "ns4.child.example. 3600 IN A 192.0.2.4"),
			NewA:     rrsOf(t, "ns1.child.example. 3600 IN A 192.0.2.1"),
		}

		sets := DsyncApiRRsetsFromSyncStatus(child, syncstate)
		found := false
		for _, s := range sets {
			if s.Owner == "ns4.child.example." && s.Type == "A" {
				found = true
				if len(s.RRs) != 0 {
					t.Errorf("the withdrawal carries %d records, want an empty RRset: %v", len(s.RRs), s.RRs)
				}
			}
		}
		if !found {
			t.Error("the glue being removed was not named in the payload at all, so the parent" +
				" keeps serving it; a declarative payload only replaces what it names")
		}
	})

	t.Run("DS withdrawn", func(t *testing.T) {
		// NewDSKnown with an empty NewDS is the documented instruction to
		// withdraw: "no opinion" and "withdraw" are the same nil slice
		// otherwise, which is why the flag exists.
		syncstate := DelegationSyncStatus{
			ZoneName:   child,
			NewNS:      rrsOf(t, "child.example. 3600 IN NS ns1.child.example."),
			NewDS:      nil,
			NewDSKnown: true,
		}

		sets := DsyncApiRRsetsFromSyncStatus(child, syncstate)
		found := false
		for _, s := range sets {
			if s.Type == "DS" {
				found = true
				if len(s.RRs) != 0 {
					t.Errorf("the DS withdrawal carries %d records: %v", len(s.RRs), s.RRs)
				}
			}
		}
		if !found {
			t.Error("a declared DS withdrawal was never sent; the guard allows it and the" +
				" payload dropped it, so the parent keeps a DS the child has withdrawn")
		}
	})

	t.Run("no opinion about the DS sends nothing", func(t *testing.T) {
		syncstate := DelegationSyncStatus{
			ZoneName:   child,
			NewNS:      rrsOf(t, "child.example. 3600 IN NS ns1.child.example."),
			NewDSKnown: false,
		}
		for _, s := range DsyncApiRRsetsFromSyncStatus(child, syncstate) {
			if s.Type == "DS" {
				t.Error("sent a DS RRset for a status with no opinion about the DS;" +
					" that withdraws a DS nobody asked to withdraw")
			}
		}
	})
}

// The guard must not block a withdrawal. Removing glue means there is nothing
// left to declare for that owner, which is the one shape where an empty
// declaration is correct.
func TestTheGuardAllowsAWithdrawal(t *testing.T) {
	removes := rrsOf(t, "ns4.child.example. 3600 IN A 192.0.2.4")

	if gaps := dsyncApiIncoherentStatus(DelegationSyncStatus{ARemoves: removes}); len(gaps) != 0 {
		t.Errorf("a glue withdrawal was refused as incoherent: %v."+
			" Removing the last address for a nameserver leaves nothing to declare,"+
			" and the empty RRset is the declaration", gaps)
	}
	// Adding glue and declaring none is still the #507 shape.
	adds := rrsOf(t, "ns4.child.example. 3600 IN A 192.0.2.4")
	if gaps := dsyncApiIncoherentStatus(DelegationSyncStatus{AAdds: adds}); len(gaps) != 1 {
		t.Errorf("glue adds with nothing declared reported %d gaps, want 1: %v", len(gaps), gaps)
	}
}
