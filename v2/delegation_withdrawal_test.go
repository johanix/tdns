/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Withdrawing an in-bailiwick nameserver, end to end (#665).
//
// Each test drives the real producer -- the update path for a tdns-auth child,
// the transfer diff for a proxy -- through the real payload builder, and then
// asks the parent's own action builder and NS/glue coherence check what it
// makes of the result. The unit under test is the join: every piece passed its
// own tests while no withdrawal ever landed.

const withdrawalChild = "child.test."

// Before: two nameservers, both in bailiwick, each with glue.
const withdrawalBefore = `child.test.	3600	IN	SOA	ns1.child.test. hostmaster.child.test. 1 7200 1800 604800 7200
child.test.	3600	IN	NS	ns1.child.test.
child.test.	3600	IN	NS	ns3.child.test.
ns1.child.test.	3600	IN	A	192.0.2.1
ns3.child.test.	3600	IN	A	192.0.2.3
`

// After: ns3 and its glue are gone.
const withdrawalAfter = `child.test.	3600	IN	SOA	ns1.child.test. hostmaster.child.test. 2 7200 1800 604800 7200
child.test.	3600	IN	NS	ns1.child.test.
ns1.child.test.	3600	IN	A	192.0.2.1
`

func withdrawalRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", s, err)
	}
	return rr
}

// withdrawalParentVerdict runs actions through the parent's NS/glue coherence
// check against a parent that currently delegates to ns1 + ns3 with glue for
// both, and a child whose nameservers serve only ns1 -- the state after a
// child-first removal.
func withdrawalParentVerdict(t *testing.T, actions []dns.RR) error {
	t.Helper()
	currentNS := []dns.RR{
		withdrawalRR(t, "child.test. 3600 IN NS ns1.child.test."),
		withdrawalRR(t, "child.test. 3600 IN NS ns3.child.test."),
	}
	glue := map[string][]dns.RR{
		"ns1.child.test./A": {withdrawalRR(t, "ns1.child.test. 3600 IN A 192.0.2.1")},
		"ns3.child.test./A": {withdrawalRR(t, "ns3.child.test. 3600 IN A 192.0.2.3")},
	}
	currentGlue := func(owner string, qtype uint16) ([]dns.RR, bool) {
		rrs, ok := glue[strings.ToLower(dns.Fqdn(owner))+"/"+dns.TypeToString[qtype]]
		return rrs, ok
	}
	served := map[string][]dns.RR{
		"child.test./NS":    {withdrawalRR(t, "child.test. 3600 IN NS ns1.child.test.")},
		"ns1.child.test./A": glue["ns1.child.test./A"],
	}
	fetch := func(_ context.Context, name string, qtype uint16) ([]dns.RR, bool, error) {
		return served[strings.ToLower(dns.Fqdn(name))+"/"+dns.TypeToString[qtype]], true, nil
	}
	return CheckDelegationNSCoherence(context.Background(), withdrawalChild, currentNS, currentGlue, actions, fetch)
}

// withdrawalApiVerdict is withdrawalParentVerdict for a DSYNC API payload,
// translated the way the endpoint translates it.
func withdrawalApiVerdict(t *testing.T, sets []DsyncApiRRset) error {
	t.Helper()
	actions, err := dsyncApiBuildActions(&ZoneData{ZoneName: "test."}, withdrawalChild, sets)
	if err != nil {
		t.Fatalf("dsyncApiBuildActions: %v (payload: %s)", err, dsyncApiRRsetsForLog(sets))
	}
	return withdrawalParentVerdict(t, actions)
}

func withdrawalNSNames(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok {
			out = append(out, ns.Ns)
		}
	}
	return out
}

func withdrawalDeletes(sets []DsyncApiRRset, owner, rrtype string) bool {
	s, ok := rrsetFor(sets, owner, rrtype)
	return ok && len(s.RRs) == 0
}

func withdrawalChildZone(t *testing.T) *ZoneData {
	t.Helper()
	zd := testZone(t, withdrawalChild, withdrawalBefore)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeNS, dns.TypeA, dns.TypeAAAA)
	return zd
}

// One delrr of the NS and its glue together, the usual way to withdraw a nameserver. The removals
// are CLASS NONE, and the status used to restate the current NS set because
// nothing matched them.
func TestChildDelrrWithdrawalReachesTheParent(t *testing.T) {
	zd := withdrawalChildZone(t)
	actions, err := BuildZoneUpdateActions(withdrawalChild, ZoneUpdateSpec{
		Verb: VerbDelRR,
		RRs:  []string{"child.test. 3600 IN NS ns3.child.test.", "ns3.child.test. 3600 IN A 192.0.2.3"},
	})
	if err != nil {
		t.Fatalf("BuildZoneUpdateActions: %v", err)
	}

	dss, err := zd.ZoneUpdateChangesDelegationDataNG(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: withdrawalChild, Actions: actions,
	})
	if err != nil {
		t.Fatalf("ZoneUpdateChangesDelegationDataNG: %v", err)
	}

	if got := withdrawalNSNames(dss.NewNS); len(got) != 1 || got[0] != "ns1.child.test." {
		t.Errorf("NewNS = %v, want [ns1.child.test.]: the removal must leave the declared NS set", got)
	}
	// The NS removal lists ns3's glue, and so does the explicit delete of it:
	// one record, counted once.
	if len(dss.ARemoves) != 1 {
		t.Errorf("ARemoves has %d records, want 1: %v", len(dss.ARemoves), dss.ARemoves)
	}

	sets := DsyncApiRRsetsFromSyncStatus(withdrawalChild, dss)
	if ns, ok := rrsetFor(sets, withdrawalChild, "NS"); !ok || len(ns.RRs) != 1 {
		t.Errorf("payload NS = %v (present=%v), want exactly ns1", ns.RRs, ok)
	}
	if !withdrawalDeletes(sets, "ns3.child.test.", "A") {
		t.Errorf("payload does not delete ns3's A glue: %s", dsyncApiRRsetsForLog(sets))
	}
	if err := withdrawalApiVerdict(t, sets); err != nil {
		t.Errorf("the parent refuses the withdrawal: %v\npayload: %s", err, dsyncApiRRsetsForLog(sets))
	}
}

// Working out the status must not change the zone. The glue records it lists
// as removals are the served zone's own; setting CLASS NONE on them in place
// left the child serving "NONE A" records that the update could then no longer
// delete.
func TestChildDelegationStatusLeavesTheServedZoneAlone(t *testing.T) {
	zd := withdrawalChildZone(t)
	actions, err := BuildZoneUpdateActions(withdrawalChild, ZoneUpdateSpec{
		Verb: VerbDelRR,
		RRs:  []string{"child.test. 3600 IN NS ns3.child.test.", "ns3.child.test. 3600 IN A 192.0.2.3"},
	})
	if err != nil {
		t.Fatalf("BuildZoneUpdateActions: %v", err)
	}
	ur := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: withdrawalChild, Actions: actions}

	if _, err := zd.ZoneUpdateChangesDelegationDataNG(ur); err != nil {
		t.Fatalf("ZoneUpdateChangesDelegationDataNG: %v", err)
	}
	od, err := zd.GetOwner("ns3.child.test.")
	if err != nil || od == nil {
		t.Fatalf("GetOwner(ns3): %v", err)
	}
	for _, rr := range od.RRtypes.GetOnlyRRSet(dns.TypeA).RRs {
		if rr.Header().Class != dns.ClassINET {
			t.Errorf("computing the status rewrote the served record to %s", rr.String())
		}
	}

	if _, err := zd.ApplyZoneUpdateToZoneData(ur, newTestKeyDB(t)); err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}
	if od, _ := zd.GetOwner("ns3.child.test."); od != nil && len(od.RRtypes.GetOnlyRRSet(dns.TypeA).RRs) > 0 {
		t.Errorf("the update did not delete ns3's glue: %v", od.RRtypes.GetOnlyRRSet(dns.TypeA).RRs)
	}
}

// replacerrset on the NS set withdraws ns3 without naming its glue at all. The
// withdrawal still has to take the glue with it.
func TestChildReplaceNSWithdrawalDeletesTheGlue(t *testing.T) {
	zd := withdrawalChildZone(t)
	actions, err := BuildZoneUpdateActions(withdrawalChild, ZoneUpdateSpec{
		Verb: VerbReplaceRRset,
		RRs:  []string{"child.test. 3600 IN NS ns1.child.test."},
	})
	if err != nil {
		t.Fatalf("BuildZoneUpdateActions: %v", err)
	}
	dss, err := zd.ZoneUpdateChangesDelegationDataNG(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: withdrawalChild, Actions: actions,
	})
	if err != nil {
		t.Fatalf("ZoneUpdateChangesDelegationDataNG: %v", err)
	}

	sets := DsyncApiRRsetsFromSyncStatus(withdrawalChild, dss)
	if !withdrawalDeletes(sets, "ns3.child.test.", "A") || !withdrawalDeletes(sets, "ns3.child.test.", "AAAA") {
		t.Errorf("payload does not delete ns3's glue: %s", dsyncApiRRsetsForLog(sets))
	}
	if err := withdrawalApiVerdict(t, sets); err != nil {
		t.Errorf("the parent refuses the withdrawal: %v\npayload: %s", err, dsyncApiRRsetsForLog(sets))
	}
}

// proxyWithdrawal runs the proxy's refresh hooks over a transfer that removes
// ns3, and returns the zone as served after the flip with the analysis the
// sync is dispatched with.
func proxyWithdrawal(t *testing.T) (*ZoneData, *ProxyDelegationAnalysis) {
	t.Helper()
	served := testZone(t, withdrawalChild, withdrawalBefore)
	incoming := testZone(t, withdrawalChild, withdrawalAfter)
	served.ProxyDelegationPreRefresh(incoming)
	analysis := served.ProxyRefreshAnalysis
	if analysis == nil || !analysis.NsOrGlueChanged {
		t.Fatalf("the transfer diff did not see the NS change: %+v", analysis)
	}

	// The diff reads the zone being replaced; it must not have changed it.
	od, err := served.GetOwner("ns3.child.test.")
	if err != nil || od == nil {
		t.Fatalf("GetOwner(ns3) in the outgoing zone: %v", err)
	}
	for _, rr := range od.RRtypes.GetOnlyRRSet(dns.TypeA).RRs {
		if rr.Header().Class != dns.ClassINET {
			t.Errorf("the transfer diff rewrote the outgoing zone's record to %s", rr.String())
		}
	}
	return incoming, analysis
}

// The proxy learns of the withdrawal by transfer, after the fact, and builds
// its payload from the zone it now serves -- where ns3 simply is not. The
// analysis is what says ns3 left.
func TestProxyApiWithdrawalReachesTheParent(t *testing.T) {
	zd, analysis := proxyWithdrawal(t)

	sets := zd.proxyApiRRsets(analysis)
	if !withdrawalDeletes(sets, "ns3.child.test.", "A") {
		t.Errorf("payload does not delete ns3's A glue: %s", dsyncApiRRsetsForLog(sets))
	}
	if err := withdrawalApiVerdict(t, sets); err != nil {
		t.Errorf("the parent refuses the withdrawal: %v\npayload: %s", err, dsyncApiRRsetsForLog(sets))
	}

	// Without the analysis, the served zone alone cannot say it.
	if withdrawalDeletes(zd.proxyApiRRsets(nil), "ns3.child.test.", "A") {
		t.Error("a payload with no removals named a glue delete; the served zone has no trace of ns3")
	}
}

// The same withdrawal over the proxy's replace-form UPDATE, which deleted glue
// only for the nameservers it was about to re-add.
func TestProxyReplaceUpdateWithdrawalReachesTheParent(t *testing.T) {
	zd, analysis := proxyWithdrawal(t)

	dss := zd.proxyReplaceSyncState(analysis)
	m, err := buildDelegationUpdate("test.", withdrawalChild, dss, UpdateModeReplace)
	if err != nil {
		t.Fatalf("buildDelegationUpdate: %v", err)
	}
	deletesGlue := map[uint16]bool{}
	for _, rr := range m.Ns {
		h := rr.Header()
		if h.Class == dns.ClassANY && strings.EqualFold(h.Name, "ns3.child.test.") {
			deletesGlue[h.Rrtype] = true
		}
	}
	if !deletesGlue[dns.TypeA] || !deletesGlue[dns.TypeAAAA] {
		t.Errorf("replace UPDATE does not delete ns3's glue:\n%s", strings.Join(ZoneUpdateActionsSummary(m.Ns), "\n"))
	}
	if err := withdrawalParentVerdict(t, m.Ns); err != nil {
		t.Errorf("the parent refuses the withdrawal: %v\nupdate:\n%s", err, strings.Join(ZoneUpdateActionsSummary(m.Ns), "\n"))
	}
}

func TestWithdrawnGlueOwners(t *testing.T) {
	status := DelegationSyncStatus{
		NewNS: []dns.RR{
			withdrawalRR(t, "child.test. 3600 IN NS ns1.child.test."),
			// Kept, in a different case from the removal below.
			withdrawalRR(t, "child.test. 3600 IN NS NS2.child.test."),
		},
		NsRemoves: []dns.RR{
			withdrawalRR(t, "child.test. 3600 IN NS ns2.child.test."),
			withdrawalRR(t, "child.test. 3600 IN NS NS3.child.test."),
			withdrawalRR(t, "child.test. 3600 IN NS ns3.child.test."),
			// Out of bailiwick: glue for it is not this delegation's.
			withdrawalRR(t, "child.test. 3600 IN NS ns.other.test."),
		},
	}
	got := withdrawnGlueOwners(withdrawalChild, status)
	if len(got) != 1 || got[0] != "ns3.child.test." {
		t.Errorf("withdrawnGlueOwners = %v, want [ns3.child.test.]", got)
	}
}

// A withdrawn nameserver whose glue removal is also listed, in another case,
// is deleted once. The endpoint refuses an RRset named twice.
func TestDsyncApiWithdrawalNamesEachGlueRRsetOnce(t *testing.T) {
	status := DelegationSyncStatus{
		NewNS:     []dns.RR{withdrawalRR(t, "child.test. 3600 IN NS ns1.child.test.")},
		NewA:      []dns.RR{withdrawalRR(t, "ns1.child.test. 3600 IN A 192.0.2.1")},
		NsRemoves: []dns.RR{withdrawalRR(t, "child.test. 3600 IN NS ns3.child.test.")},
		ARemoves:  []dns.RR{removalOf(withdrawalRR(t, "NS3.child.test. 3600 IN A 192.0.2.3"))},
	}
	sets := DsyncApiRRsetsFromSyncStatus(withdrawalChild, status)
	if _, err := dsyncApiBuildActions(&ZoneData{ZoneName: "test."}, withdrawalChild, sets); err != nil {
		t.Fatalf("the endpoint would refuse the payload: %v\npayload: %s", err, dsyncApiRRsetsForLog(sets))
	}
	if err := withdrawalApiVerdict(t, sets); err != nil {
		t.Errorf("the parent refuses the withdrawal: %v", err)
	}
}

// The outcome of a refused UPDATE carries the parent's reason. It used to
// appear only on the per-attempt retry lines.
func TestRefusedUpdateErrorCarriesTheEDE(t *testing.T) {
	_, _, err := sendUpdateWithRetry(context.Background(), 2, time.Millisecond,
		func() (int, UpdateResult, error) {
			return dns.RcodeRefused, UpdateResult{
				EDEFound: true, EDECode: edns0.EDEZoneUpdateRRtypeNotAllowed, EDEMessage: "no glue for you",
			}, nil
		},
		nil)
	if err == nil {
		t.Fatal("a REFUSED update reported success")
	}
	if !strings.Contains(err.Error(), "no glue for you") {
		t.Errorf("err = %q; want it to carry the parent's EDE text", err)
	}
}
