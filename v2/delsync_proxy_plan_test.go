/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The sync plan: which transports are usable, and why the others are not.
 *
 * The discovery itself is network and is exercised on the testbed. What is
 * unit-tested here is everything that decides what to DO with a DSYNC RRset
 * once it is in hand -- the gates, the reasons, and the synthesis that lets the
 * startup reconcile use NOTIFY without a transfer diff.
 */
package tdns

import (
	"context"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func dsyncRR(scheme core.DsyncScheme, rrtype uint16, target string) *core.DSYNC {
	return &core.DSYNC{Type: rrtype, Scheme: scheme, Port: 5303, Target: target}
}

func skipReason(plan *ParentSyncPlan, scheme string) (string, bool) {
	for _, s := range plan.Skipped {
		if s.Scheme == scheme {
			return s.Reason, true
		}
	}
	return "", false
}

func hasCandidate(plan *ParentSyncPlan, scheme string) bool {
	for _, c := range plan.Candidates {
		if c.Scheme == scheme {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// findDsync
// ---------------------------------------------------------------------------

func TestFindDsyncMatchesSchemeAndNotifyType(t *testing.T) {
	res := DsyncResult{Rdata: []*core.DSYNC{
		dsyncRR(core.SchemeUpdate, dns.TypeANY, "upd.parent."),
		dsyncRR(core.SchemeAPI, dns.TypeANY, "api.parent."),
		// A NOTIFY receiver for a type the proxy does not signal about.
		dsyncRR(core.SchemeNotify, dns.TypeDS, "notify-ds.parent."),
	}}

	if got := findDsync(res, core.SchemeUpdate, false); got == nil || got.Target != "upd.parent." {
		t.Errorf("UPDATE lookup = %v, want upd.parent.", got)
	}
	if got := findDsync(res, core.SchemeAPI, false); got == nil || got.Target != "api.parent." {
		t.Errorf("API lookup = %v, want api.parent.", got)
	}
	// NOTIFY(DS) is not something the proxy can act on; the type filter must
	// reject it rather than produce a candidate that can never work.
	if got := findDsync(res, core.SchemeNotify, true); got != nil {
		t.Errorf("NOTIFY lookup matched type %d, want no match", got.Type)
	}

	res.Rdata = append(res.Rdata, dsyncRR(core.SchemeNotify, dns.TypeCSYNC, "notify.parent."))
	if got := findDsync(res, core.SchemeNotify, true); got == nil || got.Target != "notify.parent." {
		t.Errorf("NOTIFY(CSYNC) lookup = %v, want notify.parent.", got)
	}
}

// ---------------------------------------------------------------------------
// The gates
// ---------------------------------------------------------------------------

// The rule that makes NOTIFY different: it carries no data, so for an unsigned
// zone the parent has nothing it can validate. In a ladder that would be a
// vacuous success stopping everything behind it, so the scheme is removed
// rather than ranked last.
func TestPlanExcludesNotifyForAnUnsignedZone(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone()) // no DNSKEY
	plan := &ParentSyncPlan{Parent: "example."}
	res := DsyncResult{Rdata: []*core.DSYNC{dsyncRR(core.SchemeNotify, dns.TypeCSYNC, "notify.example.")}}

	// nil imr is safe: the gate must refuse before any address resolution.
	zd.planConsiderNotify(context.Background(), nil, res, plan)

	if hasCandidate(plan, "NOTIFY") {
		t.Fatal("NOTIFY became a candidate for an unsigned zone")
	}
	reason, ok := skipReason(plan, "NOTIFY")
	if !ok {
		t.Fatal("NOTIFY was dropped without a recorded reason")
	}
	if !strings.Contains(reason, "unsigned") {
		t.Errorf("skip reason %q does not name the unsigned zone as the cause", reason)
	}
}

// A parent that does not advertise a scheme is a different problem from a
// scheme this host cannot use, and the reasons must not be interchangeable --
// one is fixed at the parent, the other here.
func TestPlanRecordsNotAdvertisedSeparately(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiSignedZone())
	plan := &ParentSyncPlan{Parent: "example."}
	res := DsyncResult{Rdata: []*core.DSYNC{dsyncRR(core.SchemeUpdate, dns.TypeANY, "upd.example.")}}

	zd.planConsiderNotify(context.Background(), nil, res, plan)

	reason, ok := skipReason(plan, "NOTIFY")
	if !ok {
		t.Fatal("no reason recorded")
	}
	if !strings.Contains(reason, "does not advertise") {
		t.Errorf("skip reason %q should say the parent does not advertise NOTIFY", reason)
	}
}

// The API gate is settled from config alone -- no round trip, because a
// credential arrives out of band and no amount of retrying produces one.
func TestPlanApiGateOnCredential(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	zd.Parent = "example."
	res := DsyncResult{Rdata: []*core.DSYNC{dsyncRR(core.SchemeAPI, dns.TypeANY, "dsync-api.example.")}}

	// No credential: skipped, with a reason naming where to fix it.
	setChildApiCredentials(t)
	plan := &ParentSyncPlan{Parent: "example."}
	zd.planConsiderApi(res, plan)
	if hasCandidate(plan, "API") {
		t.Fatal("API became a candidate with no credential configured")
	}
	reason, _ := skipReason(plan, "API")
	if !strings.Contains(reason, "credentials") {
		t.Errorf("skip reason %q should point at delegationsync.child.api.credentials", reason)
	}

	// With a credential it is a candidate -- and NO address resolution was
	// needed to get there (§16.7): an API target is a service description
	// point, and requiring A/AAAA would fail on a correctly configured parent.
	setChildApiCredentials(t, DsyncApiChildCredentialConf{
		Parent: "example.", Username: "u", Key: "k"})
	plan = &ParentSyncPlan{Parent: "example."}
	zd.planConsiderApi(res, plan)
	if !hasCandidate(plan, "API") {
		t.Fatalf("API did not become a candidate: %s", plan.Summary())
	}
	for _, c := range plan.Candidates {
		if c.Scheme == "API" && c.Target.Name != "dsync-api.example." {
			t.Errorf("API target = %q, want dsync-api.example.", c.Target.Name)
		}
	}
}

// The credential is picked per (parent, child), so the agent proxying two
// zones under one parent gets the right one in the plan too.
func TestPlanApiGateUsesTheChildSpecificCredential(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	zd.Parent = "example."
	res := DsyncResult{Rdata: []*core.DSYNC{dsyncRR(core.SchemeAPI, dns.TypeANY, "dsync-api.example.")}}

	// A credential that names a DIFFERENT child under the same parent must not
	// satisfy this zone's gate.
	setChildApiCredentials(t, DsyncApiChildCredentialConf{
		Parent: "example.", Child: "other.example.", Username: "u", Key: "k"})
	plan := &ParentSyncPlan{Parent: "example."}
	zd.planConsiderApi(res, plan)
	if hasCandidate(plan, "API") {
		t.Fatal("another child's credential satisfied this zone's API gate")
	}
}

// ---------------------------------------------------------------------------
// Plan reporting
// ---------------------------------------------------------------------------

func TestPlanSummaryNamesBothWhatWillRunAndWhatWasSkipped(t *testing.T) {
	plan := &ParentSyncPlan{
		Candidates: []SyncCandidate{{Scheme: "UPDATE"}},
		Skipped: []SkippedScheme{
			{"API", "no usable credential"},
			{"NOTIFY", "zone is unsigned"},
		},
	}
	s := plan.Summary()
	for _, want := range []string{"UPDATE", "API", "credential", "NOTIFY", "unsigned"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q is missing %q", s, want)
		}
	}
	if !plan.Usable() {
		t.Error("a plan with a candidate reports itself unusable")
	}
	if (&ParentSyncPlan{}).Usable() {
		t.Error("an empty plan reports itself usable")
	}
}

// Nothing usable is a degraded state, not an error: the zone is still served,
// and a hard failure here would take it down over a parent-side problem.
func TestSyncWithParentReportsRatherThanFailsWhenNothingIsUsable(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	plan := &ParentSyncPlan{Parent: "example.", Skipped: []SkippedScheme{
		{"NOTIFY", "zone is unsigned"}}}

	msg, err := zd.SyncWithParent(context.Background(), nil, nil, nil, plan,
		&ProxyDelegationAnalysis{NsOrGlueChanged: true})
	if err != nil {
		t.Fatalf("unusable plan returned an error: %v", err)
	}
	if !strings.Contains(msg, "unsigned") {
		t.Errorf("message %q does not carry the reason", msg)
	}
}

// ---------------------------------------------------------------------------
// Startup-reconcile NOTIFY synthesis
// ---------------------------------------------------------------------------

// The startup reconcile has no transfer diff, so the act-mapping (D4) input is
// synthesised from the parent-vs-child comparison instead. NS/glue drives
// CSYNC; DS/DNSKEY drives CDS.
func TestProxyAnalysisFromSyncStatusMapsOntoTheActMapping(t *testing.T) {
	nsOnly := proxyAnalysisFromSyncStatus(DelegationSyncStatus{
		NsAdds: []dns.RR{&dns.NS{}},
	})
	if !nsOnly.wantCSYNCNotify() {
		t.Error("an NS difference did not ask for NOTIFY(CSYNC)")
	}
	if nsOnly.wantCDSNotify() {
		t.Error("an NS difference asked for NOTIFY(CDS)")
	}

	dsOnly := proxyAnalysisFromSyncStatus(DelegationSyncStatus{
		DSRemoves: []dns.RR{&dns.DS{}},
	})
	if !dsOnly.wantCDSNotify() {
		t.Error("a DS difference did not ask for NOTIFY(CDS)")
	}
	if dsOnly.wantCSYNCNotify() {
		t.Error("a DS difference asked for NOTIFY(CSYNC)")
	}

	// Glue-only differences are still CSYNC.
	glue := proxyAnalysisFromSyncStatus(DelegationSyncStatus{AAAAAdds: []dns.RR{&dns.AAAA{}}})
	if !glue.wantCSYNCNotify() {
		t.Error("a glue difference did not ask for NOTIFY(CSYNC)")
	}

	// In sync: nothing to signal, so the NOTIFY path short-circuits.
	none := proxyAnalysisFromSyncStatus(DelegationSyncStatus{})
	if none.anyChange() {
		t.Error("an empty comparison produced a change")
	}
}

// A DS the parent holds that the child can no longer support is exactly the
// un-signing case, and the synthesised analysis must carry the witness the API
// path needs to declare an empty DS.
func TestProxyAnalysisFromSyncStatusWitnessesUnsigning(t *testing.T) {
	a := proxyAnalysisFromSyncStatus(DelegationSyncStatus{DSRemoves: []dns.RR{&dns.DS{}}})
	if !a.DnskeyChanged {
		t.Fatal("a DS removal did not set DnskeyChanged, so the API path would leave a stale DS")
	}

	zd := testZone(t, proxyApiZone, proxyApiBaseZone()) // unsigned
	rrsets := zd.proxyApiRRsets(a)
	ds, ok := rrsetFor(rrsets, proxyApiZone, "DS")
	if !ok || len(ds.RRs) != 0 {
		t.Fatalf("want an explicit empty DS rrset, got present=%v rrs=%v", ok, ds.RRs)
	}
}
