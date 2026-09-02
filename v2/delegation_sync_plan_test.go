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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	zd.planConsiderNotify(context.Background(), nil, res, plan, SyncRoleChild)

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

	zd.planConsiderNotify(context.Background(), nil, res, plan, SyncRoleChild)

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
	// Validated: the DSYNC lookup DNSSEC-validated, so the credential gate
	// below is what is actually being exercised. The validation gate itself has
	// its own test.
	res := DsyncResult{
		Validated: true,
		Rdata:     []*core.DSYNC{dsyncRR(core.SchemeAPI, dns.TypeANY, "dsync-api.example.")},
	}

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
	// Validated, or this test proves nothing: the DNSSEC gate runs BEFORE the
	// credential gate, so an unvalidated result is skipped for that reason and
	// the credential lookup never happens. The assertion below -- no candidate
	// -- would then hold even if another child's credential were wrongly
	// accepted.
	res := DsyncResult{
		Validated: true,
		Rdata:     []*core.DSYNC{dsyncRR(core.SchemeAPI, dns.TypeANY, "dsync-api.example.")},
	}

	// A credential that names a DIFFERENT child under the same parent must not
	// satisfy this zone's gate.
	setChildApiCredentials(t, DsyncApiChildCredentialConf{
		Parent: "example.", Child: "other.example.", Username: "u", Key: "k"})
	plan := &ParentSyncPlan{Parent: "example."}
	zd.planConsiderApi(res, plan)
	if hasCandidate(plan, "API") {
		t.Fatal("another child's credential satisfied this zone's API gate")
	}
	// And it must be skipped for the CREDENTIAL reason, not the DNSSEC one.
	reason, _ := skipReason(plan, "API")
	if !strings.Contains(reason, "credential") {
		t.Errorf("skip reason %q should name the credential, not something earlier in the gate order", reason)
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
		&ProxyDelegationAnalysis{NsOrGlueChanged: true}, nil)
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

// A DS the parent holds that the child does not support still counts as a
// change, so the startup reconcile treats the delegation as out of sync and
// sends. What it must NOT do is decide the DS question on its own: the API
// payload states the child's DS regardless of how the analysis was built, so a
// parent-vs-child comparison and a transfer diff reach the same request.
func TestProxyAnalysisFromSyncStatusReportsADSDisagreement(t *testing.T) {
	a := proxyAnalysisFromSyncStatus(DelegationSyncStatus{DSRemoves: []dns.RR{&dns.DS{}}})
	if !a.anyChange() {
		t.Fatal("a DS disagreement produced no change, so the reconcile would send nothing")
	}

	zd := testZone(t, proxyApiZone, proxyApiBaseZone()) // unsigned
	rrsets := zd.proxyApiRRsets()
	ds, ok := rrsetFor(rrsets, proxyApiZone, "DS")
	if !ok || len(ds.RRs) != 0 {
		t.Fatalf("want an explicit empty DS rrset, got present=%v rrs=%v", ok, ds.RRs)
	}
}

// ---------------------------------------------------------------------------
// Role: the one gate that differs between a child and a proxy
// ---------------------------------------------------------------------------

// A proxy is a SECONDARY: it cannot publish its own KEY at the child apex, so
// until the operator does it at the primary an UPDATE would be REFUSED. A
// child publishes its own and is never blocked here -- gating it would invent
// a restriction that path never had.
func TestUpdateGateIsProxyOnly(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testZone(t, proxyApiZone, proxyApiBaseZone()) // no KEY at the apex
	zd.KeyDB = kdb

	reason, blocked := zd.updateGateBlocked(kdb, SyncRoleProxy)
	if !blocked {
		t.Fatal("proxy with no KEY published at the apex was not blocked")
	}
	if !strings.Contains(reason, string(ProxyUpdateWaiting)) {
		t.Errorf("blocked reason = %q, want it to name the waiting-for-key state", reason)
	}

	if _, blocked := zd.updateGateBlocked(kdb, SyncRoleChild); blocked {
		t.Error("a child was blocked by the proxy KEY-bootstrap gate")
	}
}

// ---------------------------------------------------------------------------
// zoneIsSigned
// ---------------------------------------------------------------------------

// Published DNSKEYs are what a proxy sees (it serves a transferred copy). A
// child may sign the zone itself, where the keys are not necessarily in the
// parsed zone at the moment this is asked -- so the signing options count too.
// Asking only about the RRset would call an online-signing child unsigned and
// silently drop NOTIFY from its plan.
func TestZoneIsSignedAcceptsBothEvidence(t *testing.T) {
	unsigned := testZone(t, proxyApiZone, proxyApiBaseZone())
	if zoneIsSigned(unsigned) {
		t.Error("a zone with no DNSKEYs and no signing options reported as signed")
	}

	withKeys := testZone(t, proxyApiZone, proxyApiSignedZone())
	if !zoneIsSigned(withKeys) {
		t.Error("a zone with a published DNSKEY reported as unsigned")
	}

	for _, opt := range []ZoneOption{OptOnlineSigning, OptInlineSigning} {
		signer := testZone(t, proxyApiZone, proxyApiBaseZone())
		if signer.Options == nil {
			signer.Options = map[ZoneOption]bool{}
		}
		signer.Options[opt] = true
		if !zoneIsSigned(signer) {
			t.Errorf("a zone with %v set reported as unsigned", opt)
		}
	}
}

// ---------------------------------------------------------------------------
// walkSyncPlan
// ---------------------------------------------------------------------------

// A failure must not end the walk. This is what the child path did NOT do
// before: BestSyncScheme picked one scheme and a failure was the end of it,
// even when the parent advertised another transport that would have worked.
func TestWalkSyncPlanContinuesPastAFailure(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	plan := &ParentSyncPlan{Candidates: []SyncCandidate{
		{Scheme: "UPDATE"}, {Scheme: "API"}, {Scheme: "NOTIFY"},
	}}

	var tried []string
	msg, err := zd.walkSyncPlan(context.Background(), plan, func(c SyncCandidate) (string, error) {
		tried = append(tried, c.Scheme)
		if c.Scheme == "API" {
			return "sent via API", nil
		}
		return "", fmt.Errorf("%s is broken", c.Scheme)
	})
	if err != nil {
		t.Fatalf("walk failed even though API succeeded: %v", err)
	}
	if strings.Join(tried, ",") != "UPDATE,API" {
		t.Errorf("tried %v, want UPDATE then API and no further", tried)
	}
	// The success is reported, but so is what had to be stepped over to reach
	// it -- an operator seeing only "sent via API" would not know UPDATE broke.
	if !strings.Contains(msg, "sent via API") || !strings.Contains(msg, "UPDATE failed") {
		t.Errorf("message %q should carry both the success and the earlier failure", msg)
	}
}

func TestWalkSyncPlanStopsAtTheFirstSuccess(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	plan := &ParentSyncPlan{Candidates: []SyncCandidate{{Scheme: "UPDATE"}, {Scheme: "NOTIFY"}}}

	var tried []string
	msg, err := zd.walkSyncPlan(context.Background(), plan, func(c SyncCandidate) (string, error) {
		tried = append(tried, c.Scheme)
		return "sent via " + c.Scheme, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tried) != 1 || tried[0] != "UPDATE" {
		t.Errorf("tried %v, want only UPDATE", tried)
	}
	if msg != "sent via UPDATE" {
		t.Errorf("msg = %q", msg)
	}
}

// When nothing worked, every attempt is named. A caller shown only the last
// error cannot tell which transport was even expected to work.
func TestWalkSyncPlanReportsEveryFailure(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	plan := &ParentSyncPlan{
		Candidates: []SyncCandidate{{Scheme: "UPDATE"}, {Scheme: "API"}},
		Skipped:    []SkippedScheme{{"NOTIFY", "zone is unsigned"}},
	}

	_, err := zd.walkSyncPlan(context.Background(), plan, func(c SyncCandidate) (string, error) {
		return "", fmt.Errorf("%s exploded", c.Scheme)
	})
	if err == nil {
		t.Fatal("no error when every candidate failed")
	}
	for _, want := range []string{"UPDATE exploded", "API exploded", "NOTIFY", "unsigned"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q is missing %q", err, want)
		}
	}
}

// The walk must stop between candidates when the context is cancelled. Each
// candidate is a network round trip over a different transport, and the senders
// observe cancellation unevenly -- the UPDATE path reaches SendUpdate, which
// takes no context at all. Without a check in the walk, a shutdown left it
// working through the rest of the plan.
func TestWalkSyncPlanStopsOnCancellation(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.example."}
	plan := &ParentSyncPlan{
		Parent: "example.",
		Candidates: []SyncCandidate{
			{Scheme: "UPDATE"}, {Scheme: "API"}, {Scheme: "NOTIFY"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var attempts int
	_, err := zd.walkSyncPlan(ctx, plan, func(c SyncCandidate) (string, error) {
		attempts++
		return "sent", nil
	})

	if attempts != 0 {
		t.Errorf("walk attempted %d candidate(s) on a cancelled context; it must stop before the first", attempts)
	}
	if err == nil {
		t.Fatal("walk reported success on a cancelled context")
	}
	if !strings.Contains(err.Error(), "abandoned") {
		t.Errorf("error does not say the walk was abandoned: %v", err)
	}
}

// Cancellation partway through must not be reported as "every scheme failed":
// the remaining transports were never tried, and saying they failed would send
// an operator looking for a fault that does not exist.
func TestWalkSyncPlanCancelledMidwayReportsWhatWasTried(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.example."}
	plan := &ParentSyncPlan{
		Parent: "example.",
		Candidates: []SyncCandidate{
			{Scheme: "UPDATE"}, {Scheme: "API"}, {Scheme: "NOTIFY"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	var attempts int
	_, err := zd.walkSyncPlan(ctx, plan, func(c SyncCandidate) (string, error) {
		attempts++
		cancel() // shutdown arrives during the first attempt
		return "", fmt.Errorf("%s unreachable", c.Scheme)
	})

	if attempts != 1 {
		t.Errorf("walk made %d attempts, want 1 before noticing cancellation", attempts)
	}
	if err == nil {
		t.Fatal("walk reported success")
	}
	if !strings.Contains(err.Error(), "abandoned") {
		t.Errorf("error should say the walk was abandoned, not that every scheme failed: %v", err)
	}
	if !strings.Contains(err.Error(), "UPDATE failed") {
		t.Errorf("error should still name the attempt that was actually made: %v", err)
	}
}

// The API scheme must not be planned off an unvalidated DSYNC lookup. The DSYNC
// RR names the target whose URI carries the endpoint a bearer credential is
// posted to, so whoever can answer that query would choose where the credential
// goes. This gate existed in BestSyncScheme and was lost when the planner
// replaced it.
//
// Validating URI/TXT at the discovered target does not substitute: a spoofed
// DSYNC names an attacker-controlled zone whose own records validate fine.
func TestPlanApiRequiresAValidatedDsyncLookup(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	zd.Parent = "example."
	setChildApiCredentials(t, DsyncApiChildCredentialConf{
		Parent: "example.", Username: "u", Key: "k"})

	unvalidated := DsyncResult{
		Validated: false,
		Rdata:     []*core.DSYNC{dsyncRR(core.SchemeAPI, dns.TypeANY, "dsync-api.example.")},
	}

	plan := &ParentSyncPlan{Parent: "example."}
	zd.planConsiderApi(unvalidated, plan)
	if hasCandidate(plan, "API") {
		t.Fatal("API was planned off an unvalidated DSYNC lookup;" +
			" the bearer credential could be posted to an attacker-chosen endpoint")
	}
	reason, _ := skipReason(plan, "API")
	if !strings.Contains(reason, "DNSSEC-validate") {
		t.Errorf("skip reason %q should say the lookup did not validate", reason)
	}

	// allow-insecure is the operator saying they accept that, and it is the
	// same switch DiscoverDsyncApiEndpoint honours.
	setChildApiAllowInsecure(t, true)
	plan = &ParentSyncPlan{Parent: "example."}
	zd.planConsiderApi(unvalidated, plan)
	if !hasCandidate(plan, "API") {
		t.Fatalf("allow-insecure did not re-enable the API scheme: %s", plan.Summary())
	}
}

// No viper read of the delegationsync block may come back.
//
// config_delegationsync.go states the rule and the reason: the block is modelled
// in full, that struct is its only reader, and viper was unwound because it
// splits keys on "." and returns the zero value with no sign anything went
// wrong. On top of that, tdns-auth and tdns-agent never call
// viper.ReadInConfig() at all, so a viper read of this block returns empty in
// exactly the daemons that depend on it -- silently.
//
// BuildParentSyncPlan reintroduced one anyway, and the effect was total: no
// schemes meant an unusable plan and every configured transport skipped.
// Nothing caught it, because the failure looks identical to "not configured".
//
// A source-level guard rather than a behavioural one, because that is what the
// invariant actually is: a rule about call sites, of which the sole documented
// exception (the child keygen mode in sig0_utils.go) is not in this package's
// delegation-sync planning code.
func TestNoViperReadsOfTheDelegationsyncBlock(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// sig0_utils.go holds the one deliberate exception, documented in
	// config_delegationsync.go: the child keygen MODE.
	allowed := map[string]bool{"sig0_utils.go": true}

	pat := regexp.MustCompile(`viper\.Get[A-Za-z]*\("delegationsync\.`)
	for _, f := range files {
		if allowed[filepath.Base(f)] || strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if pat.MatchString(line) {
				t.Errorf("%s:%d reads the delegationsync block from viper: %s\n"+
					"    Use DelegationSyncConfig(). viper returns empty in tdns-auth and"+
					" tdns-agent, which never read a config file into viper.",
					f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// A NOTIFY the parent cannot act on must not be planned for a proxied zone.
//
// The walk stops at the first success and a vacuous NOTIFY looks like one, so
// with the shipped `schemes: [notify, update]` a signed zone publishing neither
// CDS nor CSYNC would have its NOTIFY "succeed" and the UPDATE and API
// transports this plan exists to offer would never run. That is the ordinary
// state of a DSYNC-unaware primary: it signs, and has never heard of CDS.
//
// Only the SKIP path is driven through planConsiderNotify. The accept path
// continues into target resolution, which needs a live IMR, so what the gate
// decides is tested through zoneHasCdsOrCsync directly rather than by
// contorting the plan call.
func TestPlanNotifyNeedsSomethingTheParentCanRead(t *testing.T) {
	notifyRR := []*core.DSYNC{dsyncRR(core.SchemeNotify, dns.TypeCSYNC, "notify.example.")}

	signedNoSignal := proxyApiBaseZone() +
		"api.example.	3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=\n"

	t.Run("proxy, signed, no CDS or CSYNC: skipped", func(t *testing.T) {
		zd := testZone(t, proxyApiZone, signedNoSignal)
		plan := &ParentSyncPlan{Parent: "example."}
		zd.planConsiderNotify(context.Background(), nil, DsyncResult{Rdata: notifyRR}, plan, SyncRoleProxy)
		if hasCandidate(plan, "NOTIFY") {
			t.Fatal("NOTIFY was planned for a zone with nothing for the parent to read;" +
				" it would succeed vacuously and stop the walk before UPDATE/API")
		}
		reason, _ := skipReason(plan, "NOTIFY")
		if !strings.Contains(reason, "neither CDS nor CSYNC") {
			t.Errorf("skip reason %q should say why there is nothing to read", reason)
		}
	})

	// The child path publishes its own CDS as part of signing, so applying the
	// same test there would race its first publication for no benefit. A child
	// with no CDS must still reach target resolution.
	t.Run("child role is not subject to the CDS test", func(t *testing.T) {
		zd := testZone(t, proxyApiZone, signedNoSignal)
		plan := &ParentSyncPlan{Parent: "example."}
		func() {
			defer func() { _ = recover() }() // target resolution needs a live IMR
			zd.planConsiderNotify(context.Background(), nil, DsyncResult{Rdata: notifyRR}, plan, SyncRoleChild)
		}()
		if reason, skipped := skipReason(plan, "NOTIFY"); skipped &&
			strings.Contains(reason, "neither CDS nor CSYNC") {
			t.Errorf("the proxy-only CDS test was applied to the child role: %s", reason)
		}
	})
}

// What the gate above decides, tested directly.
func TestZoneHasCdsOrCsync(t *testing.T) {
	signed := proxyApiBaseZone() +
		"api.example.	3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=\n"

	tests := []struct {
		name string
		zone string
		want bool
	}{
		{"signed, publishes neither", signed, false},
		{"publishes CDS", signed +
			"api.example.	3600 IN CDS 12345 15 2 0000000000000000000000000000000000000000000000000000000000000000\n", true},
		{"publishes CSYNC", signed + "api.example.	3600 IN CSYNC 66 3 A NS AAAA\n", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := zoneHasCdsOrCsync(testZone(t, proxyApiZone, tc.zone)); got != tc.want {
				t.Errorf("zoneHasCdsOrCsync = %v, want %v", got, tc.want)
			}
		})
	}

	// An unreadable apex must not remove a transport the operator configured.
	t.Run("unreadable apex is not evidence of absence", func(t *testing.T) {
		if !zoneHasCdsOrCsync(&ZoneData{ZoneName: "broken.example."}) {
			t.Error("a zone whose apex cannot be read was treated as publishing neither")
		}
	})
}

// A parent advertising exactly "DSYNC NOTIFY CDS" offers NOTIFY. The filter
// inherited from BestSyncScheme accepted CSYNC and ANY only, so such a parent
// read as offering nothing -- while this code sends CDS notifies on any DNSKEY
// change and from the startup synthesis.
func TestFindDsyncAcceptsNotifyCDS(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rtype uint16
		want  bool
	}{
		{"NOTIFY(CDS)", dns.TypeCDS, true},
		{"NOTIFY(CSYNC)", dns.TypeCSYNC, true},
		{"NOTIFY(ANY)", dns.TypeANY, true},
		{"NOTIFY(DS) is not a signal type", dns.TypeDS, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := DsyncResult{Rdata: []*core.DSYNC{dsyncRR(core.SchemeNotify, tc.rtype, "notify.example.")}}
			got := findDsync(res, core.SchemeNotify, true) != nil
			if got != tc.want {
				t.Errorf("findDsync matched=%v, want %v", got, tc.want)
			}
		})
	}
}

// The startup hole: a proxied child that is already unsigned while the parent
// still holds a DS.
//
// compareParentDS returns early for a zone whose keys tdns does not manage --
// every proxied zone -- so the DS dimension never reached InSync. Matching NS
// and glue were enough to call the delegation synchronised, and
// ProxyStartupReconcile bails on InSync, so the empty-DS repair never ran on
// restart. Steady-state un-signing was unaffected: the DNSKEY removal is itself
// a transfer change.
//
// Driven through unmanagedZoneNeedsDSRepair rather than by re-deriving the
// condition here. The first version of this test did the latter and would have
// passed with the check deleted.
func TestUnsignedChildWithParentDSNeedsRepair(t *testing.T) {
	signed := proxyApiBaseZone() +
		"api.example.\t3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=\n"
	csk := proxyApiBaseZone() +
		"api.example.\t3600 IN DNSKEY 256 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=\n"

	ds, err := dns.NewRR("api.example. 3600 IN DS 12345 15 2 " +
		"0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	apexOf := func(t *testing.T, zone string) *OwnerData {
		t.Helper()
		zd := testZone(t, proxyApiZone, zone)
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil || apex == nil {
			t.Fatalf("apex: %v", err)
		}
		return apex
	}

	tests := []struct {
		name     string
		apex     *OwnerData
		parentDS []dns.RR
		want     bool
	}{
		{"unsigned child, parent holds a DS", apexOf(t, proxyApiBaseZone()), []dns.RR{ds}, true},
		{"unsigned child, parent holds none", apexOf(t, proxyApiBaseZone()), nil, false},
		{"signed child, parent holds a DS", apexOf(t, signed), []dns.RR{ds}, false},
		{"flags-256 CSK is signed too", apexOf(t, csk), []dns.RR{ds}, false},
		{"unreadable apex is not evidence", nil, []dns.RR{ds}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := unmanagedZoneNeedsDSRepair(tc.apex, tc.parentDS); got != tc.want {
				t.Errorf("unmanagedZoneNeedsDSRepair = %v, want %v", got, tc.want)
			}
		})
	}
}
