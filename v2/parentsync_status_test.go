/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * parentsync status (#790): the plan it reports, what it leaves untouched, and
 * the per-scheme detail. The DSYNC discovery is network and is exercised on the
 * testbed; everything from a DsyncResult onwards is tested here.
 */
package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	apexDNSKEY = "upd.example.\t3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=\n"
	apexCDS    = "upd.example.\t3600 IN CDS 12345 15 2 " +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
)

// fakeResolve stands in for the IMR address lookup of a DSYNC target.
func fakeResolve(_ context.Context, rr *core.DSYNC) (*DsyncTarget, error) {
	return &DsyncTarget{Name: rr.Target, Port: rr.Port, RR: rr, Scheme: rr.Scheme}, nil
}

// setParentSyncSchemes installs parentsync.schemes for one test.
func setParentSyncSchemes(t *testing.T, schemes ...string) {
	t.Helper()
	prevCS, prevPS := *ChildSyncConfig(), *ParentSyncConfig()
	ps := prevPS
	ps.Schemes = schemes
	if err := SetDelegationSyncConfig(prevCS, ps); err != nil {
		t.Fatalf("SetDelegationSyncConfig: %v", err)
	}
	t.Cleanup(func() { SetDelegationSyncConfig(prevCS, prevPS) })
}

func outcomeNames(plan *ParentSyncPlan) []string {
	var out []string
	for _, o := range plan.Outcomes {
		verdict := "skipped"
		if o.Usable {
			verdict = "usable"
		}
		out = append(out, o.Scheme+":"+verdict)
	}
	return out
}

// ---------------------------------------------------------------------------
// The plan: every configured scheme, in order, usable or skipped with a reason
// ---------------------------------------------------------------------------

func TestPlanOutcomesPerSchemeSetup(t *testing.T) {
	notify := dsyncRR(core.SchemeNotify, dns.TypeCDS, "notify.example.")
	update := dsyncRR(core.SchemeUpdate, dns.TypeANY, "update.example.")
	api := dsyncRR(core.SchemeAPI, dns.TypeANY, "api.example.")

	for _, role := range []SyncRole{SyncRoleChild, SyncRoleProxy} {
		for _, tc := range []struct {
			name    string
			schemes []string
			rdata   []*core.DSYNC
			want    []string
			wantAll string // a plan that looked at no scheme: its reason
		}{
			{"NOTIFY only", []string{"notify"}, []*core.DSYNC{notify, update}, []string{"NOTIFY:usable"}, ""},
			{"UPDATE only", []string{"update"}, []*core.DSYNC{notify, update}, []string{"UPDATE:usable"}, ""},
			{"both, notify first", []string{"notify", "update"}, []*core.DSYNC{notify, update},
				[]string{"NOTIFY:usable", "UPDATE:usable"}, ""},
			{"both, update first", []string{"update", "notify"}, []*core.DSYNC{notify, update},
				[]string{"UPDATE:usable", "NOTIFY:usable"}, ""},
			{"neither advertised", []string{"notify", "update"}, []*core.DSYNC{api},
				[]string{"NOTIFY:skipped", "UPDATE:skipped"}, ""},
			{"no DSYNC records", []string{"notify", "update"}, nil, nil, "publishes no DSYNC records"},
			{"nothing configured", nil, []*core.DSYNC{notify, update}, nil, "no schemes configured"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				kdb := newTestKeyDB(t)
				// Signed, publishes a CDS, and carries the agent's own KEY: every
				// gate open, so what the test sees is the configuration and what
				// the parent advertises.
				key := genProxySig0Key(t, kdb, proxyUpdZone)
				zd := proxyUpdZoneData(t, kdb, proxyUpdBaseZone()+apexDNSKEY+apexCDS+key.String()+"\n")
				plan := &ParentSyncPlan{Parent: "example.", resolve: fakeResolve}

				zd.evaluateSchemes(context.Background(), kdb, nil, DsyncResult{Rdata: tc.rdata},
					tc.schemes, plan, role)

				if got := strings.Join(outcomeNames(plan), " "); got != strings.Join(tc.want, " ") {
					t.Errorf("outcomes = %q, want %q", got, strings.Join(tc.want, " "))
				}
				if tc.wantAll != "" {
					reason, ok := skipReason(plan, "all")
					if !ok || !strings.Contains(reason, tc.wantAll) {
						t.Errorf("plan-level reason = %q, want it to mention %q", reason, tc.wantAll)
					}
				}
				for _, o := range plan.Outcomes {
					if !o.Usable && o.Reason == "" {
						t.Errorf("%s skipped without a reason", o.Scheme)
					}
				}
			})
		}
	}
}

// Each gate's reason reaches the outcome, and Advertised tells "the parent
// does not offer it" from "this host cannot use it".
func TestPlanOutcomeSkipReasons(t *testing.T) {
	notifyCDS := dsyncRR(core.SchemeNotify, dns.TypeCDS, "notify.example.")
	update := dsyncRR(core.SchemeUpdate, dns.TypeANY, "update.example.")
	api := dsyncRR(core.SchemeAPI, dns.TypeANY, "api.example.")
	signed := proxyUpdBaseZone() + apexDNSKEY

	foreign, _ := genForeignProxyKey(t)

	for _, tc := range []struct {
		name       string
		zone       string
		role       SyncRole
		scheme     string
		rdata      []*core.DSYNC
		validated  bool
		resolveErr bool
		want       string
		advertised bool
	}{
		{name: "not advertised", zone: signed, role: SyncRoleChild, scheme: "update",
			rdata: []*core.DSYNC{notifyCDS}, want: "does not advertise"},
		{name: "unknown scheme", zone: signed, role: SyncRoleChild, scheme: "carrier-pigeon",
			rdata: []*core.DSYNC{update}, want: "unknown scheme name"},
		{name: "NOTIFY, unsigned zone", zone: proxyUpdBaseZone(), role: SyncRoleChild, scheme: "notify",
			rdata: []*core.DSYNC{notifyCDS}, want: "unsigned", advertised: true},
		{name: "NOTIFY proxy, no CDS or CSYNC", zone: signed, role: SyncRoleProxy, scheme: "notify",
			rdata: []*core.DSYNC{notifyCDS}, want: "neither CDS nor CSYNC", advertised: true},
		{name: "UPDATE proxy, KEY not published", zone: signed, role: SyncRoleProxy, scheme: "update",
			rdata: []*core.DSYNC{update}, want: string(ProxyUpdateWaiting), advertised: true},
		{name: "UPDATE proxy, foreign KEY", zone: signed + foreign.String() + "\n", role: SyncRoleProxy,
			scheme: "update", rdata: []*core.DSYNC{update}, want: string(ProxyUpdateForeignKey), advertised: true},
		{name: "API, no credential", zone: signed, role: SyncRoleChild, scheme: "api",
			rdata: []*core.DSYNC{api}, validated: true, want: "no usable credential", advertised: true},
		{name: "API, DSYNC not validated", zone: signed, role: SyncRoleChild, scheme: "api",
			rdata: []*core.DSYNC{api}, want: "did not DNSSEC-validate", advertised: true},
		{name: "target does not resolve", zone: signed, role: SyncRoleChild, scheme: "update",
			rdata: []*core.DSYNC{update}, resolveErr: true, want: "no address", advertised: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zd := proxyUpdZoneData(t, kdb, tc.zone)
			zd.SetParent("example.")
			plan := &ParentSyncPlan{Parent: "example.", resolve: fakeResolve}
			if tc.resolveErr {
				plan.resolve = func(context.Context, *core.DSYNC) (*DsyncTarget, error) {
					return nil, errors.New("no address for update.example.")
				}
			}

			zd.evaluateSchemes(context.Background(), kdb, nil,
				DsyncResult{Rdata: tc.rdata, Validated: tc.validated}, []string{tc.scheme}, plan, tc.role)

			if len(plan.Outcomes) != 1 {
				t.Fatalf("outcomes = %v, want exactly one", outcomeNames(plan))
			}
			o := plan.Outcomes[0]
			if o.Usable {
				t.Fatalf("%s is usable, want skipped with %q", o.Scheme, tc.want)
			}
			if !strings.Contains(o.Reason, tc.want) {
				t.Errorf("reason = %q, want it to mention %q", o.Reason, tc.want)
			}
			if o.Advertised != tc.advertised {
				t.Errorf("Advertised = %v, want %v", o.Advertised, tc.advertised)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Report mode: building the plan for the status command leaves the zone alone
// ---------------------------------------------------------------------------

func TestReportPlanLeavesWarningAndBootstrapFlagAlone(t *testing.T) {
	update := DsyncResult{Rdata: []*core.DSYNC{dsyncRR(core.SchemeUpdate, dns.TypeANY, "update.example.")}}
	foreign, _ := genForeignProxyKey(t)
	const otherWarning = "childsync-proxy advertisement: waiting for publication at the parent primary"

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, kdb *KeyDB) string // returns the zone text
		state ProxyUpdateState
	}{
		{"ready", func(t *testing.T, kdb *KeyDB) string {
			return proxyUpdBaseZone() + genProxySig0Key(t, kdb, proxyUpdZone).String() + "\n"
		}, ProxyUpdateReady},
		{"foreign-key", func(t *testing.T, kdb *KeyDB) string {
			return proxyUpdBaseZone() + foreign.String() + "\n"
		}, ProxyUpdateForeignKey},
		{"waiting-for-key", func(t *testing.T, kdb *KeyDB) string {
			return proxyUpdBaseZone()
		}, ProxyUpdateWaiting},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zd := proxyUpdZoneData(t, kdb, tc.setup(t, kdb))
			zd.Options = map[ZoneOption]bool{OptParentSyncProxy: true}
			zd.SetError(DelegationSyncWarning, "%s", otherWarning)
			zd.proxySig0ParentBootstrapped = true

			plan := &ParentSyncPlan{Parent: "example.", resolve: fakeResolve, report: true}
			zd.evaluateSchemes(context.Background(), kdb, nil, update, []string{"update"}, plan, SyncRoleProxy)

			if got := zd.delegationSyncWarningMsg(); got != otherWarning {
				t.Errorf("warning = %q, want it untouched (%q)", got, otherWarning)
			}
			if !zd.proxySig0ParentBootstrapped {
				t.Error("the report cleared the parent-bootstrap flag")
			}

			// The same plan built for the sync path does do its bookkeeping, so
			// the assertions above are about report mode and not about a gate
			// that never ran.
			if tc.state == ProxyUpdateReady {
				return
			}
			zd.evaluateSchemes(context.Background(), kdb, nil, update, []string{"update"},
				&ParentSyncPlan{Parent: "example.", resolve: fakeResolve}, SyncRoleProxy)
			if got := zd.delegationSyncWarningMsg(); got == otherWarning {
				t.Errorf("%s: the sync path left the warning alone too; the test proves nothing", tc.state)
			}
		})
	}
}

// The one side effect report mode keeps: in WAITING the agent's keypair is
// generated, so that there are records to print.
func TestReportModeStillGeneratesTheWaitingKey(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := proxyUpdZoneData(t, kdb, proxyUpdBaseZone())
	zd.Options = map[ZoneOption]bool{OptParentSyncProxy: true}

	state, err := zd.proxySig0PublicationStateFor(kdb, true)
	if err != nil || state != ProxyUpdateWaiting {
		t.Fatalf("state = %q, err = %v; want waiting-for-key", state, err)
	}
	sak, err := kdb.GetSig0Keys(proxyUpdZone, Sig0StateActive)
	if err != nil || sak == nil || len(sak.Keys) == 0 {
		t.Fatal("no keypair was generated; the report would have nothing to tell the operator to publish")
	}
	if zd.HasError(DelegationSyncWarning) {
		t.Error("report mode set the waiting warning")
	}
}

// proxy-key goes through the same report mode now: running it cannot clear
// another source's warning.
func TestProxyKeyStatusLeavesTheWarningAlone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := proxyUpdZoneData(t, kdb, proxyUpdBaseZone())
	zd.Options = map[ZoneOption]bool{OptParentSyncProxy: true}
	const other = "push to the parent primary failed: example."
	zd.SetError(DelegationSyncWarning, "%s", other)

	// No IMR: update-unsupported, the arm that used to clear the warning.
	if _, err := zd.ProxyKeyStatus(context.Background(), kdb, nil); err != nil {
		t.Fatalf("ProxyKeyStatus: %v", err)
	}
	if got := zd.delegationSyncWarningMsg(); got != other {
		t.Errorf("warning = %q, want %q", got, other)
	}
}

// ---------------------------------------------------------------------------
// The report's pieces
// ---------------------------------------------------------------------------

func TestSchemeReportsKeepOrderAndSpellReasonsOut(t *testing.T) {
	plan := &ParentSyncPlan{}
	plan.skip("NOTIFY", "proxied zone publishes neither CDS nor CSYNC", true)
	plan.use(SyncCandidate{Scheme: "UPDATE", Target: &DsyncTarget{Name: "update.example.", Port: 53}})
	plan.skip("API", "parent does not advertise it", false)

	got := schemeReports(plan)
	if len(got) != 3 || got[0].Scheme != "NOTIFY" || got[1].Scheme != "UPDATE" || got[2].Scheme != "API" {
		t.Fatalf("order lost: %+v", got)
	}
	if !got[1].Usable || got[1].Target != "update.example. port 53" {
		t.Errorf("UPDATE = %+v, want usable at update.example. port 53", got[1])
	}
	if got[0].Usable || got[0].Reason != "proxied zone publishes neither CDS nor CSYNC" {
		t.Errorf("NOTIFY = %+v", got[0])
	}

	// The proxy UPDATE gate's reason is a state name; the report says what it
	// means and keeps the name.
	for state, want := range map[ProxyUpdateState]string{
		ProxyUpdateWaiting:    "not published at the primary yet",
		ProxyUpdateForeignKey: "does not hold",
	} {
		r := describeSkipReason("UPDATE", string(state))
		if !strings.Contains(r, want) || !strings.Contains(r, string(state)) {
			t.Errorf("%s -> %q, want it to say %q and keep the state name", state, r, want)
		}
	}
	if r := describeSkipReason("NOTIFY", string(ProxyUpdateWaiting)); r != string(ProxyUpdateWaiting) {
		t.Errorf("a NOTIFY reason was rewritten: %q", r)
	}
}

// For a proxy the UPDATE detail is proxy-key's report, word for word, in each
// state the parent's UPDATE receiver makes reachable; when the parent does not
// advertise UPDATE there is no detail, only the scheme line.
func TestUpdateReportProxyIsTheProxyKeyReport(t *testing.T) {
	advertised := &ParentSyncPlan{Outcomes: []SchemeOutcome{{Scheme: "UPDATE", Advertised: true}}}
	notAdvertised := &ParentSyncPlan{Outcomes: []SchemeOutcome{{Scheme: "UPDATE", Reason: "parent does not advertise it"}}}
	foreign, _ := genForeignProxyKey(t)

	for _, tc := range []struct {
		name  string
		zone  func(t *testing.T, kdb *KeyDB) string
		state ProxyUpdateState
	}{
		{"ready", func(t *testing.T, kdb *KeyDB) string {
			return proxyUpdBaseZone() + genProxySig0Key(t, kdb, proxyUpdZone).String() + "\n"
		}, ProxyUpdateReady},
		{"foreign-key", func(t *testing.T, kdb *KeyDB) string {
			genProxySig0Key(t, kdb, proxyUpdZone)
			return proxyUpdBaseZone() + foreign.String() + "\n"
		}, ProxyUpdateForeignKey},
		{"waiting-for-key", func(t *testing.T, kdb *KeyDB) string {
			return proxyUpdBaseZone()
		}, ProxyUpdateWaiting},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zd := proxyUpdZoneData(t, kdb, tc.zone(t, kdb))
			zd.Options = map[ZoneOption]bool{OptParentSyncProxy: true}

			ur, todo := zd.updateReport(context.Background(), kdb, nil, SyncRoleProxy, advertised)
			if ur == nil {
				t.Fatal("no UPDATE detail although the parent advertises UPDATE")
			}
			want, err := zd.proxyKeyStatusMessage(tc.state, kdb)
			if err != nil {
				t.Fatal(err)
			}
			if ur.ProxyReport != want {
				t.Errorf("ProxyReport differs from proxy-key's report:\n got: %s\nwant: %s", ur.ProxyReport, want)
			}
			if len(todo) != 0 {
				t.Errorf("unexpected TODO for a proxy: %v", todo)
			}

			if ur, _ := zd.updateReport(context.Background(), kdb, nil, SyncRoleProxy, notAdvertised); ur != nil {
				t.Errorf("UPDATE detail for a parent that does not advertise UPDATE: %+v", ur)
			}
		})
	}
}

// For a child the UPDATE detail is the zone's own key. The parent is not asked
// when it does not advertise UPDATE, and a secondary is told to add the KEY at
// its primary.
func TestUpdateReportChild(t *testing.T) {
	notAdvertised := &ParentSyncPlan{Outcomes: []SchemeOutcome{{Scheme: "UPDATE"}}}
	advertised := &ParentSyncPlan{Outcomes: []SchemeOutcome{{Scheme: "UPDATE", Advertised: true}}}

	kdb := newTestKeyDB(t)
	key := genProxySig0Key(t, kdb, proxyUpdZone)
	zd := proxyUpdZoneData(t, kdb, proxyUpdBaseZone()+key.String()+"\n")
	zd.Options = map[ZoneOption]bool{OptParentSync: true}
	zd.ZoneType = Primary

	ur, todo := zd.updateReport(context.Background(), kdb, nil, SyncRoleChild, notAdvertised)
	if !ur.HaveActiveKey || ur.ActiveKeyID != key.KeyTag() {
		t.Errorf("active key = %v/%d, want %d", ur.HaveActiveKey, ur.ActiveKeyID, key.KeyTag())
	}
	if len(ur.ApexKeyIDs) != 1 || ur.ApexKeyIDs[0] != key.KeyTag() {
		t.Errorf("apex KEYs = %v, want [%d]", ur.ApexKeyIDs, key.KeyTag())
	}
	if !strings.Contains(ur.ParentKeyError, "does not advertise UPDATE") {
		t.Errorf("ParentKeyError = %q", ur.ParentKeyError)
	}
	if len(todo) != 0 {
		t.Errorf("TODO for a primary that publishes its KEY: %v", todo)
	}

	if ur, _ := zd.updateReport(context.Background(), kdb, nil, SyncRoleChild, advertised); !strings.Contains(ur.ParentKeyError, "no IMR") {
		t.Errorf("with no IMR: ParentKeyError = %q", ur.ParentKeyError)
	}

	sec := proxyUpdZoneData(t, kdb, proxyUpdBaseZone())
	sec.Options = map[ZoneOption]bool{OptParentSync: true}
	sec.ZoneType = Secondary
	if _, todo := sec.updateReport(context.Background(), kdb, nil, SyncRoleChild, notAdvertised); len(todo) != 1 ||
		!strings.Contains(todo[0], "at the primary server") {
		t.Errorf("secondary without a KEY: TODO = %v", todo)
	}
}

func TestNotifyReport(t *testing.T) {
	signedCDS := testZone(t, proxyUpdZone, proxyUpdBaseZone()+apexDNSKEY+apexCDS)
	if nr := signedCDS.notifyReport(); !nr.Signed || !nr.PublishesCDS || nr.PublishesCSYNC {
		t.Errorf("signed zone with CDS: %+v", nr)
	}
	bare := testZone(t, proxyUpdZone, proxyUpdBaseZone())
	if nr := bare.notifyReport(); nr.Signed || nr.PublishesCDS || nr.PublishesCSYNC {
		t.Errorf("unsigned zone without CDS/CSYNC: %+v", nr)
	}
}

// ---------------------------------------------------------------------------
// The whole report, without a network
// ---------------------------------------------------------------------------

// fakeDelegationSyncher answers one DELEGATION-STATUS request with dss.
func fakeDelegationSyncher(t *testing.T, dss DelegationSyncStatus) chan DelegationSyncRequest {
	t.Helper()
	q := make(chan DelegationSyncRequest, 1)
	go func() {
		req := <-q
		if req.Command != "DELEGATION-STATUS" {
			dss = DelegationSyncStatus{Error: true, ErrorMsg: "unexpected command " + req.Command}
		}
		req.Response <- dss
	}()
	return q
}

func TestParentSyncStatusReport(t *testing.T) {
	saved := Globals.ImrEngine
	Globals.ImrEngine = nil
	t.Cleanup(func() { Globals.ImrEngine = saved })
	setParentSyncSchemes(t, "notify", "update")

	kdb := newTestKeyDB(t)
	zd := proxyUpdZoneData(t, kdb, proxyUpdBaseZone()+apexDNSKEY)
	zd.Options = map[ZoneOption]bool{OptParentSyncProxy: true}
	zd.SetParent("example.")
	const warning = "DSYNC UPDATE proxy waiting: publish the KEY + HSYNCPARAM pubkey at the primary"
	zd.SetError(DelegationSyncWarning, "%s", warning)

	ns, _ := dns.NewRR("upd.example. 3600 IN NS ns2.upd.example.")
	ds, _ := dns.NewRR("upd.example. 3600 IN DS 12345 15 2 " +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	outOfSync := DelegationSyncStatus{ZoneName: proxyUpdZone, Parent: "example.",
		NsAdds: []dns.RR{ns}, DSAdds: []dns.RR{ds}}

	rep, _ := zd.ParentSyncStatus(context.Background(), kdb, nil, fakeDelegationSyncher(t, outOfSync))

	if rep.Role != "parentsync-proxy" || rep.Parent != "example." {
		t.Errorf("role/parent = %q/%q", rep.Role, rep.Parent)
	}
	if !strings.Contains(rep.PlanNote, "no IMR") {
		t.Errorf("PlanNote = %q, want the missing IMR named", rep.PlanNote)
	}
	if rep.Warning != warning {
		t.Errorf("Warning = %q, want %q", rep.Warning, warning)
	}
	if rep.Notify == nil || !rep.Notify.Signed {
		t.Errorf("NOTIFY is configured: detail = %+v", rep.Notify)
	}
	if rep.Api != nil {
		t.Error("API detail for a zone that does not configure API")
	}
	if rep.Delegation == nil || rep.Delegation.InSync ||
		len(rep.Delegation.NsAddsStr) != 1 || len(rep.Delegation.DSAddsStr) != 1 {
		t.Errorf("delegation = %+v (err %q), want the NS and DS changes as strings", rep.Delegation, rep.DelegationError)
	}

	// In sync, and a syncher that fails.
	rep, _ = zd.ParentSyncStatus(context.Background(), kdb, nil,
		fakeDelegationSyncher(t, DelegationSyncStatus{InSync: true, ZoneName: proxyUpdZone, Parent: "example."}))
	if rep.Delegation == nil || !rep.Delegation.InSync {
		t.Errorf("in sync: %+v (err %q)", rep.Delegation, rep.DelegationError)
	}
	rep, _ = zd.ParentSyncStatus(context.Background(), kdb, nil,
		fakeDelegationSyncher(t, DelegationSyncStatus{Error: true, ErrorMsg: "parent unreachable"}))
	if rep.Delegation != nil || rep.DelegationError != "parent unreachable" {
		t.Errorf("failed comparison: %+v / %q", rep.Delegation, rep.DelegationError)
	}
	rep, _ = zd.ParentSyncStatus(context.Background(), kdb, nil, nil)
	if !strings.Contains(rep.DelegationError, "not available") {
		t.Errorf("no syncher: DelegationError = %q", rep.DelegationError)
	}
}

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

func postParentSync(t *testing.T, req ZoneParentSyncPost) ZoneParentSyncResponse {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/zone/parentsync", bytes.NewReader(body))
	w := httptest.NewRecorder()
	APIzoneParentSync(context.Background(), &Globals.App, nil, newTestKeyDB(t))(w, r)
	var resp ZoneParentSyncResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding the response: %v (body %q)", err, w.Body.String())
	}
	return resp
}

func TestParentSyncStatusHandler(t *testing.T) {
	saved := Globals.ImrEngine
	Globals.ImrEngine = nil
	t.Cleanup(func() { Globals.ImrEngine = saved })

	if resp := postParentSync(t, ZoneParentSyncPost{Command: "status", Zone: "nosuch.example."}); !resp.Error ||
		!strings.Contains(resp.ErrorMsg, "unknown") {
		t.Errorf("unknown zone: %+v", resp)
	}

	zd := testZone(t, proxyUpdZone, proxyUpdBaseZone())
	zd.SetParent("example.")
	zd.Options = map[ZoneOption]bool{}
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })

	if resp := postParentSync(t, ZoneParentSyncPost{Command: "status", Zone: proxyUpdZone}); !resp.Error ||
		!strings.Contains(resp.ErrorMsg, "does not have parentsync or parentsync-proxy") {
		t.Errorf("neither option: %+v", resp)
	}
	zd.Options = map[ZoneOption]bool{OptParentSync: true, OptParentSyncProxy: true}
	if resp := postParentSync(t, ZoneParentSyncPost{Command: "status", Zone: proxyUpdZone}); !resp.Error ||
		!strings.Contains(resp.ErrorMsg, "mutually exclusive") {
		t.Errorf("both options: %+v", resp)
	}

	zd.Options = map[ZoneOption]bool{OptParentSync: true}
	resp := postParentSync(t, ZoneParentSyncPost{Command: "status", Zone: proxyUpdZone})
	if resp.Error {
		t.Fatalf("status: %s", resp.ErrorMsg)
	}
	if resp.Report == nil || resp.Report.Role != "parentsync" {
		t.Fatalf("no report, or the wrong role: %+v", resp.Report)
	}
	// The hard-coded lines are gone, and nothing replaced them in Functions.
	if len(resp.Functions) != 0 {
		t.Errorf("Functions = %v, want empty", resp.Functions)
	}
	raw, _ := json.Marshal(resp)
	for _, gone := range []string{"2024-05-01", "Latest delegation sync transaction", "is in sync with"} {
		if strings.Contains(string(raw), gone) {
			t.Errorf("the response still says %q", gone)
		}
	}
}
