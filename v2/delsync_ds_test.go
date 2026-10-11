/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * SYNC-DS: the rollover engine's DS delivery through the delegation syncher.
 * The discovery is network and is exercised on the testbed; what is tested
 * here is the scheme choice from a plan in hand, the UPDATE the parent
 * receives, the request and its answer, and the syncher's arm.
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const dsSyncChildZoneText = `child.example. 3600 IN SOA ns.child.example. hostmaster.child.example. 1 7200 1800 604800 7200
child.example. 3600 IN NS ns.child.example.
ns.child.example. 3600 IN A 192.0.2.1
`

// dsSyncTestZone is a signed child of example., the shape the DS delivery's
// plan gates ask about.
func dsSyncTestZone(t *testing.T) *ZoneData {
	t.Helper()
	zd := testZone(t, "child.example.", dsSyncChildZoneText)
	zd.SetParent("example.")
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	return zd
}

// dsSyncPlanFor builds the parent sync plan from a DSYNC result in hand, with
// address resolution stubbed, for the schemes configured (every scheme when
// nil).
func dsSyncPlanFor(t *testing.T, zd *ZoneData, res DsyncResult, schemes []string) *ParentSyncPlan {
	t.Helper()
	if schemes == nil {
		schemes = []string{"update", "notify", "api"}
	}
	plan := &ParentSyncPlan{Parent: "example.", Validated: res.Validated}
	plan.resolve = func(_ context.Context, rr *core.DSYNC) (*DsyncTarget, error) {
		return &DsyncTarget{
			Name: rr.Target, Scheme: rr.Scheme, Port: rr.Port, RR: rr,
			Addresses: []string{fmt.Sprintf("192.0.2.53:%d", rr.Port)},
		}, nil
	}
	zd.evaluateSchemes(context.Background(), nil, nil, res, schemes, plan, SyncRoleChild)
	return plan
}

func dsSyncPolicy(pref string) *DnssecPolicy {
	pol := &DnssecPolicy{}
	pol.Rollover.DsyncSchemePreference = pref
	return pol
}

// dsSyncChoiceTargets renders choices as "SCHEME target", in order.
func dsSyncChoiceTargets(choices []schemeChoice) []string {
	out := make([]string, 0, len(choices))
	for _, c := range choices {
		name := ""
		if c.Target != nil {
			name = c.Target.Name
		}
		out = append(out, schemeName(c.Scheme)+" "+name)
	}
	return out
}

// The scheme choice is the policy's preference applied to the plan's
// candidates: the plan's gates and the operator's parentsync.schemes decide
// what is on offer, the preference decides among those, and a NOTIFY target
// advertised for CSYNC alone cannot carry a DS.
func TestRolloverSchemeChoicesFollowThePlanAndThePreference(t *testing.T) {
	zd := dsSyncTestZone(t)
	setChildApiCredentials(t, ParentSyncApiCredentialConf{Parent: "example.", Username: "u", Key: "k"})
	upd := gateDsyncRR(core.SchemeUpdate, dns.TypeANY, "upd.example.")
	ntfCDS := gateDsyncRR(core.SchemeNotify, dns.TypeCDS, "ntf.example.")
	ntfCSYNC := gateDsyncRR(core.SchemeNotify, dns.TypeCSYNC, "csync.example.")
	api := gateDsyncRR(core.SchemeAPI, dns.TypeANY, "api.example.")

	cases := []struct {
		name       string
		rdata      []*core.DSYNC
		schemes    []string
		pref       string
		want       []string
		wantErr    error // errors.Is
		wantAdv    [2]bool
		wantLocal  bool // an error without the sentinel
		noCredsApi bool
	}{
		{name: "auto sends over both DNS transports",
			rdata: []*core.DSYNC{upd, ntfCDS}, pref: DsyncSchemePreferenceAuto,
			want: []string{"UPDATE upd.example.", "NOTIFY ntf.example."}, wantAdv: [2]bool{true, true}},
		{name: "a CSYNC-only NOTIFY target cannot carry a DS",
			rdata: []*core.DSYNC{upd, ntfCSYNC}, pref: DsyncSchemePreferenceAuto,
			want: []string{"UPDATE upd.example."}, wantAdv: [2]bool{true, true}},
		{name: "prefer-notify picks NOTIFY",
			rdata: []*core.DSYNC{upd, ntfCDS}, pref: DsyncSchemePreferencePreferNotify,
			want: []string{"NOTIFY ntf.example."}, wantAdv: [2]bool{true, true}},
		{name: "force-update against a NOTIFY-only parent waits for the parent",
			rdata: []*core.DSYNC{ntfCDS}, pref: DsyncSchemePreferenceForceUpdate,
			wantErr: errNoUsableScheme, wantAdv: [2]bool{false, true}},
		{name: "parentsync.schemes decides what is on offer",
			rdata: []*core.DSYNC{upd, ntfCDS}, schemes: []string{"update"}, pref: DsyncSchemePreferenceAuto,
			want: []string{"UPDATE upd.example."}, wantAdv: [2]bool{true, false}},
		{name: "API is the last resort",
			rdata: []*core.DSYNC{api}, pref: DsyncSchemePreferenceAuto,
			want: []string{"API api.example."}},
		{name: "an API-only parent with no credential here is a local gap, not a parent to wait for",
			rdata: []*core.DSYNC{api}, pref: DsyncSchemePreferenceAuto, noCredsApi: true, wantLocal: true},
		{name: "nothing on offer waits for the parent",
			rdata: nil, pref: DsyncSchemePreferenceAuto, wantErr: errNoUsableScheme},
		{name: "an invalid preference is a local error",
			rdata: []*core.DSYNC{upd}, pref: "sideways", wantLocal: true, wantAdv: [2]bool{true, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.noCredsApi {
				setChildApiCredentials(t)
			}
			plan := dsSyncPlanFor(t, zd, DsyncResult{Validated: true, Rdata: tc.rdata}, tc.schemes)
			choices, updAdv, ntfAdv, err := rolloverSchemeChoices(plan, dsSyncPolicy(tc.pref))
			if updAdv != tc.wantAdv[0] || ntfAdv != tc.wantAdv[1] {
				t.Errorf("advertised UPDATE %v NOTIFY %v, want %v %v", updAdv, ntfAdv, tc.wantAdv[0], tc.wantAdv[1])
			}
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			case tc.wantLocal:
				if err == nil || errors.Is(err, errNoUsableScheme) {
					t.Fatalf("err = %v, want an error without the waiting-for-parent sentinel", err)
				}
			default:
				if err != nil {
					t.Fatalf("scheme choice: %v", err)
				}
				if got := dsSyncChoiceTargets(choices); !slices.Equal(got, tc.want) {
					t.Errorf("choices %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// The UPDATE the parent receives: a whole-RRset replacement of the child's
// DS, the DEL ANY DS first and then every DS of the target, signed with the
// child's SIG(0) key, sent once. The accepted index range is recorded.
func TestSendDSViaUpdateReplacesTheWholeDSSet(t *testing.T) {
	sink := startUpdateSink(t, dns.RcodeSuccess)
	kdb := newTestKeyDB(t)
	zd := dsSyncTestZone(t)
	zd.KeyDB = kdb
	if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
		Command: "sig0-mgmt", SubCommand: "generate", Zone: zd.ZoneName, Keyname: zd.ZoneName,
		Algorithm: dns.ED25519, State: Sig0StateActive, Creator: "test",
	}); err != nil {
		t.Fatalf("generate the SIG(0) key: %v", err)
	}
	a := seedKeyWithIndex(t, kdb, zd.ZoneName, DnskeyStateActive, pubA, 3)
	b := seedKeyWithIndex(t, kdb, zd.ZoneName, DnskeyStateStandby, pubB, 4)
	snap, err := loadRolloverTargetSnapshot(kdb, zd.ZoneName)
	if err != nil {
		t.Fatalf("target snapshot: %v", err)
	}

	res, err := zd.sendDSViaUpdate(context.Background(), kdb, nil, snap, nil,
		&DsyncTarget{Name: "upd.example.", Addresses: []string{sink.addr}})
	if err != nil {
		t.Fatalf("sendDSViaUpdate: %v", err)
	}
	if res.Rcode != dns.RcodeSuccess || res.Scheme != "UPDATE" || res.Category != "" {
		t.Fatalf("result %+v, want NOERROR over UPDATE", res)
	}

	m := sink.wait(t, 3*time.Second)
	if m.Opcode != dns.OpcodeUpdate || len(m.Question) != 1 || m.Question[0].Name != "example." {
		t.Fatalf("not an UPDATE for the parent: %v", m)
	}
	if m.IsTsig() != nil || len(m.Extra) == 0 || m.Extra[len(m.Extra)-1].Header().Rrtype != dns.TypeSIG {
		t.Fatalf("the UPDATE must be SIG(0)-signed: %v", m)
	}
	got := actionStrings(m.Ns)
	first := m.Ns[0].Header()
	if len(m.Ns) != 3 || first.Class != dns.ClassANY || first.Rrtype != dns.TypeDS || first.Name != "child.example." {
		t.Fatalf("the UPDATE must start with a DEL ANY DS and carry the two DS:\n%s", strings.Join(got, "\n"))
	}
	var tags []uint16
	for _, rr := range m.Ns[1:] {
		ds, ok := rr.(*dns.DS)
		if !ok || ds.Hdr.Name != "child.example." || ds.Hdr.Class != dns.ClassINET {
			t.Fatalf("not a DS for the child: %v", rr)
		}
		tags = append(tags, ds.KeyTag)
	}
	slices.Sort(tags)
	want := []uint16{a, b}
	slices.Sort(want)
	if !slices.Equal(tags, want) {
		t.Errorf("DS keytags %v, want %v", tags, want)
	}

	row, err := LoadRolloverZoneRow(kdb, zd.ZoneName)
	if err != nil || row == nil {
		t.Fatalf("LoadRolloverZoneRow: row=%v err=%v", row, err)
	}
	if !row.LastSubmittedLow.Valid || row.LastSubmittedLow.Int64 != 3 ||
		!row.LastSubmittedHigh.Valid || row.LastSubmittedHigh.Int64 != 4 {
		t.Errorf("submitted range = [%v,%v], want [3,4]", row.LastSubmittedLow, row.LastSubmittedHigh)
	}
}

// A parent's refusal comes back as the rcode, with the parent-rejected
// category and no error: the rollover engine decides what it means.
func TestSendDSViaUpdateReportsTheParentsRcode(t *testing.T) {
	sink := startUpdateSink(t, dns.RcodeRefused)
	kdb := newTestKeyDB(t)
	zd := dsSyncTestZone(t)
	zd.KeyDB = kdb
	if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
		Command: "sig0-mgmt", SubCommand: "generate", Zone: zd.ZoneName, Keyname: zd.ZoneName,
		Algorithm: dns.ED25519, State: Sig0StateActive, Creator: "test",
	}); err != nil {
		t.Fatalf("generate the SIG(0) key: %v", err)
	}
	seedKeyWithIndex(t, kdb, zd.ZoneName, DnskeyStateActive, pubA, 0)
	snap, err := loadRolloverTargetSnapshot(kdb, zd.ZoneName)
	if err != nil {
		t.Fatalf("target snapshot: %v", err)
	}
	res, err := zd.sendDSViaUpdate(context.Background(), kdb, nil, snap, nil,
		&DsyncTarget{Name: "upd.example.", Addresses: []string{sink.addr}})
	if err != nil {
		t.Fatalf("a refusal is not an error: %v", err)
	}
	if res.Rcode != dns.RcodeRefused || res.Category != SoftfailParentRejected || res.Scheme != "" {
		t.Errorf("result %+v, want REFUSED, parent-rejected, no scheme completed", res)
	}
	if sink.count() != 1 {
		t.Errorf("the parent received %d UPDATEs, want exactly one: no retry loop here", sink.count())
	}
}

// The engine's push is a SYNC-DS to the syncher, carrying the snapshot and
// the policy, with the engine's deadline; the syncher's answer is the
// engine's result.
func TestRequestDSSyncForRolloverGoesThroughTheSyncher(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := dsSyncTestZone(t)
	zd.KeyDB = kdb
	keyid := seedKeyWithIndex(t, kdb, zd.ZoneName, DnskeyStateActive, pubA, 2)
	pol := dsSyncPolicy(DsyncSchemePreferenceAuto)
	q := make(chan DelegationSyncRequest, 1)
	deps := RolloverEngineDeps{KDB: kdb, Zone: zd, Policy: pol, DelegationSyncQ: q}

	var seen DelegationSyncRequest
	go func() {
		seen = <-q
		seen.DSResponse <- DSSyncResponse{Result: KSKDSPushResult{Rcode: dns.RcodeSuccess, Scheme: "UPDATE"}}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := requestDSSyncForRollover(ctx, deps)
	if err != nil {
		t.Fatalf("requestDSSyncForRollover: %v", err)
	}
	if res.Rcode != dns.RcodeSuccess || res.Scheme != "UPDATE" {
		t.Errorf("result %+v, want the syncher's answer", res)
	}
	if seen.Command != "SYNC-DS" || seen.ZoneData != zd || seen.DSSync == nil {
		t.Fatalf("the syncher was asked %+v, want a SYNC-DS for the zone", seen)
	}
	if seen.DSSync.Policy != pol || seen.DSSync.Deadline.IsZero() {
		t.Errorf("the request carries policy %p deadline %v, want the engine's policy and deadline", seen.DSSync.Policy, seen.DSSync.Deadline)
	}
	snap := seen.DSSync.Snapshot
	if snap == nil || len(snap.Rows) != 1 || snap.Rows[0].keyid != keyid || !snap.IndexRangeKnown || snap.IndexLow != 2 {
		t.Errorf("the request's snapshot is %+v, want the one target key with index 2", snap)
	}

	t.Run("no syncher", func(t *testing.T) {
		res, err := requestDSSyncForRollover(ctx, RolloverEngineDeps{KDB: kdb, Zone: zd, Policy: pol})
		if err == nil || res.Category != SoftfailChildConfigLocalError {
			t.Errorf("without a syncher: res %+v err %v, want a local error", res, err)
		}
	})

	t.Run("no answer in time", func(t *testing.T) {
		q := make(chan DelegationSyncRequest, 1)
		short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		res, err := requestDSSyncForRollover(short, RolloverEngineDeps{KDB: kdb, Zone: zd, Policy: pol, DelegationSyncQ: q})
		if !errors.Is(err, context.DeadlineExceeded) || res.Category != SoftfailTransport {
			t.Errorf("unanswered: res %+v err %v, want a transport failure at the deadline", res, err)
		}
	})
}

// The SYNC-DS arm answers every request it gets, the ones it cannot run
// included, so the engine never waits out its deadline for a local reason.
func TestTheSyncDSArmAnswersWhatItCannotRun(t *testing.T) {
	resp := make(chan DSSyncResponse, 1)
	handleDSSync(context.Background(), nil, nil, nil, DelegationSyncRequest{Command: "SYNC-DS", ZoneName: "x.", DSResponse: resp})
	select {
	case r := <-resp:
		if r.Err == nil || r.Result.Category != SoftfailChildConfigLocalError {
			t.Errorf("a request without a zone was answered %+v, want a local error", r)
		}
	default:
		t.Fatal("a request without a zone was not answered")
	}

	kdb := newTestKeyDB(t)
	zd := dsSyncTestZone(t)
	zd.KeyDB = kdb
	seedKeyWithIndex(t, kdb, zd.ZoneName, DnskeyStateActive, pubA, 0)
	resp = make(chan DSSyncResponse, 1)
	handleDSSync(context.Background(), kdb, nil, nil, DelegationSyncRequest{
		Command: "SYNC-DS", ZoneName: zd.ZoneName, ZoneData: zd,
		DSSync:     &DSSyncRequest{Deadline: time.Now().Add(time.Second)},
		DSResponse: resp,
	})
	select {
	case r := <-resp:
		if r.Err == nil || !strings.Contains(r.Err.Error(), "no IMR") || r.Result.Category != SoftfailChildConfigLocalError {
			t.Errorf("without an IMR the arm answered %+v, want a local error naming the IMR", r)
		}
	default:
		t.Fatal("the request was not answered")
	}

	// Nobody waiting: the arm must not block.
	done := make(chan struct{})
	go func() {
		handleDSSync(context.Background(), kdb, nil, nil, DelegationSyncRequest{
			Command: "SYNC-DS", ZoneName: zd.ZoneName, ZoneData: zd, DSSync: &DSSyncRequest{},
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the arm blocked on a request with no response channel")
	}
}

// The blocker line names the config when parentsync.schemes is empty (the
// parent was never asked), and the parent otherwise.
func TestRolloverBlockerTextNamesTheConfigWhenNoSchemeIsConfigured(t *testing.T) {
	empty := &ParentSyncPlan{Parent: "example.", Skipped: []SkippedScheme{{Scheme: "all", Reason: reasonNoSchemesConfigured}}}
	if got := rolloverBlockerText(empty, "auto"); !strings.Contains(got, "parentsync.schemes") || strings.Contains(got, "parent advertises") {
		t.Errorf("empty config: %q, want the config named and not the parent", got)
	}
	silent := &ParentSyncPlan{Parent: "example.", Skipped: []SkippedScheme{{Scheme: "all", Reason: "parent example. publishes no DSYNC records"}}}
	if got := rolloverBlockerText(silent, "prefer-notify"); !strings.Contains(got, "parent advertises no DSYNC scheme") || !strings.Contains(got, `"prefer-notify"`) {
		t.Errorf("a parent with no DSYNC: %q, want the parent named with the preference", got)
	}
	if got := rolloverBlockerText(nil, "auto"); !strings.Contains(got, "parent advertises") {
		t.Errorf("nil plan: %q", got)
	}
}

// The plan's "all" skip for an empty parentsync.schemes is what both the
// DS delivery's blocker line and the policy-bind warning read.
func TestPlanNoSchemesConfigured(t *testing.T) {
	var nilPlan *ParentSyncPlan
	if nilPlan.noSchemesConfigured() {
		t.Error("a nil plan says no schemes configured")
	}
	if (&ParentSyncPlan{Skipped: []SkippedScheme{{Scheme: "all", Reason: "parent x. publishes no DSYNC records"}}}).noSchemesConfigured() {
		t.Error("a parent with no DSYNC records counts as no schemes configured")
	}
	if !(&ParentSyncPlan{Skipped: []SkippedScheme{{Scheme: "API", Reason: "no credential"}, {Scheme: "all", Reason: reasonNoSchemesConfigured}}}).noSchemesConfigured() {
		t.Error("the empty-config skip was not recognised")
	}
}
