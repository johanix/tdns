/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Delegation sync on refresh, stages 2 and 3
// (docs/2026-09-23-delegation-sync-on-refresh.md): the tests of §9, T1-T8.
// The zones are the deleg.example. fixtures of delegation_changed_ng_test.go.

const refreshSyncCmd = "REFRESH-SYNC-DELEGATION"

// withApp runs the rest of the test as the given app.
func withApp(t *testing.T, app AppType) {
	t.Helper()
	old := Globals.App.Type
	Globals.App.Type = app
	t.Cleanup(func() { Globals.App.Type = old })
}

// registerTestMultiProviderAgentApp registers app as a multi-provider agent
// app for the rest of the test only: the registry is process-wide.
func registerTestMultiProviderAgentApp(t *testing.T, app AppType) {
	t.Helper()
	if multiProviderAgentApp(app) {
		t.Fatalf("app type %d is already registered as a multi-provider agent app", app)
	}
	RegisterMultiProviderAgentAppType(app)
	t.Cleanup(func() { delete(multiProviderAgentAppTypes, app) })
}

// ddcngCDS is the CDS for a DNSKEY record, as the zone would publish it.
func ddcngCDS(t *testing.T, key string) string {
	t.Helper()
	rr, err := dns.NewRR(key)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", key, err)
	}
	return rr.(*dns.DNSKEY).ToDS(dns.SHA256).ToCDS().String()
}

// ddcngSignedServedZone is ddcngServedZone as a zone that signs itself serves
// it: its own KSK, ZSK and CDS at the apex.
func ddcngSignedServedZone(t *testing.T) string {
	return ddcngZone(1, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngKSK1, ddcngZSK1, ddcngCDS(t, ddcngKSK1),
		ddcngNS1A, ddcngNS1AAAA, ddcngNS2A)
}

// childZone is a served zone with the given options set.
func childZone(t *testing.T, zoneStr string, opts ...ZoneOption) *ZoneData {
	t.Helper()
	zd := testZone(t, ddcngZoneName, zoneStr)
	zd.Options = map[ZoneOption]bool{}
	for _, opt := range opts {
		zd.SetOption(opt, true)
	}
	return zd
}

func drainRequests(q chan DelegationSyncRequest) []DelegationSyncRequest {
	var out []DelegationSyncRequest
	for {
		select {
		case req := <-q:
			out = append(out, req)
		default:
			return out
		}
	}
}

func requestCommands(reqs []DelegationSyncRequest) []string {
	var out []string
	for _, r := range reqs {
		out = append(out, r.Command)
	}
	return out
}

// runRefresh drives the delegation-change hooks the way a refresh does: every
// pre-refresh callback with the served and the incoming zone, then every
// post-refresh callback. It returns what they queued.
func runRefresh(t *testing.T, served, incoming *ZoneData) []DelegationSyncRequest {
	t.Helper()
	q := make(chan DelegationSyncRequest, 4)
	served.registerDelegationChangeHooks(q)
	for _, pre := range served.OnZonePreRefresh {
		pre(served, incoming)
	}
	for _, post := range served.OnZonePostRefresh {
		post(served)
	}
	return drainRequests(q)
}

// parentQueries is what a fakeParent was asked, by query type.
type parentQueries struct {
	mu    sync.Mutex
	types []uint16
}

func (p *parentQueries) asked(rrtype uint16) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Contains(p.types, rrtype)
}

// fakeParent answers what the NS-and-glue analysis asks the parent: the
// zone's NS RRset, the glue of its in-bailiwick nameservers, and its DS, over
// UDP as AuthQuery asks. zd is pointed at it, so FetchParentData needs no IMR.
// It records the types it was asked for. Each servfail entry, "name/TYPE",
// is answered with SERVFAIL.
func fakeParent(t *testing.T, zd *ZoneData, rrs []string, servfail ...string) *parentQueries {
	t.Helper()
	key := func(name string, rrtype uint16) string {
		return strings.ToLower(dns.Fqdn(name)) + "/" + dns.TypeToString[rrtype]
	}
	data := map[string][]dns.RR{}
	for _, s := range rrs {
		rr := mustRR(t, s)
		k := key(rr.Header().Name, rr.Header().Rrtype)
		data[k] = append(data[k], rr)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	queries := &parentQueries{}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if len(r.Question) == 1 {
			queries.mu.Lock()
			queries.types = append(queries.types, r.Question[0].Qtype)
			queries.mu.Unlock()
			k := key(r.Question[0].Name, r.Question[0].Qtype)
			if slices.Contains(servfail, k) {
				m.Rcode = dns.RcodeServerFailure
			} else {
				m.Answer = data[k]
			}
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the fake parent did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })

	zd.SetParent("example.")
	zd.ParentNS = []string{"ns.parent.example."}
	zd.ParentServers = []string{pc.LocalAddr().String()}
	return queries
}

// armRecord is what the REFRESH-SYNC-DELEGATION arm did.
type armRecord struct {
	analyses int
	synced   []DelegationSyncStatus
	requeued []DelegationSyncRequest
	delays   []time.Duration
	deferred bool
}

// runArm hands ds to the arm with the IMR up. analyse stands in for the
// parent comparison; the send step records what it was given and fails with
// syncErr.
func runArm(t *testing.T, zd *ZoneData, ds DelegationSyncRequest,
	analyse func() (DelegationSyncStatus, error), syncErr error) *armRecord {
	t.Helper()
	rec := &armRecord{}
	ready := NewImrReadiness()
	ready.Publish()
	steps := refreshSyncSteps{
		analyse: func() (DelegationSyncStatus, error) {
			rec.analyses++
			return analyse()
		},
		sync: func(dss DelegationSyncStatus) (string, uint8, UpdateResult, error) {
			rec.synced = append(rec.synced, dss)
			return "sent", dns.RcodeSuccess, UpdateResult{}, syncErr
		},
		requeue: func(next DelegationSyncRequest, delay time.Duration) {
			rec.requeued = append(rec.requeued, next)
			rec.delays = append(rec.delays, delay)
		},
	}
	if done := handleRefreshSyncDelegationWith(context.Background(), ready,
		make(chan DelegationSyncRequest, 1), zd, ds, steps); done != nil {
		rec.deferred = true
	}
	return rec
}

// realAnalyse is the arm's own analysis, as the syncher wires it. With no
// IMR it reaches only the parent fakeParent set up.
func realAnalyse(zd *ZoneData) func() (DelegationSyncStatus, error) {
	return refreshSyncStepsFor(context.Background(), &Config{}, nil, nil, nil, zd).analyse
}

func refreshRequest(zd *ZoneData) DelegationSyncRequest {
	return DelegationSyncRequest{Command: refreshSyncCmd, ZoneName: zd.ZoneName, ZoneData: zd}
}

// T1. A zone that signs itself, after an AXFR from an unsigned upstream: the
// served zone has its keys and its CDS, the incoming one has neither, and the
// NS and glue are the same. The whole comparison reads that as the DS removed
// (§2); child mode must queue nothing.
func TestRefreshSyncKeysOnlyTransferIsNoTrigger(t *testing.T) {
	withApp(t, AppTypeAuth)
	served := childZone(t, ddcngSignedServedZone(t), OptParentSync)
	incoming := ddcngIncoming(t, ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A))

	if _, dss, err := served.DelegationDataChangedNG(incoming); err != nil || len(dss.DSRemoves) == 0 {
		t.Fatalf("fixture: DelegationDataChangedNG reports no DS removal (err %v), so this is not the §2 case", err)
	}
	if got := runRefresh(t, served, incoming); len(got) != 0 {
		t.Errorf("a keys-only transfer queued %v, want nothing", requestCommands(got))
	}
}

// T1, T4. Handed a zone whose NS and glue the parent already has, the arm
// sends nothing, whether the parent's DS is the zone's own or another: DS is
// not this command's to send. The startup compare (stage 3) is this same arm,
// so a parent already in sync gets nothing at startup either.
func TestRefreshSyncInSyncParentGetsNothingWhateverItsDS(t *testing.T) {
	withApp(t, AppTypeAuth)
	for _, tc := range []struct {
		name string
		ds   string
	}{
		{"the parent holds the zone's DS", ddcngDS(t, ddcngKSK1)},
		{"the parent holds another DS", ddcngDS(t, ddcngKSK2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := childZone(t, ddcngSignedServedZone(t), OptParentSync)
			fakeParent(t, zd, []string{ddcngNS1, ddcngNS2, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A, tc.ds})

			rec := runArm(t, zd, refreshRequest(zd), realAnalyse(zd), nil)
			if rec.analyses != 1 {
				t.Fatalf("the arm analysed %d times, want 1", rec.analyses)
			}
			if len(rec.synced) != 0 || len(rec.requeued) != 0 {
				t.Errorf("an in-sync parent got %d sends and %d retries, want none", len(rec.synced), len(rec.requeued))
			}
		})
	}
}

// A parent glue query that fails leaves the comparison incomplete: the parent
// may hold glue the zone no longer has. The arm must not call that in sync:
// nothing is sent, no success is recorded, and it retries. AnalyseZoneDelegation,
// which the explicit sync, the status command and tdns-mp read, passes over the
// failed query as it always did.
func TestRefreshSyncUnreadParentGlueIsAFailure(t *testing.T) {
	withApp(t, AppTypeAuth)
	zd := childZone(t, ddcngServedZone(), OptParentSync)
	fakeParent(t, zd, []string{ddcngNS1, ddcngNS2, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A},
		"ns2.deleg.example./A")

	rec := runArm(t, zd, refreshRequest(zd), realAnalyse(zd), nil)
	if len(rec.synced) != 0 {
		t.Errorf("an incomplete comparison was sent %d times, want none", len(rec.synced))
	}
	if len(rec.requeued) != 1 {
		t.Errorf("an incomplete comparison was re-queued %d times, want 1", len(rec.requeued))
	}
	zd.mu.Lock()
	lastOK := zd.delegationLastSyncOK
	zd.mu.Unlock()
	if !lastOK.IsZero() {
		t.Error("an incomplete comparison was recorded as a success")
	}

	resp, err := zd.AnalyseZoneDelegation(nil)
	if err != nil {
		t.Fatalf("AnalyseZoneDelegation now fails on an unread glue query: %v", err)
	}
	if !resp.InSync {
		t.Error("AnalyseZoneDelegation's verdict changed: the delegation is no longer in sync")
	}
}

// T2. An added nameserver with glue, a removed nameserver and a changed glue
// address each queue one REFRESH-SYNC-DELEGATION; a serial-only change does
// not. On both transfer shapes: after an AXFR from an unsigned upstream the
// incoming zone has none of the zone's own keys, after an IXFR (the published
// snapshot plus the delta) it still has them.
func TestRefreshSyncTriggers(t *testing.T) {
	withApp(t, AppTypeAuth)
	shapes := []struct {
		name  string
		extra []string
	}{
		{"AXFR", nil},
		{"IXFR", []string{ddcngKSK1, ddcngZSK1, ddcngCDS(t, ddcngKSK1)}},
	}
	changes := []struct {
		name       string
		delegation []string
		want       bool
	}{
		{"nameserver added with glue", []string{ddcngNS1, ddcngNS2, ddcngNS3, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A, ddcngNS3A}, true},
		{"nameserver removed", []string{ddcngNS1, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA}, true},
		{"glue address changed", []string{ddcngNS1, ddcngNS2, ddcngNSOut, ddcngNS1A2, ddcngNS1AAAA, ddcngNS2A}, true},
		// Its glue is listed for removal while InSync stays true (pinned in
		// delegation_changed_ng_test.go), so a trigger read from InSync would
		// miss it.
		{"nameserver kept, all its records gone", []string{ddcngNS1, ddcngNS2, ddcngNSOut, ddcngNS2A}, true},
		{"serial only", []string{ddcngNS1, ddcngNS2, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A}, false},
	}
	for _, shape := range shapes {
		for _, c := range changes {
			t.Run(shape.name+"/"+c.name, func(t *testing.T) {
				served := childZone(t, ddcngSignedServedZone(t), OptParentSync)
				rrs := append(append([]string{}, c.delegation...), shape.extra...)
				got := runRefresh(t, served, ddcngIncoming(t, ddcngZone(2, rrs...)))
				if !c.want {
					if len(got) != 0 {
						t.Errorf("queued %v, want nothing", requestCommands(got))
					}
					return
				}
				if len(got) != 1 || got[0].Command != refreshSyncCmd ||
					got[0].ZoneName != ddcngZoneName || got[0].ZoneData != served {
					t.Fatalf("queued %+v, want one %s for %s", requestCommands(got), refreshSyncCmd, ddcngZoneName)
				}
			})
		}
	}
}

// T3. The parent holds a nameserver the zone has withdrawn, and a DS that is
// not the zone's. The analysis reports the NS difference and nothing of DS, the
// arm hands exactly that to the send step, and no scheme's payload built from
// it touches DS.
func TestRefreshSyncSendsNoDS(t *testing.T) {
	withApp(t, AppTypeAuth)
	const withdrawn = "deleg.example. 3600 IN NS ns.old.example."
	zd := childZone(t, ddcngSignedServedZone(t), OptParentSync)
	parent := fakeParent(t, zd, []string{ddcngNS1, ddcngNS2, ddcngNSOut, withdrawn,
		ddcngNS1A, ddcngNS1AAAA, ddcngNS2A, ddcngDS(t, ddcngKSK2)})

	rec := runArm(t, zd, refreshRequest(zd), realAnalyse(zd), nil)
	if len(rec.synced) != 1 {
		t.Fatalf("the arm sent %d times, want 1", len(rec.synced))
	}
	// The DS step is skipped, not run and stripped: the parent is never asked.
	if !parent.asked(dns.TypeNS) {
		t.Fatal("the parent was never asked for the NS RRset, so the analysis did not run against it")
	}
	if parent.asked(dns.TypeDS) {
		t.Error("the analysis asked the parent for the zone's DS")
	}
	dss := rec.synced[0]
	if got, want := ddcngRRs(dss.NsRemoves), ddcngWant(t, "", withdrawn); !slices.Equal(got, want) {
		t.Errorf("NsRemoves = %q, want %q", got, want)
	}
	if n := len(dss.NsAdds) + len(dss.AAdds) + len(dss.ARemoves) + len(dss.AAAAAdds) + len(dss.AAAARemoves); n != 0 {
		t.Errorf("%d other NS or glue changes reported, want none", n)
	}
	if n := len(dss.DSAdds) + len(dss.DSRemoves) + len(dss.NewDS); n != 0 || dss.NewDSKnown {
		t.Errorf("the analysis has a DS opinion: %d records, NewDSKnown %v", n, dss.NewDSKnown)
	}

	for _, mode := range []string{UpdateModeDelta, UpdateModeReplace} {
		m, err := buildDelegationUpdate("example.", ddcngZoneName, dss, mode)
		if err != nil {
			t.Fatalf("%s UPDATE: %v", mode, err)
		}
		ns := 0
		for _, rr := range m.Ns {
			switch rr.Header().Rrtype {
			case dns.TypeDS:
				t.Errorf("the %s UPDATE touches DS: %s", mode, rr)
			case dns.TypeNS:
				ns++
			}
		}
		if ns == 0 {
			t.Errorf("the %s UPDATE carries no NS change, so it shows nothing", mode)
		}
	}

	// NOTIFY: a CSYNC for the NS change and no CDS, since the status has no DS
	// difference. No KeyDB: a NOTIFY(CDS) would have to ask the DS engine for
	// its CDS first, and fail without one.
	notifyq := make(chan NotifyRequest, 4)
	if _, _, err := zd.SyncZoneDelegationViaNotify(context.Background(), nil, notifyq, dss,
		&DsyncTarget{Addresses: []string{"192.0.2.53:53"}}); err != nil {
		t.Fatalf("NOTIFY scheme: %v", err)
	}
	close(notifyq)
	var notified []string
	for req := range notifyq {
		notified = append(notified, dns.TypeToString[req.RRtype])
	}
	if !slices.Equal(notified, []string{"CSYNC"}) {
		t.Errorf("the NOTIFY scheme sent %q, want only CSYNC", notified)
	}

	// The rollover engine's API push carries a DS RRset and nothing else
	// (pushDSRRsetViaApi), so a payload of NS and glue can never name the same
	// RRset as one of its pushes.
	for _, rrset := range DsyncApiRRsetsFromSyncStatus(ddcngZoneName, dss) {
		switch rrset.Type {
		case "NS", "A", "AAAA":
		default:
			t.Errorf("the API payload declares a %s RRset at %s", rrset.Type, rrset.Owner)
		}
	}
}

// T5. A failure is retried on the proxy's schedule, and a retry is dropped
// once a later sync has succeeded. The proxy arm's use of the same helpers is
// pinned in delsync_proxy_retry_test.go.
func TestRefreshSyncRetries(t *testing.T) {
	withApp(t, AppTypeAuth)
	zd := childZone(t, ddcngServedZone(), OptParentSync)
	outOfSync := func() (DelegationSyncStatus, error) {
		return DelegationSyncStatus{ZoneName: zd.ZoneName}, nil
	}
	first := refreshRequest(zd)

	rec := runArm(t, zd, first, outOfSync, errors.New("the parent refused"))
	if len(rec.requeued) != 1 {
		t.Fatalf("a failed send was re-queued %d times, want 1", len(rec.requeued))
	}
	if next := rec.requeued[0]; next.Attempt != 1 || next.Command != refreshSyncCmd ||
		next.ZoneData != zd || next.FailedAt.IsZero() || rec.delays[0] != delegationSyncRetryDelays[0] {
		t.Errorf("retry = {%s attempt %d failedAt %v} after %s, want attempt 1 after %s",
			next.Command, next.Attempt, next.FailedAt, rec.delays[0], delegationSyncRetryDelays[0])
	}

	rec = runArm(t, zd, first, func() (DelegationSyncStatus, error) {
		return DelegationSyncStatus{}, errors.New("the parent did not answer")
	}, nil)
	if len(rec.synced) != 0 || len(rec.requeued) != 1 {
		t.Errorf("a failed analysis: %d sends and %d retries, want 0 and 1", len(rec.synced), len(rec.requeued))
	}

	last := first
	last.Attempt = len(delegationSyncRetryDelays)
	if rec = runArm(t, zd, last, outOfSync, errors.New("still refused")); len(rec.requeued) != 0 {
		t.Error("the retries never run out")
	}

	runArm(t, zd, first, outOfSync, nil)
	zd.mu.Lock()
	lastOK := zd.delegationLastSyncOK
	zd.mu.Unlock()
	if lastOK.IsZero() {
		t.Fatal("a successful sync was not recorded")
	}

	retry := first
	retry.Attempt = 1
	retry.FailedAt = lastOK.Add(-time.Minute)
	if rec = runArm(t, zd, retry, outOfSync, nil); rec.analyses != 0 {
		t.Error("a retry of a failure from before a later success asked the parent again")
	}
	retry.FailedAt = lastOK.Add(time.Minute)
	if rec = runArm(t, zd, retry, outOfSync, nil); rec.analyses != 1 {
		t.Error("a retry of a failure from after the last success was dropped")
	}
}

// The arm waits for the IMR, as the proxy arm does: at startup the request
// routinely arrives before the IMR is up, and the parent is found through it.
func TestRefreshSyncWaitsForTheImr(t *testing.T) {
	withApp(t, AppTypeAuth)
	zd := childZone(t, ddcngServedZone(), OptParentSync)
	analysed := false
	ctx, cancel := context.WithCancel(context.Background())
	done := handleRefreshSyncDelegationWith(ctx, NewImrReadiness(), make(chan DelegationSyncRequest, 1), zd,
		refreshRequest(zd), refreshSyncSteps{
			analyse: func() (DelegationSyncStatus, error) { analysed = true; return DelegationSyncStatus{}, nil },
		})
	if done == nil {
		t.Fatal("with no IMR the arm did not defer the request")
	}
	if analysed {
		t.Error("the arm asked the parent before the IMR was up")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the deferred request did not exit after the context was cancelled")
	}
}

// T6. Which mode a zone's refresh runs. parentsync-proxy runs the proxy mode as
// before (the delsync_proxy_* tests pin what it compares); a parentsync zone on
// tdns-auth runs child mode; a multi-provider zone, a zone without parentsync,
// and parentsync on any app other than tdns-auth run neither.
func TestRefreshSyncModeGates(t *testing.T) {
	const mpAgent AppType = 251 // an app type tdns does not know, as tdns-mp's agent is to tdns
	registerTestMultiProviderAgentApp(t, mpAgent)
	nsAdded := ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNS3, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A, ddcngNS3A)
	for _, tc := range []struct {
		name string
		app  AppType
		opts []ZoneOption
		want []string
	}{
		{"parentsync on tdns-auth: child mode", AppTypeAuth, []ZoneOption{OptParentSync}, []string{refreshSyncCmd}},
		{"parentsync-proxy on tdns-agent: proxy mode", AppTypeAgent, []ZoneOption{OptParentSyncProxy}, []string{"PROXY-SYNC"}},
		{"multi-provider on tdns-auth: neither", AppTypeAuth, []ZoneOption{OptParentSync, OptMultiProvider}, nil},
		{"multi-provider on a multi-provider agent: neither", mpAgent, []ZoneOption{OptParentSync, OptMultiProvider}, nil},
		{"no parentsync: neither", AppTypeAuth, nil, nil},
		{"parentsync on tdns-agent: neither", AppTypeAgent, []ZoneOption{OptParentSync}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withApp(t, tc.app)
			served := childZone(t, ddcngServedZone(), tc.opts...)
			got := requestCommands(runRefresh(t, served, ddcngIncoming(t, nsAdded)))
			if !slices.Equal(got, tc.want) {
				t.Errorf("queued %q, want %q", got, tc.want)
			}
		})
	}
}

// T6. The arm itself refuses a zone outside child mode, a multi-provider zone
// above all, so a request that reaches it some other way sends nothing.
func TestRefreshSyncArmRefusesZonesOutsideChildMode(t *testing.T) {
	withApp(t, AppTypeAuth)
	for _, tc := range []struct {
		name string
		opts []ZoneOption
	}{
		{"multi-provider", []ZoneOption{OptParentSync, OptMultiProvider}},
		{"parentsync-proxy", []ZoneOption{OptParentSyncProxy}},
		{"no parentsync", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := childZone(t, ddcngServedZone(), tc.opts...)
			rec := runArm(t, zd, refreshRequest(zd), func() (DelegationSyncStatus, error) {
				return DelegationSyncStatus{ZoneName: zd.ZoneName}, nil
			}, nil)
			if rec.analyses != 0 || len(rec.synced) != 0 || len(rec.requeued) != 0 || rec.deferred {
				t.Errorf("the arm acted on it: %+v", rec)
			}
		})
	}
}

// T7. A primary's operator edits the zone file and reloads: the refresh from
// file compares the served zone with the new one and queues the sync. The
// first load queues nothing (there is nothing to compare with; the startup
// compare is SetupZoneSync's, T8), and neither does a serial-only reload.
func TestRefreshSyncZoneFileEditTriggers(t *testing.T) {
	withApp(t, AppTypeAuth)
	kdb := newTestKeyDB(t)
	path := filepath.Join(t.TempDir(), "deleg.example.zone")
	if err := os.WriteFile(path, []byte(ddcngServedZone()), 0644); err != nil {
		t.Fatalf("writing the zone file: %v", err)
	}
	zd := &ZoneData{
		ZoneName:      ddcngZoneName,
		ZoneStore:     MapZone,
		ZoneType:      Primary,
		Zonefile:      path,
		Logger:        log.New(os.Stderr, "", 0),
		Options:       map[ZoneOption]bool{OptParentSync: true},
		KeyDB:         kdb,
		FirstZoneLoad: true,
	}
	registerZones(t, zd)
	t.Cleanup(zd.stopPublisher)
	q := make(chan DelegationSyncRequest, 8)
	zd.registerStandardRefreshHooks(q)

	ctx := context.Background()
	if _, err := zd.FetchFromFile(ctx, false, false, true, nil); err != nil {
		t.Fatalf("FetchFromFile (first load): %v", err)
	}
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	if err := completeFirstZonePolicyAndLoad(ctx, zd, conf, ""); err != nil {
		t.Fatalf("completeFirstZonePolicyAndLoad: %v", err)
	}
	if got := drainRequests(q); len(got) != 0 {
		t.Fatalf("the first load queued %v, want nothing", requestCommands(got))
	}

	edited := []string{ddcngNS1, ddcngNS2, ddcngNS3, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A, ddcngNS3A}
	operatorEdit(t, zd, ddcngZone(2, edited...))
	if _, err := zd.FetchFromFile(ctx, false, false, true, nil); err != nil {
		t.Fatalf("FetchFromFile (reload): %v", err)
	}
	if got := requestCommands(drainRequests(q)); !slices.Equal(got, []string{refreshSyncCmd}) {
		t.Errorf("a reload adding a nameserver queued %q, want one %s", got, refreshSyncCmd)
	}

	operatorEdit(t, zd, ddcngZone(3, edited...))
	if _, err := zd.FetchFromFile(ctx, false, false, true, nil); err != nil {
		t.Fatalf("FetchFromFile (serial-only reload): %v", err)
	}
	if got := drainRequests(q); len(got) != 0 {
		t.Errorf("a serial-only reload queued %v, want nothing", requestCommands(got))
	}
}

// T8. At load, SetupZoneSync queues one REFRESH-SYNC-DELEGATION for a zone in
// child mode, after DELEGATION-SYNC-SETUP and whatever the schemes. A
// multi-provider zone on a registered multi-provider agent app still gets its
// SETUP and gets no compare: that branch admits it, the child-mode predicate
// does not.
func TestRefreshSyncStartupQueue(t *testing.T) {
	oldConf := delegationSyncConf.Load()
	t.Cleanup(func() { delegationSyncConf.Store(oldConf) })
	const mpAgent AppType = 251
	registerTestMultiProviderAgentApp(t, mpAgent)

	for _, tc := range []struct {
		name    string
		app     AppType
		schemes []string
		opts    []ZoneOption
		want    []string
	}{
		{"tdns-auth, update: setup, then the compare", AppTypeAuth, []string{"update"},
			[]ZoneOption{OptParentSync}, []string{"DELEGATION-SYNC-SETUP", refreshSyncCmd}},
		{"tdns-auth, api: the compare", AppTypeAuth, []string{"api"},
			[]ZoneOption{OptParentSync}, []string{refreshSyncCmd}},
		{"tdns-auth, notify: the compare", AppTypeAuth, []string{"notify"},
			[]ZoneOption{OptParentSync}, []string{refreshSyncCmd}},
		{"multi-provider agent: setup, no compare", mpAgent, []string{"update"},
			[]ZoneOption{OptParentSync, OptMultiProvider}, []string{"DELEGATION-SYNC-SETUP"}},
		{"multi-provider on tdns-auth: nothing", AppTypeAuth, []string{"update"},
			[]ZoneOption{OptParentSync, OptMultiProvider}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withApp(t, tc.app)
			delegationSyncConf.Store(&delegationSyncRuntime{ParentSync: ParentSyncConf{Schemes: tc.schemes}})
			zd := childZone(t, ddcngServedZone(), tc.opts...)
			registerZones(t, zd)
			q := make(chan DelegationSyncRequest, 4)
			if err := zd.SetupZoneSync(q); err != nil {
				t.Fatalf("SetupZoneSync: %v", err)
			}
			if got := requestCommands(drainRequests(q)); !slices.Equal(got, tc.want) {
				t.Errorf("queued %q, want %q", got, tc.want)
			}
		})
	}

	// Callers that pass no queue must not block on the new request.
	withApp(t, AppTypeAuth)
	delegationSyncConf.Store(&delegationSyncRuntime{ParentSync: ParentSyncConf{Schemes: []string{"api"}}})
	zd := childZone(t, ddcngServedZone(), OptParentSync)
	registerZones(t, zd)
	done := make(chan error, 1)
	go func() { done <- zd.SetupZoneSync(nil) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("SetupZoneSync(nil): %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SetupZoneSync(nil) blocked")
	}
}
