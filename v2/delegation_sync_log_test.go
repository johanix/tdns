/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// withSyncLog gives the test a fresh delegation-sync log of size n, and puts
// the previous one back afterwards.
func withSyncLog(t *testing.T, n int) *DelegationSyncLog {
	t.Helper()
	prev := syncLogPtr.Load()
	syncLogPtr.Store(nil)
	installSyncLog(n)
	t.Cleanup(func() { syncLogPtr.Store(prev) })
	return syncLog()
}

func children(rep SyncLogReport) []string {
	var out []string
	for _, ev := range rep.Events {
		out = append(out, ev.Child)
	}
	return out
}

func TestSyncLogKeepsTheNewestAndCountsWhatItDrops(t *testing.T) {
	l := newDelegationSyncLog(3)
	base := time.Now().Add(-time.Hour)
	for i := 1; i <= 5; i++ {
		l.Add(SyncLogEvent{Time: base.Add(time.Duration(i) * time.Minute), Parent: "example.",
			Child: fmt.Sprintf("c%d.example.", i), Mechanism: SyncMechUpdate, Outcome: SyncApplied})
	}
	rep := l.Query(SyncLogQuery{})
	if got := strings.Join(children(rep), " "); got != "c5.example. c4.example. c3.example." {
		t.Errorf("events %q, want the three newest, newest first", got)
	}
	if rep.Dropped != 2 || rep.Size != 3 || !rep.Enabled {
		t.Errorf("dropped %d size %d enabled %v, want 2, 3, true", rep.Dropped, rep.Size, rep.Enabled)
	}

	if got := children(l.Query(SyncLogQuery{Child: "C4.Example"})); len(got) != 1 || got[0] != "c4.example." {
		t.Errorf("child filter: %v, want [c4.example.] (names compared case-insensitively)", got)
	}
	if got := children(l.Query(SyncLogQuery{Parent: "other."})); len(got) != 0 {
		t.Errorf("parent filter: %v, want none", got)
	}
	if got := children(l.Query(SyncLogQuery{Since: base.Add(4*time.Minute + time.Second)})); len(got) != 1 {
		t.Errorf("since filter: %v, want only c5", got)
	}
	if got := children(l.Query(SyncLogQuery{Limit: 2})); len(got) != 2 || got[0] != "c5.example." {
		t.Errorf("limit: %v, want the two newest", got)
	}
}

// Off means a nil log, and every hook is a no-op on it.
func TestSyncLogOffIsANilLog(t *testing.T) {
	withSyncLog(t, 0)
	if syncLog() != nil {
		t.Fatal("sync-log 0 left a log installed")
	}
	syncLog().Add(SyncLogEvent{Child: "x."})
	syncLog().AddPoll(SyncLogEvent{Child: "x.", Outcome: SyncNotProcessed})
	if rep := syncLog().Query(SyncLogQuery{}); rep.Enabled || len(rep.Events) != 0 {
		t.Errorf("query of the nil log: %+v, want empty and not enabled", rep)
	}
	if _, msg := delegationSyncLogReport(DelegationPost{Command: "sync-log"}); !strings.Contains(msg, "off") {
		t.Errorf("API with the log off: %q, want it to say the log is off", msg)
	}
}

func TestSyncLogSizeComesFromChildsync(t *testing.T) {
	prevCS, prevPS := *ChildSyncConfig(), *ParentSyncConfig()
	prevLog := syncLogPtr.Load()
	t.Cleanup(func() {
		SetDelegationSyncConfig(prevCS, prevPS)
		syncLogPtr.Store(prevLog)
	})
	syncLogPtr.Store(nil)

	if err := SetDelegationSyncConfig(ChildSyncConf{}, ParentSyncConf{}); err != nil {
		t.Fatal(err)
	}
	if l := syncLog(); l == nil || l.size != DefaultSyncLogSize {
		t.Fatalf("unset sync-log: %+v, want a log of %d (on by default)", l, DefaultSyncLogSize)
	}
	for i := 0; i < 5; i++ {
		syncLog().Add(SyncLogEvent{Child: fmt.Sprintf("c%d.", i)})
	}

	two := 2
	if err := SetDelegationSyncConfig(ChildSyncConf{SyncLog: &two}, ParentSyncConf{}); err != nil {
		t.Fatal(err)
	}
	if got := children(syncLog().Query(SyncLogQuery{})); strings.Join(got, " ") != "c4. c3." {
		t.Errorf("after shrinking to 2: %v, want the two newest kept", got)
	}

	zero := 0
	if err := SetDelegationSyncConfig(ChildSyncConf{SyncLog: &zero}, ParentSyncConf{}); err != nil {
		t.Fatal(err)
	}
	if syncLog() != nil {
		t.Error("sync-log: 0 left a log installed")
	}

	minus := -1
	if err := SetDelegationSyncConfig(ChildSyncConf{SyncLog: &minus}, ParentSyncConf{}); err == nil {
		t.Error("a negative sync-log was accepted")
	}
}

// A poll that finds nothing is not recorded, and one that repeats the same
// refusal is recorded once, not every round. Changes always are.
func TestSyncLogPollsRecordWhatMatters(t *testing.T) {
	l := newDelegationSyncLog(100)
	ev := func(outcome, reason string) SyncLogEvent {
		return SyncLogEvent{Parent: "example.", Child: "c.example.", Mechanism: SyncMechScanCSYNC, Outcome: outcome, Reason: reason}
	}
	l.AddPoll(ev(SyncNoChange, ""))
	l.AddPoll(ev(SyncNotProcessed, "child nameservers not in sync for SOA"))
	l.AddPoll(ev(SyncNotProcessed, "child nameservers not in sync for SOA"))
	l.AddPoll(ev(SyncNotProcessed, "CSYNC serial above the child's"))
	l.AddPoll(ev(SyncApplied, ""))
	l.AddPoll(ev(SyncApplied, ""))

	var outcomes []string
	for _, e := range l.Query(SyncLogQuery{}).Events {
		outcomes = append(outcomes, e.Outcome+"/"+e.Reason)
	}
	want := []string{
		"applied/", "applied/",
		"not processed/CSYNC serial above the child's",
		"not processed/child nameservers not in sync for SOA",
	}
	if strings.Join(outcomes, "|") != strings.Join(want, "|") {
		t.Errorf("recorded %q, want %q", outcomes, want)
	}
}

func TestSyncLogConcurrentUse(t *testing.T) {
	l := newDelegationSyncLog(50)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				l.Add(SyncLogEvent{Child: fmt.Sprintf("c%d-%d.", g, i)})
				l.AddPoll(SyncLogEvent{Child: fmt.Sprintf("p%d.", g), Outcome: SyncNotProcessed, Reason: fmt.Sprint(i % 3)})
				_ = l.Query(SyncLogQuery{Limit: 5})
			}
		}(g)
	}
	wg.Wait()
	if rep := l.Query(SyncLogQuery{}); len(rep.Events) != 50 {
		t.Errorf("%d events kept, want the ring full at 50", len(rep.Events))
	}
}

// The scan hook: the mechanism says whether a NOTIFY or a poll started the
// scan, and "applied" is only said of a change that landed (review S4).
func TestScanEventsNameTheMechanismAndWhatBecameOfTheChange(t *testing.T) {
	const child = "hasds.example."
	setup := func(res delegationApplyResult) (*Scanner, *ZoneData) {
		zd := trustParent(t, child, trustLax())
		zd.DelegationBackend.(*trustBackend).data[child][dns.TypeDS] = rrs(t, child+" 3600 IN DS 1111 13 2 "+strings.Repeat("cd", 32))
		n := cdsNet(t, child)
		n.set(cache.ValidationStateSecure, trustKey(child, dns.TypeCDS), trustKey(child, dns.TypeDNSKEY))
		sc := trustScanner(n)
		sc.OnDelegationChange = func(string, *ZoneData, ScanTupleResponse) delegationApplyResult { return res }
		return sc, zd
	}
	last := func(l *DelegationSyncLog) SyncLogEvent {
		t.Helper()
		rep := l.Query(SyncLogQuery{Limit: 1})
		if len(rep.Events) != 1 {
			t.Fatalf("no event recorded")
		}
		return rep.Events[0]
	}

	l := withSyncLog(t, 100)
	sc, zd := setup(delegationApplyResult{Applied: true})
	sc.scanChildAndApply(context.Background(), zd, ScanCDS, ScanTuple{Zone: child}, nil, nil)
	if ev := last(l); ev.Mechanism != SyncMechNotifyCDS || ev.Outcome != SyncApplied || ev.Changes != "ds +1 -1" {
		t.Errorf("NOTIFY-started scan, applied: %+v, want NOTIFY(CDS) applied ds +1 -1", ev)
	}

	sc, zd = setup(delegationApplyResult{Applied: true})
	sc.scanChildAndApply(context.Background(), zd, ScanCDS, ScanTuple{Zone: child}, nil, &pollScan{})
	if ev := last(l); ev.Mechanism != SyncMechScanCDS || ev.Outcome != SyncApplied {
		t.Errorf("poll-started scan: %+v, want scan(CDS) applied", ev)
	}

	sc, zd = setup(delegationApplyResult{Reason: "the zone updater refused it"})
	sc.scanChildAndApply(context.Background(), zd, ScanCDS, ScanTuple{Zone: child}, nil, nil)
	if ev := last(l); ev.Outcome != SyncApplyFailed || ev.Reason != "the zone updater refused it" {
		t.Errorf("change not applied: %+v, want apply failed with the reason, never applied", ev)
	}

	// Still queued when the scan stopped waiting: recorded as queued, and
	// the late answer is recorded when it comes.
	sc, zd = setup(delegationApplyResult{Pending: true, Reason: "not confirmed in time"})
	sc.scanChildAndApply(context.Background(), zd, ScanCDS, ScanTuple{Zone: child}, nil, nil)
	if ev := last(l); ev.Outcome != SyncQueued {
		t.Fatalf("change still queued: %+v, want queued", ev)
	}
	late := make(chan ZoneUpdateResult, 1)
	late <- ZoneUpdateResult{Applied: true}
	sc.notePendingApply(child, late)
	if err := sc.awaitPendingApply(context.Background(), child); err != nil {
		t.Fatal(err)
	}
	if ev := last(l); ev.Outcome != SyncApplied || ev.Mechanism != SyncMechNotifyCDS || !strings.Contains(ev.Reason, "late") {
		t.Errorf("late answer: %+v, want the same change recorded as applied, late", ev)
	}
}

// A scan that stops before it reads the child is in the log: the child that
// sent the NOTIFY got NOERROR, and without a line the parent would seem to
// have done nothing. A poll's repeat of the same failure is recorded once.
func TestScanThatStopsEarlyIsRecorded(t *testing.T) {
	const child = "unreadable.example."
	l := withSyncLog(t, 100)
	zd := trustParent(t, child, trustLax())
	zd.DelegationBackend = &unreadableBackend{}
	sc := trustScanner(cdsNet(t, child))

	sc.scanChildAndApply(context.Background(), zd, ScanCDS, ScanTuple{Zone: child}, nil, nil)
	rep := l.Query(SyncLogQuery{})
	if len(rep.Events) != 1 {
		t.Fatalf("%d events for a NOTIFY-started scan of an unreadable delegation, want 1", len(rep.Events))
	}
	if ev := rep.Events[0]; ev.Mechanism != SyncMechNotifyCDS || ev.Outcome != SyncNotProcessed ||
		!strings.Contains(ev.Reason, "cannot read the current delegation") {
		t.Errorf("event %+v, want NOTIFY(CDS) not processed: cannot read the current delegation", ev)
	}

	for i := 0; i < 3; i++ {
		sc.scanChildAndApply(context.Background(), zd, ScanCDS, ScanTuple{Zone: child}, nil, &pollScan{})
	}
	rep = l.Query(SyncLogQuery{})
	if len(rep.Events) != 2 || rep.Events[0].Mechanism != SyncMechScanCDS || rep.Events[0].Outcome != SyncNotProcessed {
		t.Errorf("after three polls: %+v, want one scan(CDS) not processed line added", rep.Events)
	}

	// An earlier change to the child still queued: the scan does not run.
	prev := scanApplyTimeout
	scanApplyTimeout = 50 * time.Millisecond
	t.Cleanup(func() { scanApplyTimeout = prev })
	const other = "queued.example."
	zd = trustParent(t, other, trustLax())
	sc = trustScanner(cdsNet(t, other))
	sc.notePendingApply(other, make(chan ZoneUpdateResult)) // never answered
	sc.scanChildAndApply(context.Background(), zd, ScanCSYNC, ScanTuple{Zone: other}, nil, nil)
	rep = l.Query(SyncLogQuery{Child: other})
	if len(rep.Events) != 1 || rep.Events[0].Mechanism != SyncMechNotifyCSYNC || rep.Events[0].Outcome != SyncNotProcessed ||
		!strings.Contains(rep.Events[0].Reason, "still queued") {
		t.Errorf("events %+v, want NOTIFY(CSYNC) not processed: an earlier change still queued", rep.Events)
	}
}

// A NOTIFY refused before any scan is recorded, once (review S5).
func TestRefusedNotifyIsRecorded(t *testing.T) {
	l := withSyncLog(t, 100)
	testSnapshotZone(t, ".", rootDispatchZone) // advertises no DSYNC at all

	m := new(dns.Msg)
	m.SetNotify("tld.")
	m.Question[0].Qtype = dns.TypeCSYNC
	if err := NotifyResponder(context.Background(), &DnsNotifyRequest{
		ResponseWriter: &captureWriter{}, Msg: m, Qname: "tld.", Options: &edns0.MsgOptions{}, Status: &NotifyStatus{},
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	rep := l.Query(SyncLogQuery{})
	if len(rep.Events) != 1 {
		t.Fatalf("%d events, want exactly one: %+v", len(rep.Events), rep.Events)
	}
	ev := rep.Events[0]
	if ev.Mechanism != SyncMechNotifyCSYNC || ev.Outcome != SyncRefused || ev.Parent != "." || ev.Child != "tld." ||
		!strings.Contains(ev.Reason, "does not advertise NOTIFY") || ev.Rcode != "REFUSED" {
		t.Errorf("event %+v, want NOTIFY(CSYNC) refused by . for tld.: DSYNC does not advertise NOTIFY", ev)
	}
}

// A child's UPDATE is recorded with the answer it got; an UPDATE that is no
// child's is not.
func TestChildUpdateIsRecordedWithItsAnswer(t *testing.T) {
	l := withSyncLog(t, 100)
	zd := testSnapshotZone(t, ".", rootDispatchZone)
	zd.Options = map[ZoneOption]bool{OptAllowChildUpdates: true}

	m := new(dns.Msg)
	m.SetUpdate(".")
	rr, err := dns.NewRR("tld. 3600 IN NS ns2.tld.")
	if err != nil {
		t.Fatal(err)
	}
	m.Insert([]dns.RR{rr})
	cw := &captureWriter{}
	_ = UpdateResponder(context.Background(), &DnsUpdateRequest{ResponseWriter: cw, Msg: m, Qname: ".", Status: &UpdateStatus{}}, nil)
	if cw.got == nil {
		t.Fatal("no answer written")
	}

	rep := l.Query(SyncLogQuery{})
	if len(rep.Events) != 1 {
		t.Fatalf("%d events, want one: %+v", len(rep.Events), rep.Events)
	}
	ev := rep.Events[0]
	if ev.Mechanism != SyncMechUpdate || ev.Child != "tld." || ev.Outcome != SyncRefused ||
		ev.Rcode != dns.RcodeToString[cw.got.Rcode] || ev.Changes != "ns +1 -0" {
		t.Errorf("event %+v, want UPDATE for tld. refused with the rcode it got (%s), ns +1 -0",
			ev, dns.RcodeToString[cw.got.Rcode])
	}

	// An update of the zone's own data, not a child's: not recorded.
	other := new(dns.Msg)
	other.SetUpdate("nowhere.test.")
	_ = UpdateResponder(context.Background(), &DnsUpdateRequest{ResponseWriter: &captureWriter{}, Msg: other, Qname: "nowhere.test.", Status: &UpdateStatus{}}, nil)
	if n := len(l.Query(SyncLogQuery{}).Events); n != 1 {
		t.Errorf("%d events after an UPDATE that is no child's, want still 1", n)
	}
}

// DSYNC API: a POST is recorded with the status it got; a GET is not (review C3).
func TestDsyncApiPostIsRecordedAndGetIsNot(t *testing.T) {
	l := withSyncLog(t, 100)
	registerDsyncApiParent(t, "example.")
	zd, _ := Zones.Get("example.")
	zd.Options[OptFrozen] = true

	req := func(method string) *http.Request {
		r := httptest.NewRequest(method, DsyncApiPathPrefix+"/delegation/child1.example.", strings.NewReader(`{}`))
		r = mux.SetURLVars(r, map[string]string{"child": "child1.example."})
		return r.WithContext(context.WithValue(r.Context(), dsyncApiPrincipalKey{},
			&DsyncApiCredential{Principal: "child1.example.", ParentZone: "example."}))
	}

	DsyncApiGetDelegation()(httptest.NewRecorder(), req(http.MethodGet))
	if n := len(l.Query(SyncLogQuery{}).Events); n != 0 {
		t.Fatalf("a GET was recorded (%d events)", n)
	}

	rec := httptest.NewRecorder()
	DsyncApiPostDelegation()(rec, req(http.MethodPost))
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST to a frozen zone: status %d, want 409", rec.Code)
	}
	rep := l.Query(SyncLogQuery{})
	if len(rep.Events) != 1 {
		t.Fatalf("%d events, want one", len(rep.Events))
	}
	ev := rep.Events[0]
	if ev.Mechanism != SyncMechAPI || ev.Outcome != SyncRefused || ev.Rcode != "HTTP 409" ||
		ev.Parent != "example." || !strings.Contains(ev.Reason, "frozen") {
		t.Errorf("event %+v, want API refused, HTTP 409, the frozen reason", ev)
	}
}

// The operator API: "sync-log" on /delegation, with no zone needed.
func TestDelegationAPIReturnsTheSyncLog(t *testing.T) {
	l := withSyncLog(t, 100)
	l.Add(SyncLogEvent{Parent: "example.", Child: "a.example.", Mechanism: SyncMechUpdate, Outcome: SyncApplied})
	l.Add(SyncLogEvent{Parent: "example.", Child: "b.example.", Mechanism: SyncMechAPI, Outcome: SyncRefused})

	body, _ := json.Marshal(DelegationPost{Command: "sync-log", Child: "b.example"})
	rec := httptest.NewRecorder()
	APIdelegation(nil)(rec, httptest.NewRequest(http.MethodPost, "/delegation", bytes.NewReader(body)))

	var resp DelegationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if resp.Error || resp.SyncLog == nil || len(resp.SyncLog.Events) != 1 || resp.SyncLog.Events[0].Child != "b.example." {
		t.Errorf("response %+v, want the one event for b.example.", resp)
	}

	body, _ = json.Marshal(DelegationPost{Command: "sync-log", Since: "yesterday"})
	rec = httptest.NewRecorder()
	APIdelegation(nil)(rec, httptest.NewRequest(http.MethodPost, "/delegation", bytes.NewReader(body)))
	resp = DelegationResponse{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Error {
		t.Error("an unreadable since was accepted")
	}
}
