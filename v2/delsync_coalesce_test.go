/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// laneMarkerZone is a zone under a parent of its own, whose request marks a
// point in the intake. The lanes runner dispatches intake in order, so once a
// handler has seen the marker every request sent before it has been queued or
// merged. An empty intake does not say that: the runner may have read the
// last request and not yet dispatched it.
const laneMarkerZone = "marker.elsewhere.example."

// isLaneMarker reports whether ds is the marker, and acknowledges it on marked.
func isLaneMarker(ds DelegationSyncRequest, marked chan<- struct{}) bool {
	if ds.ZoneName != laneMarkerZone {
		return false
	}
	marked <- struct{}{}
	return true
}

// allDispatched sends the marker and waits for its handler, whose lanes must
// acknowledge it with isLaneMarker.
func allDispatched(t *testing.T, q chan DelegationSyncRequest, marked <-chan struct{}) {
	t.Helper()
	offer(t, q, laneRequest(laneZone(laneMarkerZone, "elsewhere.example."), "marker"))
	receive(t, marked, "the marker, sent after every request so far")
}

// A zone that keeps changing behind a parent that does not answer must not
// grow the parent's queue with each change. The first change starts at once
// and is sent as it is. Every later one waits as a compare with the parent,
// whatever it adds or removes, and the zone's compares merge: one waiting
// request per command. The running request is never merged into, since it may
// have read the zone already.
func TestAZoneThatKeepsChangingDoesNotGrowItsParentsQueue(t *testing.T) {
	zd := laneZone("busy.down.example.", "down.example.")
	const changes = 250

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	marked := make(chan struct{}, 1)
	var mu sync.Mutex
	var ran []DelegationSyncRequest
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		if isLaneMarker(ds, marked) {
			return
		}
		mu.Lock()
		first := len(ran) == 0
		ran = append(ran, ds)
		mu.Unlock()
		if first {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	})

	// Changes that add and changes that remove, as an NS replaced again and
	// again would send.
	change := func(i int) DelegationSyncRequest {
		ds := laneRequest(zd, "SYNC-DELEGATION")
		ns := mustRR(t, fmt.Sprintf("busy.down.example. 3600 IN NS ns%d.example.", i))
		if i%2 == 0 {
			ds.SyncStatus.NsRemoves = []dns.RR{ns}
		} else {
			ds.SyncStatus.NsAdds = []dns.RR{ns}
		}
		return ds
	}
	offer(t, q, change(1))
	receive(t, started, "the first sync to start and stick")

	for i := 2; i <= changes+1; i++ {
		offer(t, q, change(i))
		se := laneRequest(zd, "SIGNALS-EDITED")
		se.SignalTypes = []uint16{dns.TypeCDS}
		if i%2 == 0 {
			se.SignalTypes = []uint16{dns.TypeCSYNC}
		}
		offer(t, q, se)
		offer(t, q, laneRequest(zd, "EXPLICIT-SYNC-DELEGATION"))
		offer(t, q, laneRequest(zd, "REFRESH-SYNC-DELEGATION"))
	}
	allDispatched(t, q, marked)
	// The running sync, one compare (the changes and the explicit syncs), one
	// SIGNALS-EDITED and one refresh sync.
	if pos := waitingIn(t, zd.ZoneName); pos.Waiting != 4 {
		t.Fatalf("the zone has %d requests in the queue, want 4: the running sync and one of each command", pos.Waiting)
	}

	close(release)
	waitFor(t, 2*time.Second, "the merged requests to run", func() bool {
		_, ok := DelegationSyncWaiting(zd.ZoneName)
		return !ok
	})

	mu.Lock()
	defer mu.Unlock()
	var cmds []string
	for _, ds := range ran {
		cmds = append(cmds, ds.Command)
	}
	want := []string{"SYNC-DELEGATION", "EXPLICIT-SYNC-DELEGATION", "SIGNALS-EDITED", "REFRESH-SYNC-DELEGATION"}
	if !slices.Equal(cmds, want) {
		t.Fatalf("ran %v, want %v", cmds, want)
	}
	if n := len(ran[0].SyncStatus.NsAdds); n != 1 {
		t.Errorf("the running sync carries %d NS adds, want its own 1: nothing may merge into it", n)
	}
	if d := ran[1].SyncStatus; len(d.NsAdds)+len(d.NsRemoves) != 0 {
		t.Errorf("the compare carries a stored difference (%d adds, %d removes); it must read the zone when it runs",
			len(d.NsAdds), len(d.NsRemoves))
	}
	if got := slices.Sorted(slices.Values(ran[2].SignalTypes)); !slices.Equal(got, []uint16{dns.TypeCDS, dns.TypeCSYNC}) {
		t.Errorf("the merged SIGNALS-EDITED names %v, want CDS and CSYNC", got)
	}
}

// A stored change is sent as it is only when it starts at once. Behind
// another zone's request in its parent's queue, or while the parent is known
// to lack an earlier change of the zone, it waits as a compare with the
// parent: a SYNC-DELEGATION as an EXPLICIT-SYNC-DELEGATION, a PROXY-SYNC as the
// proxy's compare. The compare carries no stored difference.
func TestAStoredChangeIsSentOnlyWhenItStartsAtOnce(t *testing.T) {
	for _, c := range []struct {
		name, change, want string
		busy, outOfStep    bool
	}{
		{"an idle parent: sent as it is", "SYNC-DELEGATION", "SYNC-DELEGATION", false, false},
		{"behind another zone of the parent", "SYNC-DELEGATION", "EXPLICIT-SYNC-DELEGATION", true, false},
		{"a parent known to lack an earlier change", "SYNC-DELEGATION", "EXPLICIT-SYNC-DELEGATION", false, true},
		{"a proxy's change, idle parent: sent as it is", "PROXY-SYNC", "PROXY-SYNC", false, false},
		{"a proxy's change behind another zone", "PROXY-SYNC", "PROXY-UPDATE-SETUP", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			zd := laneZone("stored.down.example.", "down.example.")
			other := laneZone("other.down.example.", "down.example.")
			zd.delegationOutOfStep.Store(c.outOfStep)
			release := make(chan struct{})
			started := make(chan struct{}, 1)
			marked := make(chan struct{}, 1)
			got := make(chan DelegationSyncRequest, 1)
			q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
				if isLaneMarker(ds, marked) {
					return
				}
				if ds.ZoneName == other.ZoneName {
					started <- struct{}{}
					select {
					case <-release:
					case <-ctx.Done():
					}
					return
				}
				got <- ds
			})
			if c.busy {
				offer(t, q, laneRequest(other, "first"))
				receive(t, started, "the other zone's request to start and stick")
			}
			ds := laneRequest(zd, c.change)
			ds.SyncStatus.NsAdds = []dns.RR{mustRR(t, "stored.down.example. 3600 IN NS ns1.example.")}
			ds.ProxyAnalysis = &ProxyDelegationAnalysis{NsOrGlueChanged: true}
			offer(t, q, ds)
			allDispatched(t, q, marked)
			close(release)

			ran := receive(t, got, "the zone's request")
			if ran.Command != c.want {
				t.Fatalf("ran %s, want %s", ran.Command, c.want)
			}
			if c.want != c.change && (len(ran.SyncStatus.NsAdds) != 0 || ran.ProxyAnalysis != nil || ran.ZoneData != zd) {
				t.Errorf("the compare carries the stored change, or lost its zone: %+v", ran)
			}
			if c.want == c.change && len(ran.SyncStatus.NsAdds) != 1 {
				t.Errorf("the change sent as it is lost its difference: %+v", ran.SyncStatus)
			}
		})
	}
}

// A stored change whose send fails is not sent again: the zone may change
// before the parent answers, and the parent may then hold less than the
// difference assumes. It is retried as a compare with the parent, after the
// first retry wait. A parent that offers no usable scheme is not a failure and
// leaves nothing to retry, but marks the parent out of step; a success leaves
// nothing to retry, and marks the parent only when it went by NOTIFY, which
// the parent has yet to act on.
func TestAFailedStoredChangeIsRetriedAsACompare(t *testing.T) {
	zd := laneZone("failed.down.example.", "down.example.")
	ds := laneRequest(zd, "SYNC-DELEGATION")
	ds.SyncStatus.NsRemoves = []dns.RR{mustRR(t, "failed.down.example. 3600 IN NS ns1.example.")}

	type requeue struct {
		ds    DelegationSyncRequest
		delay time.Duration
	}
	scheme := ""
	run := func(resolveErr, syncErr error) (sent int, out []requeue) {
		handleSyncDelegationWith(ds, syncDelegationSteps{
			resolve: func() error { return resolveErr },
			sync: func(DelegationSyncStatus) (string, uint8, UpdateResult, string, error) {
				sent++
				return "", 0, UpdateResult{}, scheme, syncErr
			},
			requeue: func(next DelegationSyncRequest, delay time.Duration) {
				out = append(out, requeue{next, delay})
			},
		})
		return sent, out
	}
	for _, c := range []struct {
		name                string
		resolveErr, syncErr error
		sent                int
	}{
		{"the parent refused", nil, errors.New("the parent answered SERVFAIL"), 1},
		{"the parent was not found", errors.New("no parent"), nil, 0},
	} {
		sent, out := run(c.resolveErr, c.syncErr)
		if sent != c.sent || len(out) != 1 {
			t.Fatalf("%s: %d sends and %d retries, want %d and 1", c.name, sent, len(out), c.sent)
		}
		next := out[0].ds
		if next.Command != "EXPLICIT-SYNC-DELEGATION" || next.ZoneData != zd || next.Attempt != 1 ||
			next.FailedAt.IsZero() || len(next.SyncStatus.NsRemoves) != 0 {
			t.Errorf("%s: retry = {%s attempt %d failedAt %v, %d stored removes}, want a compare at attempt 1",
				c.name, next.Command, next.Attempt, next.FailedAt, len(next.SyncStatus.NsRemoves))
		}
		if out[0].delay != delegationSyncRetryDelays[0] {
			t.Errorf("%s: retried after %s, want %s", c.name, out[0].delay, delegationSyncRetryDelays[0])
		}
	}
	// No usable scheme: nothing to retry through, but the parent lacks the
	// change, so the next one must go as a compare (re-review 3, F5). A
	// success leaves the mark as it was: a difference brings the parent this
	// change, not what it may have missed.
	for _, c := range []struct {
		err    error
		scheme string
		mark   bool
	}{{ErrNoUsableDsync, "", true}, {nil, "UPDATE", false}, {nil, "API", false}, {nil, "NOTIFY", true}} {
		zd.delegationOutOfStep.Store(false)
		scheme = c.scheme
		if _, out := run(nil, c.err); len(out) != 0 {
			t.Errorf("a send that returned %v by %q was retried", c.err, c.scheme)
		}
		if got := zd.delegationOutOfStep.Load(); got != c.mark {
			t.Errorf("a send that returned %v by %q left the parent marked out of step %v, want %v",
				c.err, c.scheme, got, c.mark)
		}
	}
	scheme = ""

	// The proxy's stored change is retried as the proxy's compare.
	var out []requeue
	lookAgainLater(DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: zd.ZoneName, ZoneData: zd,
		ProxyAnalysis: &ProxyDelegationAnalysis{NsOrGlueChanged: true}}, "forward", errors.New("refused"),
		func(next DelegationSyncRequest, delay time.Duration) { out = append(out, requeue{next, delay}) })
	if len(out) != 1 || out[0].ds.Command != "PROXY-UPDATE-SETUP" || out[0].ds.ProxyAnalysis != nil || out[0].ds.Attempt != 1 {
		t.Errorf("a failed PROXY-SYNC was retried as %+v, want one PROXY-UPDATE-SETUP at attempt 1", out)
	}
}

// A compare nobody waits on must reach the parent. When it fails, or could not
// read all of the parent's delegation, it is retried, however many times it
// has failed, and the zone's parent is marked out of step meanwhile. A compare
// someone waits on is answered and not retried, and one that found the parent
// in step is done. A retry whose zone is no longer loaded is dropped when due.
func TestACompareNobodyWaitsOnIsRetriedUntilTheParentAnswers(t *testing.T) {
	saved := delegationSyncRetryDelays
	delegationSyncRetryDelays = []time.Duration{time.Millisecond, 2 * time.Millisecond}
	t.Cleanup(func() { delegationSyncRetryDelays = saved })

	zd := laneZone("compare.down.example.", "down.example.")
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	q := make(chan DelegationSyncRequest, 1)

	failed := func() DelegationSyncStatus { return DelegationSyncStatus{Error: true, ErrorMsg: "SERVFAIL"} }
	unread := func() DelegationSyncStatus { return DelegationSyncStatus{InSync: true, Unread: []string{"ns1 A"}} }
	inStep := func() DelegationSyncStatus { return DelegationSyncStatus{InSync: true} }

	// Far past the schedule's end: the retries do not run out.
	look := DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: zd.ZoneName, ZoneData: zd, Attempt: 7}
	for _, c := range []struct {
		name string
		run  func() DelegationSyncStatus
	}{{"a failure", failed}, {"an incomplete read", unread}} {
		zd.delegationOutOfStep.Store(false)
		if handleExplicitSyncWith(ctx, nil, q, look, c.run) == nil {
			t.Fatalf("%s: not retried", c.name)
		}
		if !zd.delegationOutOfStep.Load() {
			t.Errorf("%s: the zone's parent is not marked out of step", c.name)
		}
		next := receive(t, q, c.name+": the retry")
		if next.Command != look.Command || next.Attempt != 8 || next.FailedAt.IsZero() || next.ZoneData != zd {
			t.Errorf("%s: retry = {%s attempt %d failedAt %v}, want the compare at attempt 8",
				c.name, next.Command, next.Attempt, next.FailedAt)
		}
	}
	zd.noteDelegationSyncInStep()
	if zd.delegationOutOfStep.Load() {
		t.Error("a compare that brought the parent in step left it marked out of step")
	}

	if handleExplicitSyncWith(ctx, nil, q, look, inStep) != nil {
		t.Error("a compare that found the parent in step was retried")
	}
	asked := look
	asked.Response = make(chan DelegationSyncStatus, 1)
	if handleExplicitSyncWith(ctx, nil, q, asked, failed) != nil {
		t.Error("a compare an operator waits on was retried")
	}
	receive(t, asked.Response, "the operator's answer")

	Zones.Remove(zd.ZoneName)
	done := handleExplicitSyncWith(ctx, nil, q, look, failed)
	if done == nil {
		t.Fatal("not retried")
	}
	receive(t, done, "the retry worker to end")
	select {
	case ds := <-q:
		t.Errorf("a retry for a zone no longer loaded was queued: %s attempt %d", ds.Command, ds.Attempt)
	default:
	}
}

// An explicit sync clears the mark that the parent may lack a change only when
// the parent is known to hold the whole delegation afterwards: the compare read
// all it asked, compared the DS (not while a rollover owns it), and found the
// parent in step or sent the difference by a scheme whose success says the
// parent applied it, UPDATE or API. A NOTIFY's success says only that the
// notifier took it, so it marks the parent, whatever the mark was (CodeRabbit
// on bb87c26b and 4d398b97). One that cannot send because the
// parent offers no usable scheme answers with no error and is not retried,
// even after an incomplete read, but marks the parent out of step, so the next
// change goes as a compare (re-review 4, F6; CodeRabbit on bb87c26b).
func TestAnExplicitSyncClearsTheMarkOnlyWhenTheParentHoldsItAll(t *testing.T) {
	saved := delegationSyncRetryDelays
	delegationSyncRetryDelays = []time.Duration{time.Millisecond}
	t.Cleanup(func() { delegationSyncRetryDelays = saved })
	// Not in Zones: an incomplete read's retry is dropped when due.
	zd := laneZone("nosend.down.example.", "down.example.")
	q := make(chan DelegationSyncRequest, 1)
	differs := DelegationSyncStatus{ZoneName: zd.ZoneName, dsCompared: true}
	incomplete := DelegationSyncStatus{ZoneName: zd.ZoneName, Unread: []string{"ns1 A"}, dsCompared: true}
	inStep := DelegationSyncStatus{ZoneName: zd.ZoneName, InSync: true, dsCompared: true}
	rolling := DelegationSyncStatus{ZoneName: zd.ZoneName}
	rollingInStep := DelegationSyncStatus{ZoneName: zd.ZoneName, InSync: true}

	for _, c := range []struct {
		name     string
		before   bool
		analysis DelegationSyncStatus
		scheme   string
		sendErr  error
		mark     bool
		retried  bool
	}{
		{"a difference with no usable scheme", false, differs, "", ErrNoUsableDsync, true, false},
		{"no usable scheme after an incomplete read", false, incomplete, "", ErrNoUsableDsync, true, false},
		{"a difference sent by UPDATE", true, differs, "UPDATE", nil, false, false},
		{"a difference sent by API", true, differs, "API", nil, false, false},
		{"a difference the notifier took", true, differs, "NOTIFY", nil, true, false},
		{"a difference the notifier took, the mark clear", false, differs, "NOTIFY", nil, true, false},
		{"a difference sent by UPDATE, the mark clear", false, differs, "UPDATE", nil, false, false},
		{"a difference sent after an incomplete read", true, incomplete, "UPDATE", nil, true, true},
		{"the parent found in step", true, inStep, "", nil, false, false},
		{"in step while a rollover owns the DS", true, rollingInStep, "", nil, true, false},
		{"sent by UPDATE while a rollover owns the DS", true, rolling, "UPDATE", nil, true, false},
	} {
		zd.delegationOutOfStep.Store(c.before)
		sent := false
		run := func() DelegationSyncStatus {
			return zd.runExplicitSyncWith(
				func() (DelegationSyncStatus, error) { return c.analysis, nil },
				func(DelegationSyncStatus) (string, uint8, UpdateResult, string, error) {
					sent = true
					return "sent", dns.RcodeSuccess, UpdateResult{}, c.scheme, c.sendErr
				})
		}
		look := DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: zd.ZoneName, ZoneData: zd}
		done := handleExplicitSyncWith(context.Background(), nil, q, look, run)
		if c.analysis.InSync == sent {
			t.Errorf("%s: sent %v, want %v", c.name, sent, !c.analysis.InSync)
		}
		if got := zd.delegationOutOfStep.Load(); got != c.mark {
			t.Errorf("%s: the parent is marked out of step %v, want %v", c.name, got, c.mark)
		}
		if (done != nil) != c.retried {
			t.Errorf("%s: retried %v, want %v", c.name, done != nil, c.retried)
		}
		if done != nil {
			<-done
			select {
			case <-q:
			default:
			}
		}
	}
}

// Two compares for different instances of a zone do not merge: a retry for a
// copy since replaced would take the replacement's compare with it (CodeRabbit
// on bb87c26b). The same instance merges, and a request without ZoneData
// merges by name as before.
func TestCompareRequestsForDifferentZoneInstancesDoNotMerge(t *testing.T) {
	old := laneZone("swap.down.example.", "down.example.")
	replacement := laneZone("swap.down.example.", "down.example.")
	ex := func(zd *ZoneData, attempt int) DelegationSyncRequest {
		return DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: "swap.down.example.",
			ZoneData: zd, Attempt: attempt}
	}
	if _, ok := mergeDelegationSyncRequests(ex(replacement, 0), ex(old, 2)); ok {
		t.Error("a retry for the old instance merged into the replacement's compare")
	}
	if _, ok := mergeDelegationSyncRequests(ex(old, 2), ex(replacement, 0)); ok {
		t.Error("the replacement's compare merged into a retry for the old instance")
	}
	if m, ok := mergeDelegationSyncRequests(ex(old, 2), ex(old, 0)); !ok || m.Attempt != 0 {
		t.Errorf("two compares of one instance: merged %v, attempt %d; want merged, attempt 0", ok, m.Attempt)
	}
	if _, ok := mergeDelegationSyncRequests(ex(nil, 0), ex(old, 0)); !ok {
		t.Error("a compare without ZoneData no longer merges by name")
	}
}

// A request someone waits on gets its own answer: it is never merged, nor is a
// request merged into it. Commands not listed are never merged either.
func TestARequestSomeoneWaitsOnIsNeverMerged(t *testing.T) {
	zd := laneZone("asked.down.example.", "down.example.")

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		if ds.Command == "first" {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		if ds.Response != nil {
			ds.Response <- DelegationSyncStatus{ZoneName: ds.ZoneName}
		}
	})
	offer(t, q, laneRequest(zd, "first"))
	receive(t, started, "the first request to start and stick")

	var answers []chan DelegationSyncStatus
	ask := func(cmd string) {
		ds := laneRequest(zd, cmd)
		ds.Response = make(chan DelegationSyncStatus, 1)
		answers = append(answers, ds.Response)
		offer(t, q, ds)
	}
	ask("DELEGATION-STATUS")
	ask("DELEGATION-STATUS")
	ask("EXPLICIT-SYNC-DELEGATION")
	offer(t, q, laneRequest(zd, "EXPLICIT-SYNC-DELEGATION")) // not into the asked one before it
	ask("EXPLICIT-SYNC-DELEGATION")                          // nor into the unasked one before it
	offer(t, q, laneRequest(zd, "SYNC-DNSKEY-RRSET"))
	offer(t, q, laneRequest(zd, "SYNC-DNSKEY-RRSET"))

	waitFor(t, 2*time.Second, "every request in the queue", func() bool {
		pos, ok := DelegationSyncWaiting(zd.ZoneName)
		return ok && pos.Waiting == 8
	})
	close(release)
	for i, ch := range answers {
		receive(t, ch, fmt.Sprintf("answer %d of %d", i+1, len(answers)))
	}
}

// The merged request takes the fresher retry counts, so a new trigger joining
// a retry close to its limit restores the zone's retries.
func TestAMergedRequestKeepsTheFresherRetryCounts(t *testing.T) {
	failed := time.Now().Add(-time.Minute)
	retry := DelegationSyncRequest{Command: "REFRESH-SYNC-DELEGATION", ZoneName: "child.example.",
		Attempt: 3, FailedAt: failed}
	fresh := DelegationSyncRequest{Command: "REFRESH-SYNC-DELEGATION", ZoneName: "child.example."}

	for _, c := range []struct {
		name          string
		waiting, next DelegationSyncRequest
	}{
		{"a fresh trigger joins a waiting retry", retry, fresh},
		{"a retry joins a waiting fresh trigger", fresh, retry},
	} {
		m, ok := mergeDelegationSyncRequests(c.waiting, c.next)
		if !ok {
			t.Fatalf("%s: not merged", c.name)
		}
		if m.Attempt != 0 || !m.FailedAt.IsZero() {
			t.Errorf("%s: attempt %d, failed at %v; want the fresh trigger's 0 and none", c.name, m.Attempt, m.FailedAt)
		}
	}

	setup := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example.", Attempt: 2, ReBootstrapRound: 1}
	m, ok := mergeDelegationSyncRequests(setup, DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example."})
	if !ok || m.Attempt != 0 || m.ReBootstrapRound != 0 {
		t.Errorf("setup merge: ok %v, attempt %d, round %d; want a fresh setup's 0 and 0", ok, m.Attempt, m.ReBootstrapRound)
	}
}

// Two retries merged stand for both, so the merged one is dropped only when
// both would have been. A refresh failed, a sync then succeeded, and a refresh
// failed again after a glue change: the success supersedes the first retry and
// not the second, so the merged retry must still run.
func TestAMergedRetryIsDroppedOnlyWhenBothWouldBe(t *testing.T) {
	firstFail := time.Now().Add(-3 * time.Minute)
	success := firstFail.Add(time.Minute)
	secondFail := success.Add(time.Minute)
	first := DelegationSyncRequest{Command: "REFRESH-SYNC-DELEGATION", ZoneName: "child.example.",
		Attempt: 1, FailedAt: firstFail}
	second := first
	second.FailedAt = secondFail

	zd := &ZoneData{ZoneName: "child.example."}
	succeededAt := func(at time.Time) {
		zd.mu.Lock()
		zd.delegationLastSyncOK = at
		zd.mu.Unlock()
	}
	for _, c := range []struct {
		name          string
		waiting, next DelegationSyncRequest
	}{
		{"the first failure's retry waits", first, second},
		{"the second failure's retry waits", second, first},
	} {
		m, ok := mergeDelegationSyncRequests(c.waiting, c.next)
		if !ok {
			t.Fatalf("%s: not merged", c.name)
		}
		succeededAt(success)
		if delegationSyncRetrySuperseded(zd, m) {
			t.Errorf("%s: the merged retry is dropped for a success between the two failures;"+
				" the second failure is never retried", c.name)
		}
		succeededAt(secondFail.Add(time.Minute))
		if !delegationSyncRetrySuperseded(zd, m) {
			t.Errorf("%s: a success after both failures does not drop the merged retry", c.name)
		}
	}
}

// A merge does not move a zone's request past one of the zone's that a caller
// waits on: the requests that arrived before the status request run before it,
// and those after it after. Both changes wait as compares, behind the zone's
// request that sticks. That is the order the handlers run in, not a view of the
// zone at the status request's arrival: the first compare reads the zone as it
// is when it runs, and may already send the later change, so the status then
// reports the parent with it (delegationSyncMayBeOvertaken).
func TestAMergeDoesNotJumpARequestACallerWaitsOn(t *testing.T) {
	zd := laneZone("order.down.example.", "down.example.")

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	marked := make(chan struct{}, 1)
	var mu sync.Mutex
	var ran []string
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		if isLaneMarker(ds, marked) {
			return
		}
		if ds.Command == "first" {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return
		}
		mu.Lock()
		ran = append(ran, ranLabel(ds))
		mu.Unlock()
		if ds.Response != nil {
			ds.Response <- DelegationSyncStatus{ZoneName: ds.ZoneName}
		}
	})
	change := func(i int) DelegationSyncRequest {
		ds := laneRequest(zd, "SYNC-DELEGATION")
		ds.SyncStatus.NsAdds = []dns.RR{mustRR(t, fmt.Sprintf("order.down.example. 3600 IN NS ns%d.example.", i))}
		return ds
	}

	offer(t, q, laneRequest(zd, "first"))
	receive(t, started, "the first request to start and stick")
	offer(t, q, change(1))
	status := laneRequest(zd, "DELEGATION-STATUS")
	status.Response = make(chan DelegationSyncStatus, 1)
	offer(t, q, status)
	offer(t, q, change(2))
	allDispatched(t, q, marked)
	if pos := waitingIn(t, zd.ZoneName); pos.Waiting != 4 {
		t.Errorf("%d of the zone's requests in the queue, want 4: the later sync was merged past the status request", pos.Waiting)
	}

	close(release)
	receive(t, status.Response, "the status answer")
	waitFor(t, 2*time.Second, "the zone's requests to run", func() bool {
		_, ok := DelegationSyncWaiting(zd.ZoneName)
		return !ok
	})
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"EXPLICIT-SYNC-DELEGATION", "DELEGATION-STATUS", "EXPLICIT-SYNC-DELEGATION"}; !slices.Equal(ran, want) {
		t.Errorf("ran %v, want %v", ran, want)
	}
}

// ranLabel is a request's command and the NS targets it adds, as a test
// records the order requests ran in.
func ranLabel(ds DelegationSyncRequest) string {
	label := ds.Command
	var targets []string
	for _, rr := range ds.SyncStatus.NsAdds {
		targets = append(targets, rr.(*dns.NS).Ns)
	}
	if len(targets) > 0 {
		label += " " + strings.Join(targets, ",")
	}
	return label
}

// A merge moves a request ahead of the zone's requests that wait between it
// and the one it joins, and only live reconciliations may be overtaken so. A
// compare merged ahead of the zone's setup could reach the parent before its
// key. A compare may pass a live reconciliation, and a live reconciliation a
// compare: each sees more when it runs later. The changes wait as compares,
// behind the zone's request that sticks.
func TestAMergeOvertakesOnlyLiveReconciliations(t *testing.T) {
	sd := func(zd *ZoneData, ns string) DelegationSyncRequest {
		ds := laneRequest(zd, "SYNC-DELEGATION")
		ds.SyncStatus.NsAdds = []dns.RR{mustRR(t, zd.ZoneName+" 3600 IN NS "+ns)}
		return ds
	}
	for _, c := range []struct {
		name    string
		send    func(zd *ZoneData) []DelegationSyncRequest
		waiting int
		ran     []string
	}{
		{"a live reconciliation past a compare merges",
			func(zd *ZoneData) []DelegationSyncRequest {
				return []DelegationSyncRequest{laneRequest(zd, "SIGNALS-EDITED"), sd(zd, "ns1.example."), laneRequest(zd, "SIGNALS-EDITED")}
			},
			3, []string{"SIGNALS-EDITED", "EXPLICIT-SYNC-DELEGATION"}},
		{"a compare past the zone's setup",
			func(zd *ZoneData) []DelegationSyncRequest {
				return []DelegationSyncRequest{sd(zd, "ns1.example."), laneRequest(zd, "DELEGATION-SYNC-SETUP"), sd(zd, "ns2.example.")}
			},
			4, []string{"EXPLICIT-SYNC-DELEGATION", "DELEGATION-SYNC-SETUP", "EXPLICIT-SYNC-DELEGATION"}},
		{"a compare past a live reconciliation merges",
			func(zd *ZoneData) []DelegationSyncRequest {
				return []DelegationSyncRequest{sd(zd, "ns1.example."), laneRequest(zd, "SIGNALS-EDITED"), sd(zd, "ns2.example.")}
			},
			3, []string{"EXPLICIT-SYNC-DELEGATION", "SIGNALS-EDITED"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			zd := laneZone("overtake.down.example.", "down.example.")
			release := make(chan struct{})
			started := make(chan struct{}, 1)
			marked := make(chan struct{}, 1)
			var mu sync.Mutex
			var ran []string
			q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
				if isLaneMarker(ds, marked) {
					return
				}
				if ds.Command == "first" {
					started <- struct{}{}
					select {
					case <-release:
					case <-ctx.Done():
					}
					return
				}
				mu.Lock()
				ran = append(ran, ranLabel(ds))
				mu.Unlock()
			})
			offer(t, q, laneRequest(zd, "first"))
			receive(t, started, "the first request to start and stick")
			for _, ds := range c.send(zd) {
				offer(t, q, ds)
			}
			allDispatched(t, q, marked)
			if pos := waitingIn(t, zd.ZoneName); pos.Waiting != c.waiting {
				t.Errorf("%d of the zone's requests in the queue, want %d", pos.Waiting, c.waiting)
			}
			close(release)
			waitFor(t, 2*time.Second, "the zone's requests to run", func() bool {
				_, ok := DelegationSyncWaiting(zd.ZoneName)
				return !ok
			})
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(ran, c.ran) {
				t.Errorf("ran %v, want %v", ran, c.ran)
			}
		})
	}
}
