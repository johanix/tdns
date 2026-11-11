/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// laneZone is a zone whose parent is cached, as GetParent reads it; "" leaves
// the parent unknown.
func laneZone(name, parent string) *ZoneData {
	zd := &ZoneData{ZoneName: name}
	if parent != "" {
		zd.SetParent(parent)
	}
	return zd
}

func laneRequest(zd *ZoneData, tag string) DelegationSyncRequest {
	return DelegationSyncRequest{Command: tag, ZoneName: zd.ZoneName, ZoneData: zd}
}

// startLanes runs RunDelegationSyncLanes with handle on a fresh intake of the
// syncher's size. stop cancels it and waits for it to return; the test's
// cleanup does that too.
func startLanes(t *testing.T, handle DelegationSyncHandler) (q chan DelegationSyncRequest, ctx context.Context, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	q = make(chan DelegationSyncRequest, 10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := RunDelegationSyncLanes(ctx, q, handle); err != nil {
			t.Errorf("RunDelegationSyncLanes: %v", err)
		}
	}()
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the lanes did not stop after the context was cancelled")
		}
	}
	t.Cleanup(stop)
	return q, ctx, stop
}

// offer hands ds to the intake, as a sender that waits a little would.
func offer(t *testing.T, q chan DelegationSyncRequest, ds DelegationSyncRequest) {
	t.Helper()
	select {
	case q <- ds:
	case <-time.After(2 * time.Second):
		t.Fatalf("the intake did not take %s for %s: it is full", ds.Command, ds.ZoneName)
	}
}

func receive[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}

func waitingIn(t *testing.T, zone string) DelegationSyncPosition {
	t.Helper()
	pos, ok := DelegationSyncWaiting(zone)
	if !ok {
		t.Fatalf("DelegationSyncWaiting(%s) found nothing waiting", zone)
	}
	return pos
}

// (a) A parent that does not answer holds only its own zones. A request for
// a zone under another parent runs while the stuck one still waits; a second
// zone under the stuck parent waits behind it.
func TestDelegationSyncDownParentDoesNotHoldOtherParents(t *testing.T) {
	stuck := laneZone("a1.down.example.", "down.example.")
	sibling := laneZone("a2.down.example.", "down.example.")
	other := laneZone("b1.up.example.", "up.example.")

	started := make(chan string, 4)
	handled := make(chan string, 4)
	release := make(chan struct{})
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		started <- ds.ZoneName
		if ds.ZoneName == stuck.ZoneName {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		handled <- ds.ZoneName
	})

	offer(t, q, laneRequest(stuck, "SYNC-DELEGATION"))
	if got := receive(t, started, "the stuck sync to start"); got != stuck.ZoneName {
		t.Fatalf("started %s first, want %s", got, stuck.ZoneName)
	}
	offer(t, q, laneRequest(sibling, "SYNC-DELEGATION"))
	offer(t, q, laneRequest(other, "SYNC-DELEGATION"))

	if got := receive(t, handled, "the other parent's sync"); got != other.ZoneName {
		t.Fatalf("handled %s while the stuck sync waited, want %s", got, other.ZoneName)
	}
	if pos := waitingIn(t, sibling.ZoneName); pos.Parent != "down.example." || pos.Ahead != 1 || pos.Running {
		t.Errorf("the stuck parent's other zone stands at %+v, want 1 ahead in down.example.", pos)
	}

	close(release)
	got := []string{receive(t, handled, "the stuck sync"), receive(t, handled, "its sibling")}
	if got[0] != stuck.ZoneName || got[1] != sibling.ZoneName {
		t.Errorf("the stuck parent's syncs ran as %v, want %s then %s", got, stuck.ZoneName, sibling.ZoneName)
	}
}

// (b) A zone's requests run in order and never at the same time, also when
// its parent changes while one runs: the zone stays in the queue it is in
// until it has nothing there, and only then moves.
func TestDelegationSyncZoneStaysInItsQueue(t *testing.T) {
	zd := laneZone("z.p1.example.", "p1.example.")
	neighbour := laneZone("n.p2.example.", "p2.example.")

	var mu sync.Mutex
	var order []string
	var inFlight, overlaps atomic.Int32
	started := make(chan string, 8)
	handled := make(chan string, 8)
	release := make(chan struct{}, 8)
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		if ds.ZoneName == zd.ZoneName {
			if inFlight.Add(1) > 1 {
				overlaps.Add(1)
			}
			defer inFlight.Add(-1)
			mu.Lock()
			order = append(order, ds.Command)
			mu.Unlock()
			started <- ds.Command
		}
		if ds.Command != "neighbour" {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		handled <- ds.Command
	})

	offer(t, q, laneRequest(zd, "first"))
	if got := receive(t, started, "the first request"); got != "first" {
		t.Fatalf("started %s, want first", got)
	}
	zd.SetParent("p2.example.") // the parent changes while the first runs
	offer(t, q, laneRequest(zd, "second"))
	offer(t, q, laneRequest(neighbour, "neighbour"))

	// p2's queue is free: the neighbour runs. The zone's second request is
	// not in it, or it would have run beside the first.
	if got := receive(t, handled, "the neighbour"); got != "neighbour" {
		t.Fatalf("handled %s first, want the neighbour", got)
	}
	if pos := waitingIn(t, zd.ZoneName); pos.Parent != "p1.example." || !pos.Running || pos.Waiting != 2 {
		t.Errorf("the zone stands at %+v, want 2 requests in p1.example., one running", pos)
	}

	release <- struct{}{}
	if got := receive(t, started, "the second request"); got != "second" {
		t.Fatalf("started %s after the first, want second", got)
	}
	release <- struct{}{}
	receive(t, handled, "the first request")
	receive(t, handled, "the second request")
	waitFor(t, 2*time.Second, "the zone's queue to empty", func() bool {
		_, ok := DelegationSyncWaiting(zd.ZoneName)
		return !ok
	})

	// Nothing of the zone is queued any more, so its next request goes to
	// the parent it has now.
	offer(t, q, laneRequest(zd, "third"))
	if got := receive(t, started, "the third request"); got != "third" {
		t.Fatalf("started %s, want third", got)
	}
	if pos := waitingIn(t, zd.ZoneName); pos.Parent != "p2.example." {
		t.Errorf("after its queue emptied the zone is in %s, want p2.example.", pos.Parent)
	}
	release <- struct{}{}
	receive(t, handled, "the third request")

	mu.Lock()
	defer mu.Unlock()
	if n := overlaps.Load(); n != 0 {
		t.Errorf("the zone's requests ran at the same time %d times", n)
	}
	if len(order) != 3 || order[0] != "first" || order[1] != "second" || order[2] != "third" {
		t.Errorf("the zone's requests ran as %v, want first, second, third", order)
	}
}

// (c) A failed sync re-enqueued after its backoff comes back through the
// lanes with its count and its failure time, no sooner than its delay, and
// stops when its retries have run out, as it did with one loop. This drives
// the refresh arm itself with the production requeue (requeueSetupAfter), and
// keeps another parent stuck the whole time.
func TestDelegationSyncRequeueKeepsItsBackoff(t *testing.T) {
	withApp(t, AppTypeAuth)
	old := delegationSyncRetryDelays
	delegationSyncRetryDelays = []time.Duration{40 * time.Millisecond, 80 * time.Millisecond}
	t.Cleanup(func() { delegationSyncRetryDelays = old })

	zd := childZone(t, ddcngServedZone(), OptParentSync)
	zd.SetParent("example.")
	stuck := laneZone("s.down.example.", "down.example.")
	ready := NewImrReadiness()
	ready.Publish()

	type arrival struct {
		ds DelegationSyncRequest
		at time.Time
	}
	arrivals := make(chan arrival, 8)
	var q chan DelegationSyncRequest
	q, _, _ = startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		if ds.ZoneName == stuck.ZoneName {
			<-ctx.Done()
			return
		}
		arrivals <- arrival{ds: ds, at: time.Now()}
		handleRefreshSyncDelegationWith(ctx, ready, q, zd, ds, refreshSyncSteps{
			analyse: func() (DelegationSyncStatus, error) {
				return DelegationSyncStatus{}, errors.New("the parent did not answer")
			},
			requeue: func(next DelegationSyncRequest, delay time.Duration) {
				requeueSetupAfter(ctx, q, next, delay)
			},
		})
	})

	offer(t, q, laneRequest(stuck, "SYNC-DELEGATION"))
	offer(t, q, refreshRequest(zd))

	var got []arrival
	for i := 0; i <= len(delegationSyncRetryDelays); i++ {
		got = append(got, receive(t, arrivals, "a retry"))
	}
	for i, a := range got {
		if a.ds.Attempt != i {
			t.Errorf("arrival %d has attempt %d, want %d", i, a.ds.Attempt, i)
		}
		if i == 0 {
			if !a.ds.FailedAt.IsZero() {
				t.Errorf("the first try carries a failure time %v", a.ds.FailedAt)
			}
			continue
		}
		if a.ds.FailedAt.IsZero() || a.ds.FailedAt.Before(got[i-1].at) {
			t.Errorf("retry %d failed at %v, want the time of the try before it (%v)", i, a.ds.FailedAt, got[i-1].at)
		}
		if gap, want := a.at.Sub(got[i-1].at), delegationSyncRetryDelays[i-1]; gap < want {
			t.Errorf("retry %d came %v after the try before it, sooner than its backoff of %v", i, gap, want)
		}
	}
	select {
	case a := <-arrivals:
		t.Errorf("a retry with attempt %d came after the retries ran out", a.ds.Attempt)
	case <-time.After(4 * delegationSyncRetryDelays[len(delegationSyncRetryDelays)-1]):
	}
}

// (d) The intake does not fill while one parent's queue is stuck: requests
// for that parent's zones are taken as fast as they come and wait in its
// queue. With one loop the twelfth was never taken.
func TestDelegationSyncIntakeDoesNotFillBehindAStuckParent(t *testing.T) {
	release := make(chan struct{})
	var handled atomic.Int32
	all := make(chan struct{})
	const n = 30
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		select {
		case <-release:
		case <-ctx.Done():
			return
		}
		if handled.Add(1) == n {
			close(all)
		}
	})

	var zones []*ZoneData
	for i := 0; i < n; i++ {
		zd := laneZone(string(rune('a'+i%26))+string(rune('a'+i/26))+".down.example.", "down.example.")
		zones = append(zones, zd)
		offer(t, q, laneRequest(zd, "EXPLICIT-SYNC-DELEGATION"))
	}

	last := zones[n-1]
	waitFor(t, 2*time.Second, "the last zone to stand behind all the others", func() bool {
		pos, ok := DelegationSyncWaiting(last.ZoneName)
		return ok && pos.Ahead == n-1
	})
	if pos := waitingIn(t, last.ZoneName); pos.Parent != "down.example." || pos.Waiting != 1 || pos.Running {
		t.Errorf("the last zone stands at %+v, want 1 request in down.example., not running", pos)
	}

	close(release)
	receive(t, all, "every queued request to run")
	waitFor(t, 2*time.Second, "a zone whose requests have all run to be reported not waiting", func() bool {
		_, ok := DelegationSyncWaiting(last.ZoneName)
		return !ok
	})
}

// (e) When the context ends the lanes stop: the running handler is told
// through its ctx, the requests still waiting are dropped, and the runner
// returns once the running handler has. Closing the intake instead runs
// everything already read, then returns.
func TestDelegationSyncLanesStop(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		zd := laneZone("c.p.example.", "p.example.")
		started := make(chan struct{}, 1)
		var handled atomic.Int32
		q, _, stop := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
			handled.Add(1)
			if ds.Command == "first" {
				started <- struct{}{}
				<-ctx.Done()
			}
		})
		offer(t, q, laneRequest(zd, "first"))
		receive(t, started, "the first request")
		offer(t, q, laneRequest(zd, "second"))
		offer(t, q, laneRequest(zd, "third"))
		waitFor(t, 2*time.Second, "three requests in the queue", func() bool {
			pos, ok := DelegationSyncWaiting(zd.ZoneName)
			return ok && pos.Waiting == 3
		})
		stop()
		if n := handled.Load(); n != 1 {
			t.Errorf("%d requests ran, want only the one running when the context ended", n)
		}
		if _, ok := DelegationSyncWaiting(zd.ZoneName); ok {
			t.Error("a stopped syncher still reports the zone waiting")
		}
	})

	t.Run("close", func(t *testing.T) {
		var handled atomic.Int32
		q := make(chan DelegationSyncRequest, 10)
		done := make(chan error, 1)
		go func() {
			done <- RunDelegationSyncLanes(context.Background(), q, func(ctx context.Context, ds DelegationSyncRequest) {
				time.Sleep(5 * time.Millisecond)
				handled.Add(1)
			})
		}()
		for _, zd := range []*ZoneData{laneZone("a.p.example.", "p.example."), laneZone("b.p.example.", "p.example."),
			laneZone("c.q.example.", "q.example."), laneZone("a.p.example.", "p.example."), laneZone("d.q.example.", "q.example.")} {
			offer(t, q, laneRequest(zd, "SYNC-DELEGATION"))
		}
		close(q)
		if err := receive(t, done, "the runner to return after the intake closed"); err != nil {
			t.Errorf("RunDelegationSyncLanes returned %v", err)
		}
		if n := handled.Load(); n != 5 {
			t.Errorf("%d of 5 requests ran before the runner returned", n)
		}
	})
}

// A parent's lane lives only while it has requests: 100 parents with one
// request each make 100 short-lived goroutines, not 100 resident ones. Once
// every request has run there is no goroutine, no lane entry and no pin
// left, without the context ending -- l.wg counts the lanes' goroutines, so
// its Wait returns only when every one has exited. A parent's next request
// makes its lane again, and it goes again.
func TestDelegationSyncLaneExitsWhenIdle(t *testing.T) {
	var handled atomic.Int32
	l := newDelegationSyncLanes(func(context.Context, DelegationSyncRequest) { handled.Add(1) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idle := func(what string) {
		t.Helper()
		exited := make(chan struct{})
		go func() { l.wg.Wait(); close(exited) }()
		receive(t, exited, what+": every lane goroutine to exit")
		l.mu.Lock()
		defer l.mu.Unlock()
		if len(l.lanes) != 0 || len(l.zones) != 0 {
			t.Errorf("%s: %d lanes and %d pins left, want none", what, len(l.lanes), len(l.zones))
		}
	}

	const parents = 100
	for i := range parents {
		parent := fmt.Sprintf("p%d.example.", i)
		l.dispatch(ctx, laneRequest(laneZone("child."+parent, parent), "SYNC-DELEGATION"))
	}
	waitFor(t, 2*time.Second, "every request to run", func() bool { return handled.Load() == parents })
	idle("after one request per parent")

	l.dispatch(ctx, laneRequest(laneZone("child.p7.example.", "p7.example."), "SYNC-DELEGATION"))
	waitFor(t, 2*time.Second, "the next request to run", func() bool { return handled.Load() == parents+1 })
	idle("after a parent's next request")
	if ctx.Err() != nil {
		t.Fatal("the lanes were idle only because the context ended")
	}
}

// (f) The queue a zone goes to, and what DelegationSyncWaiting reports for a
// zone with nothing queued.
func TestDelegationSyncLaneKey(t *testing.T) {
	for _, c := range []struct {
		zone, parent, want string
	}{
		{"child.example.", "example.", "example."},
		{"Child.Example.", "Example.", "example."},
		{"a.b.example.", "example.", "example."}, // a cut that skips a label
		{"a.b.example.", "", "b.example."},       // unknown: the name less its first label
		{"a.b.example.", ".", "b.example."},      // "." is the old "not looked up"
		{"example.", "", "."},
		{"x", "", "."},
	} {
		if got := delegationSyncLaneKey(laneRequest(laneZone(c.zone, c.parent), "SYNC-DELEGATION")); got != c.want {
			t.Errorf("zone %q with parent %q goes to %q, want %q", c.zone, c.parent, got, c.want)
		}
	}
	if got := delegationSyncLaneKey(DelegationSyncRequest{ZoneName: "z.example."}); got != "example." {
		t.Errorf("a request without zone data goes to %q, want example.", got)
	}

	if _, ok := DelegationSyncWaiting("nothing.example."); ok {
		t.Error("a zone with nothing queued is reported waiting")
	}
	startLanes(t, func(context.Context, DelegationSyncRequest) {})
	if _, ok := DelegationSyncWaiting("nothing.example."); ok {
		t.Error("a zone with nothing queued is reported waiting while the syncher runs")
	}
}

// The parent-sync status asks the syncher for its comparison. When the answer
// does not come because the zone waits behind a parent that does not answer,
// the status says so.
func TestParentSyncStatusSaysWhichParentItWaitsFor(t *testing.T) {
	stuck := laneZone("a1.down.example.", "down.example.")
	waiting := laneZone("a2.down.example.", "down.example.")
	started := make(chan struct{}, 1)
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		if ds.ZoneName == stuck.ZoneName {
			started <- struct{}{}
			<-ctx.Done()
		}
	})
	offer(t, q, laneRequest(stuck, "SYNC-DELEGATION"))
	receive(t, started, "the stuck sync")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	dss, msg := waiting.requestDelegationStatus(ctx, q)()
	if dss != nil {
		t.Fatalf("the status was answered (%+v) while its parent's queue was stuck", dss)
	}
	if want := "the zone's delegation syncs wait in the queue for parent down.example., 1 ahead"; !strings.Contains(msg, want) {
		t.Errorf("the status says %q, want it to contain %q", msg, want)
	}

	// Behind a slow sync of the same zone the status request waits too. The
	// sync running is not the status request, and the note does not say it
	// is: it speaks of the zone's syncs.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	_, msg = stuck.requestDelegationStatus(ctx2, q)()
	if want := "a delegation sync of the zone is running, in the queue for parent down.example.; 2 of its syncs in the queue"; !strings.Contains(msg, want) {
		t.Errorf("behind the zone's own slow sync the status says %q, want it to contain %q", msg, want)
	}
}

// A long queue is warned about at the threshold and at each doubling, not on
// every request.
func TestDelegationSyncLaneWarns(t *testing.T) {
	at := delegationSyncLaneWarnAt
	for _, c := range []struct {
		n, warnedAt int
		want        bool
	}{
		{at - 1, 0, false},
		{at, 0, true},
		{at + 1, at, false},
		{2*at - 1, at, false},
		{2 * at, at, true},
		{4 * at, 2 * at, true},
	} {
		if got := delegationSyncLaneWarns(c.n, c.warnedAt); got != c.want {
			t.Errorf("%d waiting, last warned at %d: warns %v, want %v", c.n, c.warnedAt, got, c.want)
		}
	}
}

// tdns's syncher runs its requests on the lanes: an operator's explicit sync
// whose answer nobody has read yet holds its own parent's queue only, and an
// explicit sync for a zone under another parent is answered meanwhile. Both
// zones' parents are unknown and there is no IMR, so each analysis fails at
// once and the answer is the error.
func TestTheSyncherRunsEachParentOnItsOwnQueue(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.ImrReady = NewImrReadiness()
	ctx, cancel := context.WithCancel(context.Background())
	q := make(chan DelegationSyncRequest, 10)
	done := make(chan struct{})
	go func() { defer close(done); _ = kdb.DelegationSyncher(ctx, q, nil, conf) }()

	held := make(chan DelegationSyncStatus) // nobody reads it yet
	heldZone := laneZone("held.p1.example.", "")
	offer(t, q, DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: heldZone.ZoneName,
		ZoneData: heldZone, Response: held})

	answered := make(chan DelegationSyncStatus, 1)
	freeZone := laneZone("free.p2.example.", "")
	offer(t, q, DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: freeZone.ZoneName,
		ZoneData: freeZone, Response: answered})
	if st := receive(t, answered, "the other parent's explicit sync"); !st.Error {
		t.Errorf("the explicit sync answered %+v, want the analysis error (no IMR)", st)
	}
	waitFor(t, 2*time.Second, "the held explicit sync to run", func() bool {
		pos, ok := DelegationSyncWaiting(heldZone.ZoneName)
		return ok && pos.Running
	})
	if pos := waitingIn(t, heldZone.ZoneName); pos.Parent != "p1.example." {
		t.Errorf("the held zone is in %s, want p1.example.", pos.Parent)
	}

	receive(t, held, "the held explicit sync's answer")
	cancel()
	receive(t, done, "the syncher to stop")
}
