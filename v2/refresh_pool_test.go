package tdns

import (
	"context"
	"errors"
	"testing"
	"time"
)

// undrainedPool is a pool with a queue and no workers, so dispatch decisions can
// be tested without timing: the first job fills the queue and every later one is
// refused.
func undrainedPool(queue int) *refreshPool {
	return &refreshPool{
		jobs: make(chan refreshJob, queue),
		done: make(chan refreshOutcome, 1),
	}
}

func waitingJob(zone string) (refreshJob, chan RefresherResponse) {
	resp := make(chan RefresherResponse, 1)
	zr := &ZoneRefresher{Name: zone, Wait: true, Response: resp}
	return refreshJob{zd: &ZoneData{ZoneName: zone}, zone: zone, zr: zr}, resp
}

// A zone already being refreshed is skipped rather than queued again. Two
// concurrent refreshes of one zone are not merely wasteful: ZoneTransferIn
// replaces zd.Data wholesale, so the second would edit a map the first is
// rebuilding.
func TestDispatchSkipsAZoneAlreadyInFlight(t *testing.T) {
	pool := undrainedPool(4)
	inflight := map[string]struct{}{}

	first, _ := waitingJob("example.test.")
	dispatchRefresh(pool, inflight, first)
	if len(pool.jobs) != 1 {
		t.Fatalf("first dispatch: %d jobs queued, want 1", len(pool.jobs))
	}

	second, resp := waitingJob("example.test.")
	dispatchRefresh(pool, inflight, second)
	if len(pool.jobs) != 1 {
		t.Fatalf("a zone already in flight was dispatched again: %d jobs queued", len(pool.jobs))
	}
	assertAnswered(t, resp, "already in progress")
}

// A saturated pool refuses, and says so to anyone waiting. The zone is left due:
// dispatchRefresh does not touch the refresh counters at all, so the next tick
// finds it still at or below zero and tries again.
func TestDispatchRefusesWhenTheQueueIsFull(t *testing.T) {
	pool := undrainedPool(1)
	inflight := map[string]struct{}{}

	first, _ := waitingJob("one.example.test.")
	dispatchRefresh(pool, inflight, first)

	second, resp := waitingJob("two.example.test.")
	dispatchRefresh(pool, inflight, second)

	if len(pool.jobs) != 1 {
		t.Fatalf("the queue took a job it had no room for: %d", len(pool.jobs))
	}
	if _, marked := inflight["two.example.test."]; marked {
		t.Fatal("a zone that was never dispatched was marked in flight; nothing will " +
			"ever clear that entry and the zone is never refreshed again")
	}
	assertAnswered(t, resp, "saturated")
}

func assertAnswered(t *testing.T, resp chan RefresherResponse, want string) {
	t.Helper()
	select {
	case got := <-resp:
		if !got.Error {
			t.Errorf("a skipped refresh answered success: %+v", got)
		}
		if want != "" && !contains(got.ErrorMsg, want) {
			t.Errorf("answer %q does not mention %q", got.ErrorMsg, want)
		}
	default:
		t.Fatal("a Wait-ing caller was never answered; tdns-cli zone reload would hang")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// The gate caps concurrent transfers, and a nil gate is ungated.
func TestTransferGateCapsAndReleases(t *testing.T) {
	var nilGate *transferGate
	if err := nilGate.acquire(context.Background()); err != nil {
		t.Fatalf("a nil gate must be ungated, got %v", err)
	}
	nilGate.release() // must not panic

	g := newTransferGate(2)
	ctx := context.Background()
	if err := g.acquire(ctx); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := g.acquire(ctx); err != nil {
		t.Fatalf("second acquire: %v", err)
	}

	blocked := make(chan error, 1)
	go func() { blocked <- g.acquire(ctx) }()
	select {
	case <-blocked:
		t.Fatal("the gate let a third transfer through a cap of two")
	case <-time.After(100 * time.Millisecond):
	}

	g.release()
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("acquire after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("releasing a token did not admit the waiter")
	}
}

// Waiting on the gate at shutdown reports cancellation, not a zone failure.
// noteRefreshFailure keys on context.Canceled to avoid marking every zone parked
// on the gate as sick while the process is dying.
func TestTransferGateReportsCancellation(t *testing.T) {
	g := newTransferGate(1)
	if err := g.acquire(context.Background()); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := g.acquire(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("gate returned %v, want context.Canceled", err)
	}
}

// Shutdown returns even with the engine no longer reading outcomes: the workers
// stop after their current job, and neither the buffered done channel nor the
// ctx-guarded send leaves one blocked on a hand-off nobody wants.
func TestPoolShutdownDrainsWithOutcomesUnread(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newRefreshPool(ctx, 4, 8, 2, &Config{})

	for i := 0; i < 8; i++ {
		zone := "z" + string(rune('a'+i)) + ".example."
		zd := &ZoneData{ZoneName: zone, ZoneType: Secondary} // no upstreams: fails fast
		Zones.Set(zone, zd)
		defer Zones.Remove(zone)
		pool.TryDispatch(refreshJob{zd: zd, zone: zone})
	}

	done := make(chan struct{})
	go func() { pool.Shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown did not return: a worker is blocked handing back an outcome")
	}
}
