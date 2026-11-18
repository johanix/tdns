/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// poolWait is how long a test waits for something that should happen at once.
// Generous: the failure it guards is "never", not "slowly".
const poolWait = 5 * time.Second

// settle is how long a test lets something that must NOT happen have to happen.
const settle = 100 * time.Millisecond

// resignPass renews every zone in zones through the pool, as the resigner's own
// workers do, and returns when they have all finished. The engine never waits
// like this; tests that want a zone renewed and then look at it do.
func resignPass(ctx context.Context, zones map[string]*ZoneData) {
	pool := newResignPool(defaultResignWorkers, liveResignWork())
	for _, zd := range zones {
		pool.submit(ctx, zd, resignJobRenew)
	}
	pool.wait()
}

// bareZones are zones for tests of the pool itself, which never look inside one.
func bareZones(n int) map[string]*ZoneData {
	zones := make(map[string]*ZoneData, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("bare%03d.example.", i)
		zones[name] = &ZoneData{ZoneName: name}
	}
	return zones
}

// gate is a work function that blocks each call it is given until released, and
// says when a call has got in.
type gate struct {
	entered chan string
	release chan struct{}
	once    sync.Once
}

func newGate(n int) *gate {
	return &gate{entered: make(chan string, n), release: make(chan struct{})}
}

func (g *gate) work(_ context.Context, zd *ZoneData) {
	g.entered <- zd.ZoneName
	<-g.release
}

func (g *gate) open() { g.once.Do(func() { close(g.release) }) }

func (g *gate) waitFor(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-g.entered:
		case <-time.After(poolWait):
			g.open()
			t.Fatalf("only %d of %d calls got in", i, n)
		}
	}
}

// TestEachZoneIsRunByExactlyOneWorker: what keeps two workers off the same zone.
// Every zone is handed over once, to one worker. The barrier makes the first
// defaultResignWorkers calls wait for each other, which proves they ran at the same
// time and that the pool did not quietly degrade to one.
func TestEachZoneIsRunByExactlyOneWorker(t *testing.T) {
	const n = 200
	zones := bareZones(n)

	var mu sync.Mutex
	inFlight := make(map[string]bool)
	calls := make(map[string]int)
	var active, maxActive int
	arrived := make(chan struct{}, defaultResignWorkers)
	barrier := make(chan struct{})
	var barrierOnce sync.Once
	var first atomic.Int32
	renew := func(_ context.Context, zd *ZoneData) {
		mu.Lock()
		if inFlight[zd.ZoneName] {
			t.Errorf("%s is in two workers at once", zd.ZoneName)
		}
		inFlight[zd.ZoneName] = true
		calls[zd.ZoneName]++
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()

		if first.Add(1) <= defaultResignWorkers {
			arrived <- struct{}{}
			select {
			case <-barrier:
			case <-time.After(poolWait):
				t.Errorf("the first %d calls did not run together: the pool is not concurrent", defaultResignWorkers)
			}
		} else {
			time.Sleep(50 * time.Microsecond)
		}

		mu.Lock()
		inFlight[zd.ZoneName] = false
		active--
		mu.Unlock()
	}

	pool := newResignPool(defaultResignWorkers, resignWork{renew: renew})
	for _, zd := range zones {
		if !pool.submit(context.Background(), zd, resignJobRenew) {
			t.Fatalf("%s: a zone that was not in flight was not taken on", zd.ZoneName)
		}
	}
	for i := 0; i < defaultResignWorkers; i++ {
		select {
		case <-arrived:
		case <-time.After(poolWait):
			barrierOnce.Do(func() { close(barrier) })
			pool.wait()
			t.Fatalf("only %d of %d workers started", i, defaultResignWorkers)
		}
	}
	barrierOnce.Do(func() { close(barrier) })
	pool.wait()

	if len(calls) != n {
		t.Errorf("%d of %d zones were run", len(calls), n)
	}
	for name, c := range calls {
		if c != 1 {
			t.Errorf("%s was run %d times for one request", name, c)
		}
	}
	if maxActive != defaultResignWorkers {
		t.Errorf("at most %d zones were run at once, want exactly the pool width %d", maxActive, defaultResignWorkers)
	}
}

// TestARequestForAZoneInFlightIsNotHandedToASecondWorker: the same zone asked
// for while a worker is inside it, over and over, as every tick of the engine
// does. None of those starts a second run; they report that the zone is in
// flight.
func TestARequestForAZoneInFlightIsNotHandedToASecondWorker(t *testing.T) {
	g := newGate(8)
	var renews atomic.Int32
	pool := newResignPool(defaultResignWorkers, resignWork{renew: func(ctx context.Context, zd *ZoneData) {
		renews.Add(1)
		g.work(ctx, zd)
	}})
	zd := &ZoneData{ZoneName: "once.example."}

	if !pool.submit(context.Background(), zd, resignJobRenew) {
		t.Fatal("a zone that was not in flight was not taken on")
	}
	g.waitFor(t, 1)
	for i := 0; i < 20; i++ {
		if pool.submit(context.Background(), zd, resignJobRenew) {
			t.Fatal("a zone with a worker inside it was handed over again")
		}
	}
	time.Sleep(settle)
	if n := renews.Load(); n != 1 {
		t.Errorf("%d runs of a zone that was in flight, want 1", n)
	}
	g.open()
	pool.wait()
	if n := renews.Load(); n != 1 {
		t.Errorf("%d runs after the release; a dropped renewal request must not come back as a run", n)
	}
	if pool.inFlight() != 0 {
		t.Error("the zone is still in flight when its work has ended")
	}
}

// A zone spelled another way is the same zone: the set is keyed by the folded
// name, as every map made from zone names is.
func TestTheSameZoneSpelledAnotherWayIsInFlightOnce(t *testing.T) {
	g := newGate(4)
	pool := newResignPool(defaultResignWorkers, resignWork{renew: g.work})
	a := &ZoneData{ZoneName: "Mixed.Example."}
	b := &ZoneData{ZoneName: "mixed.example."}

	if !pool.submit(context.Background(), a, resignJobRenew) {
		t.Fatal("not taken on")
	}
	g.waitFor(t, 1)
	if pool.submit(context.Background(), b, resignJobRenew) {
		t.Error("the same zone, spelled in lower case, was taken on as a second zone")
	}
	g.open()
	pool.wait()
}

// A zone replaced by a new ZoneData while it is in flight (ModifyDynamicZone) is
// still one zone: the work asked for is for the live copy, which nothing has
// been done to, so it is done on that after the work in hand -- or, if the old
// copy had not started, instead of it. Left on the old copy, the new one would
// be skipped as in flight, with no estimate, and nothing would wake the engine
// for it.
func TestAZoneReplacedWhileInFlightIsWorkedOnAsTheLiveCopy(t *testing.T) {
	const name = "replaced.example."
	for _, started := range []bool{true, false} {
		t.Run(fmt.Sprintf("old copy started=%v", started), func(t *testing.T) {
			g := newGate(4)
			var mu sync.Mutex
			var ran []*ZoneData
			pool := newResignPool(1, resignWork{renew: func(ctx context.Context, zd *ZoneData) {
				if zd.ZoneName == "blocker.example." {
					g.work(ctx, zd)
					return
				}
				mu.Lock()
				ran = append(ran, zd)
				mu.Unlock()
				if started && len(ran) == 1 {
					g.work(ctx, zd)
				}
			}})
			oldZd := &ZoneData{ZoneName: name}
			newZd := &ZoneData{ZoneName: name}

			if started {
				pool.submit(context.Background(), oldZd, resignJobRenew)
				g.waitFor(t, 1)
			} else {
				pool.submit(context.Background(), &ZoneData{ZoneName: "blocker.example."}, resignJobRenew)
				g.waitFor(t, 1)
				pool.submit(context.Background(), oldZd, resignJobRenew)
			}
			if pool.submit(context.Background(), newZd, resignJobRenew) {
				t.Error("the replacement was taken on as a second zone")
			}
			g.open()
			pool.wait()

			mu.Lock()
			defer mu.Unlock()
			want := []*ZoneData{newZd}
			if started {
				want = []*ZoneData{oldZd, newZd}
			}
			if len(ran) != len(want) {
				t.Fatalf("%d runs, want %d", len(ran), len(want))
			}
			for i := range want {
				if ran[i] != want[i] {
					t.Errorf("run %d was on the wrong copy of the zone", i)
				}
			}
			if ended := pool.takeEnded(); ended[name] != newZd {
				t.Error("the zone ended as the old copy; the engine would work its wake out from the wrong one")
			}
		})
	}
}

// TestAReplaceAskedForDuringARenewalFollowsIt is the exclusion the pool exists
// to keep. Both RenewZoneSignatures and ResignZone resolve the zone's keys
// before they take zd.mu, so a renewal that overlapped a replace could sign by
// keys the replace has just retired, after it. A replace asked for while the
// zone's renewal is in flight therefore waits for it, and runs after it; and
// not as a second worker's work.
func TestAReplaceAskedForDuringARenewalFollowsIt(t *testing.T) {
	g := newGate(4)
	var mu sync.Mutex
	var events []string
	var inside atomic.Int32
	enter := func(what string) {
		if inside.Add(1) != 1 {
			t.Errorf("%s began while another job of the same zone was running", what)
		}
		mu.Lock()
		events = append(events, what+" begins")
		mu.Unlock()
	}
	leave := func(what string) {
		mu.Lock()
		events = append(events, what+" ends")
		mu.Unlock()
		inside.Add(-1)
	}
	pool := newResignPool(defaultResignWorkers, resignWork{
		renew: func(ctx context.Context, zd *ZoneData) {
			enter("renew")
			g.work(ctx, zd)
			leave("renew")
		},
		replace: func(_ context.Context, _ *ZoneData) {
			enter("replace")
			leave("replace")
		},
	})
	zd := &ZoneData{ZoneName: "rolled.example."}

	pool.submit(context.Background(), zd, resignJobRenew)
	g.waitFor(t, 1)

	if pool.submit(context.Background(), zd, resignJobReplace) {
		t.Error("a replace for a zone in flight was handed to a second worker")
	}
	time.Sleep(settle)
	mu.Lock()
	during := fmt.Sprint(events)
	mu.Unlock()
	if during != "[renew begins]" {
		t.Fatalf("while the renewal was in flight: %s; the replace must not start", during)
	}

	g.open()
	pool.wait()
	mu.Lock()
	defer mu.Unlock()
	if got := fmt.Sprint(events); got != "[renew begins renew ends replace begins replace ends]" {
		t.Errorf("order of work on the zone: %s; the replace must follow the renewal it was asked for during", got)
	}
}

// The other order: a renewal asked for while a replace runs is not run beside
// it, and a second replace asked for then is not lost -- it is for a change the
// run in flight may have missed.
func TestWhatIsAskedForDuringAReplaceNeverRunsBesideIt(t *testing.T) {
	g := newGate(4)
	var inside, replaces, renews atomic.Int32
	pool := newResignPool(defaultResignWorkers, resignWork{
		replace: func(ctx context.Context, zd *ZoneData) {
			if inside.Add(1) != 1 {
				t.Error("a job began beside a replace of the same zone")
			}
			n := replaces.Add(1)
			if n == 1 {
				g.work(ctx, zd)
			}
			inside.Add(-1)
		},
		renew: func(_ context.Context, _ *ZoneData) {
			if inside.Add(1) != 1 {
				t.Error("a renewal began beside a replace of the same zone")
			}
			renews.Add(1)
			inside.Add(-1)
		},
	})
	zd := &ZoneData{ZoneName: "rolled2.example."}

	pool.submit(context.Background(), zd, resignJobReplace)
	g.waitFor(t, 1)
	pool.submit(context.Background(), zd, resignJobRenew)
	pool.submit(context.Background(), zd, resignJobReplace)
	time.Sleep(settle)
	if replaces.Load() != 1 || renews.Load() != 0 {
		t.Errorf("replaces %d, renewals %d while a replace was in flight; nothing else may start",
			replaces.Load(), renews.Load())
	}
	g.open()
	pool.wait()
	if replaces.Load() != 2 {
		t.Errorf("%d replaces, want 2: the one asked for during the first was lost", replaces.Load())
	}
	if renews.Load() != 0 {
		t.Errorf("%d renewals: a renewal asked for while the zone was in flight must be dropped,"+
			" the engine asks again when the zone ends", renews.Load())
	}
}

// A zone still queued when a second job is asked for gets both, in one run.
func TestAJobAskedForOnAQueuedZoneJoinsItsRun(t *testing.T) {
	g := newGate(4)
	var order []string
	var mu sync.Mutex
	pool := newResignPool(1, resignWork{
		renew: func(ctx context.Context, zd *ZoneData) {
			if zd.ZoneName == "blocker.example." {
				g.work(ctx, zd)
				return
			}
			mu.Lock()
			order = append(order, "renew "+zd.ZoneName)
			mu.Unlock()
		},
		replace: func(_ context.Context, zd *ZoneData) {
			mu.Lock()
			order = append(order, "replace "+zd.ZoneName)
			mu.Unlock()
		},
	})
	blocker := &ZoneData{ZoneName: "blocker.example."}
	queued := &ZoneData{ZoneName: "queued.example."}
	pool.submit(context.Background(), blocker, resignJobRenew)
	g.waitFor(t, 1)
	if !pool.submit(context.Background(), queued, resignJobRenew) {
		t.Fatal("not taken on")
	}
	if pool.submit(context.Background(), queued, resignJobReplace) {
		t.Error("a second request for a queued zone was taken on as new work")
	}
	g.open()
	pool.wait()
	if got := fmt.Sprint(order); got != "[replace queued.example. renew queued.example.]" {
		t.Errorf("the queued zone ran as %s, want the replace and then the renewal, once each", got)
	}
}

// The queue is first in, first out.
func TestTheQueueIsFirstInFirstOut(t *testing.T) {
	g := newGate(4)
	var order []string
	var mu sync.Mutex
	pool := newResignPool(1, resignWork{renew: func(ctx context.Context, zd *ZoneData) {
		if zd.ZoneName == "blocker.example." {
			g.work(ctx, zd)
			return
		}
		mu.Lock()
		order = append(order, zd.ZoneName)
		mu.Unlock()
	}})
	pool.submit(context.Background(), &ZoneData{ZoneName: "blocker.example."}, resignJobRenew)
	g.waitFor(t, 1)
	var want []string
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("q%02d.example.", i)
		want = append(want, name)
		pool.submit(context.Background(), &ZoneData{ZoneName: name}, resignJobRenew)
	}
	g.open()
	pool.wait()
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Errorf("ran in the order %v, want %v", order, want)
	}
}

// poolWidths are the widths the pool is exercised at: the default and others, so
// that what holds for the default of 3 holds for any resignerengine.workers.
var poolWidths = []int{1, 2, 3, 8}

// TestWMinusOneSlowZonesLeaveTheRestRunning is the pool's half of #1034: with
// width-1 zones stuck, the others still run, though only through the one worker
// that is left.
func TestWMinusOneSlowZonesLeaveTheRestRunning(t *testing.T) {
	for _, width := range poolWidths {
		t.Run(fmt.Sprintf("width %d", width), func(t *testing.T) {
			g := newGate(width)
			var rest atomic.Int32
			pool := newResignPool(width, resignWork{renew: func(ctx context.Context, zd *ZoneData) {
				if zd.ZoneName[0] == 's' {
					g.work(ctx, zd)
					return
				}
				rest.Add(1)
			}})
			for i := 0; i < width-1; i++ {
				pool.submit(context.Background(), &ZoneData{ZoneName: fmt.Sprintf("slow%d.example.", i)}, resignJobRenew)
			}
			g.waitFor(t, width-1)
			const free = 30
			for i := 0; i < free; i++ {
				pool.submit(context.Background(), &ZoneData{ZoneName: fmt.Sprintf("fast%02d.example.", i)}, resignJobRenew)
			}
			deadline := time.Now().Add(poolWait)
			for rest.Load() < free && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := rest.Load(); got != free {
				t.Errorf("%d zones stuck and only %d of %d others ran", width-1, got, free)
			}
			g.open()
			pool.wait()
		})
	}
}

// TestWSlowZonesExhaustThePool states the limit, so that it is a decision and
// not a surprise, for whatever width the pool is configured with. With as many
// zones stuck as there are workers, nothing else runs -- it queues, in order, and
// runs as soon as a worker is free. Nothing is lost and nothing is run twice.
func TestWSlowZonesExhaustThePool(t *testing.T) {
	for _, width := range poolWidths {
		t.Run(fmt.Sprintf("width %d", width), func(t *testing.T) {
			g := newGate(width)
			var rest atomic.Int32
			pool := newResignPool(width, resignWork{renew: func(ctx context.Context, zd *ZoneData) {
				if zd.ZoneName[0] == 's' {
					g.work(ctx, zd)
					return
				}
				rest.Add(1)
			}})
			for i := 0; i < width; i++ {
				pool.submit(context.Background(), &ZoneData{ZoneName: fmt.Sprintf("slow%d.example.", i)}, resignJobRenew)
			}
			g.waitFor(t, width)
			for i := 0; i < 5; i++ {
				pool.submit(context.Background(), &ZoneData{ZoneName: fmt.Sprintf("fast%d.example.", i)}, resignJobRenew)
			}
			time.Sleep(settle)
			if got := rest.Load(); got != 0 {
				t.Errorf("%d zones ran with every worker stuck", got)
			}
			g.open()
			pool.wait()
			if got := rest.Load(); got != 5 {
				t.Errorf("%d of 5 queued zones ran once the workers were free", got)
			}
		})
	}
}

// TestNothingStartsOnceTheContextIsDone: shutdown. A zone's lock is a plain
// mutex, so a worker inside a zone cannot be interrupted, and wait says so by
// waiting for it: the engine goroutine is what shutdown waits on, and a worker
// left behind would run on past it. What cancellation does reach is the next
// zone: no worker starts one after it, and the ones still queued are dropped.
func TestNothingStartsOnceTheContextIsDone(t *testing.T) {
	const width = 2
	zones := bareZones(10)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := newGate(len(zones))
	var started atomic.Int32
	pool := newResignPool(width, resignWork{renew: func(ctx context.Context, zd *ZoneData) {
		started.Add(1)
		g.work(ctx, zd)
	}})
	for _, zd := range zones {
		pool.submit(ctx, zd, resignJobRenew)
	}
	g.waitFor(t, width)

	cancel()
	waited := make(chan struct{})
	go func() { pool.wait(); close(waited) }()
	select {
	case <-waited:
		t.Fatal("wait returned while the workers were still inside a zone")
	case <-time.After(settle):
	}
	if pool.submit(ctx, &ZoneData{ZoneName: "late.example."}, resignJobRenew) {
		t.Error("a zone was taken on after the context was done")
	}

	g.open()
	select {
	case <-waited:
	case <-time.After(poolWait):
		t.Fatal("wait did not return after the workers were released")
	}
	if got := started.Load(); got != width {
		t.Errorf("%d zones were started, want %d: a worker took a zone after the context was done", got, width)
	}
}

// A pool of width 0 is one worker; a pool wider than its work still runs it all;
// nothing asked for is nothing run.
func TestANarrowOrWidePoolAndAnEmptyOneStillTerminate(t *testing.T) {
	var ran atomic.Int32
	work := resignWork{renew: func(context.Context, *ZoneData) { ran.Add(1) }}

	empty := newResignPool(defaultResignWorkers, work)
	empty.wait()
	if empty.submit(context.Background(), nil, resignJobRenew) || empty.submit(context.Background(), &ZoneData{ZoneName: "x."}, 0) {
		t.Error("an empty request was taken on")
	}

	narrow := newResignPool(0, work)
	for _, zd := range bareZones(5) {
		narrow.submit(context.Background(), zd, resignJobRenew)
	}
	narrow.wait()
	if got := ran.Load(); got != 5 {
		t.Errorf("a pool of width 0 ran %d of 5 zones; it must fall back to one worker", got)
	}

	ran.Store(0)
	wide := newResignPool(50, work)
	for _, zd := range bareZones(2) {
		wide.submit(context.Background(), zd, resignJobRenew)
	}
	wide.wait()
	if got := ran.Load(); got != 2 {
		t.Errorf("a pool wider than the zone list ran %d of 2 zones", got)
	}
}

// notInFlight leaves out zones the pool holds, queued or running, and is what the
// engine works its wake out from.
func TestNotInFlightLeavesOutQueuedAndRunningZones(t *testing.T) {
	g := newGate(4)
	pool := newResignPool(1, resignWork{renew: g.work})
	zones := bareZones(3)
	run := zones["bare000.example."]
	queued := zones["bare001.example."]
	idle := zones["bare002.example."]
	pool.submit(context.Background(), run, resignJobRenew)
	g.waitFor(t, 1)
	pool.submit(context.Background(), queued, resignJobRenew)

	got := pool.notInFlight(zones)
	if len(got) != 1 || got["bare002.example."] != idle {
		t.Errorf("notInFlight kept %d zones, want only the idle one", len(got))
	}
	g.open()
	pool.wait()
	if got := pool.notInFlight(zones); len(got) != 3 {
		t.Errorf("after the work ended notInFlight kept %d of 3 zones", len(got))
	}
	if ended := pool.takeEnded(); len(ended) != 2 {
		t.Errorf("takeEnded returned %d zones, want the 2 that ran", len(ended))
	}
	if ended := pool.takeEnded(); len(ended) != 0 {
		t.Error("takeEnded returned zones twice")
	}
}
