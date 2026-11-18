/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests run the engine's own loop (runResigner), at a pace of their own,
// on work of their own. What they pin down is what the pool alone cannot: that
// the engine does not wait for a zone.

// A floor short against the work, and one long against it. The engine's wake is
// worked out from the floor, so what holds for one must hold for the other.
var engineFloors = []time.Duration{15 * time.Millisecond, 150 * time.Millisecond}

// freshZones empties the zone registry, which the engine reads its candidates
// from, and the resigner's wake slot, which anything that registers fills.
func freshZones(t *testing.T) {
	t.Helper()
	resetZonesForTest()
	emptyResignWake(t)
	t.Cleanup(resetZonesForTest)
}

// engineZone is a zone on the watchlist that the pool and the engine can handle
// and nothing looks inside: it signs, by its options, and it has no renewal
// estimate, which is what a zone that has never been walked looks like.
func engineZone(t *testing.T, name string) *ZoneData {
	t.Helper()
	zd := &ZoneData{ZoneName: name, Options: map[ZoneOption]bool{OptInlineSigning: true}}
	registerZones(t, zd)
	zd.keepSigned.Store(true)
	return zd
}

type testResigner struct {
	q      chan ResignRequest
	cancel context.CancelFunc
	done   chan struct{}
}

// startResigner runs the engine loop at floor on work. It is stopped, and
// waited for, when the test ends; a test that holds a worker inside a zone
// releases it first, with a defer.
func startResigner(t *testing.T, floor time.Duration, work resignWork) *testResigner {
	t.Helper()
	r := &testResigner{q: make(chan ResignRequest, 64), done: make(chan struct{})}
	var ctx context.Context
	ctx, r.cancel = context.WithCancel(context.Background())
	go func() { runResigner(ctx, r.q, floor, work); close(r.done) }()
	t.Cleanup(func() { r.cancel(); <-r.done })
	return r
}

// zoneCount is a count per zone name, safe to share.
type zoneCount struct {
	mu sync.Mutex
	n  map[string]int
}

func (c *zoneCount) add(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = make(map[string]int)
	}
	c.n[name]++
}

func (c *zoneCount) get(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[name]
}

// waitAll waits until every one of zones has reached want.
func (c *zoneCount) waitAll(zones []*ZoneData, want int) bool {
	deadline := time.Now().Add(poolWait)
	for time.Now().Before(deadline) {
		ok := true
		for _, zd := range zones {
			if c.get(zd.ZoneName) < want {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// TestSlowZonesDoNotHoldUpTheRestOfTheEngine is #1034, at the level it was
// asked for. The engine used to wait for a pass to end before it worked out its
// next wake, so even with zones renewed side by side, no new pass began until
// the slowest zone had finished and every zone's cadence was the slowest zone's.
//
// Here resignWorkers-1 zones have their lock held for the whole test, so the
// workers that reach them wait. Three others must be renewed over and over --
// pass after pass, at the engine's own cadence -- while the locks are held.
//
// Run with a floor short against the work and one long against it, and with a
// zone that says it is due again within a floor (a short signature validity) and
// one that does not know when.
func TestSlowZonesDoNotHoldUpTheRestOfTheEngine(t *testing.T) {
	modes := []struct {
		name string
		due  func(zd *ZoneData, floor time.Duration)
	}{
		{"due again within a floor", func(zd *ZoneData, floor time.Duration) {
			if snap := zd.snapshot.Load(); snap != nil {
				zd.setResignSchedule(time.Now().Add(floor/4), snap.Serial)
			}
		}},
		{"no estimate", func(zd *ZoneData, _ time.Duration) { zd.setResignSchedule(time.Time{}, 0) }},
	}
	for _, floor := range engineFloors {
		for _, mode := range modes {
			t.Run(fmt.Sprintf("floor %s, %s", floor, mode.name), func(t *testing.T) {
				slowZonesDoNotHoldUpTheRest(t, floor, mode.due)
			})
		}
	}
}

func slowZonesDoNotHoldUpTheRest(t *testing.T, floor time.Duration, due func(*ZoneData, time.Duration)) {
	const free, passes = 3, 4
	freshZones(t)

	mine := make(map[string]bool)
	var held, rest []*ZoneData
	for i := 0; i < resignWorkers-1; i++ {
		zd := watchedTestZone(t, fmt.Sprintf("held%02d.example.", i))
		zd.KeepRenewed()
		held = append(held, zd)
		mine[zd.ZoneName] = true
	}
	for i := 0; i < free; i++ {
		zd := watchedTestZone(t, fmt.Sprintf("free%02d.example.", i))
		zd.KeepRenewed()
		rest = append(rest, zd)
		mine[zd.ZoneName] = true
	}

	for _, zd := range held {
		zd.mu.Lock()
	}
	var unlockOnce sync.Once
	unlock := func() {
		unlockOnce.Do(func() {
			for _, zd := range held {
				zd.mu.Unlock()
			}
		})
	}
	defer unlock()

	var entered, returned zoneCount
	work := liveResignWork()
	work.renew = func(ctx context.Context, zd *ZoneData) {
		if !mine[zd.ZoneName] {
			return
		}
		entered.add(zd.ZoneName)
		resignSweepZone(ctx, zd)
		due(zd, floor)
		returned.add(zd.ZoneName)
	}
	startResigner(t, floor, work)

	if !returned.waitAll(rest, passes) {
		for _, zd := range rest {
			t.Errorf("%s was renewed %d times in %s while %d zones' locks were held, want %d:"+
				" a slow zone is holding up the rest of the resigner",
				zd.ZoneName, returned.get(zd.ZoneName), poolWait, len(held), passes)
		}
	}
	for _, zd := range held {
		if n := returned.get(zd.ZoneName); n != 0 {
			t.Errorf("%s was held, and its renewal returned %d times", zd.ZoneName, n)
		}
		if n := entered.get(zd.ZoneName); n != 1 {
			t.Errorf("%s has been inside a worker %d times across the passes, want 1: a zone in flight was handed over again",
				zd.ZoneName, n)
		}
	}

	// Nothing is lost: once the zones are free they are renewed, too.
	unlock()
	if !returned.waitAll(held, 1) {
		t.Error("a zone that was held during the passes was never renewed after it was released")
	}
}

// TestAKeyStateRequestIsReadWhileAZoneIsBeingRenewed: nothing used to read the
// ResignQ while a sweep ran, and a replace ran inline in the engine goroutine,
// so a rollover waited for the slowest zone of the pass.
func TestAKeyStateRequestIsReadWhileAZoneIsBeingRenewed(t *testing.T) {
	freshZones(t)
	slow := engineZone(t, "slow.example.")
	rolled := &ZoneData{ZoneName: "rolled.example."}

	g := newGate(8)
	replaced := make(chan string, 4)
	r := startResigner(t, engineFloors[0], resignWork{
		renew: func(ctx context.Context, zd *ZoneData) {
			if zd == slow {
				g.work(ctx, zd)
			}
		},
		replace: func(_ context.Context, zd *ZoneData) { replaced <- zd.ZoneName },
	})
	defer g.open()
	g.waitFor(t, 1)

	r.q <- ResignRequest{Zd: rolled, Reason: ResignKeyStateChanged}
	select {
	case name := <-replaced:
		if name != rolled.ZoneName {
			t.Errorf("replaced %s", name)
		}
	case <-time.After(poolWait):
		t.Fatalf("a key-state request waited %s behind a zone that was being renewed", poolWait)
	}
	if len(r.q) != 0 {
		t.Error("the request is still queued")
	}
}

// TestAReplaceRequestedDuringTheZonesRenewalFollowsIt, at the engine: the zone's
// renewal is in flight when a key-state request for it arrives. The replace
// does not run beside the renewal, and it runs after it; and the ticks that
// come meanwhile do not start a second renewal.
func TestAReplaceRequestedDuringTheZonesRenewalFollowsIt(t *testing.T) {
	freshZones(t)
	zd := engineZone(t, "both.example.")

	g := newGate(8)
	var seq, renewEnded, replaceBegan atomic.Int64
	var renews atomic.Int32
	r := startResigner(t, engineFloors[0], resignWork{
		renew: func(ctx context.Context, z *ZoneData) {
			renews.Add(1)
			g.work(ctx, z)
			renewEnded.Store(seq.Add(1))
		},
		replace: func(_ context.Context, _ *ZoneData) { replaceBegan.Store(seq.Add(1)) },
	})
	defer g.open()
	g.waitFor(t, 1)

	r.q <- ResignRequest{Zd: zd, Reason: ResignKeyStateChanged}
	time.Sleep(10 * engineFloors[0])
	if replaceBegan.Load() != 0 {
		t.Fatal("the replace ran while the zone's renewal was in flight")
	}
	if n := renews.Load(); n != 1 {
		t.Errorf("%d renewals of the zone while it was in flight, want 1", n)
	}

	g.open()
	deadline := time.Now().Add(poolWait)
	for replaceBegan.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if replaceBegan.Load() == 0 {
		t.Fatal("the replace never ran after the renewal")
	}
	if replaceBegan.Load() < renewEnded.Load() {
		t.Error("the replace began before the renewal it was asked for during had ended")
	}
}

// TestNoZoneIsEverInTwoWorkersAcrossPasses: many zones, a floor far shorter than
// the work, so that most ticks find most zones still in flight, and key-state
// requests arriving all the while. A zone is never in two workers, renewal and
// replace together, and never more zones than the pool is wide. Run it with -race.
func TestNoZoneIsEverInTwoWorkersAcrossPasses(t *testing.T) {
	const n = 40
	freshZones(t)
	zones := make([]*ZoneData, n)
	for i := range zones {
		zones[i] = engineZone(t, fmt.Sprintf("many%03d.example.", i))
	}

	var mu sync.Mutex
	busy := make(map[string]string)
	var active, maxActive int
	var renews, replaces zoneCount
	do := func(what string, count *zoneCount) func(context.Context, *ZoneData) {
		return func(_ context.Context, zd *ZoneData) {
			mu.Lock()
			if prev, ok := busy[zd.ZoneName]; ok {
				t.Errorf("%s: a %s began while a %s of the same zone was running", zd.ZoneName, what, prev)
			}
			busy[zd.ZoneName] = what
			active++
			if active > maxActive {
				maxActive = active
			}
			mu.Unlock()

			time.Sleep(time.Duration(rand.Intn(1500)) * time.Microsecond)

			mu.Lock()
			delete(busy, zd.ZoneName)
			active--
			mu.Unlock()
			count.add(zd.ZoneName)
		}
	}
	r := startResigner(t, 5*time.Millisecond, resignWork{renew: do("renewal", &renews), replace: do("replace", &replaces)})

	end := time.After(500 * time.Millisecond)
feed:
	for i := 0; ; i++ {
		select {
		case <-end:
			break feed
		case r.q <- ResignRequest{Zd: zones[i%n], Reason: ResignKeyStateChanged}:
			time.Sleep(time.Millisecond)
		}
	}
	r.cancel()
	<-r.done

	mu.Lock()
	defer mu.Unlock()
	if maxActive > resignWorkers {
		t.Errorf("%d zones were in a worker at once, the pool is %d wide", maxActive, resignWorkers)
	}
	for _, zd := range zones {
		if renews.get(zd.ZoneName) < 3 {
			t.Errorf("%s was renewed %d times in half a second, want several passes", zd.ZoneName, renews.get(zd.ZoneName))
		}
		if replaces.get(zd.ZoneName) < 1 {
			t.Errorf("%s was never replaced for its key-state requests", zd.ZoneName)
		}
	}
}

// TestShutdownWaitsForTheZonesInFlightAndStartsNoOther: more zones than workers,
// every one of the workers inside a zone, and the context is cancelled. A worker
// cannot be interrupted -- zd.mu is a plain mutex -- so the engine does not
// return until each has left its zone; but nothing starts after the context is
// done, and the zones still queued are dropped.
func TestShutdownWaitsForTheZonesInFlightAndStartsNoOther(t *testing.T) {
	freshZones(t)
	for i := 0; i < resignWorkers+2; i++ {
		engineZone(t, fmt.Sprintf("stop%02d.example.", i))
	}

	g := newGate(64)
	var started atomic.Int32
	r := startResigner(t, engineFloors[0], resignWork{renew: func(ctx context.Context, zd *ZoneData) {
		started.Add(1)
		g.work(ctx, zd)
	}})
	defer g.open()
	g.waitFor(t, resignWorkers)

	r.cancel()
	select {
	case <-r.done:
		t.Fatal("the engine returned while its workers were still inside a zone")
	case <-time.After(settle):
	}
	if n := started.Load(); n != resignWorkers {
		t.Errorf("%d zones started before the stop, want %d", n, resignWorkers)
	}

	g.open()
	select {
	case <-r.done:
	case <-time.After(poolWait):
		t.Fatal("the engine did not return after its workers were released")
	}
	if n := started.Load(); n != resignWorkers {
		t.Errorf("%d zones were started in all, want %d: a worker took a zone after the stop", n, resignWorkers)
	}
}

// TestAZoneInFlightDoesNotSpinTheEngine: a zone held by a long refresh has no
// renewal estimate. Counted in the wake it would pull every wake down to the
// floor -- the engine ticking, and walking every other zone, for work that a
// worker already has. The other zone here is not due for a month, and must be
// walked about once, not once per floor.
func TestAZoneInFlightDoesNotSpinTheEngine(t *testing.T) {
	freshZones(t)
	held := watchedTestZone(t, "held.example.")
	held.KeepRenewed()
	idle := watchedTestZone(t, "idle.example.")
	idle.KeepRenewed()
	held.mu.Lock()
	var unlockOnce sync.Once
	unlock := func() { unlockOnce.Do(held.mu.Unlock) }
	defer unlock()

	var calls zoneCount
	work := liveResignWork()
	work.renew = func(ctx context.Context, zd *ZoneData) {
		if zd == idle {
			calls.add(zd.ZoneName)
		}
		if zd == idle || zd == held {
			resignSweepZone(ctx, zd)
		}
	}
	floor := engineFloors[0]
	startResigner(t, floor, work)

	if !calls.waitAll([]*ZoneData{idle}, 1) {
		t.Fatal("the idle zone was never renewed")
	}
	time.Sleep(40 * floor)
	if n := calls.get(idle.ZoneName); n > 2 {
		t.Errorf("a zone not due for a month was walked %d times in %s while another zone was held:"+
			" the zone in flight is pulling the engine's wake down to the floor", n, 40*floor)
	}
}

// TestAZoneThatEndsOwingWorkIsNotSleptThrough is the other side of leaving a zone
// in flight out of the wake. The wake worked out while it ran did not count it,
// so it can be an hour; when the zone's work ends the engine has to bring the
// wake forward for whatever the zone is owed, here a replace whose request was
// dropped while it was being renewed.
func TestAZoneThatEndsOwingWorkIsNotSleptThrough(t *testing.T) {
	freshZones(t)
	zd := engineZone(t, "owed.example.")

	g := newGate(8)
	var calls atomic.Int32
	startResigner(t, engineFloors[0], resignWork{renew: func(ctx context.Context, z *ZoneData) {
		if calls.Add(1) == 1 {
			g.work(ctx, z)
		}
	}})
	defer g.open()
	g.waitFor(t, 1)

	time.Sleep(10 * engineFloors[0]) // ticks that find the zone in flight, and leave it out
	zd.markResignPending()
	g.open()

	deadline := time.Now().Add(poolWait)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Errorf("the zone ended owing a replace and the engine did not look at it again in %s", poolWait)
	}
}
