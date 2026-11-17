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

// TestSlowZonesDoNotHoldUpTheRestOfThePass is #1034. The sweep renewed zones one
// after another, so one zone that is slow -- large, or behind a long refresh
// holding its zd.mu -- delayed every zone after it in the pass. Which zones
// those were was down to map order.
//
// Here resignWorkers-1 zones have their lock held for the whole test, so the
// workers that reach them wait; thirty others must be renewed regardless, while
// the locks are still held. The pass itself has to wait for the held zones, and
// finish them once they are free: a pass is over when every zone has been seen.
func TestSlowZonesDoNotHoldUpTheRestOfThePass(t *testing.T) {
	const free = 30

	zones := make(map[string]*ZoneData)
	var held, rest []*ZoneData
	for i := 0; i < resignWorkers-1; i++ {
		zd := watchedTestZone(t, fmt.Sprintf("held%02d.example.", i))
		zd.KeepRenewed()
		zones[zd.ZoneName] = zd
		held = append(held, zd)
	}
	for i := 0; i < free; i++ {
		zd := watchedTestZone(t, fmt.Sprintf("free%02d.example.", i))
		zd.KeepRenewed()
		zones[zd.ZoneName] = zd
		rest = append(rest, zd)
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

	passDone := make(chan struct{})
	go func() {
		defer close(passDone)
		resignPass(context.Background(), zones)
	}()
	// However the test ends, the locks go and the pass is waited for, so nothing
	// outlives it to touch zones the cleanups are about to remove.
	defer func() {
		unlock()
		<-passDone
	}()

	allRenewed := func() bool {
		for _, zd := range rest {
			if !renewed(zd) {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(poolWait)
	for !allRenewed() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !allRenewed() {
		n := 0
		for _, zd := range rest {
			if renewed(zd) {
				n++
			}
		}
		t.Errorf("%d zones' locks were held and only %d of %d other zones were renewed within %s:"+
			" a slow zone is holding up the rest of the pass", len(held), n, free, poolWait)
	}

	select {
	case <-passDone:
		t.Error("the pass returned while the held zones were still locked; it must wait for every zone")
	default:
	}

	unlock()
	select {
	case <-passDone:
	case <-time.After(poolWait):
		t.Fatal("the pass did not finish after the held zones were released")
	}
	for _, zd := range held {
		if !renewed(zd) {
			t.Errorf("%s was held during the pass and never renewed after it was released", zd.ZoneName)
		}
	}
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

// TestEachZoneIsSweptByExactlyOneWorker: what keeps two workers off the same
// zone. Every zone is handed over once, to one worker, and the pass returns
// only after all of them -- so the resigner's key-state replace, which runs in
// the engine goroutine between passes, can never overlap a renewal.
//
// The barrier makes the first resignWorkers calls wait for each other, which
// proves they ran at the same time and that the pool did not quietly degrade
// to one.
func TestEachZoneIsSweptByExactlyOneWorker(t *testing.T) {
	const n = 200
	zones := bareZones(n)

	var mu sync.Mutex
	inFlight := make(map[string]bool)
	calls := make(map[string]int)
	var active, maxActive int
	arrived := make(chan struct{}, resignWorkers)
	barrier := make(chan struct{})
	var barrierOnce sync.Once
	var first atomic.Int32
	sweep := func(_ context.Context, zd *ZoneData) {
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

		if first.Add(1) <= resignWorkers {
			arrived <- struct{}{}
			select {
			case <-barrier:
			case <-time.After(poolWait):
				t.Errorf("the first %d calls did not run together: the pool is not concurrent", resignWorkers)
			}
		} else {
			time.Sleep(50 * time.Microsecond)
		}

		mu.Lock()
		inFlight[zd.ZoneName] = false
		active--
		mu.Unlock()
	}

	passDone := make(chan struct{})
	go func() {
		defer close(passDone)
		sweepZones(context.Background(), zones, resignWorkers, sweep)
	}()
	for i := 0; i < resignWorkers; i++ {
		select {
		case <-arrived:
		case <-time.After(poolWait):
			barrierOnce.Do(func() { close(barrier) })
			<-passDone
			t.Fatalf("only %d of %d workers started", i, resignWorkers)
		}
	}
	barrierOnce.Do(func() { close(barrier) })
	select {
	case <-passDone:
	case <-time.After(poolWait):
		t.Fatal("the pass did not finish")
	}

	if len(calls) != n {
		t.Errorf("%d of %d zones were swept", len(calls), n)
	}
	for name, c := range calls {
		if c != 1 {
			t.Errorf("%s was swept %d times in one pass", name, c)
		}
	}
	if maxActive != resignWorkers {
		t.Errorf("at most %d zones were swept at once, want exactly the pool width %d", maxActive, resignWorkers)
	}
}

// TestACancelledPassStartsNoNewZoneAndWaitsForItsWorkers: shutdown. A zone's
// lock is a plain mutex, so a worker inside a zone cannot be interrupted, and
// the pass says so by waiting for it: the engine goroutine is what shutdown
// waits on, and a worker left behind would run on past it. What cancellation
// does reach is the next zone: no worker starts one after it.
func TestACancelledPassStartsNoNewZoneAndWaitsForItsWorkers(t *testing.T) {
	const width = 2
	zones := bareZones(10)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var swept atomic.Int32
	started := make(chan struct{}, len(zones))
	release := make(chan struct{})
	sweep := func(_ context.Context, _ *ZoneData) {
		swept.Add(1)
		started <- struct{}{}
		<-release
	}

	passDone := make(chan struct{})
	go func() {
		defer close(passDone)
		sweepZones(ctx, zones, width, sweep)
	}()
	for i := 0; i < width; i++ {
		select {
		case <-started:
		case <-time.After(poolWait):
			close(release)
			<-passDone
			t.Fatalf("only %d of %d workers started", i, width)
		}
	}

	cancel()
	select {
	case <-passDone:
		t.Fatal("the pass returned while its workers were still inside a zone;" +
			" shutdown would not wait for them")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-passDone:
	case <-time.After(poolWait):
		t.Fatal("the pass did not return after its workers were released")
	}
	if got := swept.Load(); got != width {
		t.Errorf("%d zones were swept, want %d: a worker started a zone after the context was cancelled", got, width)
	}
}

// A pass over nothing, or with a nonsensical width, still terminates.
func TestAPassOverNoZonesAndANarrowPoolStillTerminate(t *testing.T) {
	var swept atomic.Int32
	sweep := func(context.Context, *ZoneData) { swept.Add(1) }

	sweepZones(context.Background(), nil, resignWorkers, sweep)
	if swept.Load() != 0 {
		t.Error("an empty pass swept a zone")
	}

	sweepZones(context.Background(), bareZones(5), 0, sweep)
	if got := swept.Load(); got != 5 {
		t.Errorf("a pool of width 0 swept %d of 5 zones; it must fall back to one worker", got)
	}

	swept.Store(0)
	sweepZones(context.Background(), bareZones(2), 50, sweep)
	if got := swept.Load(); got != 2 {
		t.Errorf("a pool wider than the zone list swept %d of 2 zones", got)
	}
}
