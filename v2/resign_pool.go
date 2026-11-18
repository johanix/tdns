/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"sync"

	"github.com/johanix/tdns/v2/core"
)

// resignWorkers is how many zones the resigner works on at the same time.
//
// More than one, so that a zone that is slow -- large, signed with an expensive
// algorithm, or waiting on a zd.mu that a long refresh holds -- costs the
// resigner one worker and not every zone behind it (#1034). Few, because what
// the workers share is serial: the keystore is one SQLite handle behind kdb.mu,
// so a wider pool only queues there, and a mint or a promotion under it stalls
// every worker, the KeyStateWorker and the API alike. Three is inside the 2-4
// the issue asks for.
//
// A constant and not a setting: nothing an operator can usefully tune.
//
// THE LIMIT. The pool tolerates resignWorkers-1 slow zones: with that many in
// flight one worker is left, and every other zone is still renewed on the
// engine's cadence, one after another. With resignWorkers slow zones in flight
// at once the pool is exhausted and no other zone is renewed until one of them
// finishes -- the engine keeps ticking and the zones wait in the queue, in
// order. Raising the constant raises the limit and the queue on kdb.mu with it.
const resignWorkers = 3

// resignJobs is what a worker may be asked to do for a zone, as flags: a zone
// has at most one job, and a second request for it adds to the first.
const (
	// resignJobRenew is the periodic job: resignSweepZone, which replaces the
	// zone's signatures first if a replace is owed, and then renews.
	resignJobRenew = 1 << iota
	// resignJobReplace is a key-state request: replaceSignaturesNow.
	resignJobReplace
)

// resignWork is what the workers do for a zone. Functions, so a test can stand
// in for the signing without a signed zone behind every one.
type resignWork struct {
	renew   func(context.Context, *ZoneData)
	replace func(context.Context, *ZoneData)
}

// liveResignWork is the resigner's own work.
func liveResignWork() resignWork {
	return resignWork{
		renew:   resignSweepZone,
		replace: func(ctx context.Context, zd *ZoneData) { zd.replaceSignaturesNow(ctx) },
	}
}

// resignJob is one zone's place in the pool: from the moment it is queued until
// its worker is done with it, and for exactly that long.
type resignJob struct {
	zd      *ZoneData
	todo    int  // resignJob* flags not yet run
	running bool // a worker has taken it
}

// resignPool is the resigner's workers, and the set of zones they own.
//
// ONE ZONE, ONE WORKER, ACROSS PASSES. flight holds every zone that is queued or
// running, by name, so a zone is in it once -- whoever asks for it, whenever, in
// whichever pass. Everything the resigner does to a zone's signatures, a renewal
// and a key-state replace alike, is a job here, and a job runs on one worker
// from start to end. So a replace and a renewal of one zone never overlap, and
// they cannot be reordered either: both RenewZoneSignatures and ResignZone
// resolve the zone's keys BEFORE they take zd.mu, so a renewal that overlapped
// a replace could sign with keys the replace has just retired, after it. A
// request for a zone that is running is deferred to the end of its run, on the
// same worker (see submit).
//
// The pool starts a worker when there is a job and fewer than width of them,
// and a worker leaves when the queue is empty, so nothing idles. The queue is
// first in, first out, and holds each zone once, so it is never longer than the
// number of zones.
//
// submit and wait are for ONE caller, the engine goroutine; the rest is
// goroutine-safe.
type resignPool struct {
	width int
	work  resignWork
	// ended is poked, without blocking, when a worker has finished a zone: the
	// engine then reads what ended (takeEnded) and works out when to wake for it.
	ended chan struct{}

	mu       sync.Mutex
	flight   map[string]*resignJob // zones queued or running, by resignKey
	queue    []*resignJob          // queued, first in front
	workers  int                   // running worker goroutines
	finished map[string]*ZoneData  // zones finished since takeEnded
	wg       sync.WaitGroup
}

func newResignPool(width int, work resignWork) *resignPool {
	if width < 1 {
		width = 1
	}
	return &resignPool{
		width:    width,
		work:     work,
		ended:    make(chan struct{}, 1),
		flight:   make(map[string]*resignJob),
		finished: make(map[string]*ZoneData),
	}
}

// resignKey is the name a zone is in flight under. Folded, as every map key made
// from a zone name is, so that a request that spells a zone another way is
// still the same zone.
func resignKey(zd *ZoneData) string {
	return core.CanonicalizeName(zd.ZoneName)
}

// submit asks for the job want on zd and never blocks. It reports whether the
// zone was taken on as new work: false means it is already in flight, and
// nothing more was started for it.
//
// A zone already QUEUED just gets the job added to its entry; it runs when its
// turn comes, and then reads whatever is current, which covers every request
// made until then. The entry is by name: if the request carries another
// ZoneData of that name -- the zone was replaced -- the entry is retargeted to
// it, running or not.
//
// A zone already RUNNING is not handed to a second worker. A renewal request is
// dropped: the run in flight is a renewal, which looks at the zone as it is
// now, or a replace, after which the zone has changed under its estimate; and
// either way the engine is told when the zone's work ends (takeEnded) and works
// out its wake from what the work has just recorded, so the request is not lost,
// only not started twice. A replace request is NOT dropped: it is for a
// key-state change the run in flight may not have seen -- the run may have
// resolved its keys before the change -- so the job is added to the zone's
// entry, and the same worker runs it when it has finished its current one. A
// renewal that began before a key-state change can therefore never sign after
// the replace that followed it.
//
// Nothing is taken once ctx is done.
func (p *resignPool) submit(ctx context.Context, zd *ZoneData, want int) bool {
	if zd == nil || want == 0 || ctx.Err() != nil {
		return false
	}
	key := resignKey(zd)

	p.mu.Lock()
	defer p.mu.Unlock()
	if j := p.flight[key]; j != nil {
		switch {
		case !j.running:
			j.todo |= want
		case want&resignJobReplace != 0:
			j.todo |= resignJobReplace
		}
		if j.zd != zd {
			// Another ZoneData of the same name: the zone was replaced while
			// it was in flight (ModifyDynamicZone). What is asked for is for
			// the live copy, and nothing has been done to that yet, so the
			// entry now belongs to it and the work is done on it after the
			// work in hand.
			j.zd = zd
			j.todo |= want
		}
		return false
	}
	j := &resignJob{zd: zd, todo: want}
	p.flight[key] = j
	p.queue = append(p.queue, j)
	if p.workers < p.width {
		p.workers++
		p.wg.Add(1)
		go p.worker(ctx)
	}
	return true
}

// worker runs jobs until the queue is empty or ctx is done. It is handed ctx,
// and takes no zone once it is done.
func (p *resignPool) worker(ctx context.Context) {
	defer p.wg.Done()
	for {
		j := p.take(ctx)
		if j == nil {
			return
		}
		p.run(ctx, j)
	}
}

// take hands the worker the next queued zone, and marks it running; or, when
// there is none or ctx is done, says the worker is leaving.
func (p *resignPool) take(ctx context.Context) *resignJob {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil || len(p.queue) == 0 {
		p.workers--
		return nil
	}
	j := p.queue[0]
	p.queue[0] = nil
	p.queue = p.queue[1:]
	j.running = true
	return j
}

// run does a zone's jobs and then lets it go. A replace goes before a renewal.
// Anything asked for while it ran -- only ever a replace, see submit -- is done
// before the zone is released, so the zone is never between workers.
//
// The work cannot be interrupted: a worker inside a zone is inside zd.mu, a
// plain mutex. ctx is checked between jobs, and by the zone's own work on entry.
func (p *resignPool) run(ctx context.Context, j *resignJob) {
	for {
		p.mu.Lock()
		zd, todo := j.zd, j.todo
		j.todo = 0
		p.mu.Unlock()

		if todo&resignJobReplace != 0 && ctx.Err() == nil {
			p.work.replace(ctx, zd)
		}
		if todo&resignJobRenew != 0 && ctx.Err() == nil {
			p.work.renew(ctx, zd)
		}

		p.mu.Lock()
		if j.todo != 0 && ctx.Err() == nil {
			p.mu.Unlock()
			continue
		}
		key := resignKey(j.zd)
		delete(p.flight, key)
		p.finished[key] = j.zd
		p.mu.Unlock()

		select {
		case p.ended <- struct{}{}:
		default:
		}
		return
	}
}

// takeEnded returns the zones whose work has finished since it was last called,
// and forgets them.
func (p *resignPool) takeEnded() map[string]*ZoneData {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.finished
	p.finished = make(map[string]*ZoneData)
	return out
}

// notInFlight is zones without those the pool holds, queued or running. What
// the engine works out its wake from: a zone in flight has no due time worth
// sleeping on until it ends, and one it is owed anyway.
func (p *resignPool) notInFlight(zones map[string]*ZoneData) map[string]*ZoneData {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]*ZoneData, len(zones))
	for name, zd := range zones {
		if zd != nil {
			if _, busy := p.flight[resignKey(zd)]; busy {
				continue
			}
		}
		out[name] = zd
	}
	return out
}

// inFlight is how many zones are queued or running.
func (p *resignPool) inFlight() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.flight)
}

// wait returns when every worker has. With ctx done that is when each has
// finished the zone it is inside; with it not done, when the queue has been
// worked off.
func (p *resignPool) wait() {
	p.wg.Wait()
}
