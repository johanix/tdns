/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"sync"

	"github.com/spf13/viper"
)

// Defaults for the two pool dimensions, applied when service.refreshworkers /
// service.transferconcurrency are unset.
//
// They are far apart because they bound different resources. A worker parked on
// an unreachable primary costs a goroutine and a socket, so width is cheap and
// exists to ABSORB stuck refreshes -- in the healthy steady state one worker
// does everything (N x RTT / interval is well under 1 even at 100k zones). A
// transfer costs bandwidth, parse CPU, and roughly twice the zone in memory
// while it runs, so that one is deliberately narrow.
const (
	defaultRefreshWorkers      = 64
	defaultTransferConcurrency = 10
)

// transferGate caps concurrent inbound zone transfers.
//
// Owned by the pool and threaded down to the transfer itself, which is the only
// span worth capping: the SOA probe is one query, the transfer is the expensive
// part. Acquiring it higher up -- around Refresh, or in the worker -- would hold
// a transfer slot for the whole probe, because Refresh does probe and transfer
// in one call. That would cap PROBE concurrency at the transfer limit and make
// the gate a worse bottleneck than the one it replaces.
//
// A nil gate is ungated, which is what tests and the first-load path get. First
// load runs one zone at a time on the engine goroutine, so it cannot produce the
// concurrency the gate exists to bound -- and gating it there would block the
// engine on a full semaphore, which is the one thing the whole design forbids.
// Peak concurrent transfers is therefore transferconcurrency + 1 while a first
// load overlaps the pool: one zone, ending when first load does.
type transferGate struct {
	tokens chan struct{}
}

func newTransferGate(n int) *transferGate {
	if n <= 0 {
		return nil
	}
	return &transferGate{tokens: make(chan struct{}, n)}
}

// acquire blocks until a token is free or ctx ends.
//
// It returns ctx.Err() in the latter case, deliberately: on shutdown that is
// context.Canceled, which noteRefreshFailure already recognises as a dying
// process rather than a sick zone. A bespoke error here would flag every zone
// waiting on the gate at shutdown as failed.
func (g *transferGate) acquire(ctx context.Context) error {
	if g == nil {
		return nil
	}
	select {
	case g.tokens <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *transferGate) release() {
	if g == nil {
		return
	}
	<-g.tokens
}

// refreshOutcome is what a worker reports back to the engine goroutine.
type refreshOutcome struct {
	Zone    string
	Updated bool
	Err     error
}

// refreshPool runs zone refreshes away from the engine goroutine, bounded.
//
// The engine dispatches and reads outcomes; it never blocks on either. That is
// the whole point: one unreachable primary must not stop the engine reading its
// other channels, which is what #502 was.
type refreshPool struct {
	jobs chan refreshJob
	done chan refreshOutcome
	gate *transferGate
	wg   sync.WaitGroup
}

func newRefreshPool(ctx context.Context, width, queue, transfers int, conf *Config) *refreshPool {
	if width <= 0 {
		width = 1
	}
	if queue <= 0 {
		queue = 4 * width
	}
	p := &refreshPool{
		jobs: make(chan refreshJob, queue),
		// Buffered to width so every worker can hand back an outcome without
		// waiting for the engine to be looking. See Shutdown for the other half.
		done: make(chan refreshOutcome, width),
		gate: newTransferGate(transfers),
	}
	for i := 0; i < width; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for job := range p.jobs {
				job.gate = p.gate
				updated, err := runZoneRefresh(ctx, job, conf)
				select {
				case p.done <- refreshOutcome{Zone: job.zone, Updated: updated, Err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	lgEngine.Info("refresh pool started", "workers", width, "queue", queue, "transfers", transfers)
	return p
}

// TryDispatch hands a job to the pool without blocking, and reports whether it
// was accepted. False means the pool is saturated: the caller leaves the zone
// due so the next tick retries it.
func (p *refreshPool) TryDispatch(job refreshJob) bool {
	select {
	case p.jobs <- job:
		return true
	default:
		return false
	}
}

func (p *refreshPool) Done() <-chan refreshOutcome { return p.done }

// Shutdown stops the workers and waits for them, letting each finish the job it
// already holds.
//
// It drains outcomes while it waits, and that is not tidiness -- without it this
// deadlocks. Closing jobs ends each worker's range, but a worker that has just
// finished a refresh still has an outcome to hand back, and by then the engine
// has stopped reading them. The buffer absorbs `width` of those and no more; the
// ctx-guarded send only helps if the context was cancelled, which is true of one
// of the engine's three exits and not of the other two (zonerefch or bumpch
// closing). So on those exits every worker past the buffer would block forever
// on a hand-off nobody wants, and Wait would never return: the daemon hangs on
// shutdown rather than exiting.
func (p *refreshPool) Shutdown() {
	close(p.jobs)

	drained := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(drained)
	}()
	for {
		select {
		case <-p.done: // discard: nobody is scheduling any more
		case <-drained:
			return
		}
	}
}

// refreshWorkers and transferConcurrency are read ONCE, at engine start.
// Resizing a live pool would be complexity for no benefit: the width absorbs
// stuck refreshes, and how many zones are stuck is not something an operator
// changes their mind about mid-run.
func refreshWorkers() int {
	if cfg := viper.GetInt("service.refreshworkers"); cfg > 0 {
		return cfg
	}
	return defaultRefreshWorkers
}

func transferConcurrency() int {
	if cfg := viper.GetInt("service.transferconcurrency"); cfg > 0 {
		return cfg
	}
	return defaultTransferConcurrency
}

// dispatchRefresh hands a zone to the pool, or answers the operator if it
// cannot.
//
// Runs on the engine goroutine, which is what makes inflight correct with no
// synchronisation at all: dispatch and completion are the same goroutine, so the
// map is never read and written concurrently. Two concurrent refreshes of one
// zone would not merely duplicate work -- ZoneTransferIn replaces zd.Data
// wholesale, and the FetchFrom* paths do a read-modify-write on FirstZoneLoad.
//
// The entry is set only AFTER a successful dispatch. Marking the zone in flight
// and then attempting the send would pin it forever whenever the queue is full:
// nothing was dispatched, so no outcome ever arrives to clear the entry, and the
// zone is never refreshed again for the life of the process.
//
// A skipped zone that has somebody waiting is ANSWERED. Silently skipping a
// Wait-ing refresher hangs `tdns-cli zone reload`, and the operator's next move
// is a restart.
func dispatchRefresh(pool *refreshPool, inflight map[string]struct{}, job refreshJob) {
	if _, busy := inflight[job.zone]; busy {
		lgEngine.Debug("refresh already in progress, not dispatching again", "zone", job.zone)
		respondToRefresher(job.zr, RefresherResponse{
			Error:    true,
			ErrorMsg: "refresh already in progress for zone " + job.zone,
		})
		return
	}
	if !pool.TryDispatch(job) {
		lgEngine.Warn("refresh pool saturated, leaving the zone due", "zone", job.zone)
		respondToRefresher(job.zr, RefresherResponse{
			Error:    true,
			ErrorMsg: "refresh pool saturated; zone " + job.zone + " will retry on its next tick",
		})
		return
	}
	inflight[job.zone] = struct{}{}
}
