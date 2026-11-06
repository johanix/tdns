/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// DelegationSyncHandler runs one delegation-sync request to its end: the body
// of a delegation syncher. tdns's is KeyDB.handleDelegationSyncRequest; an
// application with its own syncher hands RunDelegationSyncLanes its own.
type DelegationSyncHandler func(ctx context.Context, ds DelegationSyncRequest)

// delegationSyncLaneWarnAt is the length of one parent's queue at which a
// warning is logged, and again at each doubling. It is not a bound: nothing is
// dropped. A variable only so a test need not queue a hundred requests.
var delegationSyncLaneWarnAt = 100

// activeDelegationSyncLanes is the running syncher's lanes, for
// DelegationSyncWaiting. A process has one delegation-sync queue, and so one.
var activeDelegationSyncLanes atomic.Pointer[delegationSyncLanes]

// RunDelegationSyncLanes reads delegation-sync requests from intake and runs
// each with handle, on a queue of its own per parent (#1002).
//
// The syncher used to be one loop reading intake. A sync whose parent did not
// answer held that loop while its UPDATE waited out the retries -- 75 s of
// backoff alone per request -- and every other zone waited behind it, whatever
// its parent. With many zones intake stayed full: senders that do not wait saw
// "queue full", and the ZoneUpdater, whose send waits, stopped serving updates
// for every zone.
//
// Now intake is drained at once into a FIFO per parent, each served by its own
// goroutine, so a parent that does not answer holds only its own zones'
// requests. What does not change:
//
//   - A parent's requests run one at a time, in the order they arrived. A
//     zone's requests all go to one queue and their handlers never run at the
//     same time: the zone stays in the queue it was put in while it has
//     requests waiting or running there, even if its parent changes
//     meanwhile. A handler that starts work of its own and returns, as
//     SYNC-DS starts its delivery, is done as far as the queue is concerned,
//     as it was for the single loop.
//   - Nothing gets a timeout it did not have. A handler runs to its own end,
//     and its failure path, retries and backoff are what they were. A delayed
//     re-enqueue (deferForImr, requeueSetupAfter, deferUntilHoldEnds) sends to
//     intake as before, with its counts, and comes back through here.
//   - intake is the same channel, so no sender changes. It just rarely fills.
//
// The parent is the zone's cached parent (GetParent). While that is not known
// yet, the zone's name less its first label stands in. The stand-in is only a
// grouping: a wrong guess puts the zone in a queue of its own, or beside
// unrelated zones, and never splits its requests.
//
// It returns when ctx ends, once the running handlers have returned (requests
// still waiting are dropped, as the single loop left its channel), or when
// intake is closed, once every request read from it has run.
func RunDelegationSyncLanes(ctx context.Context, intake chan DelegationSyncRequest, handle DelegationSyncHandler) error {
	l := newDelegationSyncLanes(handle)
	activeDelegationSyncLanes.Store(l)
	defer activeDelegationSyncLanes.CompareAndSwap(l, nil)
	defer l.wg.Wait()
	for {
		select {
		case <-ctx.Done():
			lgDns.Info("DelegationSyncher: terminating due to context cancelled")
			return nil
		case ds, ok := <-intake:
			if !ok {
				lgDns.Info("DelegationSyncher: delsyncq closed, terminating once the queued requests have run")
				return nil
			}
			l.dispatch(ctx, ds)
		}
	}
}

// delegationSyncLanes is the per-parent queues of one syncher.
type delegationSyncLanes struct {
	handle DelegationSyncHandler
	wg     sync.WaitGroup // the lanes' goroutines

	mu    sync.Mutex
	lanes map[string]*delegationSyncLane // by parent
	zones map[string]*delegationSyncPin  // by zone, while it has requests in a lane
}

// delegationSyncLane is one parent's queue. It lives while it has requests,
// and is served by one goroutine at a time.
type delegationSyncLane struct {
	parent   string
	queue    []delegationSyncItem
	current  *delegationSyncItem // the request running now; nil between requests
	running  bool                // a goroutine serves the lane
	warnedAt int                 // the length last warned about; 0 since it was last empty
}

type delegationSyncItem struct {
	zone string
	ds   DelegationSyncRequest
}

// delegationSyncPin holds a zone to the lane its requests are in.
type delegationSyncPin struct {
	lane  *delegationSyncLane
	count int // the zone's requests in the lane, waiting or running
}

func newDelegationSyncLanes(handle DelegationSyncHandler) *delegationSyncLanes {
	return &delegationSyncLanes{
		handle: handle,
		lanes:  map[string]*delegationSyncLane{},
		zones:  map[string]*delegationSyncPin{},
	}
}

// dispatch puts ds at the back of its zone's lane, and starts the lane's
// goroutine if none serves it. It never waits on a handler.
func (l *delegationSyncLanes) dispatch(ctx context.Context, ds DelegationSyncRequest) {
	zone := delegationSyncZoneKey(ds)

	l.mu.Lock()
	pin := l.zones[zone]
	if pin == nil {
		parent := delegationSyncLaneKey(ds)
		ln := l.lanes[parent]
		if ln == nil {
			ln = &delegationSyncLane{parent: parent}
			l.lanes[parent] = ln
		}
		pin = &delegationSyncPin{lane: ln}
		l.zones[zone] = pin
	}
	pin.count++
	ln := pin.lane
	ln.queue = append(ln.queue, delegationSyncItem{zone: zone, ds: ds})
	waiting := len(ln.queue)
	warn := delegationSyncLaneWarns(waiting, ln.warnedAt)
	if warn {
		ln.warnedAt = waiting
	}
	start := !ln.running
	ln.running = true
	if start {
		l.wg.Add(1)
	}
	l.mu.Unlock()

	if warn {
		lgDns.Warn("DelegationSyncher: many delegation syncs wait for one parent; it may be slow or not answering",
			"parent", ln.parent, "waiting", waiting, "zone", ds.ZoneName, "command", ds.Command)
	}
	if start {
		go l.runLane(ctx, ln)
	}
}

// runLane serves ln until it is empty or ctx ends, one request at a time.
func (l *delegationSyncLanes) runLane(ctx context.Context, ln *delegationSyncLane) {
	defer l.wg.Done()
	for {
		l.mu.Lock()
		if len(ln.queue) == 0 || ctx.Err() != nil {
			ln.running = false
			if len(ln.queue) == 0 {
				delete(l.lanes, ln.parent)
			}
			l.mu.Unlock()
			return
		}
		it := ln.queue[0]
		ln.queue[0] = delegationSyncItem{}
		ln.queue = ln.queue[1:]
		if len(ln.queue) == 0 {
			ln.queue, ln.warnedAt = nil, 0
		}
		ln.current = &it
		l.mu.Unlock()

		l.handle(ctx, it.ds)

		l.mu.Lock()
		ln.current = nil
		if pin := l.zones[it.zone]; pin != nil {
			if pin.count--; pin.count == 0 {
				delete(l.zones, it.zone)
			}
		}
		l.mu.Unlock()
	}
}

// delegationSyncLaneWarns reports whether a lane that has grown to n waiting
// requests is to be warned about, given the length it was last warned about:
// at delegationSyncLaneWarnAt, and at each doubling after it.
func delegationSyncLaneWarns(n, warnedAt int) bool {
	if n < delegationSyncLaneWarnAt {
		return false
	}
	return warnedAt == 0 || n >= 2*warnedAt
}

// delegationSyncZoneKey is the zone a request is for, as the lanes key it.
func delegationSyncZoneKey(ds DelegationSyncRequest) string {
	zone := ds.ZoneName
	if zone == "" && ds.ZoneData != nil {
		zone = ds.ZoneData.ZoneName
	}
	return core.CanonicalizeName(dns.Fqdn(zone))
}

// delegationSyncLaneKey is the parent whose lane a request goes to: the
// zone's cached parent, or, while that is not known, the zone's name less its
// first label. "." is the old sentinel for "not looked up" (ResolveParentVia),
// so it does not count as known.
func delegationSyncLaneKey(ds DelegationSyncRequest) string {
	if ds.ZoneData != nil {
		if p := ds.ZoneData.GetParent(); p != "" && p != "." {
			return core.CanonicalizeName(dns.Fqdn(p))
		}
	}
	zone := delegationSyncZoneKey(ds)
	if off, end := dns.NextLabel(zone, 0); !end {
		return zone[off:]
	}
	return "."
}

// DelegationSyncPosition is where a zone's delegation-sync requests stand in
// their parent's queue.
type DelegationSyncPosition struct {
	Parent  string // the queue's parent: the zone's parent, or the stand-in while that is not known
	Ahead   int    // requests for other zones before the zone's first, the running one included
	Running bool   // one of the zone's requests is running now
	Waiting int    // the zone's requests in the queue, a running one included
}

// DelegationSyncWaiting reports where zone's delegation-sync requests stand in
// their parent's queue. It is false when the zone has none waiting or running,
// or when no syncher runs on per-parent queues.
func DelegationSyncWaiting(zone string) (DelegationSyncPosition, bool) {
	l := activeDelegationSyncLanes.Load()
	if l == nil {
		return DelegationSyncPosition{}, false
	}
	return l.waiting(zone)
}

// delegationSyncQueueNote says where zone's requests stand, for a message
// about an answer from the syncher that did not come: behind a parent that
// does not answer, they wait in that parent's queue. It speaks of the zone's
// syncs, not of the request that waited for the answer: the one running may
// be another of the zone's. "" when the zone has nothing queued.
func delegationSyncQueueNote(zone string) string {
	pos, ok := DelegationSyncWaiting(zone)
	switch {
	case !ok:
		return ""
	case pos.Running:
		return fmt.Sprintf(" (a delegation sync of the zone is running, in the queue for parent %s; %d of its syncs in the queue)",
			pos.Parent, pos.Waiting)
	default:
		return fmt.Sprintf(" (the zone's delegation syncs wait in the queue for parent %s, %d ahead)", pos.Parent, pos.Ahead)
	}
}

func (l *delegationSyncLanes) waiting(zone string) (DelegationSyncPosition, bool) {
	zone = core.CanonicalizeName(dns.Fqdn(zone))
	l.mu.Lock()
	defer l.mu.Unlock()
	pin := l.zones[zone]
	if pin == nil {
		return DelegationSyncPosition{}, false
	}
	ln := pin.lane
	pos := DelegationSyncPosition{Parent: ln.parent, Waiting: pin.count}
	if ln.current != nil {
		if ln.current.zone == zone {
			pos.Running = true
			return pos, true
		}
		pos.Ahead++
	}
	for _, it := range ln.queue {
		if it.zone == zone {
			break
		}
		pos.Ahead++
	}
	return pos, true
}
