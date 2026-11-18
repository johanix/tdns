/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"time"

	"github.com/spf13/viper"
)

// ResignReason says WHY a zone was handed to the resigner.
//
// The queue used to carry a bare *ZoneData, so "this zone's data changed" and
// "this zone's key state changed" arrived indistinguishable -- and the resigner
// applied a FORCED re-sign to both. Forced is right for exactly one of them, and
// wrong as a steady-state tool: it re-signs RRsets whose signatures are valid,
// which after a refresh means re-signing everything the refresh just signed.
type ResignReason uint8

const (
	// ResignKeyStateChanged: a key became active, inactive or retired, or was
	// removed. The served RRSIG set has to match the new active set now, and
	// that means REPLACING signatures rather than adding to them.
	ResignKeyStateChanged ResignReason = iota + 1
)

func (r ResignReason) String() string {
	switch r {
	case ResignKeyStateChanged:
		return "key-state-changed"
	}
	return "unknown"
}

// ResignRequest is what the ResignQ carries. Changing the channel's element type
// rather than adding a parallel channel is deliberate: every producer becomes a
// compile error until it says what it means, so none can be missed.
type ResignRequest struct {
	Zd     *ZoneData
	Reason ResignReason
}

// resignSafetyTick bounds how long the resigner will sleep on its own estimate.
// See nextResignWake.
const resignSafetyTick = time.Hour

// resignWake tells the resigner that a zone has joined the watchlist. One slot,
// sent to without blocking: a full slot means a wake is already owed, and the
// engine reads the watchlist itself when it wakes.
var resignWake = make(chan struct{}, 1)

// KeepRenewed puts the zone on the resigner's renewal watchlist, so its
// signatures are renewed before they age out. It cannot fail and does not wait.
//
// Registration used to be a send on the ResignQ, bounded at two seconds. The
// resigner is one goroutine, and while it replaced a zone's signatures or swept
// the watchlist nothing read the queue -- so a registration that arrived then
// timed out, the zone was never renewed, and its signatures expired. The
// watchlist is now this flag, and the resigner's pass reads it (#1033).
//
// No checks: the caller has decided the zone signs here. registerForPeriodicResign
// is the checked form, for zones whose config says whether they sign.
func (zd *ZoneData) KeepRenewed() {
	if zd == nil || !zd.keepSigned.CompareAndSwap(false, true) {
		return
	}
	lgSigner.Info("adding zone to re-sign list", "zone", zd.ZoneName)
	select {
	case resignWake <- struct{}{}:
	default:
	}
}

// resignCandidates picks the zones a resigner pass looks at from zones, which is
// Zones.Items(): those on the watchlist, and those owed a replace. The second
// kind is a key-state request that was dropped (triggerResign marks the zone
// first), and it is honoured whether or not the zone ever registered -- as it
// would have been had the request been delivered.
//
// Walking the live registry, rather than a list of its own, is what keeps the
// watchlist honest: a zone removed from Zones leaves the pass with it, and a
// zone replaced by a new ZoneData is renewed as the new one, once that one
// registers. The list this replaced kept every ZoneData it was ever handed.
func resignCandidates(zones map[string]*ZoneData) map[string]*ZoneData {
	out := make(map[string]*ZoneData)
	for name, zd := range zones {
		if zd.keepSigned.Load() || zd.resignPendingSet() {
			out[name] = zd
		}
	}
	return out
}

// nextResignWake returns how long the resigner may sleep before its next pass:
// until the earliest renewal any watched zone reports, bounded at both ends.
//
// floor -- the configured interval -- is the lower bound, so two passes are
// never closer together than the engine's own cadence and a zone reporting a
// time in the past cannot spin it. resignSafetyTick is the upper bound, and it
// is what keeps this an optimisation rather than a new way to fail: a zone whose
// estimate is stale, a clock step, or a signing path that does not update the
// estimate degrades to a late renewal instead of a missed one.
//
// A zone that does not know when it is next due pulls the whole wake down to the
// floor. Sleeping through an unknown is the one thing this must not do.
//
// The caller leaves out the zones the pool has in flight (resignPool.notInFlight).
// A zone being worked on has no estimate worth sleeping on: it has none yet, or
// the one it has is about to be replaced by what the work records. Counted, it
// would pull every wake down to the floor for as long as the work ran, for
// something that is already owed to a worker and cannot be started a second time
// -- the engine spinning on a slow zone. The sleep-through is closed the other
// way: when a zone's work ends the engine is told (resignPool.ended) and runs
// this over the zones that ended, with the estimate the work has just recorded.
func nextResignWake(zones map[string]*ZoneData, floor time.Duration) time.Duration {
	var earliest time.Time
	for _, zd := range zones {
		if zd == nil {
			continue
		}
		if !zd.Options[OptInlineSigning] && !zd.Options[OptOnlineSigning] {
			continue
		}
		if zd.resignPendingSet() {
			// Work already owed. Sleeping an hour on the renewal estimate
			// would be sleeping through it.
			return floor
		}
		due, ok := zd.resignDue()
		if !ok {
			return floor
		}
		if earliest.IsZero() || due.Before(earliest) {
			earliest = due
		}
	}
	if earliest.IsZero() {
		// Nothing signed on the watchlist.
		return resignSafetyTick
	}
	switch d := time.Until(earliest); {
	case d < floor:
		return floor
	case d > resignSafetyTick:
		return resignSafetyTick
	default:
		return d
	}
}

// ResignerEngine runs the resigner: a timer that decides when the zones on the
// watchlist are looked at, a pool of workers that looks at them, and the
// ResignQ.
//
// THE ENGINE GOROUTINE NEVER DOES A ZONE'S WORK, so nothing it waits for is a
// zone. On a tick it hands every zone that is owed a look to the pool and goes
// straight back to its select; a key-state request is handed over the same way.
// A zone that is slow -- large, an expensive algorithm, behind a zd.mu a long
// refresh holds -- is held by a worker and nothing else, and the other zones are
// handed over on the next tick regardless, and renewed, while it is still in
// there. Which pass a zone belongs to does not matter: a pass is only the set of
// zones one tick handed over, and it is never waited for (#1034).
//
// The pool is bounded (resignWorkers) and owns a zone for as long as it works
// on it, so a zone that is still in flight when the next tick comes is skipped,
// not handed to a second worker. See resignPool.
func ResignerEngine(ctx context.Context, zoneresignch chan ResignRequest) {

	//	var zoneresignch = conf.Internal.ResignZoneCh

	interval := ConfLive().ResignerInterval
	if interval < 60 {
		interval = 60
	}
	if interval > 3600 {
		interval = 3600
	}

	// The periodic pass is unconditional. It used to be gated on
	// service.resign, and there is no deployment that wants signatures to
	// expire without being renewed: a zone that should not be re-signed by this
	// server says so per zone, by not carrying online-signing or
	// inline-signing, and the ticker loop below already skips those. The global
	// switch could therefore only ever disable something wanted, silently, for
	// every zone at once.
	//
	// b59f85a4 removed the same switch from the OTHER half of this engine, for
	// the same reason found the hard way: with service.resign unset the engine
	// drained triggerResign requests and dropped them, so a rollover left the
	// DNSKEY RRset signed by a retired key. This is the rest of that fix.
	lgSigner.Info("ResignerEngine starting", "interval_sec", interval)

	// A config that has stopped meaning what it says is its own trap, so an
	// explicit setting is called out rather than ignored in silence.
	if viper.IsSet("service.resign") && !viper.GetBool("service.resign") {
		lgSigner.Warn("service.resign: false is no longer honoured; expiring signatures" +
			" are always renewed. Remove the setting from the config.")
	}

	// The renewal pass is scheduled rather than merely periodic. Every zone
	// records when its earliest signature crosses the renewal threshold, so
	// there is no reason to wake every minute and walk every zone to be told
	// that nothing is due.
	//
	// The configured interval stays the FLOOR: two passes are never closer
	// together than it, so a zone reporting a time in the past -- a signature
	// this pass collected and SignRRset then declined -- cannot spin the engine.
	// resignSafetyTick is the CEILING, and it is what keeps this an
	// optimisation rather than a new way to fail: a clock step, or any path that
	// signs without updating the estimate, degrades to a late renewal instead of
	// a missed one.
	floor := time.Duration(interval) * time.Second

	runResigner(ctx, zoneresignch, floor, liveResignWork())
}

// runResigner is ResignerEngine's loop, with the floor and the zones' work
// handed in so that a test can run it at a pace and on work of its own.
func runResigner(ctx context.Context, zoneresignch chan ResignRequest, floor time.Duration,
	work resignWork) {

	pool := newResignPool(resignWorkers, work)
	// A stop waits for the workers, as it always waited for the sweep: the engine
	// is what the daemon's shutdown waits on, and a worker left running would
	// touch zones and the keystore after the daemon has torn them down. A worker
	// inside a zone cannot be interrupted -- zd.mu is a plain mutex -- so this is
	// the zones in flight, no more: no worker takes another once ctx is done, and
	// the zones still queued are dropped.
	defer func() {
		if n := pool.inFlight(); n > 0 {
			lgSigner.Info("ResignerEngine waiting for zones in flight", "zones", n)
		}
		pool.wait()
	}()

	// Go 1.23 and later discard a stopped timer's pending send, so Stop
	// followed by Reset needs no drain.
	timer := time.NewTimer(floor)
	defer timer.Stop()
	// When the timer is currently due to fire. A request may only ever bring
	// this EARLIER; see earlierResignWake.
	nextWake := time.Now().Add(floor)

	setWake := func(at time.Time) {
		timer.Stop()
		timer.Reset(time.Until(at))
		nextWake = at
	}

	// Whatever the engine is currently sleeping through was computed without
	// the zone that just arrived, which has no estimate of its own yet -- so it
	// may need an earlier wake. Never a later one.
	wakeSooner := func() {
		if at, sooner := earlierResignWake(nextWake, time.Now(), floor); sooner {
			setWake(at)
		}
	}

	for {
		select {
		case <-ctx.Done():
			lgSigner.Info("ResignerEngine terminating")
			return
		case <-resignWake:
			wakeSooner()
		case req, ok := <-zoneresignch:
			if !ok {
				return
			}

			zd := req.Zd
			if zd == nil {
				lgSigner.Warn("ResignerEngine: nil zone data received, cannot resign")
				continue
			}

			// A key-state change cannot wait for the ticker: the zone is
			// serving signatures by keys that are no longer active. It does not
			// wait for the zones in flight either, but it does wait for its own
			// zone's worker, if it has one: the pool runs it on that worker,
			// after the work in hand (resignPool.submit).
			switch req.Reason {
			case ResignKeyStateChanged:
				// Before the worker reads the keystore: a trigger from here
				// on is for a change it may not see.
				zd.resignQueued.Store(false)
				pool.submit(ctx, zd, resignJobReplace)
			default:
				lgSigner.Warn("ResignerEngine: unknown resign reason, registering only",
					"zone", zd.ZoneName, "reason", uint8(req.Reason))
			}

			// Keep the zone on the watchlist for the periodic re-sign ticker,
			// which since #515 always runs.
			zd.KeepRenewed()
			wakeSooner()

		case <-pool.ended:
			// A worker has finished a zone. The wake the last tick worked out
			// left that zone out, being in flight, and it has now recorded when
			// it is next due (or that it does not know, or that it is still
			// owed a replace). Bring the wake forward to that, and never back:
			// postponing the tick for every zone that finishes is how the
			// timer used to be starved (earlierResignWake).
			ended := pool.notInFlight(pool.takeEnded())
			if len(ended) > 0 {
				if at := time.Now().Add(nextResignWake(ended, floor)); at.Before(nextWake) {
					setWake(at)
				}
			}

		case <-timer.C:
			zones := resignCandidates(Zones.Items())
			started := 0
			for _, zd := range zones {
				if pool.submit(ctx, zd, resignJobRenew) {
					started++
				}
			}

			// Without the zones in flight: see nextResignWake. That includes the
			// ones this tick just handed over; they bring the wake forward when
			// they end.
			wake := nextResignWake(pool.notInFlight(zones), floor)
			setWake(time.Now().Add(wake))
			lgSigner.Debug("ResignerEngine sleeping until the next renewal is due",
				"zones", len(zones), "started", started,
				"in_flight", pool.inFlight(), "sleep", wake.String())
		}
	}
}

// replaceSignaturesNow brings the served RRSIG set into line with the zone's
// currently-active keys, immediately. It cannot wait for the renewal pass,
// because NeedsResigning short-circuits while validity is healthy -- which is
// exactly the case after a rollover, where the existing RRSIGs are perfectly
// valid and merely made by the wrong key.
//
// ResignZone, not SignZone(force=true), and the difference is the point.
// SignZone is ADDITIVE: it writes signatures by the active keys and leaves
// RRSIGs by no-longer-active ones in place -- SignRRset says so itself, and
// says that replacing them belongs to ResignZone. So the forced pass this
// replaces added the right signatures and left the wrong ones on the wire,
// which is not what a key-state change needs. ResignZone strips and re-signs
// per RRset, on a local copy, so readers never see an unsigned intermediate.
func (zd *ZoneData) replaceSignaturesNow(ctx context.Context) {
	if zd == nil {
		return
	}
	if !zd.signsItsOwnContent() {
		// Nothing here signs, so nothing is owed. Leaving the flag set would
		// make every sweep retry a zone that can never satisfy it.
		zd.takeResignPending()
		return
	}
	// Claimed, not read: a concurrent trigger for the same zone should not
	// produce two replaces of the same signatures.
	zd.takeResignPending()
	lgSigner.Debug("resigner: replacing signatures after a key-state change", "zone", zd.ZoneName)
	newrrsigs, err := zd.ResignZone(ctx, zd.KeyDB)
	if err != nil {
		// Put it back. A failed replace leaves the zone serving signatures by
		// keys that are no longer active, and the renewal pass will not find
		// them: they are valid, just made by the wrong key.
		zd.markResignPending()
		lgSigner.Error("resigner: replacing signatures failed, will retry on the next pass",
			"zone", zd.ZoneName, "err", err)
		return
	}
	lgSigner.Info("resigner: signatures replaced", "zone", zd.ZoneName, "new_rrsigs", newrrsigs)
}

// resignSweepZone is one zone's share of a periodic resigner pass.
//
// Lifted out of the engine loop so the two things it has to get right can be
// asserted without waiting out a real tick: an owed replace is not skipped, and
// renewal does not stand in for one.
func resignSweepZone(ctx context.Context, zd *ZoneData) {
	// Skip zones where signing has been disabled since they were added to the
	// list. MP zones can toggle OptInlineSigning dynamically based on HSYNC
	// analysis.
	if !zd.Options[OptInlineSigning] && !zd.Options[OptOnlineSigning] {
		return
	}
	// A replace that never happened comes first: the request was dropped by a
	// full queue, or the pass itself failed. Renewal cannot substitute for it
	// -- it looks at signature AGE, and a post-rollover RRSIG by a retired key
	// is valid and not old -- so without this the zone would go on serving
	// signatures by a key that is gone until they finally expired.
	if zd.resignPendingSet() {
		zd.replaceSignaturesNow(ctx)
	}
	// Renewal, not a rebuild. SignZone(force=false) used to be called here, and
	// it rebuilt the NSEC chain and the DNSKEY RRset unsigned before checking
	// anything -- so the freshness check was unreachable, everything was
	// restaged, and the unconditional publish bumped the serial and notified.
	// Once a minute, on every signed zone, whether or not anything had changed.
	// See docs/2026-09-05-signing-build-vs-renewal.md.
	lgSigner.Debug("renewing ageing signatures (periodic)", "zone", zd.ZoneName)
	renewed, err := zd.RenewZoneSignatures(ctx, zd.KeyDB)
	if err != nil {
		// Nothing was signed, so do not go on to say it was. An operator
		// watching for "signatures renewed" would read the success line and
		// miss the failure above it -- on the one pass whose whole job is to
		// stop signatures ageing out.
		lgSigner.Error("failed to renew zone signatures", "zone", zd.ZoneName, "err", err)
		return
	}
	if renewed == 0 {
		// The overwhelmingly common outcome, and not news. A line per zone per
		// minute saying nothing happened is how this log stopped being readable.
		return
	}
	lgSigner.Info("zone signatures renewed (periodic)", "zone", zd.ZoneName, "rrsets_renewed", renewed)
}

// earlierResignWake reports whether a zone just added to the watchlist needs
// the resigner to wake sooner than it is already going to, and if so, when.
//
// A new zone has no renewal estimate of its own, so it wants a pass within one
// floor. That can only ever move the wake EARLIER. Each request used to stop the
// timer and reset it to a full floor unconditionally, so a request arriving
// before the timer fired pushed the sweep out by another floor -- and on a
// server where zone loads and key-state changes arrive more often than once a
// floor, the timer never fired at all and nothing on the watchlist was renewed.
// The one pass whose whole job is to stop signatures expiring, postponed
// indefinitely by the traffic it exists to serve.
func earlierResignWake(nextWake, now time.Time, floor time.Duration) (time.Time, bool) {
	want := now.Add(floor)
	if want.Before(nextWake) {
		return want, true
	}
	return nextWake, false
}
