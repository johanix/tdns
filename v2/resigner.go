/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"time"

	"github.com/spf13/viper"
)

// resignSafetyTick bounds how long the resigner will sleep on its own estimate.
// See nextResignWake.
const resignSafetyTick = time.Hour

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
func nextResignWake(zones map[string]*ZoneData, floor time.Duration) time.Duration {
	var earliest time.Time
	for _, zd := range zones {
		if zd == nil {
			continue
		}
		if !zd.Options[OptInlineSigning] && !zd.Options[OptOnlineSigning] {
			continue
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

// func ResignerEngine(zoneresignch chan ZoneRefresher, stopch chan struct{}) {
func ResignerEngine(ctx context.Context, zoneresignch chan *ZoneData) {

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

	ZonesToKeepSigned := make(map[string]*ZoneData)

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

	// Go 1.23 and later discard a stopped timer's pending send, so Stop
	// followed by Reset needs no drain.
	timer := time.NewTimer(floor)
	defer timer.Stop()

	// resignNow performs an immediate force re-sign of zd. Used when
	// triggerResign fires (key-state change, etc.) — we can't wait for the
	// periodic ticker, because NeedsResigning short-circuits when validity is
	// healthy, which is exactly the case after a rollover when the existing
	// RRSIGs are perfectly valid but signed by the wrong key.
	resignNow := func(zd *ZoneData) {
		if zd == nil {
			return
		}
		if !zd.Options[OptInlineSigning] && !zd.Options[OptOnlineSigning] {
			return
		}
		lgSigner.Debug("triggerResign: forcing zone re-sign", "zone", zd.ZoneName)
		newrrsigs, err := zd.SignZone(zd.KeyDB, true) // force=true
		if err != nil {
			lgSigner.Error("triggerResign: zone re-sign failed", "zone", zd.ZoneName, "err", err)
			return
		}
		lgSigner.Info("triggerResign: zone re-signed", "zone", zd.ZoneName, "new_rrsigs", newrrsigs)
	}

	for {
		select {
		case <-ctx.Done():
			lgSigner.Info("ResignerEngine terminating")
			return
		case zd, ok := <-zoneresignch:
			if !ok {
				return
			}

			if zd == nil {
				lgSigner.Warn("ResignerEngine: nil zone data received, cannot resign")
				continue
			}

			// Always force-resign right now — that's the whole point
			// of the channel: an explicit "this zone needs new RRSIGs"
			// signal that should not wait for the next ticker.
			resignNow(zd)

			// Keep the zone on the watchlist for the periodic re-sign ticker.
			if _, exist := ZonesToKeepSigned[zd.ZoneName]; !exist {
				lgSigner.Info("adding zone to re-sign list", "zone", zd.ZoneName)
			}
			ZonesToKeepSigned[zd.ZoneName] = zd

			// Whatever the engine is currently sleeping through was computed
			// without this zone, which has no estimate of its own yet.
			timer.Stop()
			timer.Reset(floor)

		case <-timer.C:
			for _, zd := range ZonesToKeepSigned {
				// Shutdown latency here is one pass per zone, not one pass, so
				// the check belongs between zones: a stop during a sweep of
				// several hundred should not wait out the whole sweep. Inside a
				// pass there is nothing useful to abandon -- it holds zd.mu and
				// signs only what is due, and SignZone and ResignZone bound
				// themselves the same way.
				if ctx.Err() != nil {
					lgSigner.Info("ResignerEngine terminating during a renewal sweep")
					return
				}
				// Skip zones where signing has been disabled since
				// they were added to the list. MP zones can toggle
				// OptInlineSigning dynamically based on HSYNC analysis.
				if !zd.Options[OptInlineSigning] && !zd.Options[OptOnlineSigning] {
					continue
				}
				// Renewal, not a rebuild. SignZone(force=false) used to be
				// called here, and it rebuilt the NSEC chain and the DNSKEY
				// RRset unsigned before checking anything -- so the freshness
				// check was unreachable, everything was restaged, and the
				// unconditional publish bumped the serial and notified. Once a
				// minute, on every signed zone, whether or not anything had
				// changed. See docs/2026-09-05-signing-build-vs-renewal.md.
				lgSigner.Debug("renewing ageing signatures (periodic)", "zone", zd.ZoneName)
				renewed, err := zd.RenewZoneSignatures(zd.KeyDB)
				if err != nil {
					lgSigner.Error("failed to renew zone signatures", "zone", zd.ZoneName, "err", err)
					// Nothing was signed, so do not go on to say it was. An
					// operator watching for "signatures renewed" would read the
					// success line and miss the failure above it -- on the one
					// pass whose whole job is to stop signatures ageing out.
					continue
				}
				if renewed == 0 {
					// The overwhelmingly common outcome, and not news. A line
					// per zone per minute saying nothing happened is how this
					// log stopped being readable.
					continue
				}
				lgSigner.Info("zone signatures renewed (periodic)", "zone", zd.ZoneName, "rrsets_renewed", renewed)
			}

			wake := nextResignWake(ZonesToKeepSigned, floor)
			lgSigner.Debug("ResignerEngine sleeping until the next renewal is due",
				"zones", len(ZonesToKeepSigned), "sleep", wake.String())
			timer.Reset(wake)
		}
	}
}
