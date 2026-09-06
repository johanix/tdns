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

	// ResignPeriodic: keep this zone on the watchlist that renews ageing
	// signatures. No immediate pass -- the ticker decides when one is due.
	ResignPeriodic
)

func (r ResignReason) String() string {
	switch r {
	case ResignKeyStateChanged:
		return "key-state-changed"
	case ResignPeriodic:
		return "periodic"
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

	// replaceSignatures brings the served RRSIG set into line with the zone's
	// currently-active keys, immediately. It cannot wait for the periodic
	// ticker, because NeedsResigning short-circuits while validity is healthy --
	// which is exactly the case after a rollover, where the existing RRSIGs are
	// perfectly valid and merely made by the wrong key.
	//
	// ResignZone, not SignZone(force=true), and the difference is the point.
	// SignZone is ADDITIVE: it writes signatures by the active keys and leaves
	// RRSIGs by no-longer-active ones in place -- SignRRset says so itself, and
	// says that replacing them belongs to ResignZone. So the forced pass this
	// replaces added the right signatures and left the wrong ones on the wire,
	// which is not what a key-state change needs. ResignZone strips and re-signs
	// per RRset, on a local copy, so readers never see an unsigned intermediate.
	replaceSignatures := func(zd *ZoneData) {
		if zd == nil {
			return
		}
		if !zd.signsItsOwnContent() {
			return
		}
		lgSigner.Debug("resigner: replacing signatures after a key-state change", "zone", zd.ZoneName)
		newrrsigs, err := zd.ResignZone(zd.KeyDB)
		if err != nil {
			lgSigner.Error("resigner: replacing signatures failed", "zone", zd.ZoneName, "err", err)
			return
		}
		lgSigner.Info("resigner: signatures replaced", "zone", zd.ZoneName, "new_rrsigs", newrrsigs)
	}

	for {
		select {
		case <-ctx.Done():
			lgSigner.Info("ResignerEngine terminating")
			return
		case req, ok := <-zoneresignch:
			if !ok {
				return
			}

			zd := req.Zd
			if zd == nil {
				lgSigner.Warn("ResignerEngine: nil zone data received, cannot resign")
				continue
			}

			// What to do now depends on why the zone was sent. A key-state
			// change cannot wait for the ticker: the zone is serving signatures
			// by keys that are no longer active. A periodic registration is the
			// opposite -- it asks to be watched, and the ticker decides when
			// anything is due.
			switch req.Reason {
			case ResignKeyStateChanged:
				replaceSignatures(zd)
			case ResignPeriodic:
				// Registration only; the watchlist add below is the whole effect.
			default:
				lgSigner.Warn("ResignerEngine: unknown resign reason, registering only",
					"zone", zd.ZoneName, "reason", uint8(req.Reason))
			}

			// Keep the zone on the watchlist for the periodic re-sign ticker,
			// which since #515 always runs.
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
