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

func ResignerEngine(ctx context.Context, zoneresignch chan ResignRequest) {

	//	var zoneresignch = conf.Internal.ResignZoneCh

	interval := ConfLive().ResignerInterval
	if interval < 60 {
		interval = 60
	}
	if interval > 3600 {
		interval = 3600
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

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

		case <-ticker.C:
			for _, zd := range ZonesToKeepSigned {
				// Skip zones where signing has been disabled since
				// they were added to the list. MP zones can toggle
				// OptInlineSigning dynamically based on HSYNC analysis.
				if !zd.Options[OptInlineSigning] && !zd.Options[OptOnlineSigning] {
					continue
				}
				lgSigner.Debug("re-signing zone (periodic)", "zone", zd.ZoneName)
				newrrsigs, err := zd.SignZone(zd.KeyDB, false)
				if err != nil {
					lgSigner.Error("failed to re-sign zone", "zone", zd.ZoneName, "err", err)
				}
				lgSigner.Info("zone re-signed (periodic)", "zone", zd.ZoneName, "new_rrsigs", newrrsigs)
			}
		}
	}
}
