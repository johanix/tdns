/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"time"

	"github.com/spf13/viper"
)

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
					// Nothing was signed, so do not go on to say it was. An
					// operator watching for "zone re-signed" would read the
					// success line and miss the failure above it -- on the one
					// pass whose whole job is to stop signatures ageing out.
					continue
				}
				lgSigner.Info("zone re-signed (periodic)", "zone", zd.ZoneName, "new_rrsigs", newrrsigs)
			}
		}
	}
}
