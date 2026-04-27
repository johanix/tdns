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

	interval := viper.GetInt("resignerengine.interval")
	if interval < 60 {
		interval = 60
	}
	if interval > 3600 {
		interval = 3600
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	// service.resign controls only the *periodic* re-sign ticker that
	// keeps RRSIG validity fresh. Explicit one-shot resign requests
	// arriving on zoneresignch (from triggerResign, e.g. after an
	// AtomicRollover or other key-state change) are always honored,
	// regardless of this setting — otherwise rollovers can leave
	// the DNSKEY RRset signed by a key that's no longer active.
	periodic := viper.GetBool("service.resign")
	if !periodic {
		lgSigner.Info("ResignerEngine: periodic mode OFF; explicit triggerResign requests still honored")
	} else {
		lgSigner.Info("ResignerEngine starting", "interval_sec", interval)
	}

	ZonesToKeepSigned := make(map[string]*ZoneData)

	// resignNow performs an immediate force re-sign of zd. Used when
	// triggerResign fires (key-state change, etc.) — we can't wait for
	// the periodic ticker because (a) ticker may be disabled, and
	// (b) even if enabled, NeedsResigning short-circuits when validity
	// is healthy, which is exactly the case after a rollover when the
	// existing RRSIGs are perfectly valid but signed by the wrong key.
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

			// Also keep the zone on the watchlist for the periodic
			// re-sign ticker (only effective when periodic mode is on).
			if periodic {
				if _, exist := ZonesToKeepSigned[zd.ZoneName]; !exist {
					lgSigner.Info("adding zone to re-sign list", "zone", zd.ZoneName)
				}
				ZonesToKeepSigned[zd.ZoneName] = zd
			}

		case <-ticker.C:
			if !periodic {
				continue
			}
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
