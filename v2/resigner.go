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

	if !viper.GetBool("service.resign") {
		lgSigner.Info("ResignerEngine is NOT active, zones updated only on Notifies")
		for {
			select {
			case <-ctx.Done():
				lgSigner.Info("ResignerEngine terminating (inactive mode)")
				return
			case _, ok := <-zoneresignch:
				if !ok {
					return
				}
				// ensure that we keep reading to keep the channel open
				continue
			}
		}
	} else {
		lgSigner.Info("ResignerEngine starting", "interval_sec", interval)
	}

	ZonesToKeepSigned := make(map[string]*ZoneData)
	//	var zr ZoneRefresher // We're reusing the ZoneRefresher struct also for the resigner
	// var zone string

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

			if _, exist := ZonesToKeepSigned[zd.ZoneName]; exist {
				continue
			}
			lgSigner.Info("adding zone to re-sign list", "zone", zd.ZoneName)
			ZonesToKeepSigned[zd.ZoneName] = zd

		case <-ticker.C:
			for _, zd := range ZonesToKeepSigned {
				// Skip multi-provider zones where our HSYNC says NOSIGN
				if zd.Options[OptMultiProvider] {
					shouldSign, _ := zd.weAreASigner()
					if !shouldSign {
						continue
					}
				}
				lgSigner.Debug("re-signing zone", "zone", zd.ZoneName)
				newrrsigs, err := zd.SignZone(zd.KeyDB, false)
				if err != nil {
					lgSigner.Error("failed to re-sign zone", "zone", zd.ZoneName, "err", err)
				}
				lgSigner.Info("zone re-signed", "zone", zd.ZoneName, "new_rrsigs", newrrsigs)
			}
		}
	}
}
