/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"log"
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

	if !viper.GetBool("service.resign") {
		log.Printf("ResignerEngine is NOT active. Zones will only be updated on receipt on Notifies.")
		for {
			select {
			case <-ctx.Done():
				log.Printf("ResignerEngine: terminating due to context cancelled (inactive mode)")
				ticker.Stop()
				return
			case _, ok := <-zoneresignch:
				if !ok {
					ticker.Stop()
					return
				}
				// ensure that we keep reading to keep the channel open
				continue
			}
		}
	} else {
		log.Printf("*** ResignerEngine: Starting with interval %d seconds ***", interval)
	}

	ZonesToKeepSigned := make(map[string]*ZoneData)
	//	var zr ZoneRefresher // We're reusing the ZoneRefresher struct also for the resigner
	// var zone string

	for {
		select {
		case <-ctx.Done():
			log.Printf("ResignerEngine: terminating due to context cancelled")
			ticker.Stop()
			return
		case zd, ok := <-zoneresignch:
			if !ok {
				ticker.Stop()
				return
			}

			if zd == nil {
				log.Printf("ResignerEngine: Zone <nil> does not exist, cannot resign")
				continue
			}

			if _, exist := ZonesToKeepSigned[zd.ZoneName]; exist {
				continue
			}
			log.Printf("ResignerEngine: Adding zone %s to ZonesToKeepSigned", zd.ZoneName)
			ZonesToKeepSigned[zd.ZoneName] = zd

		case <-ticker.C:
			// log.Printf("RefEng: ticker. refCounters: %v", refreshCounters)
			for _, zd := range ZonesToKeepSigned {
				log.Printf("ResignerEngine: Re-signing zone %s", zd.ZoneName)
				newrrsigs, err := zd.SignZone(zd.KeyDB, false)
				if err != nil {
					log.Printf("ResignerEngine: Error re-signing zone %s: %s", zd.ZoneName, err)
				}
				log.Printf("ResignerEngine: zone %s re-signed. %d new RRSIGs", zd.ZoneName, newrrsigs)
			}
		}
	}
}
