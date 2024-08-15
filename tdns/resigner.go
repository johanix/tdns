/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"log"
	"time"

	"github.com/spf13/viper"
)

type xxxRefreshCounter struct {
	Name           string
	SOARefresh     uint32
	CurRefresh     uint32
	IncomingSerial uint32
	Upstream       string
	Downstreams    []string
	Zonefile       string
}

// func ResignerEngine(zoneresignch chan ZoneRefresher, stopch chan struct{}) {
func ResignerEngine(zoneresignch chan *ZoneData, stopch chan struct{}) {

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
		for range zoneresignch {
			// ensure that we keep reading to keep the channel open
			continue
		}
	} else {
		log.Printf("*** ResignerEngine: Starting with interval %d seconds ***", interval)
	}

	ZonesToKeepSigned := make(map[string]*ZoneData)
	//	var zr ZoneRefresher // We're reusing the ZoneRefresher struct also for the resigner
	// var zone string

	for {
		select {
		case zd := <-zoneresignch:

			//			zd, exist := Zones.Get(zone)
			if zd == nil {
				log.Printf("ResignerEngine: Zone <nil> does not exist, cannot resign")
				continue
			}

			//			if slices.Contains(ZonesToKeepSigned, zd) {
			//				continue
			//			}

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
