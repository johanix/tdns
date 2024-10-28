/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/viper"

	cmap "github.com/orcaman/concurrent-map/v2"
)

type RefreshCounter struct {
	Name           string
	SOARefresh     uint32
	CurRefresh     uint32
	IncomingSerial uint32
	Upstream       string
	Downstreams    []string
	Zonefile       string
}

func RefreshEngine(conf *Config, stopch chan struct{}, appMode string) {

	var zonerefch = conf.Internal.RefreshZoneCh
	var bumpch = conf.Internal.BumpZoneCh

	// var refreshCounters = make(map[string]*RefreshCounter, 5)
	var refreshCounters = cmap.New[*RefreshCounter]()
	ticker := time.NewTicker(1 * time.Second)

	if !viper.GetBool("service.refresh") {
		log.Printf("Refresh Engine is NOT active. Zones will only be updated on receipt of Notifies.")
		for range zonerefch {
			// ensure that we keep reading to keep the channel open
			continue
		}
	} else {
		log.Printf("RefreshEngine: Starting")
	}

	var upstream, zone string
	var downstreams []string
	// var refresh uint32
	//	var rc *RefreshCounter
	var updated bool
	var err error
	var bd BumperData
	var zr ZoneRefresher

	resetSoaSerial := viper.GetBool("service.reset_soa_serial")

	for {
		select {
		case zr = <-zonerefch:
			log.Printf("***** RefreshEngine: zonerefch: zone %s", zr.Name)
			zone = zr.Name
			resp := RefresherResponse{
				Zone: zr.Name,
			}
			if zone != "" {
				if zd, exist := Zones.Get(zone); exist {
					if zd.ZoneType == Primary && zd.Options[OptDirty] {
						resp.Msg = fmt.Sprintf("RefreshEngine: Zone %s has modifications, reload not possible", zone)
						log.Printf(resp.Msg)
						if zr.Response != nil {
							zr.Response <- resp
						}
						continue
					}
					log.Printf("RefreshEngine: scheduling immediate refresh for known zone '%s'",
						zone)
					// if _, haveParams := refreshCounters[zone]; !haveParams {
					if _, haveParams := refreshCounters.Get(zone); !haveParams {
						soa, _ := zd.GetSOA()
						refreshCounters.Set(zone, &RefreshCounter{
							Name:        zone,
							SOARefresh:  soa.Refresh,
							CurRefresh:  1, // force immediate refresh
							Upstream:    zr.Primary,
							Downstreams: zr.Notify,
							Zonefile:    zr.Zonefile,
						})
					}
					// XXX: Should do refresh in parallel
					go func(zd *ZoneData) {
						updated, err := zd.Refresh(Globals.Verbose, Globals.Debug, zr.Force)
						if err != nil {
							log.Printf("RefreshEngine: Error from zone refresh(%s): %v",
								zone, err)
						}
						if updated {
							log.Printf("Zone %s was updated via refresh operation", zd.ZoneName)
						}
					}(zd)

				} else {
					log.Printf("***** RefreshEngine: adding the new zone '%s'", zone)
					// XXX: We want to do this in parallel
					// go func() {
					dp, _ := conf.Internal.DnssecPolicies[zr.DnssecPolicy]
					msc, _ := conf.MultiSigner[zr.MultiSigner]
					zd := &ZoneData{
						ZoneName:         zone,
						ZoneStore:        zr.ZoneStore,
						Logger:           log.Default(),
						Upstream:         zr.Primary,
						Downstreams:      zr.Notify,
						Zonefile:         zr.Zonefile,
						ZoneType:         zr.ZoneType,
						Options:          zr.Options,
						UpdatePolicy:     zr.UpdatePolicy,
						DnssecPolicy:     &dp,
						MultiSigner:      &msc,
						DelegationSyncQ:  conf.Internal.DelegationSyncQ,
						MultiSignerSyncQ: conf.Internal.MultiSignerSyncQ,
						Data:             cmap.New[OwnerData](),
						KeyDB:            conf.Internal.KeyDB,
					}

					updated, err = zd.Refresh(Globals.Verbose, Globals.Debug, zr.Force)
					if err != nil {
						log.Printf("RefreshEngine: Error from zone refresh(%s): %v",
							zone, err)
						continue // cannot do much else
						// return // terminate goroutine
					}

					refresh, err := FindSoaRefresh(zd)
					if err != nil {
						log.Printf("Error from FindSoaRefresh(%s): %v", zone, err)
					}
					// soa, _ := zonedata.GetSOA()
					// if soa != nil {
					//	refresh = soa.Refresh
					// }
					// Is there a max refresh counter configured, then use it.
					// maxrefresh := uint32(viper.GetInt("service.maxrefresh"))
					// if maxrefresh != 0 && maxrefresh < refresh {
					//	refresh = maxrefresh
					//}

					// not refreshing from file all the time. use reload
					// if zr.ZoneType == tdns.Primary {
					//	refresh = 86400 // 24h
					// }

					refreshCounters.Set(zone, &RefreshCounter{
						Name:        zone,
						SOARefresh:  refresh,
						CurRefresh:  refresh,
						Upstream:    upstream,
						Downstreams: downstreams,
					})

					if appMode != "agent" {
						err = zd.SetupZoneSigning(conf.Internal.ResignQ)
						if err != nil {
							log.Printf("Error from SetupZoneSigning(%s): %v", zone, err)
						}
					}

					// This is a new zone being added to the server. Let's see if the zone
					// config should cause any specific changes to the zone data to be made.
					err = zd.SetupZoneSync(conf.Internal.DelegationSyncQ)
					if err != nil {
						log.Printf("Error from SetupZoneSync(%s): %v", zone, err)
					}

					Zones.Set(zone, zd)

					if updated {
						if resetSoaSerial {
							zd.CurrentSerial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, zd.CurrentSerial)
						}
						zd.NotifyDownstreams()
					}
				}
			}
			if zr.Response != nil {
				zd, _ := Zones.Get(zr.Name)
				resp.Msg = fmt.Sprintf("RefreshEngine: %s zone %s refreshing (force=%v)",
					ZoneTypeToString[zd.ZoneType], zr.Name,
					zr.Force)
				zr.Response <- resp
			}

		case <-ticker.C:
			// log.Printf("RefEng: ticker. refCounters: %v", refreshCounters)
			for zone, rc := range refreshCounters.Items() {
				// log.Printf("RefEng: ticker for %s: curref: %d", zone, v.CurRefresh)
				rc.CurRefresh--
				if rc.CurRefresh <= 0 {
					upstream = rc.Upstream

					log.Printf("RefreshEngine: will refresh zone %s due to refresh counter", zone)
					// log.Printf("Len(Zones) = %d", len(Zones))
					zd, _ := Zones.Get(zone)
					updated, err := zd.Refresh(Globals.Verbose, Globals.Debug, false)
					rc.CurRefresh = rc.SOARefresh
					if err != nil {
						log.Printf("RefreshEngine: Error from zd.Refresh(%s): %v", zone, err)
					}
					if updated {
						if resetSoaSerial {
							zd.CurrentSerial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, zd.CurrentSerial)

						}
					}
					if updated {
						zd.NotifyDownstreams()
					}
				}
			}

		case bd = <-bumpch:
			zone = bd.Zone
			resp := BumperResponse{}
			var err error
			if zone != "" {
				if zd, exist := Zones.Get(zone); exist {
					resp, err = zd.BumpSerial()
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Error bumping SOA serial for zone '%s': %v", zone, err)
						log.Printf(resp.ErrorMsg)
					}
					log.Printf("RefreshEngine: bumping SOA serial for known zone '%s'", zone)
				} else {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Request to bump serial for unknown zone '%s'", zone)
					log.Printf(resp.ErrorMsg)
				}
			}
			bd.Result <- resp
		}
	}
}

func FindSoaRefresh(zd *ZoneData) (uint32, error) {
	var refresh uint32
	soa, _ := zd.GetSOA()
	if soa != nil {
		refresh = soa.Refresh
	}
	// Is there a max refresh counter configured, then use it.
	maxrefresh := uint32(viper.GetInt("service.maxrefresh"))
	if maxrefresh != 0 && maxrefresh < refresh {
		refresh = maxrefresh
	}

	// not refreshing from file all the time. use reload
	if zd.ZoneType == Primary {
		refresh = 86400 // 24h
	}
	return refresh, nil
}
