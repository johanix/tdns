/*
 * Copyright (c) 2024 ohan Stenstam, johani@johani.org
 */
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/viper"

	"github.com/johanix/tdns/tdns"
)

type RefreshCounter struct {
	Name           string
	SOARefresh     uint32
	CurRefresh     uint32
	IncomingSerial uint32
	KeepFunc       func(uint16) bool
	Upstream       string
	Downstreams    []string
	Zonefile       string
}

func RefreshEngine(conf *Config, stopch chan struct{}) {

	var zonerefch = conf.Internal.RefreshZoneCh
	var bumpch = conf.Internal.BumpZoneCh

	var refreshCounters = make(map[string]*RefreshCounter, 5)
	ticker := time.NewTicker(1 * time.Second)

	if !viper.GetBool("service.refresh") {
		log.Printf("Refresh Engine is NOT active. Zones will only be updated on receipt on Notifies.")
		for {
			select {
			case <-zonerefch: // ensure that we keep reading to keep the
				continue // channel open
			}
		}
	} else {
		log.Printf("RefreshEngine: Starting")
	}

	var upstream, zone string
	var downstreams []string
	var refresh uint32
//	var rc *RefreshCounter
	var updated bool
	var err error
	var bd BumperData
	var zr tdns.ZoneRefresher

	resetSoaSerial := viper.GetBool("service.reset_soa_serial")

	for {
		select {
		case zr = <-zonerefch:
			zone = zr.Name
			resp := tdns.RefresherResponse{
					Zone:	zr.Name,
			        }
			if zone != "" {
				if zonedata, exist := Zones.Get(zone); exist {
					log.Printf("RefreshEngine: scheduling immediate refresh for known zone '%s'",
						zone)
					if _, haveParams := refreshCounters[zone]; !haveParams {
						soa, _ := zonedata.GetSOA()
						refreshCounters[zone] = &RefreshCounter{
							Name:        zone,
							SOARefresh:  soa.Refresh,
							CurRefresh:  1, // force immediate refresh
							Upstream:    zr.Primary,
							Downstreams: zr.Notify,
							Zonefile:    zr.Zonefile,
						}
					}
					updated, err = zonedata.Refresh(zr.Force)
					if err != nil {
						log.Printf("RefreshEngine: Error from zone refresh(%s): %v",
									   zone, err)
					}


					if updated {
						if resetSoaSerial {
							zonedata.CurrentSerial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, zonedata.CurrentSerial)
						}
						zonedata.NotifyDownstreams()
					}
					log.Printf("Showing some details for zone %s:", zone)
				} else {
					log.Printf("RefreshEngine: adding the new zone '%s'", zone)
					zonedata = &tdns.ZoneData{
						ZoneName:    zone,
						ZoneStore:   zr.ZoneStore,
						Logger:      log.Default(),
						Upstream:    zr.Primary,
						Downstreams: zr.Notify,
						Zonefile:    zr.Zonefile,
						ZoneType:    zr.ZoneType,
					}
					updated, err := zonedata.Refresh(zr.Force)
					if err != nil {
						log.Printf("RefreshEngine: Error from zone refresh(%s): %v",
									   zone, err)
					}

					soa, _ := zonedata.GetSOA()
					if soa != nil {
						refresh = soa.Refresh
					}
					// Is there a max refresh counter configured, then use it.
					maxrefresh := uint32(viper.GetInt("service.maxrefresh"))
					if maxrefresh != 0 && maxrefresh < refresh {
						refresh = maxrefresh
					}
					refreshCounters[zone] = &RefreshCounter{
						Name:        zone,
						SOARefresh:  refresh,
						CurRefresh:  refresh,
						Upstream:    upstream,
						Downstreams: downstreams,
					}

					if updated {
						if resetSoaSerial {
							zonedata.CurrentSerial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, zonedata.CurrentSerial)
						}
						zonedata.NotifyDownstreams()
					}
					Zones.Set(zone, zonedata)
				}
			}
			if zr.Response != nil {
			   zd, _ := Zones.Get(zr.Name)
			   resp.Msg = fmt.Sprintf("RefreshEngine: %s zone %s refreshing (force=%v)",
			   	      				  tdns.ZoneTypeToString[zd.ZoneType], zr.Name,
								  zr.Force)
			   zr.Response <- resp
			}

		case <-ticker.C:
			// log.Printf("RefEng: ticker. refCounters: %v", refreshCounters)
			for zone, rc := range refreshCounters {
				// log.Printf("RefEng: ticker for %s: curref: %d", zone, v.CurRefresh)
				rc.CurRefresh--
				if rc.CurRefresh <= 0 {
					upstream = rc.Upstream

					log.Printf("RefreshEngine: will refresh zone %s due to refresh counter", zone)
					// log.Printf("Len(Zones) = %d", len(Zones))
					zd, _ := Zones.Get(zone)
					updated, err := zd.Refresh(false)
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
			resp := BumperResponse{
				Zone: zone,
			}
			if zone != "" {
				if zd, exist := Zones.Get(zone); exist {
					log.Printf("RefreshEngine: bumping SOA serial for known zone '%s'", zone)
					resp.OldSerial = zd.CurrentSerial
					zd.CurrentSerial++
					resp.NewSerial = zd.CurrentSerial

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
