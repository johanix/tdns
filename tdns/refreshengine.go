/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/spf13/viper"

	cmap "github.com/orcaman/concurrent-map/v2"
)

// After all zones are initialized, (re)compute transport signals across zones to resolve cross-zone dependencies.
func runTransportSignalPostpass(conf *Config) {
	for zname, zdz := range Zones.Items() {
		if zdz != nil && zdz.Options[OptAddTransportSignal] {
			if err := zdz.CreateTransportSignalRRs(conf); err != nil {
				log.Printf("Postpass CreateTransportSignalRRs(%s): %v", zname, err)
			}
		}
	}
}

type RefreshCounter struct {
	Name           string
	SOARefresh     uint32
	CurRefresh     uint32
	IncomingSerial uint32
	Upstream       string
	Downstreams    []string
	Zonefile       string
}

func RefreshEngine(ctx context.Context, conf *Config) {

	var zonerefch = conf.Internal.RefreshZoneCh
	var bumpch = conf.Internal.BumpZoneCh

	// var refreshCounters = make(map[string]*RefreshCounter, 5)
	var refreshCounters = cmap.New[*RefreshCounter]()
	var ticker *time.Ticker

	// Build expected zone set from config for a robust post-initialization barrier
	expected := map[string]struct{}{}
	for _, zn := range conf.Internal.AllZones {
		expected[zn] = struct{}{}
	}
	tryPostpass := func(doneZone string) {
		if doneZone != "" {
			delete(expected, doneZone)
		}
		if len(expected) == 0 {
			runTransportSignalPostpass(conf)
		}
	}

	if !viper.GetBool("service.refresh") {
		log.Printf("RefreshEngine: NOT active. Will accept zone definitions but skip periodic refreshes.")
		for {
			select {
			case <-ctx.Done():
				log.Printf("RefreshEngine: terminating due to context cancelled (inactive mode)")
				return
			case <-zonerefch:
			}
			// ensure that we keep reading to keep the channel open
			continue
		}
	} else {
		ticker = time.NewTicker(1 * time.Second)
		log.Printf("RefreshEngine: Starting")
	}

	var upstream, zone string
	var downstreams []string
	// var refresh uint32
	//	var rc *RefreshCounter
	var updated bool
	var err error
	var bd BumperData

	resetSoaSerial := viper.GetBool("service.reset_soa_serial")

	for {
		select {
		case <-ctx.Done():
			log.Printf("RefreshEngine: terminating due to context cancelled")
			ticker.Stop()
			return
		case zr, ok := <-zonerefch:
			if !ok {
				log.Printf("RefreshEngine: terminating due to zonerefch closed")
				ticker.Stop()
				return
			}
			// log.Printf("***** RefreshEngine: zonerefch: zone %s", zr.Name)
			zone = zr.Name
			resp := RefresherResponse{
				Zone: zr.Name,
			}
			if zone != "" {
				if zd, exist := Zones.Get(zone); exist {
					if zd.Error && zd.ErrorType != RefreshError {
						log.Printf("RefreshEngine: Zone %s is in %s error state: %s", zone, ErrorTypeToString[zd.ErrorType], zd.ErrorMsg)
						resp.Msg = fmt.Sprintf("RefreshEngine: Zone %s is in %s error state: %s", zone, ErrorTypeToString[zd.ErrorType], zd.ErrorMsg)
						if zr.Response != nil {
							zr.Response <- resp
						}
						continue
					}
					if zd.ZoneType == Primary && zd.Options[OptDirty] {
						resp.Msg = fmt.Sprintf("RefreshEngine: Zone %s has modifications, reload not possible", zone)
						log.Printf(resp.Msg)
						if zr.Response != nil {
							zr.Response <- resp
						}
						continue
					}
					log.Printf("RefreshEngine: scheduling immediate refresh for known zone '%s'", zone)
					// if _, haveParams := refreshCounters[zone]; !haveParams {
					if _, haveParams := refreshCounters.Get(zone); !haveParams {
						var refresh uint32 = 300 // 5 minutes, must have something even if we don't get SOA
						soa, err := zd.GetSOA()
						if err != nil {
							log.Printf("RefreshEngine: Error from GetSOA(%s): %v", zone, err)
							zd.SetError(RefreshError, "get soa error: %v", err)
							zd.LatestError = time.Now()
						} else {
							refresh = soa.Refresh
						}
						refreshCounters.Set(zone, &RefreshCounter{
							Name:        zone,
							SOARefresh:  refresh,
							CurRefresh:  1, // force immediate refresh
							Upstream:    zr.Primary,
							Downstreams: zr.Notify,
							Zonefile:    zr.Zonefile,
						})
					}
					// XXX: Should do refresh in parallel
					go func(zd *ZoneData, zone string, conf *Config) {
						updated, err := zd.Refresh(Globals.Verbose, Globals.Debug, zr.Force, conf)
						if err != nil {
							log.Printf("RefreshEngine: Error from zone refresh(%s): %v", zone, err)
							zd.SetError(RefreshError, "refresh error: %v", err)
							zd.LatestError = time.Now()
						}
						if updated {
							log.Printf("Zone %s was updated via refresh operation", zd.ZoneName)
						}
					}(zd, zone, conf)

				} else {
					log.Printf("***** RefreshEngine: adding the new zone '%s'", zone)
					// XXX: We want to do this in parallel
					// go func() {
					dp := conf.Internal.DnssecPolicies[zr.DnssecPolicy]
					msc := conf.MultiSigner[zr.MultiSigner]
					zd := &ZoneData{
						ZoneName:        zone,
						ZoneStore:       zr.ZoneStore,
						Logger:          log.Default(),
						Upstream:        zr.Primary,
						Downstreams:     zr.Notify,
						Zonefile:        zr.Zonefile,
						ZoneType:        zr.ZoneType,
						Options:         zr.Options,
						UpdatePolicy:    zr.UpdatePolicy,
						DnssecPolicy:    &dp,
						MultiSigner:     &msc,
						DelegationSyncQ: conf.Internal.DelegationSyncQ,
						MusicSyncQ:      conf.Internal.MusicSyncQ, // TODO: remove this
						SyncQ:           conf.Internal.SyncQ,
						Data:            cmap.New[OwnerData](),
						KeyDB:           conf.Internal.KeyDB,
					}

					updated, err = zd.Refresh(Globals.Verbose, Globals.Debug, zr.Force, conf)
					if err != nil {
						log.Printf("RefreshEngine: Error from zone refresh(%s): %v", zone, err)
						zd.SetError(RefreshError, "refresh error: %v", err)
						zd.LatestError = time.Now()
						continue // cannot do much else
						// return // terminate goroutine
					}

					refresh, err := FindSoaRefresh(zd)
					if err != nil {
						log.Printf("Error from FindSoaRefresh(%s): %v", zone, err)
					}

					refreshCounters.Set(zone, &RefreshCounter{
						Name:        zone,
						SOARefresh:  refresh,
						CurRefresh:  refresh,
						Upstream:    upstream,
						Downstreams: downstreams,
					})

					// Register the zone before any per-zone actions.
					Zones.Set(zone, zd)

					// Defer transport signal synthesis until all zones are initialized.
					tryPostpass(zone)

					if Globals.App.Type != AppTypeAgent {
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

					if updated {
						zd.LatestRefresh = time.Now()
						zd.RefreshCount++
						if zd.Error && zd.ErrorType == RefreshError {
							zd.SetError(NoError, "")
						}
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
					if zd.Error {
						log.Printf("RefreshEngine: Zone %s is in error state: %s. Not refreshing.", zone, zd.ErrorMsg)
						continue
					}
					updated, err := zd.Refresh(Globals.Verbose, Globals.Debug, false, conf)
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
					if zd.Error {
						log.Printf("RefreshEngine: Zone %s is in error state: %s. Not bumping serial.", zone, zd.ErrorMsg)
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Zone %s is in error state: %s. Not bumping serial.", zone, zd.ErrorMsg)
						log.Printf(resp.ErrorMsg)
					}
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
