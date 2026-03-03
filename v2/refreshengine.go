/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"

	cmap "github.com/orcaman/concurrent-map/v2"
)

// After all zones are initialized, (re)compute transport signals across zones to resolve cross-zone dependencies.
func runTransportSignalPostpass(conf *Config) {
	for zname, zdz := range Zones.Items() {
		if zdz != nil && zdz.Options[OptAddTransportSignal] {
			if err := zdz.CreateTransportSignalRRs(conf); err != nil {
				lgEngine.Error("postpass CreateTransportSignalRRs failed", "zone", zname, "error", err)
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
		lgEngine.Info("refresh engine not active, will accept zone definitions but skip periodic refreshes")
		for {
			select {
			case <-ctx.Done():
				lgEngine.Info("terminating (inactive mode)", "reason", "context cancelled")
				return
			case <-zonerefch:
			}
			// ensure that we keep reading to keep the channel open
			continue
		}
	} else {
		ticker = time.NewTicker(1 * time.Second)
		lgEngine.Info("refresh engine starting")
	}

	var upstream, zone string
	var downstreams []string
	// var refresh uint32
	//	var rc *RefreshCounter
	var updated bool
	var err error
	// var bd BumperData

	resetSoaSerial := viper.GetBool("service.reset_soa_serial")

	for {
		select {
		case <-ctx.Done():
			lgEngine.Info("refresh engine terminating", "reason", "context cancelled")
			ticker.Stop()
			return
		case zr, ok := <-zonerefch:
			if !ok {
				lgEngine.Info("refresh engine terminating", "reason", "zonerefch closed")
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
						lgEngine.Warn("zone in error state", "zone", zone, "errortype", ErrorTypeToString[zd.ErrorType], "error", zd.ErrorMsg)
						resp.Msg = fmt.Sprintf("RefreshEngine: Zone %s is in %s error state: %s", zone, ErrorTypeToString[zd.ErrorType], zd.ErrorMsg)
						if zr.Response != nil {
							zr.Response <- resp
						}
						continue
					}
					if zd.ZoneType == Primary && zd.Options[OptDirty] {
						resp.Msg = fmt.Sprintf("RefreshEngine: Zone %s has modifications, reload not possible", zone)
						lgEngine.Warn("zone has modifications, reload not possible", "zone", zone)
						if zr.Response != nil {
							zr.Response <- resp
						}
						continue
					}
					lgEngine.Debug("scheduling immediate refresh for known zone", "zone", zone)
					// Update configuration fields from ZoneRefresher for existing zones
					// This ensures that config reload (reload-zones, zone reload) picks up changes to:
					// notify addresses, upstream, zonefile, zone store, options, update policy, DNSSEC policy, etc.
					// Only update fields that are actually set in ZoneRefresher (non-zero/non-empty values)
					zd.mu.Lock()
					// Update notify addresses only if provided
					if zr.Notify != nil {
						zd.Downstreams = NormalizeAddresses(zr.Notify)
					}
					// Update upstream only if provided
					if zr.Primary != "" {
						zd.Upstream = NormalizeAddress(zr.Primary)
					}
					// Update zonefile only if provided
					if zr.Zonefile != "" {
						zd.Zonefile = zr.Zonefile
					}
					// Update ZoneStore only if provided (non-zero value)
					if zr.ZoneStore != 0 {
						zd.ZoneStore = zr.ZoneStore
					}
					// Replace options only if provided (don't merge) to match config reload behavior
					if zr.Options != nil {
						zd.Options = zr.Options
					}
					// Update UpdatePolicy only if provided (check if it has meaningful content)
					// UpdatePolicy is a struct, so we check if any fields are set
					if zr.UpdatePolicy.Child.Type != "" || zr.UpdatePolicy.Zone.Type != "" || zr.UpdatePolicy.Validate {
						zd.UpdatePolicy = zr.UpdatePolicy
					}
					// Update ZoneType only if provided (non-zero value)
					if zr.ZoneType != 0 {
						if zd.ZoneType != zr.ZoneType {
							lgEngine.Info("zone type changed", "zone", zone, "from", ZoneTypeToString[zd.ZoneType], "to", ZoneTypeToString[zr.ZoneType])
						}
						zd.ZoneType = zr.ZoneType
					}
					// Lookup DNSSEC policy and MultiSigner from config (same as new zone creation)
					if zr.DnssecPolicy != "" {
						if dp, exists := conf.Internal.DnssecPolicies[zr.DnssecPolicy]; exists {
							zd.DnssecPolicy = &dp
						} else {
							lgEngine.Warn("DNSSEC policy not found, keeping existing", "policy", zr.DnssecPolicy, "zone", zone)
						}
					}
					if zr.MultiSigner != "" {
						if msc, exists := conf.MultiSigner[zr.MultiSigner]; exists {
							zd.MultiSigner = &msc
						} else {
							lgEngine.Warn("MultiSigner config not found, keeping existing", "multisigner", zr.MultiSigner, "zone", zone)
						}
					}
					zd.mu.Unlock()
					lgEngine.Debug("updated configuration for zone", "zone", zone, "notify", zd.Downstreams, "upstream", zd.Upstream, "zonefile", zd.Zonefile, "store", ZoneStoreToString[zd.ZoneStore])

					// Update or create refreshCounter with current config values
					var refresh uint32 = 300 // 5 minutes, must have something even if we don't get SOA
					soa, err := zd.GetSOA()
					if err != nil {
						lgEngine.Error("GetSOA failed", "zone", zone, "error", err)
						zd.SetError(RefreshError, "get soa error: %v", err)
						zd.LatestError = time.Now()
					} else {
						refresh = soa.Refresh
					}
					if rc, haveParams := refreshCounters.Get(zone); haveParams {
						// Update existing refreshCounter with new config values
						rc.Upstream = NormalizeAddress(zr.Primary)
						rc.Downstreams = NormalizeAddresses(zr.Notify)
						rc.Zonefile = zr.Zonefile
						rc.SOARefresh = refresh
						rc.CurRefresh = refresh // immediate refresh handled by goroutine below
					} else {
						// Create new refreshCounter
						refreshCounters.Set(zone, &RefreshCounter{
							Name:        zone,
							SOARefresh:  refresh,
							CurRefresh:  refresh, // immediate refresh handled by goroutine below
							Upstream:    NormalizeAddress(zr.Primary),
							Downstreams: NormalizeAddresses(zr.Notify),
							Zonefile:    zr.Zonefile,
						})
					}
					// XXX: Should do refresh in parallel
					go func(zd *ZoneData, zone string, force bool, conf *Config) {
						updated, err := zd.Refresh(Globals.Verbose, Globals.Debug, force, conf)
						if err != nil {
							lgEngine.Error("zone refresh failed", "zone", zone, "error", err)
							zd.SetError(RefreshError, "refresh error: %v", err)
							zd.LatestError = time.Now()
						} else {
							// Clear any previous error state after successful refresh
							if zd.Error {
								lgEngine.Info("zone refresh succeeded, clearing error state", "zone", zone, "errortype", ErrorTypeToString[zd.ErrorType])
								zd.SetError(NoError, "")
							}
							// No error from refresh - zone data is valid
							if updated {
								lgEngine.Info("zone updated via refresh", "zone", zd.ZoneName)

								// Write zone file after successful update
								// Two cases:
								// 1. Auto-configured zones -> write to dynamic zone directory
								// 2. Regular zones with zonefile configured -> write to configured file
								if conf.ShouldPersistZone(zd) && zd.Options[OptAutomaticZone] {
									// Auto-configured catalog member zone
									_, err := zd.WriteDynamicZoneFile(conf.DynamicZones.ZoneDirectory)
									if err != nil {
										lgEngine.Warn("failed to write dynamic zone file", "zone", zd.ZoneName, "error", err)
										// Don't fail the operation, just log the warning
									}

									// Update dynamic config file (zone file path may have changed, or this is first write)
									if err := conf.AddDynamicZoneToConfig(zd); err != nil {
										lgEngine.Warn("failed to update dynamic config file", "zone", zd.ZoneName, "error", err)
										// Don't fail the operation, just log the warning
									}
								} else if zd.Zonefile != "" {
									// Regular zone with zonefile configured (typically secondary zones)
									lgEngine.Info("writing updated zone to file", "zone", zd.ZoneName, "file", zd.Zonefile)
									_, err := zd.WriteFile(zd.Zonefile)
									if err != nil {
										lgEngine.Warn("failed to write zone file", "zone", zd.ZoneName, "error", err)
									}
								}
							}

							// Send NOTIFY to downstreams after successful refresh (updated OR forced)
							// Force typically means "config reload-zones", so we want to notify even if unchanged
							if updated || force {
								if len(zd.Downstreams) > 0 {
									lgEngine.Info("zone refreshed, sending NOTIFY to downstreams", "zone", zd.ZoneName, "updated", updated, "forced", force, "downstreams", len(zd.Downstreams))
									conf.Internal.NotifyQ <- NotifyRequest{
										ZoneName: zd.ZoneName,
										ZoneData: zd,
										RRtype:   dns.TypeSOA,
										Targets:  zd.Downstreams,
										Urgent:   false,
									}
								}
							}

							// Parse catalog zones after EVERY successful refresh (updated or not)
							// This ensures membership is populated even if zone file hasn't changed
							if zd.Options[OptCatalogZone] {
								lgEngine.Info("parsing catalog zone member zones", "zone", zone, "updated", updated)
								catalogUpdate, err := ParseCatalogZone(zd)
								if err != nil {
									lgEngine.Error("failed to parse catalog zone", "zone", zone, "error", err)
								} else {
									lgEngine.Info("parsed catalog zone", "zone", zone, "members", len(catalogUpdate.MemberZones), "serial", catalogUpdate.Serial)

									// Notify all registered callbacks
									if err := NotifyCatalogZoneUpdate(catalogUpdate); err != nil {
										lgEngine.Error("failed to notify catalog zone callbacks", "error", err)
									} else {
										lgEngine.Debug("notified catalog zone callbacks")
									}

									// Auto-configure zones if enabled (in goroutine to avoid blocking on RefreshZoneCh send)
									// Policy is now per-catalog-zone via catalog-member-auto-create option
									go func(update *CatalogZoneUpdate, c *Config, refreshCtx context.Context) {
										defer func() {
											if r := recover(); r != nil {
												lgEngine.Error("panic in catalog auto-configure goroutine", "panic", r)
											}
										}()
										if err := AutoConfigureZonesFromCatalog(refreshCtx, update, c); err != nil {
											lgEngine.Error("failed to auto-configure zones from catalog", "error", err)
										}
									}(catalogUpdate, conf, ctx)
								}
							}
						}
					}(zd, zone, zr.Force, conf)

				} else {
					lgEngine.Info("adding new zone", "zone", zone)
					// XXX: We want to do this in parallel
					// go func() {
					dp := conf.Internal.DnssecPolicies[zr.DnssecPolicy]
					msc := conf.MultiSigner[zr.MultiSigner]
					zd := &ZoneData{
						ZoneName:        zone,
						ZoneStore:       zr.ZoneStore,
						Logger:          log.Default(),
						Upstream:        NormalizeAddress(zr.Primary),
						Downstreams:     NormalizeAddresses(zr.Notify),
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
						FirstZoneLoad:   true,
					}

					updated, err = zd.Refresh(Globals.Verbose, Globals.Debug, zr.Force, conf)
					if err != nil {
						lgEngine.Error("zone refresh failed", "zone", zone, "error", err)
						zd.SetError(RefreshError, "refresh error: %v", err)
						zd.LatestError = time.Now()
						continue // cannot do much else
						// return // terminate goroutine
					}

					refresh, err := FindSoaRefresh(zd)
					if err != nil {
						lgEngine.Error("FindSoaRefresh failed", "zone", zone, "error", err)
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

					// Check if this is a catalog zone and parse it (for new zones)
					if zd.Options[OptCatalogZone] {
						lgEngine.Info("new zone is a catalog zone, parsing member zones", "zone", zone)
						catalogUpdate, err := ParseCatalogZone(zd)
						if err != nil {
							lgEngine.Error("failed to parse catalog zone", "zone", zone, "error", err)
						} else {
							lgEngine.Info("parsed catalog zone", "zone", zone, "members", len(catalogUpdate.MemberZones), "serial", catalogUpdate.Serial)

							// Notify all registered callbacks
							if err := NotifyCatalogZoneUpdate(catalogUpdate); err != nil {
								lgEngine.Error("failed to notify catalog zone callbacks", "error", err)
							} else {
								lgEngine.Debug("notified catalog zone callbacks")
							}

							// Auto-configure zones if enabled (in goroutine to avoid blocking on RefreshZoneCh send)
							// Policy is now per-catalog-zone via catalog-member-auto-create option
							go func(update *CatalogZoneUpdate, c *Config, refreshCtx context.Context) {
								defer func() {
									if r := recover(); r != nil {
										lgEngine.Error("panic in catalog auto-configure goroutine", "panic", r)
									}
								}()
								if err := AutoConfigureZonesFromCatalog(refreshCtx, update, c); err != nil {
									lgEngine.Error("failed to auto-configure zones from catalog", "error", err)
								}
							}(catalogUpdate, conf, ctx)
						}
					}

					// Defer transport signal synthesis until all zones are initialized.
					tryPostpass(zone)

					if Globals.App.Type != AppTypeAgent {
						err = zd.SetupZoneSigning(conf.Internal.ResignQ)
						if err != nil {
							lgEngine.Error("SetupZoneSigning failed", "zone", zone, "error", err)
						}
					}

					// This is a new zone being added to the server. Let's see if the zone
					// config should cause any specific changes to the zone data to be made.
					err = zd.SetupZoneSync(conf.Internal.DelegationSyncQ)
					if err != nil {
						lgEngine.Error("SetupZoneSync failed", "zone", zone, "error", err)
					}

					if updated {
						zd.LatestRefresh = time.Now()
						zd.RefreshCount++
						if zd.Error && zd.ErrorType == RefreshError {
							zd.SetError(NoError, "")
						}
						if resetSoaSerial {
							zd.CurrentSerial = uint32(time.Now().Unix())
							lgEngine.Info("zone updated from upstream, resetting serial to unixtime", "zone", zone, "serial", zd.CurrentSerial)
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

					lgEngine.Debug("refreshing zone due to refresh counter", "zone", zone)
					// log.Printf("Len(Zones) = %d", len(Zones))
					zd, _ := Zones.Get(zone)
					if zd.Error {
						lgEngine.Warn("zone in error state, not refreshing", "zone", zone, "error", zd.ErrorMsg)
						continue
					}
					updated, err := zd.Refresh(Globals.Verbose, Globals.Debug, false, conf)
					rc.CurRefresh = rc.SOARefresh
					if err != nil {
						lgEngine.Error("zone refresh failed", "zone", zone, "error", err)
						zd.SetError(RefreshError, "refresh error: %v", err)
						zd.LatestError = time.Now()
					} else if updated {
						// Clear error state on successful refresh
						if zd.Error && zd.ErrorType == RefreshError {
							zd.SetError(NoError, "")
						}
						if resetSoaSerial {
							zd.CurrentSerial = uint32(time.Now().Unix())
							lgEngine.Info("zone updated from upstream, resetting serial to unixtime", "zone", zone, "serial", zd.CurrentSerial)

						}
					}
					if updated {
						zd.NotifyDownstreams()

						// Write zone file after successful update
						// Two cases:
						// 1. Auto-configured zones -> write to dynamic zone directory
						// 2. Regular zones with zonefile configured -> write to configured file
						if conf.ShouldPersistZone(zd) && zd.Options[OptAutomaticZone] {
							// Auto-configured catalog member zone
							_, err := zd.WriteDynamicZoneFile(conf.DynamicZones.ZoneDirectory)
							if err != nil {
								lgEngine.Warn("failed to write dynamic zone file", "zone", zd.ZoneName, "error", err)
								// Don't fail the operation, just log the warning
							}

							// Update dynamic config file (zone file path may have changed, or this is first write)
							if err := conf.AddDynamicZoneToConfig(zd); err != nil {
								lgEngine.Warn("failed to update dynamic config file", "zone", zd.ZoneName, "error", err)
								// Don't fail the operation, just log the warning
							}
						} else if zd.Zonefile != "" {
							// Regular zone with zonefile configured (typically secondary zones)
							lgEngine.Info("writing updated zone to file", "zone", zd.ZoneName, "file", zd.Zonefile)
							_, err := zd.WriteFile(zd.Zonefile)
							if err != nil {
								lgEngine.Warn("failed to write zone file", "zone", zd.ZoneName, "error", err)
							}
						}
					}
				}
			}

		case bd, ok := <-bumpch:
			if !ok {
				lgEngine.Info("refresh engine terminating", "reason", "bumpch closed")
				ticker.Stop()
				return
			}
			zone = bd.Zone
			resp := BumperResponse{}
			var err error
			if zone != "" {
				if zd, exist := Zones.Get(zone); exist {
					if zd.Error {
						lgEngine.Warn("zone in error state, not bumping serial", "zone", zone, "error", zd.ErrorMsg)
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Zone %s is in error state: %s. Not bumping serial.", zone, zd.ErrorMsg)
						lgEngine.Warn(resp.ErrorMsg)
						// do not bump serial when in error state
						if bd.Result != nil {
							select {
							case bd.Result <- resp:
							case <-ctx.Done():
							}
						}
						continue
					}
					resp, err = zd.BumpSerial()
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Error bumping SOA serial for zone '%s': %v", zone, err)
						lgEngine.Error("failed to bump SOA serial", "zone", zone, "error", err)
					}
					lgEngine.Debug("bumping SOA serial", "zone", zone)
				} else {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Request to bump serial for unknown zone '%s'", zone)
					lgEngine.Warn("request to bump serial for unknown zone", "zone", zone)
				}
			}
			if bd.Result != nil {
				select {
				case bd.Result <- resp:
				case <-ctx.Done():
				}
			}
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
