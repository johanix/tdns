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

	core "github.com/johanix/tdns/v2/core"
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

// initialLoadZone handles the first load of a zone: refresh, counter setup,
// post-init hooks, OnFirstLoad callbacks, and downstream notification.
// Called for both newly-created zones and pre-registered zone stubs.
func initialLoadZone(ctx context.Context, zd *ZoneData, zone string, zr ZoneRefresher, conf *Config,
	refreshCounters *core.ConcurrentMap[string, *RefreshCounter],
	tryPostpass func(string), resetSoaSerial bool) (bool, error) {

	updated, err := zd.Refresh(Globals.Verbose, Globals.Debug, zr.Force, conf)
	if err != nil {
		return false, err
	}

	refresh, err := FindSoaRefresh(zd)
	if err != nil {
		lgEngine.Error("FindSoaRefresh failed", "zone", zone, "error", err)
	}
	refreshCounters.Set(zone, &RefreshCounter{
		Name:        zone,
		SOARefresh:  refresh,
		CurRefresh:  refresh,
		Upstream:    NormalizeAddress(zr.Primary),
		Downstreams: NormalizeAddresses(zr.Notify),
	})

	// Check if this is a catalog zone and parse it
	if zd.Options[OptCatalogZone] {
		lgEngine.Info("parsing catalog zone member zones", "zone", zone)
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

	// Note: SetupZoneSigning and SetupZoneSync are NOT called here.
	// For config-defined zones, they are registered as OnFirstLoad callbacks
	// in ParseZones. For dynamic zones (catalog, API), they are called
	// explicitly after initialLoadZone.

	// Execute OnFirstLoad callbacks (one-shot)
	zd.mu.Lock()
	callbacks := zd.OnFirstLoad
	zd.OnFirstLoad = nil
	zd.mu.Unlock()
	for i, cb := range callbacks {
		lgEngine.Info("executing OnFirstLoad callback", "zone", zone, "callback", i+1, "total", len(callbacks))
		cb(zd)
	}

	if updated {
		zd.LatestRefresh = time.Now()
		zd.RefreshCount++
		if zd.Error && zd.ErrorType == RefreshError {
			zd.SetError(NoError, "")
		}
		if resetSoaSerial {
			zd.CurrentSerial = uint32(time.Now().Unix())
			lgEngine.Info("zone updated from upstream, resetting serial to unixtime",
				"zone", zone, "serial", zd.CurrentSerial)
		}
		zd.NotifyDownstreams()
	}

	return updated, nil
}

func RefreshEngine(ctx context.Context, conf *Config) {

	var zonerefch = conf.Internal.RefreshZoneCh
	var bumpch = conf.Internal.BumpZoneCh

	// var refreshCounters = make(map[string]*RefreshCounter, 5)
	var refreshCounters = core.NewCmap[*RefreshCounter]()
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

	var zone string

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
					if zd.FirstZoneLoad {
						// PRE-REGISTERED STUB: zone was pre-registered with
						// OnFirstLoad callbacks but not yet loaded. Merge config
						// from ZoneRefresher, do initial load, run callbacks.
						lgEngine.Info("loading pre-registered zone", "zone", zone)

						// Only merge config from ZoneRefresher if the zd has not
						// been configured yet (ZoneType still 0). The first
						// ZoneRefresher from ParseZones has all fields set. On
						// retry (CLI reload, ticker), the zd already has config
						// from the first attempt — must not overwrite with zeros.
						if zd.ZoneType == 0 {
							dp := conf.Internal.DnssecPolicies[zr.DnssecPolicy]
							msc := conf.MultiSigner[zr.MultiSigner]

							zd.mu.Lock()
							zd.ZoneStore = zr.ZoneStore
							zd.Upstream = NormalizeAddress(zr.Primary)
							zd.Downstreams = NormalizeAddresses(zr.Notify)
							zd.Zonefile = zr.Zonefile
							zd.ZoneType = zr.ZoneType
							zd.Options = zr.Options
							zd.UpdatePolicy = zr.UpdatePolicy
							zd.DnssecPolicy = &dp
							zd.MultiSigner = &msc
							zd.DelegationSyncQ = conf.Internal.DelegationSyncQ
							zd.MusicSyncQ = conf.Internal.MusicSyncQ
							zd.SyncQ = conf.Internal.SyncQ
							zd.KeyDB = conf.Internal.KeyDB
							zd.Data = core.NewCmap[OwnerData]()
							zd.mu.Unlock()
						}

						if _, err := initialLoadZone(ctx, zd, zone, zr, conf, refreshCounters,
							tryPostpass, resetSoaSerial); err != nil {
							lgEngine.Error("zone refresh failed", "zone", zone, "error", err)
							zd.SetError(RefreshError, "refresh error: %v", err)
							zd.LatestError = time.Now()

							// Set a refresh counter so the ticker can retry.
							if _, exists := refreshCounters.Get(zone); !exists {
								refreshCounters.Set(zone, &RefreshCounter{
									Name:       zone,
									SOARefresh: 300, // 5 min fallback
									CurRefresh: 30,  // retry sooner on initial failure
								})
							}

							// Send response if someone is waiting (e.g. CLI reload)
							if zr.Response != nil {
								resp.Error = true
								resp.ErrorMsg = err.Error()
								zr.Response <- resp
							}
							continue
						}
					} else {
						// EXISTING ZONE: already loaded, normal refresh path.
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
						go func(zd *ZoneData, zone string, force bool, conf *Config, zr ZoneRefresher) {
							updated, err := zd.Refresh(Globals.Verbose, Globals.Debug, force, conf)
							if err != nil {
								lgEngine.Error("zone refresh failed", "zone", zone, "error", err)
								zd.SetError(RefreshError, "refresh error: %v", err)
								zd.LatestError = time.Now()
								// If caller requested error reporting, send the error
								if zr.Wait && zr.Response != nil {
									zr.Response <- RefresherResponse{
										Error:    true,
										ErrorMsg: err.Error(),
									}
								}
							} else {
								// Clear any previous error state after successful refresh
								if zd.Error {
									lgEngine.Info("zone refresh succeeded, clearing error state", "zone", zone, "errortype", ErrorTypeToString[zd.ErrorType])
									zd.SetError(NoError, "")
								}
								// No error from refresh - zone data is valid
								if updated {
									lgEngine.Info("zone updated via refresh", "zone", zd.ZoneName)

									// Re-sign zone after refresh (upstream data has no RRSIGs)
									if err := zd.SetupZoneSigning(conf.Internal.ResignQ); err != nil {
										lgEngine.Error("SetupZoneSigning failed after refresh", "zone", zd.ZoneName, "error", err)
									}

									// Write zone file after successful update.
									// Skip for primary zones loaded from file — rewriting the source
									// is pointless unless dynamic changes have been made (OptDirty).
									if zd.ZoneType == Primary && !zd.Options[OptDirty] {
										lgEngine.Debug("skipping zone file write for unmodified primary zone", "zone", zd.ZoneName)
									} else if conf.ShouldPersistZone(zd) && zd.Options[OptAutomaticZone] {
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
							// If caller requested error reporting, send success
							if zr.Wait && zr.Response != nil {
								zr.Response <- RefresherResponse{
									Msg: fmt.Sprintf("zone %s: reloaded (updated=%v)", zone, updated),
								}
							}
						}(zd, zone, zr.Force, conf, zr)
					}
				} else {
					// DYNAMIC ZONE: not from config (catalog member, API-created).
					// Config-defined zones are always pre-registered by ParseZones.
					lgEngine.Info("adding dynamic zone (not pre-registered)", "zone", zone)
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
						MusicSyncQ:      conf.Internal.MusicSyncQ,
						SyncQ:           conf.Internal.SyncQ,
						Data:            core.NewCmap[OwnerData](),
						KeyDB:           conf.Internal.KeyDB,
						FirstZoneLoad:   true,
					}

					Zones.Set(zone, zd)

					if _, err := initialLoadZone(ctx, zd, zone, zr, conf, refreshCounters,
						tryPostpass, resetSoaSerial); err != nil {
						lgEngine.Error("zone refresh failed", "zone", zone, "error", err)
						zd.SetError(RefreshError, "refresh error: %v", err)
						zd.LatestError = time.Now()
						continue
					}

					// Dynamic zones: set up signing if needed
					// (config zones do this via OnFirstLoad callback registered in ParseZones)
					if Globals.App.Type != AppTypeAgent {
						if err := zd.SetupZoneSigning(conf.Internal.ResignQ); err != nil {
							lgEngine.Error("SetupZoneSigning failed", "zone", zone, "error", err)
						}
					}
				}
			}
			if zr.Response != nil && !zr.Wait {
				// Only send immediate "refreshing..." when NOT in error-reporting mode.
				// When Wait is set, the goroutine sends the actual result.
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
					lgEngine.Debug("refreshing zone due to refresh counter", "zone", zone)
					// log.Printf("Len(Zones) = %d", len(Zones))
					zd, _ := Zones.Get(zone)
					if zd.Error && zd.ErrorType != RefreshError {
						lgEngine.Warn("zone in error state, not refreshing", "zone", zone, "errortype", ErrorTypeToString[zd.ErrorType], "error", zd.ErrorMsg)
						continue
					}

					// If zone never completed initial load, retry via initialLoadZone
					// to get the full treatment (callbacks, signing, sync setup).
					if zd.FirstZoneLoad {
						lgEngine.Info("retrying initial load for zone", "zone", zone)
						zd.SetError(NoError, "") // clear error to allow load
						if _, err := initialLoadZone(ctx, zd, zone, ZoneRefresher{Name: zone, Force: true}, conf,
							refreshCounters, tryPostpass, resetSoaSerial); err != nil {
							lgEngine.Error("initial load retry failed", "zone", zone, "error", err)
							zd.SetError(RefreshError, "refresh error: %v", err)
							zd.LatestError = time.Now()
						}
						rc.CurRefresh = rc.SOARefresh
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

						// Re-sign zone after refresh (upstream data has no RRSIGs)
						if err := zd.SetupZoneSigning(conf.Internal.ResignQ); err != nil {
							lgEngine.Error("SetupZoneSigning failed after refresh", "zone", zone, "error", err)
						}
					}
					if updated {
						zd.NotifyDownstreams()

						// Write zone file after successful update.
						// Skip for primary zones loaded from file — rewriting the source
						// is pointless unless dynamic changes have been made (OptDirty).
						if zd.ZoneType == Primary && !zd.Options[OptDirty] {
							lgEngine.Debug("skipping zone file write for unmodified primary zone", "zone", zd.ZoneName)
						} else if conf.ShouldPersistZone(zd) && zd.Options[OptAutomaticZone] {
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
