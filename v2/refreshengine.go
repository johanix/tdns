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

	core "github.com/johanix/tdns/v2/core"
)

// zoneStillLive reports whether zd is still the live, unchanged entry for its
// zone — used as the pre-persist guard (B5b) that closes the resurrection race.
// A persist must be dropped if, since the refresh was dispatched, the zone was
// removed (!live), replaced by a new ZoneData (cur != zd — e.g. ModifyDynamicZone),
// or its generation was bumped (delete/modify/config-reload). For call sites with
// no dispatch-time snapshot, pass zd.generation.Load() and the check reduces to
// the liveness+identity test.
func zoneStillLive(zd *ZoneData, gen uint64) bool {
	cur, live := Zones.Get(zd.ZoneName)
	return live && cur == zd && zd.generation.Load() == gen
}

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
	Zonefile       string
}

// initialLoadZone handles the first load of a zone: refresh, counter setup,
// post-init hooks, OnFirstLoad callbacks, and downstream notification.
// Called for both newly-created zones and pre-registered zone stubs.
func initialLoadZone(ctx context.Context, zd *ZoneData, zone string, zr ZoneRefresher, conf *Config,
	refreshCounters *core.ConcurrentMap[string, *RefreshCounter],
	tryPostpass func(string)) (bool, error) {

	updated, err := zd.Refresh(Globals.Verbose, Globals.Debug, zr.Force, conf)
	if err != nil {
		return false, err
	}

	refresh, err := FindSoaRefresh(zd)
	if err != nil {
		lgEngine.Error("FindSoaRefresh failed", "zone", zone, "error", err)
	}
	refreshCounters.Set(zone, &RefreshCounter{
		Name:       zone,
		SOARefresh: refresh,
		CurRefresh: refresh,
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
	// OnFirstLoad callbacks (incl. SetupZoneSigning from ParseZones) are
	// drained by completeFirstZonePolicyAndLoad AFTER InstallInitialSnapshot
	// and syncZoneDnssecPolicyFromConfig so the served-SOA-RRSIG backfill GATE
	// and first-sign see a Ready zone with the correct binding (#286 deferral
	// preserved; order moved post-Ready for PR-2).

	if updated {
		zd.LatestRefresh = time.Now()
		zd.RefreshCount++
		// Successful refresh clears RefreshError specifically — other
		// error categories (rollover policy, parent DSYNC blockers,
		// config errors) are independent and must survive.
		zd.ClearError(RefreshError)
		// Apply outbound_soa_serial mode for the serial we'll advertise
		// to secondaries.
		if zd.KeyDB != nil {
			serialChanged := false
			switch zd.KeyDB.OutboundSoaSerial {
			case OutboundSoaSerialUnixtime:
				zd.CurrentSerial = uint32(time.Now().Unix())
				lgEngine.Info("zone loaded; outbound_soa_serial=unixtime",
					"zone", zone, "serial", zd.CurrentSerial)
				serialChanged = true
			case OutboundSoaSerialPersist:
				// Only restore the persisted serial when it is *ahead* of
				// the freshly loaded inbound serial. If upstream advanced
				// while we were down, the inbound serial is the one to
				// honour — moving zd.CurrentSerial backwards would break
				// secondaries.
				if saved, err := zd.KeyDB.LoadOutgoingSerial(zone); err == nil && saved > zd.CurrentSerial {
					lgEngine.Info("zone loaded; outbound_soa_serial=persist (restored saved serial)",
						"zone", zone, "incoming", zd.CurrentSerial, "persisted", saved)
					zd.CurrentSerial = saved
					serialChanged = true
				}
			}
			if serialChanged {
				zd.mu.Lock()
				zd.ensureWorkingSet()
				zd.publishWorkingSetLocked(zd.generation.Load(), false)
				zd.mu.Unlock()
			}
		}
		zd.NotifyDownstreams()
	}

	return updated, nil
}

// drainAndRunOnFirstLoad clears zd.OnFirstLoad and runs the callbacks. Called
// AFTER InstallInitialSnapshot + syncZoneDnssecPolicyFromConfig on first-bind
// paths so SetupZoneSigning (registered by ParseZones) sees a Ready zone with
// the correct policy binding. Preserves the #286 one-shot deferral: callbacks
// still run once, just post-Ready rather than mid-load.
func drainAndRunOnFirstLoad(zd *ZoneData) {
	zd.mu.Lock()
	callbacks := zd.OnFirstLoad
	zd.OnFirstLoad = nil
	zd.mu.Unlock()
	for i, cb := range callbacks {
		lgEngine.Info("executing OnFirstLoad callback", "zone", zd.ZoneName, "callback", i+1, "total", len(callbacks))
		cb(zd)
	}
}

// hasPendingOnFirstLoad reports whether OnFirstLoad callbacks are still waiting
// to run (e.g. after a first-load policy sync failure). Reads under zd.mu.
func hasPendingOnFirstLoad(zd *ZoneData) bool {
	if zd == nil {
		return false
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return len(zd.OnFirstLoad) > 0
}

// finishFirstLoadPolicy is the post-Ready tail of first-bind completion: sync
// DNSSEC policy then drain OnFirstLoad. Assumes the zone is already Ready —
// does not call InstallInitialSnapshot (ticker completion retries must not
// rebuild the snapshot from zd.Data).
// On sync failure OnFirstLoad is retained for a later retry.
func finishFirstLoadPolicy(ctx context.Context, zd *ZoneData, conf *Config, configPolicyName string) error {
	if err := syncZoneDnssecPolicyFromConfig(ctx, zd, conf.Internal.KeyDB, conf, configPolicyName); err != nil {
		lgEngine.Warn("DNSSEC policy sync after first load failed", "zone", zd.ZoneName, "err", err)
		return err
	}
	drainAndRunOnFirstLoad(zd)
	return nil
}

// completeFirstZonePolicyAndLoad finishes a first-bind after initialLoadZone:
// publish the snapshot (Ready), then finishFirstLoadPolicy (sync + OnFirstLoad).
func completeFirstZonePolicyAndLoad(ctx context.Context, zd *ZoneData, conf *Config, configPolicyName string) error {
	zd.InstallInitialSnapshot()
	return finishFirstLoadPolicy(ctx, zd, conf, configPolicyName)
}

func RefreshEngine(ctx context.Context, conf *Config) {

	var zonerefch = conf.Internal.RefreshZoneCh
	var bumpch = conf.Internal.BumpZoneCh

	// var refreshCounters = make(map[string]*RefreshCounter, 5)
	var refreshCounters = core.NewCmap[*RefreshCounter]()

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

	ticker := time.NewTicker(1 * time.Second)
	lgEngine.Info("refresh engine starting")

	var zone string

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
							// Effective policy name is resolved later by
							// syncZoneDnssecPolicyFromConfig (post-Ready). Do NOT
							// bind intent here — on restart that pre-bind hides
							// applied≠intent (blocking ①). Quarantine for an
							// unresolvable intent happens inside the sync helper.
							msc := ConfLive().MultiSigner[zr.MultiSigner]

							zd.mu.Lock()
							zd.ZoneStore = zr.ZoneStore
							if len(zr.PrimariesConf) > 0 {
								zd.PrimariesConf = clonePeerConfs(zr.PrimariesConf)
								zd.Upstreams = clonePeerConfs(zr.Primaries)
							}
							zd.Notify = normalizePeerAddrs(zr.Notify)
							zd.AllowNotify = zr.AllowNotify
							zd.Downstreams = zr.Downstreams
							zd.Zonefile = zr.Zonefile
							zd.ZoneType = zr.ZoneType
							zd.Options = zr.Options
							zd.UpdatePolicy = zr.UpdatePolicy
							// Record the config-base policy name only (no struct bind).
							// syncZoneDnssecPolicyFromConfig binds post-Ready; this
							// name survives a failed first load so ticker retry can
							// still resolve intent.
							zd.DnssecPolicyName = zr.DnssecPolicy
							zd.MultiSigner = &msc
							zd.DelegationSyncQ = conf.Internal.DelegationSyncQ
							zd.KeyDB = conf.Internal.KeyDB
							zd.Data = core.NewCmap[OwnerData]()
							zd.mu.Unlock()
						}

						if _, err := initialLoadZone(ctx, zd, zone, zr, conf, refreshCounters,
							tryPostpass); err != nil {
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
						if err := completeFirstZonePolicyAndLoad(ctx, zd, conf, zr.DnssecPolicy); err != nil {
							lgEngine.Error("zone policy sync after first load failed", "zone", zone, "error", err)
							zd.SetError(DnssecPolicyWarning, "DNSSEC policy sync failed: %v", err)
							zd.LatestError = time.Now()
							if _, exists := refreshCounters.Get(zone); !exists {
								refreshCounters.Set(zone, &RefreshCounter{
									Name:       zone,
									SOARefresh: 300,
									CurRefresh: 30,
								})
							}
							if zr.Response != nil {
								resp.Error = true
								resp.ErrorMsg = err.Error()
								zr.Response <- resp
							}
							continue
						}
					} else {
						// EXISTING ZONE: already loaded, normal refresh path.
						if zd.HasServiceImpactingError() {
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
						// Notify + ACLs. For a config-bearing refresher (reload),
						// assign even when nil/empty so a config that REMOVES a notify
						// list or an ACL actually clears it (empty downstreams => deny,
						// empty allow-notify => fall back to primaries) instead of
						// leaving stale permissions. A NOTIFY/refresh-only trigger
						// (ConfigUpdate=false) carries none of these and must not touch
						// them.
						if zr.ConfigUpdate {
							zd.Notify = normalizePeerAddrs(zr.Notify)
							zd.AllowNotify = zr.AllowNotify
							zd.Downstreams = zr.Downstreams
						} else if zr.Notify != nil {
							zd.Notify = normalizePeerAddrs(zr.Notify)
						}
						// Update primaries only if provided (config-bearing refresher).
						if len(zr.PrimariesConf) > 0 {
							zd.PrimariesConf = clonePeerConfs(zr.PrimariesConf)
							zd.Upstreams = clonePeerConfs(zr.Primaries)
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
						// Lookup MultiSigner from config. DNSSEC policy sync runs
						// AFTER unlock via syncZoneDnssecPolicyFromConfig (applied
						// vs intent; replaces applyReloadedPolicyLocked).
						if zr.MultiSigner != "" {
							if msc, exists := ConfLive().MultiSigner[zr.MultiSigner]; exists {
								zd.MultiSigner = &msc
							} else {
								lgEngine.Warn("MultiSigner config not found, keeping existing", "multisigner", zr.MultiSigner, "zone", zone)
							}
						}
						zd.mu.Unlock()

						// Policy sync only on config-bearing refreshers (same gate
						// as notify/ACL). NOTIFY/CLI refreshes must not re-run
						// resolve→backfill→classify→apply. First-load OnFirstLoad
						// completion retries on the ticker (hasPendingOnFirstLoad),
						// not here.
						if zr.ConfigUpdate && (zr.DnssecPolicy != "" || zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]) {
							if err := syncZoneDnssecPolicyFromConfig(ctx, zd, conf.Internal.KeyDB, conf, zr.DnssecPolicy); err != nil {
								lgEngine.Warn("DNSSEC policy sync on reload failed", "zone", zone, "err", err)
								if zr.Response != nil {
									resp.Error = true
									resp.ErrorMsg = fmt.Sprintf("DNSSEC policy sync failed: %v", err)
									zr.Response <- resp
								}
								continue
							}
						}
						lgEngine.Debug("updated configuration for zone", "zone", zone, "notify", zd.Notify, "primaries", zd.PrimariesConf, "upstreams", zd.Upstreams, "zonefile", zd.Zonefile, "store", ZoneStoreToString[zd.ZoneStore])

						// Update or create refreshCounter with current config values
						var refresh uint32 = 300 // 5 minutes, must have something even if we don't get SOA
						soa, err := zd.GetSOA()
						if err != nil {
							lgEngine.Error("GetSOA failed", "zone", zone, "error", err)
							zd.SetError(RefreshError, "get soa error: %v", err)
							zd.LatestError = time.Now()
						} else if soa != nil {
							refresh = soa.Refresh
						}
						if rc, haveParams := refreshCounters.Get(zone); haveParams {
							// Update existing refreshCounter with new config values
							rc.Zonefile = zr.Zonefile
							rc.SOARefresh = refresh
							rc.CurRefresh = refresh // immediate refresh handled by goroutine below
						} else {
							// Create new refreshCounter
							refreshCounters.Set(zone, &RefreshCounter{
								Name:       zone,
								SOARefresh: refresh,
								CurRefresh: refresh, // immediate refresh handled by goroutine below
								Zonefile:   zr.Zonefile,
							})
						}
						// XXX: Should do refresh in parallel
						go func(zd *ZoneData, zone string, force bool, conf *Config, zr ZoneRefresher) {
							// Snapshot the generation at dispatch. The pre-persist
							// guard below drops the persist if the zone was deleted
							// or replaced mid-refresh (generation bumped), closing
							// the resurrection race (B5b).
							gen := zd.generation.Load()
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
								// Clear refresh-specific error state after successful refresh.
								// Other categories (rollover-policy, parent-DSYNC, config) are
								// independent and survive a successful refresh.
								if zd.HasError(RefreshError) {
									lgEngine.Info("zone refresh succeeded, clearing RefreshError", "zone", zone)
									zd.ClearError(RefreshError)
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
									} else if conf.ShouldPersistZone(zd) && zoneStillLive(zd, gen) {
										// Any persistable dynamic zone (catalog zone, catalog
										// member, or API-managed — B5a widened this beyond
										// OptAutomaticZone so API zones rewrite their files too).
										// zoneStillLive guards the resurrection race: if the
										// zone was deleted or replaced mid-refresh, skip the
										// persist so we do not re-write a removed zone (B5b).
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
									if len(zd.Notify) > 0 {
										lgEngine.Info("zone refreshed, sending NOTIFY to downstreams", "zone", zd.ZoneName, "updated", updated, "forced", force, "downstreams", len(zd.Notify))
										conf.Internal.NotifyQ <- NotifyRequest{
											ZoneName: zd.ZoneName,
											ZoneData: zd,
											RRtype:   dns.TypeSOA,
											Targets:  peerAddrs(zd.Notify),
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
					// Do not bind DNSSEC policy pre-load (blocking ①); sync runs
					// post-Ready via completeFirstZonePolicyAndLoad.
					msc := ConfLive().MultiSigner[zr.MultiSigner]
					// Resolution happens at every ingress path (parse/load/add/
					// modify/catalog), so a config-bearing refresher always carries
					// the resolved Primaries alongside the as-written PrimariesConf.
					primariesConf := clonePeerConfs(zr.PrimariesConf)
					upstreams := clonePeerConfs(zr.Primaries)
					zd := &ZoneData{
						ZoneName:         zone,
						ZoneStore:        zr.ZoneStore,
						Logger:           log.Default(),
						PrimariesConf:    primariesConf,
						Upstreams:        upstreams,
						Notify:           normalizePeerAddrs(zr.Notify),
						AllowNotify:      zr.AllowNotify,
						Downstreams:      zr.Downstreams,
						Zonefile:         zr.Zonefile,
						ZoneType:         zr.ZoneType,
						Options:          zr.Options,
						UpdatePolicy:     zr.UpdatePolicy,
						DnssecPolicyName: zr.DnssecPolicy, // config-base hint; struct bound post-Ready
						MultiSigner:      &msc,
						DelegationSyncQ:  conf.Internal.DelegationSyncQ,
						Data:             core.NewCmap[OwnerData](),
						KeyDB:            conf.Internal.KeyDB,
						FirstZoneLoad:    true,
						Status:           ZoneStatusPending, // registered + enqueued, no data yet (B6)
					}

					Zones.Set(zone, zd)

					if _, err := initialLoadZone(ctx, zd, zone, zr, conf, refreshCounters,
						tryPostpass); err != nil {
						lgEngine.Error("zone refresh failed", "zone", zone, "error", err)
						zd.SetError(RefreshError, "refresh error: %v", err)
						zd.LatestError = time.Now()
						continue
					}

					zd.InstallInitialSnapshot()
					// Dynamic zones historically called SetupZoneSigning inline
					// (not via OnFirstLoad). Register it on OnFirstLoad so a
					// sync failure is retryable by the ticker completion path
					// (hasPendingOnFirstLoad → finishFirstLoadPolicy) the same
					// way as config zones. Agent: empty marker so policy sync
					// still retries without signing.
					zd.mu.Lock()
					if Globals.App.Type != AppTypeAgent {
						resignQ := conf.Internal.ResignQ
						zd.OnFirstLoad = append(zd.OnFirstLoad, func(z *ZoneData) {
							if err := z.SetupZoneSigning(resignQ); err != nil {
								lgEngine.Error("SetupZoneSigning failed", "zone", z.ZoneName, "error", err)
							}
						})
					} else if len(zd.OnFirstLoad) == 0 {
						zd.OnFirstLoad = append(zd.OnFirstLoad, func(*ZoneData) {})
					}
					zd.mu.Unlock()
					if err := finishFirstLoadPolicy(ctx, zd, conf, zr.DnssecPolicy); err != nil {
						lgEngine.Warn("DNSSEC policy sync for dynamic zone failed", "zone", zone, "err", err)
						zd.SetError(DnssecPolicyWarning, "DNSSEC policy sync failed: %v", err)
						zd.LatestError = time.Now()
						// OnFirstLoad retained — ticker completion retry will finish.
						if _, exists := refreshCounters.Get(zone); !exists {
							refreshCounters.Set(zone, &RefreshCounter{
								Name:       zone,
								SOARefresh: 300,
								CurRefresh: 30,
							})
						}
						if zr.Response != nil {
							resp.Error = true
							resp.ErrorMsg = err.Error()
							zr.Response <- resp
						}
						continue
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
					zd, ok := Zones.Get(zone)
					if !ok || zd == nil {
						// Zone was deleted (RemoveDynamicZone / config reload)
						// after its counter was created. Drop the orphaned counter
						// so we never dereference a missing entry on the next tick.
						lgEngine.Debug("ticker: zone gone, dropping stale refresh counter", "zone", zone)
						refreshCounters.Remove(zone)
						continue
					}
					if zd.HasServiceImpactingError() {
						lgEngine.Warn("zone in error state, not refreshing", "zone", zone, "errortype", ErrorTypeToString[zd.ErrorType], "error", zd.ErrorMsg)
						continue
					}

					// If zone never completed initial load, retry via initialLoadZone
					// to get the full treatment (callbacks, signing, sync setup).
					if zd.FirstZoneLoad {
						lgEngine.Info("retrying initial load for zone", "zone", zone)
						// Clear RefreshError to allow the retry. Other categories
						// (rollover-policy, config) are independent and survive.
						zd.ClearError(RefreshError)
						if _, err := initialLoadZone(ctx, zd, zone, ZoneRefresher{Name: zone, Force: true}, conf,
							refreshCounters, tryPostpass); err != nil {
							lgEngine.Error("initial load retry failed", "zone", zone, "error", err)
							zd.SetError(RefreshError, "refresh error: %v", err)
							zd.LatestError = time.Now()
						} else {
							if err := completeFirstZonePolicyAndLoad(ctx, zd, conf, zd.DnssecPolicyName); err != nil {
								lgEngine.Error("initial load retry: policy sync failed", "zone", zone, "error", err)
								zd.SetError(DnssecPolicyWarning, "DNSSEC policy sync failed: %v", err)
								zd.LatestError = time.Now()
								rc.CurRefresh = 30 // retry sooner
								continue
							}
						}
						rc.CurRefresh = rc.SOARefresh
						continue
					}

					// Data loaded + Ready, but first-load policy sync/drain did
					// not finish (OnFirstLoad retained). Retry only that — no
					// re-Refresh, no re-InstallInitialSnapshot.
					if hasPendingOnFirstLoad(zd) {
						if err := finishFirstLoadPolicy(ctx, zd, conf, zd.DnssecPolicyName); err != nil {
							lgEngine.Warn("first-load policy completion retry failed", "zone", zone, "err", err)
							zd.SetError(DnssecPolicyWarning, "DNSSEC policy sync failed: %v", err)
							zd.LatestError = time.Now()
							rc.CurRefresh = 30
							continue
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
						// Successful refresh clears RefreshError. Other categories
						// (rollover-policy, parent-DSYNC, config) survive.
						zd.ClearError(RefreshError)
						// Apply outbound_soa_serial mode after upstream refresh.
						if zd.KeyDB != nil {
							serialChanged := false
							switch zd.KeyDB.OutboundSoaSerial {
							case OutboundSoaSerialUnixtime:
								zd.CurrentSerial = uint32(time.Now().Unix())
								lgEngine.Info("zone updated from upstream; outbound_soa_serial=unixtime",
									"zone", zone, "serial", zd.CurrentSerial)
								serialChanged = true
							case OutboundSoaSerialPersist:
								// Only restore if the persisted serial is
								// ahead of the just-refreshed inbound
								// serial. See the matching note in the
								// initial-load branch above.
								if saved, err := zd.KeyDB.LoadOutgoingSerial(zone); err == nil && saved > zd.CurrentSerial {
									zd.CurrentSerial = saved
									serialChanged = true
								}
							}
							if serialChanged {
								zd.mu.Lock()
								zd.ensureWorkingSet()
								zd.publishWorkingSetLocked(zd.generation.Load(), false)
								zd.mu.Unlock()
							}
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
						} else if conf.ShouldPersistZone(zd) && zoneStillLive(zd, zd.generation.Load()) {
							// Any persistable dynamic zone (catalog zone, catalog
							// member, or API-managed — B5a widened this beyond
							// OptAutomaticZone so API zones rewrite their files too).
							// zoneStillLive guards against a delete landing mid-tick:
							// zd is the current map entry here, so the check reduces
							// to the identity test (B5b).
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

// Compile-time bounds applied when service.minrefresh / service.maxrefresh
// are not configured. They protect against pathological SOA Refresh values
// (e.g. a 1-second refresh from a misconfigured upstream, or a 30-day SOA
// that effectively disables secondary refreshes).
const (
	defaultMinRefresh uint32 = 60       // 1 minute
	defaultMaxRefresh uint32 = 8 * 3600 // 8 hours
)

func FindSoaRefresh(zd *ZoneData) (uint32, error) {
	var refresh uint32
	soa, _ := zd.GetSOA()
	if soa != nil {
		refresh = soa.Refresh
	}

	// Primaries reload from file on SIGHUP; refresh just controls how
	// often we re-stat. 24h is plenty.
	if zd.ZoneType == Primary {
		return 86400, nil
	}

	// Use signed-int reads + a positive-value gate so a negative
	// value in the config falls back to the default rather than
	// wrapping to ~4 billion seconds via the uint32 cast.
	maxrefresh := defaultMaxRefresh
	if cfg := ConfLive().MaxRefresh; cfg > 0 {
		maxrefresh = uint32(cfg)
	}
	if maxrefresh < refresh {
		refresh = maxrefresh
	}

	minrefresh := defaultMinRefresh
	if cfg := ConfLive().MinRefresh; cfg > 0 {
		minrefresh = uint32(cfg)
	}
	if minrefresh > refresh {
		refresh = minrefresh
	}
	return refresh, nil
}
