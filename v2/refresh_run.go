/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"time"
)

// refreshJob is one zone's refresh, described completely enough that it can be
// performed away from the engine goroutine.
//
// gen is the zone's generation READ AT DISPATCH. It is not a detail: the persist
// steps are gated on zoneStillLive(zd, gen), which is what stops a zone deleted
// or replaced mid-refresh from being written back to disk (B5b). Reading the
// generation inside the refresh instead would compare the zone against itself
// and the guard would silently pass.
type refreshJob struct {
	zd    *ZoneData
	zone  string
	gen   uint64
	force bool
	// zr carries the operator's request, when there is one: a CLI reload or an
	// API call waiting for a result. nil for a ticker-originated refresh.
	zr *ZoneRefresher
	// gate caps concurrent inbound transfers. Set by the pool on dispatch; nil
	// means ungated, which is what first load and tests get.
	gate *transferGate
}

// runZoneRefresh performs one complete refresh of a zone and everything that
// must follow it.
//
// This is the union of two bodies that had drifted apart -- the operator path's
// and the ticker's -- and the drift was not cosmetic. Row by row, the version
// kept here is the one that was right:
//
//   - RefreshError is cleared on ANY successful refresh, not only on one that
//     changed something. The ticker cleared it only under `updated`, so a zone
//     whose primary came back but whose serial had not moved stayed marked
//     failed until the serial next changed. A recovered zone reporting as
//     broken, indefinitely.
//   - The outbound-soa-serial modes, and the DeleteOutgoingSerial that a
//     mirroring secondary needs, come from the ticker: the operator path never
//     had them, so a forced reload of a unixtime zone silently stopped
//     advancing its outbound serial.
//   - The catalog re-parse comes from the operator path: the ticker never had
//     it, so catalog membership went stale on every timer-driven refresh.
//   - The persist guard uses the DISPATCH-time generation from both. The ticker
//     read it live, which was correct only because it ran inline.
//
// Every step in it can block. It must not run on the engine goroutine.
func runZoneRefresh(ctx context.Context, job refreshJob, conf *Config) (bool, error) {
	zd, zone := job.zd, job.zone

	updated, err := zd.refresh(ctx, Globals.Verbose, Globals.Debug, job.force, conf, job.gate)
	if err != nil {
		noteRefreshFailure(zd, zone, err, "zone refresh failed")
		respondToRefresher(job.zr, RefresherResponse{Error: true, ErrorMsg: err.Error()})
		return false, err
	}

	// Refresh-specific error state only. The other categories -- rollover
	// policy, parent DSYNC, config -- are independent and survive a successful
	// refresh.
	if zd.HasError(RefreshError) {
		lgEngine.Info("zone refresh succeeded, clearing RefreshError", "zone", zone)
		zd.ClearError(RefreshError)
	}

	if updated {
		lgEngine.Info("zone updated via refresh", "zone", zone)
		applyOutboundSerialAfterRefresh(zd, zone)
		persistRefreshedZone(zd, zone, job.gen, conf)
	}

	// After EVERY successful refresh, changed or not: membership has to be
	// populated even when the catalog itself did not change, or a member added
	// while we were down is never noticed.
	reparseCatalogZone(ctx, zd, zone, updated, conf)

	respondToRefresher(job.zr, RefresherResponse{
		Msg: "zone " + zone + " refreshed",
	})
	return updated, nil
}

// respondToRefresher answers an operator who is waiting for a result. A ticker
// refresh has nobody to answer, and a caller that did not ask to wait has
// already been told "refreshing...".
func respondToRefresher(zr *ZoneRefresher, resp RefresherResponse) {
	if zr == nil || !zr.Wait || zr.Response == nil {
		return
	}
	zr.Response <- resp
}

// applyOutboundSerialAfterRefresh settles what serial this server advertises for
// a zone it has just refreshed.
func applyOutboundSerialAfterRefresh(zd *ZoneData, zone string) {
	if zd.KeyDB == nil {
		return
	}

	// MUST-NOT-MODIFY: a secondary that did not originate this content mirrors
	// the upstream serial verbatim, so neither outbound mode may touch it.
	// applyRefreshReplacementLocked has already set it. The delete matters as
	// much as the refusal: a zone that becomes non-originating through a live
	// config reload never passes through initialLoadZone, so a row persisted
	// before that would survive, and a later flip back would let
	// LoadOutgoingSerial resurrect an inflated serial.
	if !zoneMayOriginateContent(zd) {
		if err := zd.KeyDB.DeleteOutgoingSerial(zone); err != nil {
			lgEngine.Warn("failed to clear persisted outgoing serial for mirroring secondary",
				"zone", zone, "err", err)
		}
		return
	}

	serialChanged := false
	switch zd.EffectiveOutboundSoaSerial() {
	case OutboundSoaSerialUnixtime:
		zd.CurrentSerial = uint32(time.Now().Unix())
		lgEngine.Info("zone updated from upstream; outbound-soa-serial=unixtime",
			"zone", zone, "serial", zd.CurrentSerial)
		serialChanged = true
	case OutboundSoaSerialPersist:
		// Only when the persisted serial is AHEAD of the one just refreshed in.
		// If upstream advanced while we were down, the inbound serial is the one
		// to honour: moving backwards would break every downstream.
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

// persistRefreshedZone writes a refreshed zone out, if it is the sort of zone
// that is written out at all.
//
// gen is the dispatch-time generation. zoneStillLive closes the resurrection
// race: a zone deleted or replaced while its refresh was in flight must not be
// written back to disk, nor re-added to the dynamic config.
func persistRefreshedZone(zd *ZoneData, zone string, gen uint64, conf *Config) {
	switch {
	case zd.ZoneType == Primary && !zd.Options[OptDirty]:
		// A primary's file is its SOURCE and the refresh has just read it.
		// Writing it back rewrites the operator's file behind their back.
		lgEngine.Debug("skipping zone file write for unmodified primary zone", "zone", zone)

	case conf.ShouldPersistZone(zd) && zoneStillLive(zd, gen):
		if _, err := zd.WriteDynamicZoneFile(conf.DynamicZones.ZoneDirectory); err != nil {
			lgEngine.Warn("failed to write dynamic zone file", "zone", zone, "error", err)
		}
		// The zone file path may have changed, or this may be its first write.
		if err := conf.AddDynamicZoneToConfig(zd); err != nil {
			lgEngine.Warn("failed to update dynamic config file", "zone", zone, "error", err)
		}

	case refreshWritesZoneToSourceFile(zd):
		lgEngine.Info("writing updated zone to file", "zone", zone, "file", zd.Zonefile)
		if _, err := zd.WriteFile(zd.Zonefile); err != nil {
			lgEngine.Warn("failed to write zone file", "zone", zone, "error", err)
		}
	}
}

// reparseCatalogZone re-reads a catalog zone's membership and hands any
// auto-configuration off to its own goroutine.
//
// The goroutine is not decoration. AutoConfigureZonesFromCatalog sends on
// RefreshZoneCh, whose only reader is the refresh engine -- so doing it inline
// from a refresh would let a full channel deadlock the engine against itself.
func reparseCatalogZone(ctx context.Context, zd *ZoneData, zone string, updated bool, conf *Config) {
	if !zd.Options[OptCatalogZone] {
		return
	}
	lgEngine.Info("parsing catalog zone member zones", "zone", zone, "updated", updated)
	catalogUpdate, err := ParseCatalogZone(zd)
	if err != nil {
		lgEngine.Error("failed to parse catalog zone", "zone", zone, "error", err)
		return
	}
	lgEngine.Info("parsed catalog zone", "zone", zone,
		"members", len(catalogUpdate.MemberZones), "serial", catalogUpdate.Serial)

	if err := NotifyCatalogZoneUpdate(catalogUpdate); err != nil {
		lgEngine.Error("failed to notify catalog zone callbacks", "error", err)
		return
	}
	lgEngine.Debug("notified catalog zone callbacks")

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
