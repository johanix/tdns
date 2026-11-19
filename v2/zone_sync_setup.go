/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * When SetupZoneSync runs, for every way a zone comes into being.
 */

package tdns

import "sync/atomic"

// wantsZoneSyncSetup reports whether a zone with these options needs
// SetupZoneSync: the four options it acts on. SetupZoneSync's own early exit,
// the static path in ParseZones and registerZoneSyncSetup all ask this, so
// adding an option to SetupZoneSync cannot leave one of them behind. Leaving
// one behind is what #1151 was: the run-time paths asked for childsync or
// parentsync only, and a parentsync-proxy zone never got its setup.
func wantsZoneSyncSetup(opts map[ZoneOption]bool) bool {
	return opts[OptChildSync] || opts[OptParentSync] ||
		opts[OptParentSyncProxy] || opts[OptChildSyncProxy]
}

// runZoneSyncSetup runs SetupZoneSync for zd, whose configuration gave it the
// options in configured.
//
// A zone that has parentsync or childsync now but was not configured with it
// got it at run time, from the multi-provider HSYNCPARAM callback, and that
// callback set up delegation sync for the zone itself. Running the setup again
// here would do it twice.
func runZoneSyncSetup(zd *ZoneData, configured map[ZoneOption]bool, delsyncq chan<- DelegationSyncRequest) {
	if zd.Option(OptParentSync) && !configured[OptParentSync] {
		return
	}
	if zd.Option(OptChildSync) && !configured[OptChildSync] {
		return
	}
	if delsyncq == nil {
		lg.Error("DelegationSyncQ not available", "zone", zd.ZoneName)
		return
	}
	if err := zd.SetupZoneSync(delsyncq); err != nil {
		lg.Error("SetupZoneSync failed", "zone", zd.ZoneName, "error", err)
	}
}

// registerZoneSyncSetup arranges for SetupZoneSync to run once, after the
// zone's first load, for a zone created while the server runs: an API add or
// modify, a catalog member, a dynamic primary, and a persisted dynamic zone
// that the refresh engine creates at startup. Static zones are not covered
// here: ParseZones does the same for them, and also runs the setup again on
// a reload.
//
// Whether the setup is owed depends on the zone's options alone
// (wantsZoneSyncSetup), not on whether the zone came from a template. When it
// runs depends on how the zone first loads:
//
//   - A zone created with FirstZoneLoad set loads through the first-load path.
//     The setup goes on OnFirstLoad, as it does for a static zone, and runs
//     after the zone is Ready and its DNSSEC policy is bound. That path also
//     retains the callback across a failed first load and retries it.
//
//   - A zone created without it (API add, modify, catalog member) first loads
//     through an ordinary refresh, and OnFirstLoad never drains for it. The
//     setup runs from the zone's post-refresh callbacks instead, at the first
//     refresh that publishes, and only that once. A first refresh that fails
//     leaves it owed.
//
// Once per ZoneData, then. A modify builds a new ZoneData, so it gets the
// setup again for its new options, as a static zone does on a reload. A
// ZoneData that is not the one in Zones when its callback runs (deleted, or
// replaced by a modify while its first load was in flight) is passed over and
// keeps the setup owed: if it is a modify that fails to persist, the rollback
// puts it back, and resumeOwedZoneSyncSetup dispatches what it still owes.
//
// Call it where the ZoneData is constructed, with its options final, while it
// is still private to the creating goroutine: after registerStandardRefreshHooks
// and before Zones.Set. The post-refresh callback is appended to
// OnZonePostRefresh, which must not change once the zone is live.
func (zd *ZoneData) registerZoneSyncSetup(delsyncq chan DelegationSyncRequest) {
	// The zone's own copy of its options, which is what is recorded.
	configured := zd.OptionsSnapshot()
	if !wantsZoneSyncSetup(configured) {
		return
	}
	zd.zoneSyncSetup = &owedZoneSyncSetup{configured: configured, delsyncq: delsyncq}
	run := func(z *ZoneData) { z.runOwedZoneSyncSetup() }
	if zd.FirstZoneLoad {
		zd.OnFirstLoad = append(zd.OnFirstLoad, run)
		return
	}
	zd.OnZonePostRefresh = append(zd.OnZonePostRefresh, run)
}

// owedZoneSyncSetup is what registerZoneSyncSetup records for a zone: the
// options it was configured with, the queue, and whether the setup has been
// dispatched.
type owedZoneSyncSetup struct {
	configured map[ZoneOption]bool
	delsyncq   chan DelegationSyncRequest
	done       atomic.Bool
}

// runOwedZoneSyncSetup dispatches the setup zd owes, if it still owes it and
// is the ZoneData in Zones, and reports whether it did.
//
// The check against Zones comes before the guard is spent. A ZoneData that is
// out of Zones, deleted or replaced by a modify, gets nothing and keeps the
// setup owed: a modify that fails to persist puts it back.
func (zd *ZoneData) runOwedZoneSyncSetup() bool {
	s := zd.zoneSyncSetup
	if s == nil || s.done.Load() {
		return false
	}
	if cur, ok := Zones.Get(zd.ZoneName); !ok || cur != zd {
		lg.Debug("SetupZoneSync: zone is not the one in Zones (deleted or replaced); setup stays owed",
			"zone", zd.ZoneName)
		return false
	}
	if !s.done.CompareAndSwap(false, true) {
		return false
	}
	// Not on the caller's goroutine. SetupZoneSync's sends to DelegationSyncQ
	// block while the queue is full, and the caller is the refresh engine's
	// loop (OnFirstLoad), a refresh worker, or the API handler (a rollback).
	go runZoneSyncSetup(zd, s.configured, s.delsyncq)
	return true
}

// resumeOwedZoneSyncSetup is for a ZoneData that has been put back into Zones
// after it was replaced: the rollback of a modify that failed to persist.
// While it was out of Zones, the callback that dispatches its setup may have
// run and passed it over, and nothing would run that callback again. For a
// zone that first loaded through an ordinary refresh, the next run is the next
// refresh that publishes, which an unchanged upstream serial never brings.
//
// So if that callback has had its turn, dispatch the setup here. The zone must
// be Ready, its first load done with no OnFirstLoad callbacks left, and no
// post-refresh callbacks owed. Otherwise a callback is still to come, and it
// dispatches the setup itself, now that the zone is back in Zones. The guard
// in runOwedZoneSyncSetup makes it once either way.
func (zd *ZoneData) resumeOwedZoneSyncSetup() bool {
	if zd.zoneSyncSetup == nil {
		return false
	}
	zd.mu.Lock()
	callbacksHadTheirTurn := zd.Ready && !zd.withheld && !zd.FirstZoneLoad &&
		len(zd.OnFirstLoad) == 0 && !zd.postRefreshOwed
	zd.mu.Unlock()
	if !callbacksHadTheirTurn {
		return false
	}
	return zd.runOwedZoneSyncSetup()
}
