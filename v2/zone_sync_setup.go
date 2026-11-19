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
	if zd.Options[OptParentSync] && !configured[OptParentSync] {
		return
	}
	if zd.Options[OptChildSync] && !configured[OptChildSync] {
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
// ZoneData that is no longer the one in Zones (deleted, or replaced by a
// modify while its first refresh was in flight) gets nothing: its replacement
// has the setup owed.
//
// Call it where the ZoneData is constructed, with its options final, while it
// is still private to the creating goroutine: after registerStandardRefreshHooks
// and before Zones.Set. The post-refresh callback is appended to
// OnZonePostRefresh, which must not change once the zone is live.
func (zd *ZoneData) registerZoneSyncSetup(delsyncq chan DelegationSyncRequest) {
	if !wantsZoneSyncSetup(zd.Options) {
		return
	}
	configured := make(map[ZoneOption]bool, len(zd.Options))
	for opt, on := range zd.Options {
		configured[opt] = on
	}
	run := func(z *ZoneData) {
		if cur, ok := Zones.Get(z.ZoneName); !ok || cur != z {
			lg.Debug("SetupZoneSync: zone was deleted or replaced before its first load finished; skipped",
				"zone", z.ZoneName)
			return
		}
		// Not on the caller's goroutine. SetupZoneSync's sends to
		// DelegationSyncQ block while the queue is full, and the caller is the
		// refresh engine's loop (OnFirstLoad) or a refresh worker.
		go runZoneSyncSetup(z, configured, delsyncq)
	}
	if zd.FirstZoneLoad {
		zd.OnFirstLoad = append(zd.OnFirstLoad, run)
		return
	}
	var done atomic.Bool
	zd.OnZonePostRefresh = append(zd.OnZonePostRefresh, func(z *ZoneData) {
		if done.CompareAndSwap(false, true) {
			run(z)
		}
	})
}
