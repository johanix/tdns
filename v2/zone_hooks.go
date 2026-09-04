/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The standard per-zone refresh hooks, and the one place that attaches them.
 */

package tdns

// registerStandardRefreshHooks attaches the OnZone*Refresh callbacks every
// live zone is entitled to. EVERY path that builds a ZoneData the server will
// serve must call it, and must call it while the ZoneData is still private to
// the creating goroutine -- before Zones.Set and before the zone is enqueued
// for refresh.
//
// Why unconditionally, for every zone, exactly once:
//
// The hooks' eligibility can change under a running server. A zone can be
// reconfigured from primary to secondary, and either option can be added on a
// later reload. ParseZones reuses the ZoneData, so keying registration on the
// option or the zone type would miss a zone that only becomes eligible after
// its first load (FirstZoneLoad is already false by then), while re-appending
// on every reload would both duplicate the callbacks AND mutate the
// OnZone*Refresh slices while a concurrent refresh ranges them -- a data race.
//
// Registering once, for everything, and self-gating at run time resolves both:
// the slices are frozen before the zone goes live, so the refresh engine can
// range them without a lock, and each callback reads its option on every run,
// so enabling or disabling it takes effect on `config reload` rather than on
// restart.
//
// The hooks:
//
//   - delegation-sync-proxy: an agent secondary forwards NOTIFY(CDS/CSYNC) to
//     the parent when a relevant RRset changes in an incoming transfer. The
//     OnZonePreRefresh callback diffs old vs new into zd.ProxyRefreshAnalysis
//     and the OnZonePostRefresh callback acts on it (P-3). Mirrors the tdns-mp
//     MPPreRefresh/PostRefresh pattern for the non-MP agent path. Both
//     self-gate on OptDelSyncProxy.
//   - use-hsyncparam: a secondary watches incoming transfers for an apex
//     HSYNCPARAM pubkey/pubcds flag and republishes the customer's apex KEY /
//     CDS(+CDNSKEY) under the _sig0key/_dsboot signal names owned by each NS,
//     into whichever local primary zone the signal name falls in (see
//     signal_republish.go). Self-gates on OptUseHsyncparam.
//
// Both were registered only from ParseZones, which meant a zone created over
// the API or reloaded from the dynamic config file carried neither: the option
// was accepted, stored, persisted and displayed, and the code that reads it was
// never attached (#500).
//
// Call it where the ZoneData is CONSTRUCTED, not at some later point in the
// same function. ParseZones publishes its zone early and then populates it in
// place, so registering further down would have appended to a slice a
// concurrent refresh could already be ranging -- and, because it keyed on
// FirstZoneLoad (cleared only by a SUCCESSFUL first load), would have appended
// a second copy of every hook on the reload after a failed one. Registering at
// construction makes "exactly once, before anyone can see it" true by
// construction rather than by argument.
func (zdp *ZoneData) registerStandardRefreshHooks(delsyncq chan DelegationSyncRequest) {
	zdp.registerProxyDelegationHooks(delsyncq)
	zdp.registerSignalRepublishHook()
}
