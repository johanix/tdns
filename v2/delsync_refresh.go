/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Delegation sync on refresh (docs/2026-09-23-delegation-sync-on-refresh.md).
 *
 * The refresh hooks parentsync-proxy uses, with a second mode for a zone that
 * syncs its own delegation (parentsync). Without it such a zone told its parent
 * about an NS or glue change only when the change came by DNS UPDATE or the
 * API: never after a zone-file reload, never after a transfer (a signing
 * secondary has no other input), and never at startup.
 *
 * Child mode compares NS and glue only, and acts by comparing the served zone
 * with the parent (REFRESH-SYNC-DELEGATION) rather than by sending the
 * difference between two versions of the zone. It never sends DS.
 */
package tdns

import (
	"context"
	"time"
)

// childDelegationSyncPredicate is the child-mode predicate (design §4.1),
// stated once: parentsync, not multi-provider, not parentsync-proxy, on the
// authoritative app. Every place that queues or runs REFRESH-SYNC-DELEGATION
// asks it, through childDelegationSyncEnabled or delegationChangeModeOf.
//
// It is not the condition of SetupZoneSync's parentsync branch, which also
// admits a registered multi-provider agent app with a multi-provider zone. A
// request queued there would reach every such agent, not only the one tdns-mp
// elected, and send around its leader gate.
//
// tdns-signer runs as AppTypeAuth, so it is covered here too.
func childDelegationSyncPredicate(app AppType, opts map[ZoneOption]bool) bool {
	return app == AppTypeAuth && opts[OptParentSync] && !opts[OptMultiProvider] && !opts[OptParentSyncProxy]
}

// childDelegationSyncEnabled asks the predicate for zd, reading its options
// under zd.mu: a config reload replaces zd.Options wholesale under that lock.
func (zd *ZoneData) childDelegationSyncEnabled() bool {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return childDelegationSyncPredicate(Globals.App.Type, zd.Options)
}

type delegationChangeMode int

const (
	delegationChangeNone delegationChangeMode = iota
	delegationChangeProxy
	delegationChangeChild
)

// delegationChangeModeOf is the mode a refresh of zd runs in. parentsync-proxy
// is checked exactly as before, on any app; the two options are mutually
// exclusive (parseoptions), so the order only matters for a zone that somehow
// has both, and the predicate excludes that one from child mode anyway.
func (zd *ZoneData) delegationChangeModeOf() delegationChangeMode {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	switch {
	case zd.Options[OptParentSyncProxy]:
		return delegationChangeProxy
	case childDelegationSyncPredicate(Globals.App.Type, zd.Options):
		return delegationChangeChild
	}
	return delegationChangeNone
}

// registerDelegationChangeHooks appends the delegation-change pre/post-refresh
// callbacks to zdp: one pair, which picks its mode at every refresh.
//
// Not called directly: registerStandardRefreshHooks (v2/zone_hooks.go) is the
// single entry point, and every path that CONSTRUCTS a live ZoneData calls it
// before publishing the zone. See that function for the ordering contract and
// why registration is unconditional and once-per-ZoneData.
//
// Registered for EVERY zone regardless of type or option -- so a zone that
// gains parentsync-proxy or parentsync on a later reload (including one
// reconfigured from primary to secondary) already carries the hooks.
//
// The mode is decided HERE, in the closures, not inside the pre/post-refresh
// methods: those are the diff/act primitives (and the unit tests exercise them
// directly), while these closures are the live wiring that decides whether to
// invoke them for this zone on this refresh. Reading the options under zd.mu
// is what makes a change on reload take effect without a restart -- a config
// reload replaces zd.Options wholesale under zd.mu, and the closures run with
// no lock held, so the read is race-free and cannot deadlock.
func (zdp *ZoneData) registerDelegationChangeHooks(delsyncq chan DelegationSyncRequest) {
	zdp.OnZonePreRefresh = append(zdp.OnZonePreRefresh,
		func(zd, new_zd *ZoneData) {
			switch zd.delegationChangeModeOf() {
			case delegationChangeProxy:
				zd.ProxyDelegationPreRefresh(new_zd)
			case delegationChangeChild:
				zd.childDelegationPreRefresh(new_zd)
			}
		})
	zdp.OnZonePostRefresh = append(zdp.OnZonePostRefresh,
		func(zd *ZoneData) {
			switch zd.delegationChangeModeOf() {
			case delegationChangeProxy:
				zd.ProxyDelegationPostRefresh(delsyncq)
			case delegationChangeChild:
				zd.childDelegationPostRefresh(delsyncq)
			}
		})
}

// nsOrGlueChanged reports whether the NS RRset or the in-bailiwick glue
// differs between the served zone and newzd. Nothing else is looked at: on a
// zone that signs itself the DNSKEYs and the CDS are ours, and they are put
// back only after the swap, so an AXFR from an unsigned upstream would read as
// every DS removed (design §2).
//
// The answer is the delta lists, not InSync. A nameserver that stays but loses
// every record has its glue listed while InSync stays true (pinned in
// delegation_changed_ng_test.go); the parent is asked either way.
func (zd *ZoneData) nsOrGlueChanged(newzd *ZoneData) (bool, error) {
	oldapex, newapex, err := zd.delegationApexes(newzd)
	if err != nil || oldapex == nil || newapex == nil {
		return false, err
	}
	dss := DelegationSyncStatus{ZoneName: zd.ZoneName, InSync: true}
	zd.diffNSAndGlue(newzd, oldapex, newapex, &dss)
	return len(dss.NsAdds)+len(dss.NsRemoves)+len(dss.AAdds)+len(dss.ARemoves)+
		len(dss.AAAAAdds)+len(dss.AAAARemoves) > 0, nil
}

// childDelegationPreRefresh runs before the swap on a zone in child mode and
// records only whether NS or glue changed. The action does not use the
// comparison's contents: it asks the parent.
//
// On a first load there is no served zone to compare with, so this records
// nothing. The startup compare that SetupZoneSync queues covers that.
func (zd *ZoneData) childDelegationPreRefresh(new_zd *ZoneData) {
	changed, err := zd.nsOrGlueChanged(new_zd)
	if err != nil {
		lgDns.Warn("parentsync: could not compare NS and glue of the incoming zone", "zone", zd.ZoneName, "err", err)
	}
	zd.mu.Lock()
	zd.childRefreshNSGlueChanged = changed
	zd.mu.Unlock()
}

// childDelegationPostRefresh runs after the swap on a zone in child mode and,
// when the pre-refresh hook saw an NS or glue change, queues a compare with the
// parent. The record is cleared whether or not anything was queued.
func (zd *ZoneData) childDelegationPostRefresh(delsyncq chan DelegationSyncRequest) {
	zd.mu.Lock()
	changed := zd.childRefreshNSGlueChanged
	zd.childRefreshNSGlueChanged = false
	zd.mu.Unlock()

	if !changed {
		return
	}
	if delsyncq == nil {
		lgDns.Warn("parentsync: NS or glue changed in a refresh, but there is no delegation sync queue", "zone", zd.ZoneName)
		return
	}
	lgDns.Info("parentsync: NS or glue changed in a refresh; queueing a compare with the parent", "zone", zd.ZoneName)

	// Non-blocking, as the proxy's post-refresh send: this runs on the refresh
	// path, which has no ctx to select on. Dropping loses this trigger, not
	// the change: the next refresh compares against a copy that already has
	// it, but the startup compare and the next NS or glue change both ask the
	// parent about the whole delegation.
	select {
	case delsyncq <- DelegationSyncRequest{Command: "REFRESH-SYNC-DELEGATION", ZoneName: zd.ZoneName, ZoneData: zd}:
	default:
		lgDns.Warn("parentsync: delegation sync queue full; dropping this compare with the parent"+
			" (a restart or the next NS or glue change asks again)", "zone", zd.ZoneName)
	}
}

// refreshSyncSteps are the parts of the REFRESH-SYNC-DELEGATION arm that talk
// to the parent, passed in so a test can stand in for them.
type refreshSyncSteps struct {
	analyse func() (DelegationSyncStatus, error)
	sync    func(DelegationSyncStatus) (string, uint8, UpdateResult, error)
	requeue func(next DelegationSyncRequest, delay time.Duration)
}

// handleRefreshSyncDelegation is the REFRESH-SYNC-DELEGATION arm of the
// syncher: compare the served zone's NS and glue with the parent, and send the
// difference if there is one.
func handleRefreshSyncDelegation(ctx context.Context, conf *Config, delsyncq chan DelegationSyncRequest,
	kdb *KeyDB, notifyq chan NotifyRequest, zd *ZoneData, ds DelegationSyncRequest) {

	_ = handleRefreshSyncDelegationWith(ctx, conf.Internal.ImrReady, delsyncq, zd, ds,
		refreshSyncStepsFor(ctx, conf, delsyncq, kdb, notifyq, zd))
}

// refreshSyncStepsFor are the arm's real steps. The analysis is
// analyseNSAndGlue and never AnalyseZoneDelegation: the DS step is not run.
// The tests take their analysis from here, so they check this wiring too.
func refreshSyncStepsFor(ctx context.Context, conf *Config, delsyncq chan DelegationSyncRequest,
	kdb *KeyDB, notifyq chan NotifyRequest, zd *ZoneData) refreshSyncSteps {

	imr := func() *Imr { return conf.Internal.ImrEngine }
	return refreshSyncSteps{
		analyse: func() (DelegationSyncStatus, error) {
			resp, _, _, err := zd.analyseNSAndGlue(imr())
			return resp, err
		},
		sync: func(dss DelegationSyncStatus) (string, uint8, UpdateResult, error) {
			return zd.SyncZoneDelegation(ctx, kdb, notifyq, dss, imr())
		},
		requeue: func(next DelegationSyncRequest, delay time.Duration) {
			requeueSetupAfter(ctx, delsyncq, next, delay)
		},
	}
}

// handleRefreshSyncDelegationWith is the arm with its parent-facing steps
// supplied (design §4.3). It returns the deferred worker's channel when it put
// the request back to wait for the IMR, and nil otherwise.
//
//  1. It refuses a zone outside child mode -- a multi-provider zone above all
//     -- so a request that reaches it some other way sends nothing.
//  2. It waits for the IMR, as the proxy arm does: the parent is found through
//     it, and at startup this request routinely arrives first.
//  3. It compares the served zone's NS and glue with the parent. The DS step
//     is not run, so the status has no DS opinion and NewDSKnown is false:
//     delta UPDATEs carry no DS, replace UPDATEs leave the parent's DS alone,
//     the API payload declares none, and NOTIFY(CDS) is not sent.
//  4. It stops if the parent is in sync, and otherwise sends the difference.
//  5. A failure is retried on the proxy's schedule. A parent found in sync
//     counts as a success, as a sent difference does, for dropping an older
//     retry: either way the parent holds what the zone says.
func handleRefreshSyncDelegationWith(ctx context.Context, ready *ImrReadiness, delsyncq chan DelegationSyncRequest,
	zd *ZoneData, ds DelegationSyncRequest, steps refreshSyncSteps) <-chan struct{} {

	if zd == nil || !zd.childDelegationSyncEnabled() {
		lgDns.Warn("DelegationSyncher: refresh sync refused; the zone does not sync its own delegation here",
			"zone", ds.ZoneName)
		return nil
	}
	if !ready.Published() {
		return deferForImr(ctx, delsyncq, ready, ds)
	}
	if delegationSyncRetrySuperseded(zd, ds) {
		lgDns.Info("DelegationSyncher: refresh sync retry dropped; a later sync has succeeded",
			"zone", ds.ZoneName, "attempt", ds.Attempt)
		return nil
	}

	retry := func(what string, err error) {
		next, delay, ok := nextDelegationSyncRetry(ds, time.Now())
		if !ok {
			lgDns.Error("DelegationSyncher: refresh sync failed; no retries left, the next NS or glue change or a restart will try again",
				"zone", ds.ZoneName, "step", what, "attempts", ds.Attempt+1, "err", err)
			return
		}
		lgDns.Error("DelegationSyncher: refresh sync failed; will retry", "zone", ds.ZoneName,
			"step", what, "attempt", ds.Attempt+1, "retry_in", delay, "err", err)
		steps.requeue(next, delay)
	}
	succeeded := func() {
		zd.mu.Lock()
		zd.delegationLastSyncOK = time.Now()
		zd.mu.Unlock()
	}

	dss, err := steps.analyse()
	if err != nil {
		retry("compare with the parent", err)
		return nil
	}
	if dss.InSync {
		lgDns.Info("DelegationSyncher: refresh sync: the parent has the zone's NS and glue; nothing to send",
			"zone", ds.ZoneName, "parent", dss.Parent)
		succeeded()
		return nil
	}

	lgDns.Info("DelegationSyncher: refresh sync: the parent differs; sending the NS and glue difference",
		"zone", ds.ZoneName, "parent", dss.Parent,
		"ns_removes", len(dss.NsRemoves), "ns_adds", len(dss.NsAdds),
		"a_removes", len(dss.ARemoves), "a_adds", len(dss.AAdds),
		"aaaa_removes", len(dss.AAAARemoves), "aaaa_adds", len(dss.AAAAAdds))
	msg, rcode, _, err := steps.sync(dss)
	if err != nil {
		retry("send", err)
		return nil
	}
	succeeded()
	lgDns.Info("DelegationSyncher: refresh sync done", "zone", ds.ZoneName, "msg", msg, "rcode", rcode)
	return nil
}
