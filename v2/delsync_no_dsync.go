/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"errors"
	"fmt"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
)

// A parent that publishes no DSYNC, or none with a scheme this child can
// use, is the overwhelmingly common case, not a fault (Johan, 2026-11-09).
// The child says so once per zone, as a warning, and moves on: nothing is
// sent, nothing is logged as an error, and no retry is scheduled. A later
// look that finds the same is logged at DEBUG; one that finds a usable
// scheme is logged at INFO. A failure where a usable scheme exists (the
// parent refuses the UPDATE, the API call fails, a timeout) is not this
// case and is reported as before.

// ErrNoUsableDsync marks a delegation sync, or a SIG(0) bootstrap, that was
// not attempted because the parent publishes no DSYNC record this child can
// use: none at all, none for a configured scheme, or none past its gate.
// The DSYNC discovery itself succeeded; a failed discovery is a different
// error. Callers log it at DEBUG and do not retry it (the warning is given
// once per zone where the sentinel is made).
var ErrNoUsableDsync = errors.New("the parent publishes no usable DSYNC scheme")

// dsyncNoticeBook is what the log has been told about each zone's parent:
// that it offers nothing of the kind the book is for. Keyed by the zone's
// name, so a reload, which replaces the zone's ZoneData, does not warn
// again.
type dsyncNoticeBook struct {
	mu    sync.Mutex
	zones map[string]dsyncNotice
}

type dsyncNotice struct {
	parent string
	since  time.Time
}

// note records that the zone's parent offers nothing, and reports whether
// that is news: the first time, or a new parent.
func (b *dsyncNoticeBook) note(zone, parent string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.zones == nil {
		b.zones = map[string]dsyncNotice{}
	}
	zone = core.CanonicalizeName(zone)
	if n, ok := b.zones[zone]; ok && core.EqualNames(n.parent, parent) {
		return false
	}
	b.zones[zone] = dsyncNotice{parent: parent, since: time.Now()}
	return true
}

// clear forgets the zone's note, and returns it when there was one.
func (b *dsyncNoticeBook) clear(zone string) (dsyncNotice, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	zone = core.CanonicalizeName(zone)
	n, ok := b.zones[zone]
	delete(b.zones, zone)
	return n, ok
}

// noDsyncNotices: zones whose parent offers no usable delegation sync
// scheme (SyncZoneDelegation). noUpdateNotices: zones whose parent offers
// no UPDATE target for the SIG(0) bootstrap (finishDelegationSyncSetup).
var (
	noDsyncNotices  = &dsyncNoticeBook{}
	noUpdateNotices = &dsyncNoticeBook{}
)

// planUsable says whether the plan has a scheme to try. A plan built from a
// DSYNC discovery that found nothing usable is ErrNoUsableDsync: warned
// about once per zone, DEBUG after that. A plan that could make no
// discovery at all (no IMR) is not that case: it is reported as before. A
// usable plan after a warning is logged at INFO, once.
func (zd *ZoneData) planUsable(plan *ParentSyncPlan) error {
	if plan.Usable() {
		if n, ok := noDsyncNotices.clear(zd.ZoneName); ok {
			lgDns.Info("delegation sync: the parent now offers a scheme this zone can use",
				"zone", zd.ZoneName, "parent", plan.Parent, "plan", plan.Summary(),
				"none_since", n.since.UTC().Format(time.RFC3339))
		}
		return nil
	}
	if !plan.discovered {
		lgDns.Warn("DelegationSyncEngine: no usable sync scheme", "zone", zd.ZoneName,
			"parent", plan.Parent, "plan", plan.Summary())
		return fmt.Errorf("zone %s: no usable delegation sync scheme: %s",
			zd.ZoneName, plan.Summary())
	}
	if noDsyncNotices.note(zd.ZoneName, plan.Parent) {
		lgDns.Warn("delegation sync: the parent offers no scheme this zone can use; nothing is sent to it",
			"zone", zd.ZoneName, "parent", plan.Parent, "found", plan.Summary())
	} else {
		lgDns.Debug("delegation sync: the parent still offers no scheme this zone can use",
			"zone", zd.ZoneName, "parent", plan.Parent, "found", plan.Summary())
	}
	return fmt.Errorf("zone %s: %w (parent %s): %s", zd.ZoneName, ErrNoUsableDsync, plan.Parent, plan.Summary())
}

// noteNoUpdateTarget is the SIG(0) bootstrap's warning for a parent that
// advertises no UPDATE target: once per zone, DEBUG after that.
func (zd *ZoneData) noteNoUpdateTarget(err error) {
	parent := zd.GetParent()
	if noUpdateNotices.note(zd.ZoneName, parent) {
		lgDns.Warn("DelegationSyncSetup: the parent offers no UPDATE scheme; the zone's SIG(0) key is not bootstrapped with it",
			"zone", zd.ZoneName, "parent", parent, "found", err)
		return
	}
	lgDns.Debug("DelegationSyncSetup: the parent still offers no UPDATE scheme", "zone", zd.ZoneName, "parent", parent)
}

// noteUpdateTargetFound logs, once, that a parent warned about for having
// no UPDATE target has one now.
func (zd *ZoneData) noteUpdateTargetFound() {
	if n, ok := noUpdateNotices.clear(zd.ZoneName); ok {
		lgDns.Info("DelegationSyncSetup: the parent now offers the UPDATE scheme", "zone", zd.ZoneName,
			"parent", zd.GetParent(), "none_since", n.since.UTC().Format(time.RFC3339))
	}
}
