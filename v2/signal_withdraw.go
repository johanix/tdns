/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

// Withdrawal of records published at the RFC 9615 signal names, and the
// reconciler that drives both directions. See
// docs/2026-09-03-signal-name-withdrawal.md.
//
// Publication (signal_republish.go) is content-gated: it writes when what is
// at the name differs from what the zone owner asks for. Withdrawal cannot
// work that way. The target is an ordinary primary zone of this server's, an
// operator may have published a signal name there by hand, and zone data
// carries no provenance -- so "this record is not one we want" says nothing
// about whose it is. The SignalPublication ledger does, and it is the only
// thing consulted before a delete.
//
// The reconciler is the OnZonePostRefresh callback on EVERY zone, and that one
// placement covers configuration changes as well as content changes: a config
// reload enqueues a forced refresh for every zone, and `force` bypasses both
// the untouched-file skip in FetchFromFile and the unchanged-serial discard in
// FetchFromUpstream, so the callbacks run. A restart does the same on first
// load. Nothing here compares before against after -- it reads the CURRENT
// options and the CURRENT ledger -- so an edit made while the daemon was
// stopped is settled exactly like one made while it was running.

package tdns

import (
	"fmt"
	"sync/atomic"

	"github.com/miekg/dns"
)

// ReconcileSignalPublications is the OnZonePostRefresh callback registered on
// every zone. It publishes what this zone's owner currently asks for and
// withdraws what nobody asks for any more, in that order: the publish half
// records its ledger rows first, so the withdrawal half never sees a
// just-published name as unwarranted.
func (zd *ZoneData) ReconcileSignalPublications() {
	zd.RepublishAtSignalNames()
	zd.withdrawUnwarrantedSignalPublications()
	zd.withdrawOrphanSignalPublications()
}

// recordSignalPublication notes in the ledger that this server put the
// prefix's RRsets at tgt.Owner. A failure to record is logged and not fatal:
// the record IS published, and reporting the publication as failed would be a
// worse lie than the one this costs -- an unrecorded publication that will
// never be withdrawn.
func (childZD *ZoneData) recordSignalPublication(tgt signalPublishTarget, source, prefix string) {
	// No keystore, no ledger, and therefore no way to withdraw later. That is
	// a deployment without a keystore at all, where none of this can work;
	// nothing to report per publication.
	if tgt.Zone == nil || !SignalLedgerReadable(tgt.Zone.KeyDB) {
		return
	}
	err := tgt.Zone.KeyDB.RecordSignalPublication(SignalPublication{
		Target: tgt.Zone.ZoneName,
		Owner:  tgt.Owner,
		Zone:   childZD.ZoneName,
		NS:     tgt.NS,
		Prefix: prefix,
		Source: source,
	})
	if err != nil {
		lgSignal.Error("failed to record a signal publication; it will not be withdrawable",
			"zone", childZD.ZoneName, "signal", tgt.Owner, "target", tgt.Zone.ZoneName, "err", err)
	}
}

// withdrawUnwarrantedSignalPublications is the zone acting as the zone
// PUBLISHED FOR: it withdraws every record the ledger says we put somewhere on
// this zone's behalf that the zone's current configuration and current content
// no longer justify. That is one function for four situations --
// use-hsyncparam removed, a pubkey/pubcds flag dropped from the apex
// HSYNCPARAM, a nameserver dropped from the apex NS RRset, and parentsync
// turned off for a zone whose at-ns bootstrap published a _sig0key -- because
// all four are the same question asked of current state.
func (zd *ZoneData) withdrawUnwarrantedSignalPublications() {
	if signalLedgerEmpty.Load() || !SignalLedgerReadable(zd.KeyDB) {
		return
	}
	rows, err := zd.KeyDB.SignalPublicationsForZone(zd.ZoneName)
	if err != nil {
		lgSignal.Error("failed to read the signal publication ledger",
			"zone", zd.ZoneName, "err", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	// Two states from which "which nameservers does this zone have" has no
	// answer. Answering "none" would withdraw every record for the zone on the
	// strength of a zone we cannot read, so answer nothing instead and let the
	// next refresh decide. Losing ONE nameserver from a populated RRset is a
	// real withdrawal and is handled below; losing all of them is not a zone.
	//
	// The snapshot check does not change the withdrawal decision -- apexNSNames
	// reads through publishedSnapshot, so an unloaded zone reaches the second
	// check with an empty list anyway. It separates the two states for the LOG:
	// "has not loaded yet" is the normal condition of every zone at startup and
	// says nothing, while "loaded, and its apex has no NS RRset" is a broken
	// zone and warrants a warning. Without it, every zone with publications
	// would warn once per boot.
	if zd.publishedSnapshot() == nil {
		return
	}
	nsNames := zd.apexNSNames()
	if len(nsNames) == 0 {
		lgSignal.Warn("zone has published signal names but no apex NS RRset; withdrawing nothing",
			"zone", zd.ZoneName, "publications", len(rows))
		return
	}

	keepHsync, keepAtNs := zd.warrantedSignalOwners(nsNames)
	for _, p := range rows {
		switch p.Source {
		case signalSourceHsyncparam:
			if keepHsync[p.Owner] {
				continue
			}
		case signalSourceAtNs:
			if keepAtNs[p.Owner] {
				continue
			}
		default:
			// A row written by something this build does not know about. Not
			// ours to reason about, so not ours to delete.
			lgSignal.Warn("signal publication with an unknown source; leaving it alone",
				"zone", zd.ZoneName, "signal", p.Owner, "source", p.Source)
			continue
		}
		withdrawSignalPublication(p, "no longer warranted by the zone's configuration or content")
	}
}

// warrantedSignalOwners returns the signal names this zone's current state
// justifies, split by which publisher's rows they justify. The two are kept
// apart on purpose: a zone can carry parentsync (OptDelSyncChild) without
// carrying use-hsyncparam, and a shared set would then let one option's
// warrant retain the other option's records.
//
// The at-ns set is a RETENTION set, not a publication set. Putting a _sig0key
// at a signal name for our own zone is the bootstrap ceremony's decision
// (publishSig0KeyAtSignalNames); the reconciler never starts doing it, it only
// keeps or withdraws what the ceremony recorded.
func (zd *ZoneData) warrantedSignalOwners(nsNames []string) (keepHsync, keepAtNs map[string]bool) {
	keepHsync = map[string]bool{}
	keepAtNs = map[string]bool{}
	useHsyncparam, delSyncChild := zd.signalOptions()

	if useHsyncparam {
		if hp := zd.apexHsyncparam(); hp != nil {
			for _, spec := range signalSpecs {
				if !spec.active(hp) {
					continue
				}
				// A flag whose apex RRset is empty asks us to mirror nothing.
				// The republisher warns and publishes nothing; a record left
				// at the signal name would advertise, to a parent doing at-ns
				// verification, a key the child no longer publishes.
				if len(zd.apexRRsFor(spec.rrtypes)) == 0 {
					continue
				}
				for _, tgt := range zd.signalPublishTargets(spec.prefix, nsNames) {
					keepHsync[tgt.Owner] = true
				}
			}
		}
	}

	if delSyncChild {
		for _, tgt := range zd.signalPublishTargets(signalPrefixSig0Key, nsNames) {
			keepAtNs[tgt.Owner] = true
		}
	}
	return keepHsync, keepAtNs
}

// signalOptions reads the two options every decision in this file turns on,
// together and under zd.mu. ParseZones replaces zd.Options wholesale on a
// config reload (under that lock) and SetOption mutates it in place under it,
// while these callbacks run from the post-refresh path holding no lock -- so an
// unsynchronized map read here races the reload, and two separate reads could
// straddle one and see half of each. Same treatment the ZONE-UPDATE admission
// check gives its own pair. RepublishAtSignalNames reads through this too, so
// the publish and withdrawal halves of one pass agree about the zone.
//
// Race-free and deadlock-free: zd.mu is the lock these fields are mutated
// under, the callbacks hold none of their own, and the lock is released before
// the callers touch zone data (publishedSnapshot, apexNSNames,
// signalPublishTargets take their own).
func (zd *ZoneData) signalOptions() (useHsyncparam, delSyncChild bool) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.Options[OptUseHsyncparam], zd.Options[OptDelSyncChild]
}

// signalOrphanSweepArmed gates the target-side role below, and
// signalConfiguredZones is what makes that gate sound.
//
// "Missing from the registry" is not the same as "removed". A zone can be
// absent because it has not been CONSTRUCTED yet: LoadDynamicZoneFiles
// registers dynamic primaries itself but only ENQUEUES dynamic secondaries and
// catalog members, whose ZoneData the RefreshEngine builds when it drains the
// channel (see registerStandardRefreshHooks, #500/#501). So arming after
// loadDynamicZonesIfConfigured is not enough on its own -- a dynamic SECONDARY,
// which is exactly the zone shape use-hsyncparam is for, can still be missing
// at that moment, and sweeping on registry-absence alone would withdraw its
// records and then watch the next refresh publish them straight back.
//
// signalConfiguredZones is therefore captured at startup from CONFIGURATION
// rather than liveness: every zone named in the static config or the dynamic
// config file. A row whose zone appears there is never an orphan, however
// absent it currently is. A zone genuinely removed while the daemon was stopped
// is in neither, which is the case the sweep exists for.
var signalOrphanSweepArmed atomic.Bool

var signalConfiguredZones atomic.Pointer[map[string]bool]

// zoneIsConfigured reports whether some configuration names this zone, even if
// no ZoneData has been built for it yet.
func zoneIsConfigured(zone string) bool {
	m := signalConfiguredZones.Load()
	return m != nil && (*m)[zone]
}

// withdrawOrphanSignalPublications is the zone acting as the TARGET: it
// withdraws records published into it for a zone this server no longer serves
// at all. Those rows have no other owner -- the zone they were published for
// is gone, so its own reconciler will never run again.
//
// This is the backstop for every zone-removal path, including a removal made
// while the daemon was stopped and the catalog and dynamic-primary removals
// that are not hooked individually. The two prompt paths (a zone dropped from
// the config on reload, and RemoveDynamicZone) call
// WithdrawSignalPublicationsForZone directly so a live removal does not wait
// for this zone's next refresh.
func (zd *ZoneData) withdrawOrphanSignalPublications() {
	if !signalOrphanSweepArmed.Load() || signalLedgerEmpty.Load() || !SignalLedgerReadable(zd.KeyDB) {
		return
	}
	if zd.ZoneType != Primary {
		return
	}
	rows, err := zd.KeyDB.SignalPublicationsForTarget(zd.ZoneName)
	if err != nil {
		lgSignal.Error("failed to read the signal publication ledger",
			"target", zd.ZoneName, "err", err)
		return
	}
	withdrawOrphanRows(rows)
}

// withdrawOrphanRows withdraws the rows whose published-for zone this server
// neither serves nor is configured for. A zone that IS in the registry is left
// to its own reconciler, which knows about its options and its content and this
// does not; a zone that is merely CONFIGURED is left alone because it has not
// been built yet, not because nobody wants it (see signalConfiguredZones).
func withdrawOrphanRows(rows []SignalPublication) {
	for _, p := range rows {
		if _, live := Zones.Get(p.Zone); live {
			continue
		}
		if zoneIsConfigured(p.Zone) {
			lgSignal.Debug("not an orphan: the zone is configured but not constructed yet",
				"zone", p.Zone, "signal", p.Owner, "target", p.Target)
			continue
		}
		withdrawSignalPublication(p, "the zone it was published for is no longer served here")
	}
}

// WithdrawSignalPublicationsForZone withdraws everything published on a zone's
// behalf. Called when the zone is being removed from the running server, where
// there is no later refresh of that zone to notice.
func WithdrawSignalPublicationsForZone(kdb *KeyDB, zone string) {
	if signalLedgerEmpty.Load() || !SignalLedgerReadable(kdb) {
		return
	}
	rows, err := kdb.SignalPublicationsForZone(zone)
	if err != nil {
		lgSignal.Error("failed to read the signal publication ledger", "zone", zone, "err", err)
		return
	}
	for _, p := range rows {
		withdrawSignalPublication(p, "the zone it was published for is being removed")
	}
}

// ReconcileSignalPublicationsAtStartup arms the target-side role and sweeps
// the ledger once for zones that were removed while the daemon was stopped.
//
// Both halves are needed and neither is redundant. A target that had already
// loaded before arming would not be revisited until its own refresh interval,
// which for a file-backed primary can be hours; the sweep catches it now. A
// target not yet loaded is not readable now; its own post-refresh catches it,
// and that runs after this has armed.
//
// Call it after loadDynamicZonesIfConfigured. That is not what makes the sweep
// safe -- signalConfiguredZones is -- but it is where the persisted dynamic
// zones have at least been enqueued, so the registry is as complete as it gets
// without waiting on the refresh engine.
func (conf *Config) ReconcileSignalPublicationsAtStartup() {
	// Arm only if the configured set is trustworthy. Without it "absent from
	// the registry" means "orphan", which during startup is false for every
	// zone the refresh engine has not built yet -- so an unreadable dynamic
	// config must leave the sweep OFF, not run it against an empty set.
	if !conf.captureConfiguredZoneNames(conf.staticZoneNames()) {
		lgSignal.Warn("signal-name orphan sweep stays disarmed: the configured zone set could not be established")
		return
	}
	signalOrphanSweepArmed.Store(true)

	kdb := conf.Internal.KeyDB
	if signalLedgerEmpty.Load() || !SignalLedgerReadable(kdb) {
		return
	}
	rows, err := kdb.AllSignalPublications()
	if err != nil {
		lgSignal.Error("failed to read the signal publication ledger at startup", "err", err)
		return
	}
	withdrawOrphanRows(rows)
}

// withdrawSignalPublication deletes one published signal RRset and forgets the
// row. The target is looked up by the name we RECORDED writing into, not by
// FindZone(owner): if the zone structure has changed under us, the zone that
// now owns the name is not the one holding the record.
//
// A row is forgotten only once the zone it names has been read. An unready
// target reports "nothing at that name" for every name, so forgetting on that
// answer would drop the row with the record still on disk and nothing left to
// find it. Rows whose target is unready, gone, or no longer ours are left for
// a later pass.
//
// "Gone" and "no longer primary" are kept rather than tidied away on purpose.
// A target that leaves this server takes its records with it, so the row looks
// like dead weight -- but if that zone comes back, from the same zone file, the
// signal RRsets come back with it, and the row is the only thing that would
// still authorize withdrawing them. Retrying a row we cannot act on costs a
// registry lookup and a Debug line; forgetting one costs the ability to undo a
// publication. The ledger is bounded by the number of signal names ever
// published, so it can afford to remember.
func withdrawSignalPublication(p SignalPublication, why string) {
	target, ok := Zones.Get(p.Target)
	if !ok || target == nil {
		lgSignal.Debug("cannot withdraw a signal RRset: target zone is not served here",
			"zone", p.Zone, "signal", p.Owner, "target", p.Target)
		return
	}
	if target.ZoneType != Primary {
		lgSignal.Warn("cannot withdraw a signal RRset: no longer primary for the target zone",
			"zone", p.Zone, "signal", p.Owner, "target", p.Target)
		return
	}
	if target.publishedSnapshot() == nil {
		lgSignal.Debug("deferring a signal withdrawal: target zone is not loaded yet",
			"zone", p.Zone, "signal", p.Owner, "target", p.Target)
		return
	}

	rrtypes := signalRRtypesForPrefix(p.Prefix)
	if rrtypes == nil {
		lgSignal.Warn("signal publication with an unknown prefix; leaving it alone",
			"zone", p.Zone, "signal", p.Owner, "prefix", p.Prefix)
		return
	}

	// An absent RRset is not an error: the updater treats a ClassANY delete of
	// one as a no-op (no serial bump, no re-sign), so the check is only here to
	// keep a withdrawal that has nothing to do out of the log and off the queue.
	if signalRRsPresent(target, p.Owner, rrtypes) {
		// Fire-and-forget (nil ctx): this runs inside a post-refresh hook,
		// which must not block on the zone updater.
		if err := target.publishSignalRRs(nil, p.Owner, rrtypes, nil); err != nil {
			lgSignal.Error("failed to withdraw signal RRset",
				"zone", p.Zone, "signal", p.Owner, "target", p.Target, "err", err)
			return
		}
		lgSignal.Info("withdrew RRset at signal name",
			"zone", p.Zone, "signal", p.Owner, "target", p.Target,
			"source", p.Source, "reason", why)
	} else {
		lgSignal.Debug("signal RRset was already gone; forgetting the publication",
			"zone", p.Zone, "signal", p.Owner, "target", p.Target)
	}

	if err := target.KeyDB.ForgetSignalPublication(p.Target, p.Owner); err != nil {
		lgSignal.Error("failed to forget a withdrawn signal publication",
			"zone", p.Zone, "signal", p.Owner, "target", p.Target, "err", err)
	}
}

// signalRRtypesForPrefix maps a ledger row's prefix back to the RRtypes the
// publication covers. The specs are the single definition of that pairing;
// a prefix no spec claims is a row this build cannot act on.
func signalRRtypesForPrefix(prefix string) []uint16 {
	for _, spec := range signalSpecs {
		if spec.prefix == prefix {
			return spec.rrtypes
		}
	}
	return nil
}

// staticZoneNames snapshots the names of the statically configured zones.
// Split out so a caller can take it under whatever lock already protects
// conf.Zones (confMu) and hand the result to the builders below, which do file
// I/O and must not run under that lock.
func (conf *Config) staticZoneNames() []string {
	out := make([]string, 0, len(conf.Zones))
	for i := range conf.Zones {
		out = append(out, conf.Zones[i].Name)
	}
	return out
}

// configuredZoneNames builds the set of every zone name some configuration
// names: the static names the caller passes in, plus whatever the dynamic
// config file holds. The registry is deliberately not consulted -- it is
// exactly what cannot be trusted here (see signalConfiguredZones).
func (conf *Config) configuredZoneNames(static []string) (map[string]bool, error) {
	names := make(map[string]bool, len(static))
	for _, n := range static {
		names[dns.Fqdn(n)] = true
	}
	if conf.DynamicZones.ConfigFile == "" {
		return names, nil
	}
	// A dynamic config file that does not exist yet is the normal first-run
	// state; loadDynamicConfigFile returns an empty config for it, not an error.
	cf, err := conf.loadDynamicConfigFile()
	if err != nil {
		return nil, fmt.Errorf("dynamic zone config %s: %w", conf.DynamicZones.ConfigFile, err)
	}
	if cf != nil {
		for _, zconf := range cf.Zones {
			names[dns.Fqdn(zconf.Name)] = true
		}
	}
	return names, nil
}

// captureConfiguredZoneNames establishes the set for the FIRST time, at
// startup. Returns false when it could not be established, which must leave the
// sweep disarmed: without a set, "absent from the registry" means "orphan", and
// during startup that is false for every zone the refresh engine has not built
// yet.
func (conf *Config) captureConfiguredZoneNames(static []string) bool {
	names, err := conf.configuredZoneNames(static)
	if err != nil {
		lgSignal.Error("cannot establish the configured zone set; leaving the signal-name orphan sweep disarmed",
			"err", err)
		signalConfiguredZones.Store(nil)
		return false
	}
	lgSignal.Debug("captured the configured zone set for the signal-name orphan sweep", "zones", len(names))
	signalConfiguredZones.Store(&names)
	return true
}

// refreshConfiguredZoneNames updates the set after the configuration CHANGES --
// a reload, or a dynamic zone removed over the API. Without this the set is
// whatever startup saw, so a zone dropped from the config still counts as
// configured and its rows are never swept: a prompt withdrawal that had to
// defer (target not loaded) would then wait for a restart.
//
// The failure policy is the opposite of capture's, deliberately. Capture runs
// before the sweep is armed, so failing closed means not arming. This runs when
// the sweep may already be live, and storing nil or a partial set would make
// every ledger row whose zone is not in the registry look like an orphan --
// turning a failed file read into a mass withdrawal. A stale set only delays a
// withdrawal; a cleared one performs the wrong ones.
func (conf *Config) refreshConfiguredZoneNames(static []string) {
	names, err := conf.configuredZoneNames(static)
	if err != nil {
		lgSignal.Warn("could not refresh the configured zone set; keeping the previous one (orphan sweeps stay conservative)",
			"err", err)
		return
	}
	lgSignal.Debug("refreshed the configured zone set", "zones", len(names))
	signalConfiguredZones.Store(&names)
}
