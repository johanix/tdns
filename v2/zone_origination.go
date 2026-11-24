/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The MUST-NOT-MODIFY invariant for tdns-auth secondary zones.
 * See docs/2026-07-25-secondary-zones-immutable.md.
 */
package tdns

import "fmt"

// zoneMayOriginateContent reports whether this zone is allowed to ORIGINATE
// content — that is, to publish anything of its own into the zone, or to
// advance the zone's SOA serial beyond what upstream handed it.
//
// The question the invariant turns on is NOT "is this zone signed" but "did WE
// originate this content?". A secondary serves a copy whose authoritative
// source is upstream, so what it serves — content AND serial — must match what
// it received; that is what makes multiple secondaries of one primary
// interchangeable. Two cases may originate:
//
//   - a PRIMARY, trivially: it is the source;
//   - an INLINE-SIGNING secondary, the one sanctioned exception: it
//     deliberately transforms upstream content by adding locally generated
//     RRSIGs, so its content — and therefore its serial — legitimately
//     diverges from upstream.
//
// SCOPE (load-bearing): the rule applies to the app types in
// originationRuleAppTypes below: tdns-auth, and a derived app that registered
// its own type. tdns-agent has a rule of its own (agentZoneMayOriginateContent).
// For every other app type this returns true, which makes every gate built on
// it a complete no-op there. v2/ is a shared library and several derived apps
// deliberately mutate a zone while holding the Secondary role --
// tdns-mpcombiner edits zones as a secondary (that is its whole job), and
// tdns-mpagent has its own permissions. Their rules must survive the next time
// they bump their tdns pin. Keeping the app-type test HERE, in one place,
// rather than repeating it at each call site, means no future gate can forget
// it.
//
// NOTE for tests: Globals.App.Type must be set to AppTypeAuth, AppTypeAgent, or
// a type registered with RegisterOriginationRuleAppType, for any of the gates
// to engage; an unset (zero) app type reads as "the rule does not apply" and
// every gate stands down. That is deliberate -- it is the same property that
// protects the derived apps -- but it means a test asserting a gate must set
// the app type explicitly.
func zoneMayOriginateContent(zd *ZoneData) bool {
	if zd == nil {
		return true // nothing to protect; never gate on a nil zone
	}
	if Globals.App.Type == AppTypeAgent {
		return agentZoneMayOriginateContent(zd)
	}
	if !originationRuleAppTypes[Globals.App.Type] {
		return true
	}
	return zd.ZoneType == Primary || zd.Options[OptInlineSigning]
}

// agentZoneMayOriginateContent is the rule for tdns-agent. A primary or an
// inline-signing secondary originates, as on tdns-auth. Any other secondary
// originates only when its options give it content of its own to write: one of
// the originationOptions, which the option normalizer strips from a tdns-auth
// secondary and leaves on an agent's (parentsync publishes the zone's SIG(0)
// KEY, childsync its DSYNC RRset, and so on).
//
// A secondary with none of them -- a parentsync-proxy zone, or a plain one --
// writes nothing into the zone, so it serves what it received at the serial it
// received it with (#1157). Before, every agent zone counted as originating:
// each transfer advanced the served serial by one instead of taking the
// received one, each restart lifted it past the highest one served, and the
// zone copy on disk carried that serial, which the next start read back as
// the received one.
//
// A childsync-proxy zone is one of these too, although it carries childsync
// (implied) and allow-child-updates: see childUpdatesLeaveTheZone.
func agentZoneMayOriginateContent(zd *ZoneData) bool {
	if zd.ZoneType == Primary || zd.Options[OptInlineSigning] {
		return true
	}
	for _, opt := range originationOptions {
		if zd.Options[opt] && !childUpdatesLeaveTheZone(zd, opt) {
			return true
		}
	}
	return false
}

// markRelayCopyIfOriginationEnded marks a running tdns-agent zone's copy
// unconfirmed when a change ends its origination. The copy then holds content
// and a serial the zone wrote itself, which a relay must not serve, and the
// upstream need not move for a probe to see that. The next refresh with a
// usable SOA replaces it with a full transfer (relayCopyNeedsTransfer), also
// when the forced refresh a reload queues was skipped or failed. Any other
// change leaves the mark as it is, so a confirmed relay copy is not
// transferred again at every reload. A zone that has never published has no
// copy of its own to replace.
//
// Called, under zd.mu, wherever a running zone's options or type are replaced:
// ParseZones (a config reload swaps the options before it queues the
// refresher), the refresh engine (options and type from a refresher), and
// setRuntimeOptionLocked. wasOriginating is zoneMayOriginateContent before
// the change.
func (zd *ZoneData) markRelayCopyIfOriginationEnded(wasOriginating bool) {
	if wasOriginating && Globals.App.Type == AppTypeAgent && zd.snapshot.Load() != nil &&
		!zoneMayOriginateContent(zd) {
		zd.relayCopyUnconfirmed.Store(true)
		lg.Info("zone stopped originating content: its copy is replaced by a full transfer at the next refresh",
			"zone", zd.ZoneName)
	}
}

// childUpdatesLeaveTheZone reports whether opt, on this zone, only receives
// child updates that are written somewhere else. A childsync-proxy implies
// childsync and carries allow-child-updates to receive on every scheme, but it
// publishes nothing into its own copy of the zone (SetupZoneSync), and what it
// accepts goes to the parent primary through its delegation backend, which
// config validation keeps off the served zone (store direct is refused for a
// proxy). The proxy flag wins over both options, or the zone would count as
// originating: each transfer would advance the served serial and a restart
// would lift it.
func childUpdatesLeaveTheZone(zd *ZoneData, opt ZoneOption) bool {
	return zd.Options[OptChildSyncProxy] && (opt == OptChildSync || opt == OptAllowChildUpdates)
}

// originationRuleAppTypes are the app types whose zones follow the rule above.
// tdns-auth, and tdns-signer with it (it runs as AppTypeAuth). Every other app
// type originates in every zone, unless it registered itself here.
var originationRuleAppTypes = map[AppType]bool{AppTypeAuth: true}

// RegisterOriginationRuleAppType makes the zones of a derived app follow the
// tdns-auth origination rule: a primary, or a secondary with inline-signing
// on, may originate content and keeps a serial of its own; any other zone
// serves what it received, at the serial it received it with.
//
// For a derived app that relays some zones unchanged and signs others, and
// switches inline-signing on for exactly the ones it signs. Without this such
// an app counts its own serial for a relayed zone too, and the SOA it serves
// then carries that serial under the upstream's RRSIG, which does not validate
// (johanix/tdns-mp#144).
//
// The whole rule comes with it, not the serial alone: every gate built on
// zoneMayOriginateContent engages for the app's zones. One thing does not:
// the option normalizer (normalizeOptionsForRole) stays tdns-auth's. It
// decides when the configuration is parsed, and such an app may switch
// inline-signing on later, so stripping an option there would take it from a
// zone the app goes on to sign. For a registered app the gates act where the
// content would be written instead.
//
// One thing a registered app's relayed zone does that tdns-auth's does not:
// it keeps a record of the serial it serves (relayedZoneRecordsItsSerial).
//
// Call it from the derived package's init, beside its other registrations:
// the map is read without a lock, and the rule has to hold before the first
// zone is loaded.
func RegisterOriginationRuleAppType(t AppType) { originationRuleAppTypes[t] = true }

// relayedZoneRecordsItsSerial says whether a zone that may not originate
// content keeps a record of the serial it serves, in OutgoingSerials.
//
// A tdns-auth secondary keeps none, and the record it had is deleted
// (MUST-NOT-MODIFY, Fix A). A registered derived app's relayed zone keeps one:
// such an app turns a zone from relayed to signed by itself, from what the
// zone says, and the turn can fall across a restart. The first load of the
// zone it now signs starts from its new upstream's serial, which may be far
// below the one it was serving, and the servers downstream of it hold that
// one and would not transfer. With the record the first load lands past it,
// as it does for any zone that originates (#655).
//
// The record of a relayed zone is the serial it serves, set at every publish,
// so a serial the zone counted before it became a relay does not stay in it.
func relayedZoneRecordsItsSerial() bool {
	return Globals.App.Type != AppTypeAuth && originationRuleAppTypes[Globals.App.Type]
}

// originationAPICommands are the /zone and /zone/childsync API commands that make
// the server ORIGINATE content: they either write into the zone or advance its
// serial. Refused on a zone that may not originate (Fix C).
//
// Deliberately NOT a blanket secondary-refusal. `write-zone` in particular
// stays allowed: it depends only on OptDirty/force, touches no options, and
// dumping a transferred zone to disk is a legitimate secondary operation.
// Read-only commands (list-zones, show-nsec-chain, status, ...) are untouched.
//
// freeze/thaw are handled separately at their own cases: they need the role
// check to fire BEFORE their allow-updates precondition, so the operator gets
// the true reason rather than being sent to enable an option the normalizer
// would immediately strip again.
var originationAPICommands = map[string]bool{
	// /zone
	"bump":          true,
	"sign-zone":     true,
	"resign-zone":   true,
	"policy-set":    true,
	"change-policy": true,
	"policy-reset":  true,
	// /zone/childsync — publishes the _dsync DSYNC RRset into the zone
	"publish":   true,
	"unpublish": true,
}

// zoneOriginationRefusal returns the operator-facing refusal message for an
// action on a zone that may not originate content, or "" when the action is
// allowed. The wording deliberately matches the option normalizer's warning and
// the applier gate's log line, so all three name the same reason.
func zoneOriginationRefusal(zd *ZoneData, action string) string {
	if zoneMayOriginateContent(zd) {
		return ""
	}
	return fmt.Sprintf("zone %s is a secondary and may not originate content: %q refused "+
		"(a secondary serves what it received from upstream, unmodified)", zd.ZoneName, action)
}
