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
// SCOPE (load-bearing): this returns true for every app type other than
// tdns-auth, which makes every gate built on it a complete no-op there. v2/ is
// a shared library and several derived apps deliberately mutate a zone while
// holding the Secondary role — tdns-mpcombiner edits zones as a secondary (that
// is its whole job), tdns-mpagent has its own permissions, tdns-agent already
// carries secondary special-cases. Their rules must survive the next time they
// bump their tdns pin. Keeping the app-type test HERE, in one place, rather
// than repeating `Globals.App.Type == AppTypeAuth &&` at each call site, means
// no future gate can forget it.
//
// NOTE for tests: Globals.App.Type must be set to AppTypeAuth for any of the
// gates to engage; an unset (zero) app type reads as "not tdns-auth" and every
// gate stands down. That is deliberate — it is the same property that protects
// the derived apps — but it means a test asserting a gate must set the app type
// explicitly.
func zoneMayOriginateContent(zd *ZoneData) bool {
	if zd == nil {
		return true // nothing to protect; never gate on a nil zone
	}
	if Globals.App.Type != AppTypeAuth {
		return true
	}
	return zd.ZoneType == Primary || zd.Options[OptInlineSigning]
}

// originationAPICommands are the /zone and /zone/dsync API commands that make
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
	"generate-nsec": true,
	// /zone/dsync — publishes the _dsync DSYNC RRset into the zone
	"publish-dsync-rrset":   true,
	"unpublish-dsync-rrset": true,
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
