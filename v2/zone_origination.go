/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The MUST-NOT-MODIFY invariant for tdns-auth secondary zones.
 * See docs/2026-07-25-secondary-zones-immutable.md.
 */
package tdns

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
