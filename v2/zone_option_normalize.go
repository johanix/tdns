/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Option normalization for the MUST-NOT-MODIFY invariant.
 * See docs/2026-07-25-secondary-zones-immutable.md §3 (Fix B) and §4.
 */
package tdns

import (
	"fmt"
	"sort"
	"strings"
)

// originationOptions are the zone options that let a zone ORIGINATE content —
// publish something of its own into the zone. None of them is legitimate on a
// tdns-auth secondary that is not inline-signing, because whatever they publish
// did not come from upstream. See §4 of the design doc for the per-option
// reasoning; briefly:
//
//   - allow-updates / allow-child-updates: DDNS and child-delegation writes.
//   - add-transport-signal: synthesizes SVCB/TSYNC signal records into the zone.
//   - delegation-sync-parent: publishes the _dsync DSYNC RRset (and, as an
//     intended consequence, gates KeyState EDNS(0) processing — a secondary can
//     never hold the receiver SIG(0) key, so leaving it on would emit UNSIGNED
//     KeyState responses, worse than not answering).
//   - online-signing: on tdns-auth the only keys available are LOCAL ones, and
//     signing upstream content with local keys is unsafe and plain wrong — it
//     unlocks whole-zone re-signing via the ResignQ path, standby-key minting,
//     per-refresh DNSKEY injection, and BOGUS ephemeral signing of denial NSECs.
//     (Signing at the edge with DISTRIBUTED keys is legitimate, but that is the
//     tdns-nm/tdns-es project — most likely a separate app, which the app-scope
//     in §1.1 accommodates untouched.)
//
// Deliberately NOT here: inline-signing (the sanctioned exception), the catalog
// options (consumption provisions OTHER zones and is the whole point of RFC 9432),
// delegation-sync-child (its publishing paths are allow-updates-gated and Fix D
// backstops them), and every serving-behaviour option.
var originationOptions = []ZoneOption{
	OptAllowUpdates,
	OptAllowChildUpdates,
	// allow-api-updates is origination by definition: it admits operator RR
	// changes over the management API. A tdns-auth secondary that may not
	// originate content must not accept them either, or the API becomes a way
	// around the MUST-NOT-MODIFY invariant that allow-updates already enforces
	// for the DDNS channel.
	OptAllowApiUpdates,
	OptAddTransportSignal,
	OptDelSyncParent,
	OptOnlineSigning,
	// publish-zonemd writes a locally computed record into the zone. On a
	// secondary that mirrors upstream content that record is ours, not
	// upstream's, and publishing it means the zone this server serves is no
	// longer the zone it received. An inline-signing secondary is exempt for
	// the usual reason -- it re-signs what it receives and therefore already
	// originates, and any ZONEMD from upstream is invalid for what it serves.
	OptPublishZonemd,
}

// normalizeOptionsForRole strips origination settings a zone may not act on,
// and reports what it stripped so the caller can tell the operator.
//
// It returns the EFFECTIVE options, the EFFECTIVE outbound serial mode, the set
// of options that were suppressed (nil if none), and a human-readable message
// (empty if nothing was suppressed).
//
// It is a no-op unless the zone is a tdns-auth secondary that may not originate
// content — the same predicate every other gate uses, so off tdns-auth this
// changes nothing at all and the derived apps keep their own rules (§1.1).
//
// The caller owns the maps it passes in; this function does not mutate them.
//
// NOTE the outbound serial mode is handled here too even though it is a string
// rather than a ZoneOption: `persist`/`unixtime` on a mirroring secondary is the
// same class of misconfiguration (it would rewrite a serial that belongs to
// upstream), and the operator deserves one consistent message for all of it.
func normalizeOptionsForRole(appType AppType, ztype ZoneType, opts map[ZoneOption]bool, serialMode string) (
	effective map[ZoneOption]bool, effectiveSerialMode string, suppressed map[ZoneOption]bool, msg string) {

	// Mirrors zoneMayOriginateContent, but on loose values: this runs during
	// config parsing, before a ZoneData necessarily exists.
	mayOriginate := appType != AppTypeAuth || ztype == Primary || opts[OptInlineSigning]
	if mayOriginate {
		return opts, serialMode, nil, ""
	}

	effective = opts
	effectiveSerialMode = serialMode
	var stripped []string

	for _, opt := range originationOptions {
		if !opts[opt] {
			continue
		}
		if suppressed == nil {
			suppressed = map[ZoneOption]bool{}
			// Copy-on-first-write: never mutate the caller's map, which may be
			// shared with a live ZoneData or a config struct.
			effective = make(map[ZoneOption]bool, len(opts))
			for k, v := range opts {
				effective[k] = v
			}
		}
		suppressed[opt] = true
		delete(effective, opt)
		stripped = append(stripped, ZoneOptionToString[opt])
	}

	// persist/unixtime would rewrite a serial that is upstream's property.
	// Empty ("inherit the global") is fine — the global is suppressed per-zone
	// at the point of use, and warning about a server-wide default on every
	// secondary would be noise. Only an EXPLICIT per-zone value is flagged.
	serialStripped := false
	if serialMode == OutboundSoaSerialPersist || serialMode == OutboundSoaSerialUnixtime {
		effectiveSerialMode = ""
		serialStripped = true
	}

	if len(stripped) == 0 && !serialStripped {
		return effective, effectiveSerialMode, nil, ""
	}

	sort.Strings(stripped)
	var b strings.Builder
	b.WriteString("secondary zone may not originate content; ignoring ")
	switch {
	case len(stripped) > 0 && serialStripped:
		fmt.Fprintf(&b, "option(s) %s and outbound-soa-serial=%s", strings.Join(stripped, ", "), serialMode)
	case len(stripped) > 0:
		fmt.Fprintf(&b, "option(s) %s", strings.Join(stripped, ", "))
	default:
		fmt.Fprintf(&b, "outbound-soa-serial=%s", serialMode)
	}
	// The likeliest operator intent behind online-signing on a secondary is the
	// sanctioned signing-secondary setup, which is a different option.
	if suppressed[OptOnlineSigning] {
		b.WriteString(" (for a signing secondary use inline-signing instead)")
	}
	return effective, effectiveSerialMode, suppressed, b.String()
}

// applyOptionNormalization runs normalizeOptionsForRole for a zone and records
// the outcome on the ZoneData: the effective options and serial mode are
// installed, the suppressed set is remembered so the AS-CONFIGURED view can be
// reconstructed when the config is re-serialized, and the operator gets a
// ConfigWarning.
//
// ConfigWarning, NOT ConfigError, is deliberate: ConfigError is in
// serviceImpactingErrors ("a NOTIFY/UPDATE/query handler should refuse with
// SERVFAIL"), so using it would eventually take a merely-misconfigured
// secondary out of service — and would park it permanently in the error column
// of `zone list`. The zone here is serving correctly; only some of its config
// is being ignored.
//
// Recomputed on every parse, so fixing the YAML clears the warning on reload.
// ztype is passed explicitly rather than read from zd.ZoneType because the
// static-config path normalizes before the parsed type has been assigned to the
// ZoneData.
// The caller MUST already hold zd.mu: this records the outcome on the
// ZoneData, and two of the four call sites run inside the refresh engine's
// per-zone critical section. Holding it at the other two costs nothing and
// makes the contract uniform, which is what keeps this from silently becoming
// a data race the next time a call site is added.
func (zd *ZoneData) applyOptionNormalization(ztype ZoneType, opts map[ZoneOption]bool, serialMode string) (map[ZoneOption]bool, string) {
	effective, effSerial, suppressed, msg := normalizeOptionsForRole(
		Globals.App.Type, ztype, opts, serialMode)

	zd.SuppressedOptions = suppressed
	// The *Locked variants, because the CALLER MUST ALREADY HOLD zd.mu (see the
	// doc comment above). ClearError and SetError take zd.mu themselves, so
	// calling them from here deadlocked the zone against itself: RefreshEngine
	// holds the lock across this call, the first zone never finished loading,
	// and the refresh engine never reached the second. Every zone after it sat
	// with no published snapshot, answering SERVFAIL.
	if msg == "" {
		zd.clearErrorLocked(ConfigWarning)
		return effective, effSerial
	}
	lg.Warn("zone option normalization", "zone", zd.ZoneName, "detail", msg)
	zd.setErrorLocked(ConfigWarning, "%s", msg)
	return effective, effSerial
}

// asConfiguredOptions reconstructs the options the OPERATOR wrote, by unioning
// the effective set with whatever normalization suppressed.
//
// This exists because the dynamic config file is REGENERATED from live state on
// every successful refresh of a persistable dynamic zone. Serializing the
// effective set would permanently delete the operator's `allow-updates` from
// their own config file — after which the warning would clear and the
// misconfiguration would become invisible, having been silently "fixed" by
// deleting the evidence. YAML is the source of truth for static zones; for
// dynamic zones the file is written from state, so state has to remember what
// was asked for.
func (zd *ZoneData) asConfiguredOptions() map[ZoneOption]bool {
	if len(zd.SuppressedOptions) == 0 {
		return zd.Options
	}
	out := make(map[ZoneOption]bool, len(zd.Options)+len(zd.SuppressedOptions))
	for k, v := range zd.Options {
		out[k] = v
	}
	for k := range zd.SuppressedOptions {
		out[k] = true
	}
	return out
}
