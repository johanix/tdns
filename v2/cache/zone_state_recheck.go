/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * How long a zone's Indeterminate or Insecure validation state stands before
 * the validator looks at the zone again (#636).
 */
package cache

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// DefaultZoneStateRecheck is the recheck interval until SetZoneStateRecheck is
// called, and what a non-positive setting restores.
const DefaultZoneStateRecheck = 30 * time.Second

// zoneStateRecheck holds the interval in nanoseconds; zero means the default.
var zoneStateRecheck atomic.Int64

// SetZoneStateRecheck installs the recheck interval for every cache in the
// process; a non-positive interval restores the default. Like the TTL limits
// and the backoff policy it is process-wide, and the IMR sets it once, at init,
// from imrengine.tuning.zone-state-recheck.
func SetZoneStateRecheck(d time.Duration) {
	zoneStateRecheck.Store(int64(max(d, 0)))
}

// ZoneStateRecheck returns how long a zone's Indeterminate or Insecure state
// stands before the validator looks at the zone again.
//
// Both states are verdicts about a zone's chain of trust at one moment, kept in
// ZoneMap so that the validator does not walk the chain for everything the zone
// signs. Nothing used to end either of them: ZoneMap entries are never removed,
// so a verdict lasted for the life of the process and only a restart got it
// revisited.
//
//   - Indeterminate means the chain could not be followed: a DNSKEY fetch that
//     timed out, a parent that did not answer, an anchor not usable yet. Once
//     the interval has passed, GetState reports it as ValidationStateNone and
//     the next reader follows the chain again.
//
//   - Insecure means the parent delegated the zone without a DS. It does not
//     lapse to "not known": the verdict rests on a proof that there is no DS,
//     and the only thing worth asking again is whether a DS has appeared since.
//     So once the interval has passed, the next signature from the zone that is
//     checked has the parent asked for the zone's DS (recheckInsecureZone). A DS that validates makes the zone
//     Secure; no DS, or a DS that does not validate, leaves it Insecure for
//     another interval. A recheck only ever upgrades.
//
// The default leans towards noticing a change soon -- a child's first DS, a
// repaired chain -- rather than towards quiet. Waiting instead for the negative
// answer that showed "no DS" to expire would leave the wait to the parent's
// negative TTL, commonly hours, chosen by an operator with no reason to expect
// the data to change.
//
// TODO: a better way to decide which zones to recheck, and when. Every zone
// holding one of these states is rechecked on its own clock for as long as its
// data is being validated, and while nothing changes that is busy work: a DS
// query per Insecure zone per interval. Some of it is redundant by construction:
//   - The cause is often several parents up. A zone below an Insecure or
//     Indeterminate parent cannot become Secure before its parent does, so only
//     the topmost zone of such a subtree needs a recheck of its own; the zones
//     below it could follow it when it changes.
//   - A parent that has not changed cannot have published a DS. Its SOA serial
//     is a cheaper signal than a DS query for each of its children.
//   - A zone that has stayed Insecure through many rechecks is less likely to
//     change than one that has just become Insecure. The interval could back
//     off, as the address backoffs do, and start over when anything changes.
func ZoneStateRecheck() time.Duration {
	if d := zoneStateRecheck.Load(); d > 0 {
		return time.Duration(d)
	}
	return DefaultZoneStateRecheck
}

// claimInsecureRecheck reports whether the caller is to recheck this Insecure
// zone now: the state has stood for longer than ZoneStateRecheck. Claiming
// restarts the clock, so validations running at the same time keep the
// Insecure verdict and only the claimant pays for the recheck.
func (z *Zone) claimInsecureRecheck() bool {
	if z == nil {
		return false
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.State != ValidationStateInsecure {
		return false
	}
	now := time.Now()
	if z.stateSince.IsZero() {
		// Written by a struct literal: the clock starts now.
		z.stateSince = now
		return false
	}
	if now.Sub(z.stateSince) <= ZoneStateRecheck() {
		return false
	}
	z.stateSince = now
	return true
}

// recheckInsecureZone asks the parent again for the DS of a zone held Insecure,
// once that state has stood for ZoneStateRecheck; see there for why this is a
// recheck and not a lapse.
//
// It is called where the validator is about to act on the zone's state for
// signed data: the signer of an RRSIG, the zone of a signed RRset, a signed
// DNSKEY RRset. Signed data is the only sign that an Insecure zone may have
// become validatable, so a zone that is still unsigned costs no queries.
//
// A DS that validates Secure makes the zone Secure, in the DS case of
// validateRRsetWithRRSIG. No DS, a DS that does not validate, or no answer at
// all leaves the zone Insecure until the next interval, as it was.
func (rrcache *RRsetCacheT) recheckInsecureZone(ctx context.Context, name string, fetcher RRsetFetcher) {
	if rrcache == nil || ctx == nil || fetcher == nil {
		return
	}
	name = dns.Fqdn(name)
	if name == "." {
		return
	}
	zone, ok := rrcache.ZoneMap.Get(name)
	if !ok || !zone.claimInsecureRecheck() {
		return
	}
	// The DS entry cached alongside the Insecure verdict would be reused as it
	// stands, since ValidateRRsetWithParentZone keeps the verdict of an RRset
	// that has not changed. The recheck is a question about the DS, so the
	// entry goes.
	rrcache.RRsets.Remove(rrsetKey(name, dns.TypeDS))
	if rrcache.Verbose {
		log.Printf("recheckInsecureZone: zone %q has been insecure for %s; asking its parent for a DS", name, ZoneStateRecheck())
	}
	entry := rrcache.backfillDS(ctx, name, fetcher)
	if z, ok := rrcache.ZoneMap.Get(name); ok && z.GetState() == ValidationStateSecure {
		log.Printf("recheckInsecureZone: zone %q is now secure: its parent publishes a DS that validates", name)
		return
	}
	if rrcache.Verbose {
		found := "no DS"
		if len(actualDSRecords(entry)) > 0 {
			found = "a DS that is " + ValidationStateToString[entry.State]
		}
		log.Printf("recheckInsecureZone: zone %q stays insecure (%s); next recheck in %s", name, found, ZoneStateRecheck())
	}
}
