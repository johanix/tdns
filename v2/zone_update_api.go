/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// ApiZoneUpdate applies one zone-content statement that arrived over the
// management API.
//
// Admission, in order:
//
//  1. The zone must originate its own content. A secondary's content belongs
//     to its primary; letting the API edit it would be the same violation the
//     MUST-NOT-MODIFY invariant closes for every other path.
//  2. The zone must carry allow-api-updates. This is a separate consent from
//     allow-updates, which governs RFC 2136: an operator who opened a zone to
//     SIG(0) DDNS has not thereby opened it to the API, and vice versa.
//  3. A frozen zone refuses updates on BOTH channels. Freeze means the zone
//     file on disk is the authority right now; accepting API changes while
//     frozen would silently strand them the next time the file is read.
//
// Only after all three does the request get PreAuthorized, which is what tells
// the ZoneUpdater that authorization was settled here (the API key is the
// credential) and that update-policy does not apply. Nothing on the DNS path
// sets that flag.
func (zd *ZoneData) ApiZoneUpdate(ctx context.Context, zp ZonePost) (string, error) {
	if zd == nil {
		return "", fmt.Errorf("no such zone")
	}

	// Snapshot both options together under the lock. RefreshEngine and config
	// reload mutate zd.Options under zd.mu, so reading the map here unlocked is
	// a data race, and reading the two independently would let a reload flip
	// one between the checks. Matches the CHILD-UPDATE handling in the updater.
	zd.mu.Lock()
	allowApi := zd.Options[OptAllowApiUpdates]
	frozen := zd.Options[OptFrozen]
	zd.mu.Unlock()

	if !allowApi {
		return "", fmt.Errorf(
			"zone %s does not allow updates via the management API (needs the allow-api-updates option)",
			zd.ZoneName)
	}
	if frozen {
		return "", fmt.Errorf("zone %s is frozen; thaw it before updating", zd.ZoneName)
	}

	actions, err := BuildZoneUpdateActions(zd.ZoneName, ZoneUpdateSpec{
		Verb:   zp.UpdateVerb,
		RRs:    zp.UpdateRRs,
		Name:   zp.UpdateName,
		Rrtype: zp.UpdateRrtype,
	})
	if err != nil {
		return "", err
	}
	if len(actions) == 0 {
		return "", fmt.Errorf("statement produced no changes")
	}

	if zd.KeyDB == nil || zd.KeyDB.UpdateQ == nil {
		return "", fmt.Errorf("zone updater is not available")
	}

	// Answer only once the change has actually been made, for the same reason
	// the DNS UPDATE responder does: a 200 that means "queued" is a promise the
	// server has not kept, and the caller has no way to find out later whether
	// it was. Buffered, so the updater's non-blocking reply always lands even
	// if the wait below has already given up.
	respch := make(chan ZoneUpdateResult, 1)

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:           "ZONE-UPDATE",
		ZoneName:      zd.ZoneName,
		Actions:       actions,
		PreAuthorized: true,
		Description:   fmt.Sprintf("API %s", zp.UpdateVerb),
		Resp:          respch,
	}:
	case <-ctx.Done():
		// The HTTP client hung up. Stop waiting rather than hold a handler
		// goroutine on a queue nobody is going to read the answer from.
		return "", fmt.Errorf("request cancelled while queueing the update for zone %s: %w",
			zd.ZoneName, ctx.Err())
	case <-time.After(5 * time.Second):
		return "", fmt.Errorf("timeout while queueing the update for zone %s", zd.ZoneName)
	}

	select {
	case res := <-respch:
		if res.Err != nil {
			return "", fmt.Errorf("zone %s: %s not applied: %v",
				zd.ZoneName, zp.UpdateVerb, res.Err)
		}
		if !res.Applied {
			// Accepted and durable, but nothing actually changed -- e.g. adding
			// an RR that is already present. Worth saying plainly rather than
			// reporting a change that did not happen.
			lgApi.Info("api zone update was a no-op", "zone", zd.ZoneName, "verb", zp.UpdateVerb)
			return fmt.Sprintf("Zone %s: %s changed nothing", zd.ZoneName, zp.UpdateVerb), nil
		}

	case <-time.After(UpdateApplyTimeout):
		return "", fmt.Errorf(
			"zone %s: timed out after %s waiting for %s to be applied;"+
				" it may or may not have taken effect",
			zd.ZoneName, UpdateApplyTimeout, zp.UpdateVerb)
	}

	lgApi.Info("api zone update applied", "zone", zd.ZoneName,
		"verb", zp.UpdateVerb, "actions", len(actions))

	return fmt.Sprintf("Zone %s: %s applied (%d update record%s)",
		zd.ZoneName, zp.UpdateVerb, len(actions), plural(len(actions))), nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// ZoneUpdateActionsSummary renders an action list the way the update section
// reads on the wire, for logs and for the CLI's confirmation output.
func ZoneUpdateActionsSummary(actions []dns.RR) []string {
	out := make([]string, 0, len(actions))
	for _, rr := range actions {
		switch rr.Header().Class {
		case dns.ClassANY:
			if rr.Header().Rrtype == dns.TypeANY {
				out = append(out, fmt.Sprintf("DELNAME  %s", rr.Header().Name))
				continue
			}
			out = append(out, fmt.Sprintf("DELRRSET %s %s",
				rr.Header().Name, dns.TypeToString[rr.Header().Rrtype]))
		case dns.ClassNONE:
			out = append(out, fmt.Sprintf("DEL      %s", rr.String()))
		default:
			out = append(out, fmt.Sprintf("ADD      %s", rr.String()))
		}
	}
	return out
}
