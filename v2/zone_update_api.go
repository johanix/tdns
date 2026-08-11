/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
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
func (zd *ZoneData) ApiZoneUpdate(zp ZonePost) (string, error) {
	if zd == nil {
		return "", fmt.Errorf("no such zone")
	}

	if !zd.Options[OptAllowApiUpdates] {
		return "", fmt.Errorf(
			"zone %s does not allow updates via the management API (needs the allow-api-updates option)",
			zd.ZoneName)
	}
	if zd.Options[OptFrozen] {
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

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:           "ZONE-UPDATE",
		ZoneName:      zd.ZoneName,
		Actions:       actions,
		PreAuthorized: true,
		Description:   fmt.Sprintf("API %s", zp.UpdateVerb),
	}:
	case <-time.After(5 * time.Second):
		return "", fmt.Errorf("timeout while queueing the update for zone %s", zd.ZoneName)
	}

	lgApi.Info("api zone update queued", "zone", zd.ZoneName,
		"verb", zp.UpdateVerb, "actions", len(actions))

	return fmt.Sprintf("Zone %s: %s queued (%d update record%s)",
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
