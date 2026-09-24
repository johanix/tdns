/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// An operator's edit of the apex CDS, CDNSKEY or CSYNC, through the management
// API or DNS UPDATE, is told to the parent (#752; design
// docs/2026-09-24-cds-publication-and-rfc-conformance.md §1.2 (d)).
//
// Only updates without InternalUpdate count. Every tdns writer of these RRsets
// -- the DS engine, the rollover push, the CSYNC publisher, PublishCdsRRs for
// tdns-mp, the RFC 9615 republisher, journal replay and zone merge -- sets it,
// and sends its own NOTIFY where one is due, so that is how they are told
// apart, with no marker of their own.

// apexSignalTypes are the RRsets whose edit is passed on.
var apexSignalTypes = []uint16{dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeCSYNC}

// touchesApexSignals reports whether an update names the zone's apex with one
// of the signal types, or with ANY.
func touchesApexSignals(zone string, actions []dns.RR) bool {
	for _, rr := range actions {
		h := rr.Header()
		if !core.EqualNames(h.Name, zone) {
			continue
		}
		switch h.Rrtype {
		case dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeCSYNC, dns.TypeANY:
			return true
		}
	}
	return false
}

// servedApexSignals reads the apex signal RRsets the zone serves.
func (zd *ZoneData) servedApexSignals() map[uint16][]dns.RR {
	return apexSignalsOf(getOwnerFrom(zd.publishedSnapshot(), zd.ZoneName))
}

// stagedApexSignals reads the apex signal RRsets an update just left: the
// working set's when one remains -- the zone is held by a transaction, and the
// served zone is still the old one -- otherwise the served zone, which the
// update has just published.
func (zd *ZoneData) stagedApexSignals() map[uint16][]dns.RR {
	zd.mu.Lock()
	var apex *OwnerData
	staged := zd.workingSet != nil
	if staged {
		apex = zd.workingSet[core.CanonicalizeName(zd.ZoneName)]
	}
	zd.mu.Unlock()
	if !staged {
		return zd.servedApexSignals()
	}
	return apexSignalsOf(apex)
}

func apexSignalsOf(apex *OwnerData) map[uint16][]dns.RR {
	out := make(map[uint16][]dns.RR, len(apexSignalTypes))
	if apex == nil || apex.RRtypes == nil {
		return out
	}
	for _, t := range apexSignalTypes {
		out[t] = apex.RRtypes.GetOnlyRRSet(t).RRs
	}
	return out
}

// editedSignalTypes lists the signal types whose RRset differs between before
// and after. Records are compared without their TTL, so an identical republish
// is no edit.
func editedSignalTypes(before, after map[uint16][]dns.RR) []uint16 {
	var out []uint16
	for _, t := range apexSignalTypes {
		if !sameRecords(before[t], after[t]) {
			out = append(out, t)
		}
	}
	return out
}

func sameRecords(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			if dns.IsDuplicate(caselessDigest(x), caselessDigest(y)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// caselessDigest is rr with a DS-shaped digest in lower case: hex has no case,
// and the DNS library prints it upper, so the same CDS read back from text
// would otherwise differ from itself (newCdsTuple).
func caselessDigest(rr dns.RR) dns.RR {
	switch v := rr.(type) {
	case *dns.CDS:
		c := *v
		c.Digest = strings.ToLower(c.Digest)
		return &c
	case *dns.DS:
		c := *v
		c.Digest = strings.ToLower(c.Digest)
		return &c
	}
	return rr
}

// signalsEditedSteps are what the SIGNALS-EDITED handler does, separated so
// its decisions can be tested without a parent.
type signalsEditedSteps struct {
	// managed reports whether tdns manages the zone's keys (a known DS intent).
	managed func() (bool, error)
	// explicitSync runs the EXPLICIT-SYNC-DELEGATION path.
	explicitSync func()
	// markKeys tells the DS engine to bring the CDS in step with the keys.
	markKeys func()
	// served reads the apex RRset of a type as the zone serves it now.
	served func(rrtype uint16) []dns.RR
	// target looks up the parent's NOTIFY target for a type.
	target func(rrtype uint16) (*DsyncTarget, error)
	// notify hands one NOTIFY of the type to the notifier.
	notify func(rrtype uint16, target *DsyncTarget) bool
}

// handleSignalsEditedWith tells the parent about an operator's edit of the
// types listed.
//
// CDS or CDNSKEY on a zone whose keys tdns manages: the DS engine owns that
// CDS, so the parent is told what the keys call for, not what was typed. The
// explicit sync compares the parent's DS with the keys and, for a NOTIFY
// parent, has the DS engine restore the CDS before the NOTIFY (ensureCDS); an
// UPDATE or API parent gets the DS. Then the engine is marked, so an edit that
// differs from the keys is replaced now rather than at the next tick. Sync
// first, then mark: marking first would have the engine restore the CDS and
// queue a sync of its own, and a parent that is behind would get two NOTIFYs.
// With the parent in step, the mark leads to one sync that sends nothing; that
// is accepted.
//
// CDS or CDNSKEY on a zone whose keys tdns does not manage: the CDS is the
// operator's, and the explicit sync leaves the parent's DS alone for such a
// zone. So a NOTIFY(CDS) goes to the parent's NOTIFY target -- RFC 9859 uses
// NOTIFY(CDS) for both types -- when either RRset is non-empty. A parent with
// no NOTIFY target gets nothing: UPDATE and API carry a DS, and tdns does not
// turn an operator's CDS into one. A hand-published delete CDS is non-empty and
// is announced: that is the operator taking the zone insecure, not tdns.
//
// CSYNC: a NOTIFY(CSYNC) when the RRset is non-empty.
//
// A removed RRset sends nothing: under RFC 8078, no CDS means no change.
func handleSignalsEditedWith(zd *ZoneData, types []uint16, steps signalsEditedSteps) {
	var cds, csync bool
	for _, t := range types {
		switch t {
		case dns.TypeCDS, dns.TypeCDNSKEY:
			cds = true
		case dns.TypeCSYNC:
			csync = true
		}
	}

	if cds {
		managed, err := steps.managed()
		switch {
		case err != nil:
			lgDns.Warn("SIGNALS-EDITED: could not tell whether tdns manages this zone's keys;"+
				" the parent is not told of the CDS edit", "zone", zd.ZoneName, "err", err)
		case managed:
			lgDns.Info("SIGNALS-EDITED: CDS edited on a zone whose keys tdns manages;"+
				" telling the parent what the keys call for", "zone", zd.ZoneName)
			steps.explicitSync()
			steps.markKeys()
		case len(steps.served(dns.TypeCDS)) > 0 || len(steps.served(dns.TypeCDNSKEY)) > 0:
			notifyParentOfEdit(zd, dns.TypeCDS, steps)
		default:
			lgDns.Debug("SIGNALS-EDITED: CDS and CDNSKEY removed; nothing to tell the parent",
				"zone", zd.ZoneName)
		}
	}

	if csync {
		if len(steps.served(dns.TypeCSYNC)) > 0 {
			notifyParentOfEdit(zd, dns.TypeCSYNC, steps)
		} else {
			lgDns.Debug("SIGNALS-EDITED: CSYNC removed; nothing to tell the parent", "zone", zd.ZoneName)
		}
	}
}

func notifyParentOfEdit(zd *ZoneData, rrtype uint16, steps signalsEditedSteps) {
	target, err := steps.target(rrtype)
	if err != nil || target == nil || len(target.Addresses) == 0 {
		lgDns.Info("SIGNALS-EDITED: the parent advertises no usable NOTIFY target; nothing sent",
			"zone", zd.ZoneName, "rrtype", dns.TypeToString[rrtype], "err", err)
		return
	}
	if steps.notify(rrtype, target) {
		lgDns.Info("SIGNALS-EDITED: sent NOTIFY after an operator's edit", "zone", zd.ZoneName,
			"rrtype", dns.TypeToString[rrtype], "target", target.Name)
	}
}

// signalsEditedStepsFor are the handler's real steps.
func signalsEditedStepsFor(ctx context.Context, kdb *KeyDB, notifyq chan NotifyRequest, imr *Imr,
	zd *ZoneData) signalsEditedSteps {

	return signalsEditedSteps{
		managed: func() (bool, error) {
			intent, err := DSIntentForZone(kdb, zd.ZoneName, dns.SHA256)
			return intent.Known, err
		},
		explicitSync: func() { _ = zd.runExplicitSync(ctx, kdb, notifyq, imr) },
		markKeys:     func() { kdb.KeysChanged(zd) },
		served: func(rrtype uint16) []dns.RR {
			return zd.servedApexSignals()[rrtype]
		},
		target: func(rrtype uint16) (*DsyncTarget, error) {
			if imr == nil {
				return nil, ErrNoImrEngine
			}
			return imr.LookupDSYNCTarget(ctx, zd.ZoneName, rrtype, core.SchemeNotify)
		},
		notify: func(rrtype uint16, target *DsyncTarget) bool {
			return sendNotifyRequest(ctx, notifyq, NotifyRequest{
				ZoneName: zd.ZoneName,
				ZoneData: zd,
				RRtype:   rrtype,
				Targets:  target.Addresses,
			})
		},
	}
}
