/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"errors"
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// Note that there are two types of determining whether delegation synchronization is needed:
// 1. Implicit: we notice that the delegation information in the child has changed and therefore NOTIFY or UPDATE the parent.
// 2. Explicit: we query the parent for the delegation information and if it differs from the child, we NOTIFY or UPDATE the parent.
// AnalyseZoneDelegation() is used for the second type of delegation synchronization.

// 1. Query parent servers until we get a child NS RRset back
// 2. Iterate over child NS RRset from parent and identify all in-bailiwick NS
// 3. Query same parent server as returned the NS RRset for the glue for this child NS
// 4. When all parent-side data is collected, compare to the data in the ZoneData struct

// Return insync (bool), adds, removes ([]dns.RR) and error
func (zd *ZoneData) AnalyseZoneDelegation(imr *Imr) (DelegationSyncStatus, error) {
	var resp = DelegationSyncStatus{
		ZoneName: zd.ZoneName,
		Time:     time.Now(),
	}

	err := zd.FetchParentData(imr)
	if err != nil {
		return resp, err
	}

	resp.Parent = zd.Parent

	var p_nsrrs []dns.RR
	var pserver string // outside loop to preserve for later re-use

	// 1. Compare NS RRsets between parent and child
	for _, pserver = range zd.ParentServers {
		p_nsrrs, err = AuthQuery(zd.ZoneName, pserver, dns.TypeNS)
		if err != nil {
			lgDns.Warn("error from AuthQuery for NS", "server", pserver, "zone", zd.ZoneName, "err", err)
			continue
		}

		if len(p_nsrrs) == 0 {
			lgDns.Warn("empty response to AuthQuery for NS", "server", pserver, "zone", zd.ZoneName)
			continue
		}

		// We have a response, no need to talk to rest of parent servers
		break
	}
	if len(p_nsrrs) == 0 {
		return resp, fmt.Errorf("no NS RRsets found for zone %s", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return resp, err
	}

	differ, adds, removes := core.RRsetDiffer(zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs,
		p_nsrrs, dns.TypeNS, zd.Logger, Globals.Verbose, Globals.Debug)
	resp.InSync = !differ
	// log.Printf("AnalyseZoneDelegation: Zone %s: NS RRsetDiffer: %v InSync: %v", zd.ZoneName, differ, resp.InSync)

	resp.NsAdds = append(resp.NsAdds, adds...)
	resp.NsRemoves = append(resp.NsRemoves, removes...)

	// 2. Compute the names of the in-bailiwick subset of nameservers
	child_inb, _ := BailiwickNS(zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
	// parent_inb, _ := BailiwickNS(zd.ZoneName, apex.RRtypes[dns.TypeNS].RRs)

	// 3. Compare A and AAAA glue for in child in-bailiwick nameservers
	for _, ns := range child_inb {
		owner, err := zd.GetOwner(ns)
		if err != nil {
			lgDns.Warn("error from GetOwner", "name", ns, "err", err)
			continue
		}
		if owner == nil {
			lgDns.Warn("AnalyseZoneDelegation: owner data is nil for NS", "zone", zd.ZoneName, "ns", ns)
			continue
		}
		child_a_glue := owner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs
		parent_a_glue, err := AuthQuery(ns, pserver, dns.TypeA)
		if err != nil {
			lgDns.Warn("error from AuthQuery for A glue", "server", pserver, "ns", ns, "err", err)
			continue
		}
		gluediff, adds, removes := core.RRsetDiffer(ns, child_a_glue, parent_a_glue,
			dns.TypeA, zd.Logger, Globals.Verbose, Globals.Debug)
		if gluediff {
			resp.InSync = false
			resp.AAdds = append(resp.AAdds, adds...)
			resp.ARemoves = append(resp.ARemoves, removes...)
		}

		child_aaaa_glue := owner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs
		parent_aaaa_glue, err := AuthQuery(ns, pserver, dns.TypeAAAA)
		if err != nil {
			lgDns.Warn("error from AuthQuery for AAAA glue", "server", pserver, "ns", ns, "err", err)
			continue
		}
		differ, adds, removes = core.RRsetDiffer(ns, child_aaaa_glue, parent_aaaa_glue,
			dns.TypeAAAA, zd.Logger, Globals.Verbose, Globals.Debug)
		if differ {
			resp.InSync = false
			resp.AAAAAdds = append(resp.AAAAAdds, adds...)
			resp.AAAARemoves = append(resp.AAAARemoves, removes...)
		}
	}
	// 4. Compare DS RRsets between parent and child -- unless a KSK rollover is
	// in flight, in which case the DS RRset is not this function's to have an
	// opinion about.
	//
	// A rollover deliberately puts the parent and the child's published
	// DNSKEYs out of step: a double-DS roll places the new DS at the parent
	// BEFORE the matching DNSKEY appears in the zone. The comparison below
	// derives the child's DS from published SEP DNSKEYs, so it sees that new DS
	// as surplus and reports it for removal. Acting on that deletes the DS the
	// rollover just placed, and the roll then swaps onto a KSK the parent has
	// no DS for.
	//
	// The engine owns the DS while it is rolling, and sources its set from the
	// keystore and the rollover target rather than from published keys. Only
	// the DS dimension is suppressed: NS and glue are independent of a key roll,
	// and a rollover window is days wide, so suppressing the whole comparison
	// would stall ordinary delegation edits for the duration. Those are
	// analysed above and their results stand.
	//
	// Written as a wrapped block rather than an early return so that anything
	// added after this point is not silently skipped along with the DS.
	if !zd.rolloverOwnsDS() {
		if err := zd.compareParentDS(&resp, pserver, apex); err != nil {
			return resp, err
		}
	}

	return resp, nil
}

// unmanagedZoneNeedsDSRepair reports whether a zone whose keys tdns does not
// manage is nonetheless in a state that needs the parent's attention: the
// parent holds a DS and the child publishes no DNSKEY RRset at all.
//
// Split out so the decision can be tested. compareParentDS reaches it only
// after a live AuthQuery to the parent, and a test that re-derived the
// condition instead of calling this would pass with the check removed -- which
// is what the first attempt did.
//
// The test is the ABSENCE of the RRset, not an empty derived DS set: SEP is
// advisory, so a zone signed with a flags-256 CSK derives nothing while being
// perfectly signed.
func unmanagedZoneNeedsDSRepair(apex *OwnerData, parentDS []dns.RR) bool {
	if len(parentDS) == 0 {
		return false
	}
	if apex == nil || apex.RRtypes == nil {
		// Unknown, not unsigned. A zone whose apex cannot be read is not
		// evidence that the child publishes no keys.
		return false
	}
	return len(apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs) == 0
}

// compareParentDS fills in the DS dimension of a delegation analysis: it asks
// the parent what DS it holds, works out what this zone's keys say it should
// hold, and records the difference.
//
// What the child "should" hold comes from the keystore, not from the published
// DNSKEY RRset -- a rollover places a DS at the parent before the matching
// DNSKEY appears, so anything derived from published keys omits exactly the
// record just placed. For a zone whose keys tdns does not manage there is no
// such view at all, and the one state that needs none is handled by
// unmanagedZoneNeedsDSRepair.
//
// Split out of AnalyseZoneDelegation so the rollover suppression there reads as
// one decision rather than an early return threaded through the function.
func (zd *ZoneData) compareParentDS(resp *DelegationSyncStatus, pserver string, apex *OwnerData) error {
	// Query parent for DS records
	p_dsrrs, err := AuthQuery(zd.ZoneName, pserver, dns.TypeDS)
	if err != nil {
		lgDns.Warn("error from AuthQuery for DS", "server", pserver, "zone", zd.ZoneName, "err", err)
		// DS query failure — skip DS comparison entirely
	} else if len(p_dsrrs) > 0 || len(apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs) > 0 {
		// What the parent should hold comes from the keystore, not from the
		// published DNSKEY RRset. Under multi-DS the new DS is placed at the
		// parent BEFORE its DNSKEY appears in the zone, so a set derived from
		// published keys is missing exactly the record the rollover just added
		// and would report it for deletion.
		//
		// An unknown intent is not an empty one: it means tdns does not manage
		// this zone's keys, and the parent's DS is then none of our business.
		intent, ierr := DSIntentForZone(zd.KeyDB, zd.ZoneName, dns.SHA256)
		if ierr != nil {
			lgDns.Warn("AnalyseZoneDelegation: could not determine the DS intent; leaving the parent DS alone",
				"zone", zd.ZoneName, "err", ierr)
			return nil
		}
		if !intent.Known {
			// tdns does not manage this zone's keys, so it has no view of what
			// the parent's DS SHOULD be -- with one state that needs no view.
			//
			// A child publishing no DNSKEY RRset at all while the parent holds
			// a DS is unambiguously broken: every validating resolver declares
			// the whole child bogus, no procedure produces the state on
			// purpose, and the child cannot signal its way out because
			// CDS-delete needs a validation it has no key for. That is the
			// exception the scope doc grants, and the API payload already acts
			// on it -- but only if something reports the delegation as out of
			// sync first.
			//
			// Returning unconditionally here is what stopped that. The DS
			// dimension never reached InSync for a proxied zone, matching NS
			// and glue were enough to call it synchronised, and
			// ProxyStartupReconcile bailed before the repair could run. An
			// agent restarting while the child was already unsigned left the
			// zone bogus indefinitely -- steady-state un-signing worked,
			// because the DNSKEY removal is itself a transfer change.
			//
			// Deliberately no DSAdds/DSRemoves and no NewDS: this says the
			// delegation needs attention, not what the DS set should become.
			// Deciding that from published keys is what B1 replaces.
			if unmanagedZoneNeedsDSRepair(apex, p_dsrrs) {
				lgDns.Info("AnalyseZoneDelegation: parent holds a DS for a child that publishes"+
					" no DNSKEY RRset; reporting the delegation as out of sync so the repair can run",
					"zone", zd.ZoneName, "parent_ds", len(p_dsrrs))
				resp.InSync = false
				return nil
			}
			lgDns.Debug("AnalyseZoneDelegation: no keystore KSKs for this zone; leaving the parent DS alone",
				"zone", zd.ZoneName)
			return nil
		}
		childDS := intent.Set

		dsdiff, dsadds, dsremoves := core.RRsetDiffer(zd.ZoneName, childDS,
			p_dsrrs, dns.TypeDS, zd.Logger, Globals.Verbose, Globals.Debug)
		if dsdiff {
			resp.InSync = false
			resp.DSAdds = append(resp.DSAdds, dsadds...)
			resp.DSRemoves = append(resp.DSRemoves, dsremoves...)
		}

		// Compute NewDS for replace mode. Authoritative even when empty: an
		// un-signed zone whose keys tdns holds is a real instruction to
		// withdraw the DS, not an absence of opinion.
		resp.NewDS = childDS
		resp.NewDSKnown = true
	}

	return nil
}

// Only used from CLI (tdns-cli ddns sync)
// Returns unsynched bool, adds, removes []dns.RR, error

// XXX: This requires lots of recursive queries and does not take advantage of the zonedata struct
//      in tdns-auth most likely having cached most of this information. Since the only reason for
//      the tdns-cli tool is to interact with tdns-auth, it really should leverage from that rather
//      than just do everything in the CLI.

func ChildDelegationDataUnsynched(zone, pzone, childpri, parpri string) (bool, []dns.RR, []dns.RR, error) {

	var differ bool
	var adds, removes []dns.RR

	if viper.GetBool("childsync.update-ns") {
		var err error
		differ, adds, removes, err = ComputeRRDiff(childpri, parpri,
			Globals.Zonename, dns.TypeNS)
		if err != nil {
			return false, nil, nil, fmt.Errorf("computing NS diff: %w", err)
		}
	} else {
		fmt.Printf("*** Note: configured NOT to update NS RRset.\n")
	}

	child_ns_inb, parent_ns_inb, err := ComputeBailiwickNS(childpri, parpri,
		Globals.Zonename)
	if err != nil {
		return false, nil, nil, fmt.Errorf("computing bailiwick NS: %w", err)
	}
	for _, ns := range child_ns_inb {
		fmt.Printf("Child in-bailiwick NS: %s\n", ns)
	}
	for _, ns := range parent_ns_inb {
		fmt.Printf("Parent in-bailiwick NS: %s\n", ns)
	}

	for _, ns := range child_ns_inb {
		if viper.GetBool("childsync.update-a") {
			fmt.Printf("Comparing A glue for child NS %s:\n", ns)
			gluediff, a_glue_adds, a_glue_removes, err := ComputeRRDiff(childpri,
				parpri, ns, dns.TypeA)
			if err != nil {
				return false, nil, nil, fmt.Errorf("computing A glue diff for %s: %w", ns, err)
			}
			if gluediff {
				differ = true
				removes = append(removes, a_glue_removes...)
				adds = append(adds, a_glue_adds...)
			}
		} else {
			fmt.Printf("*** Note: configured NOT to update A glue.\n")
		}

		if viper.GetBool("childsync.update-aaaa") {
			fmt.Printf("Comparing AAAA glue for child NS %s:\n", ns)
			gluediff, aaaa_glue_adds, aaaa_glue_removes, err := ComputeRRDiff(childpri,
				parpri, ns, dns.TypeAAAA)
			if err != nil {
				return false, nil, nil, fmt.Errorf("computing AAAA glue diff for %s: %w", ns, err)
			}
			if gluediff {
				differ = true
				removes = append(removes, aaaa_glue_removes...)
				adds = append(adds, aaaa_glue_adds...)
			}
		} else {
			fmt.Printf("*** Note: configured NOT to update AAAA glue.\n")
		}
	}

	if !differ {
		fmt.Printf("Parent delegation data is in sync with child. No update needed.\n")
		return false, []dns.RR{}, []dns.RR{}, nil
	}
	return true, adds, removes, nil
}

// XXX: This is similar to ChildDelegationDataUnsynched, but instead of querying the
//      child and parent primaries we compare the delegation data in the *ZoneData
//      structs.

// DelegationDataChanged() compares the delegation data in the old vs new *ZoneData structs.
// Returns unsynched bool, adds, removes []dns.RR, error

func (zd *ZoneData) DelegationDataChangedNG(newzd *ZoneData) (bool, DelegationSyncStatus, error) {
	lgDns.Debug("entering DelegationDataChangedNG", "zone", newzd.ZoneName)
	var dss = DelegationSyncStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
		InSync:   true,
	}

	oldapex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		if errors.Is(err, ErrZoneNotReady) {
			lgDns.Debug("DDCNG: old zone not ready (initial load), no delegation change", "zone", zd.ZoneName)
			return false, dss, nil
		}
		return false, dss, fmt.Errorf("error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}
	if oldapex == nil {
		lgDns.Debug("DDCNG: old apexdata was nil, this is the initial zone load", "zone", zd.ZoneName)
		return false, dss, nil
	}

	// ownerForAnalysis, not GetOwner: newzd is the not-yet-published incoming
	// zone, and GetOwner would read its (absent) snapshot and return nil.
	newapex, err := newzd.ownerForAnalysis(zd.ZoneName)
	if err != nil {
		return false, dss, fmt.Errorf("error from newzd.ownerForAnalysis(%s): %v", zd.ZoneName, err)
	}
	if newapex == nil {
		// An incoming zone with no apex is a broken or empty transfer. It is
		// deliberately NOT reported as a delegation change: doing so would
		// drive a withdrawal of the delegation at the parent.
		lgDns.Warn("DDCNG: no apex in the incoming zone; treating as no delegation change",
			"zone", zd.ZoneName)
		return false, dss, nil
	}

	lgDns.Debug("DDCNG: comparing NS RRtypes", "zone", zd.ZoneName)
	// dump.P(oldapex.RRtypes[dns.TypeNS])
	// dump.P(newapex.RRtypes[dns.TypeNS])

	var nsdiff bool

	nsdiff, dss.NsAdds, dss.NsRemoves = core.RRsetDiffer(zd.ZoneName, newapex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs,
		oldapex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs, dns.TypeNS, zd.Logger, Globals.Verbose, Globals.Debug)

	dss.InSync = !nsdiff

	for _, ns := range dss.NsRemoves {
		lgDns.Debug("DDCNG: removed NS", "ns", ns.String())
		if nsrr, ok := ns.(*dns.NS); ok {
			nsowner, err := zd.GetOwner(nsrr.Ns)
			if err != nil {
				lgDns.Warn("DDCNG: nsname of NS has no RRs", "nsname", nsrr.Ns, "ns", nsrr.String())
			} else if nsowner != nil { // nsowner != nil if the NS is in bailiwick
				if a_rrset, exists := nsowner.RRtypes.Get(dns.TypeA); exists {
					for _, rr := range a_rrset.RRs {
						rr.Header().Class = dns.ClassNONE
						dss.ARemoves = append(dss.ARemoves, rr)
						dss.InSync = false
					}
				}
				if aaaa_rrset, exists := nsowner.RRtypes.Get(dns.TypeAAAA); exists {
					for _, rr := range aaaa_rrset.RRs {
						rr.Header().Class = dns.ClassNONE
						dss.AAAARemoves = append(dss.AAAARemoves, rr)
						dss.InSync = false
					}
				}
			}
		}
	}

	for _, ns := range dss.NsAdds {
		lgDns.Debug("DDCNG: added NS", "ns", ns.String())
		if nsrr, ok := ns.(*dns.NS); ok {
			nsowner, err := newzd.ownerForAnalysis(nsrr.Ns)
			if err != nil {
				lgDns.Warn("DDCNG: nsname of NS has no RRs", "nsname", nsrr.Ns, "ns", nsrr.String())
			} else if nsowner != nil { // nsowner != nil if the NS is in bailiwick
				if a_rrset, exists := nsowner.RRtypes.Get(dns.TypeA); exists {
					for _, rr := range a_rrset.RRs {
						dss.AAdds = append(dss.AAdds, rr)
						dss.InSync = false
					}
				}
				if aaaa_rrset, exists := nsowner.RRtypes.Get(dns.TypeAAAA); exists {
					for _, rr := range aaaa_rrset.RRs {
						dss.AAAAAdds = append(dss.AAAAAdds, rr)
						dss.InSync = false
					}
				}
			}
		}
	}

	// we need a third loop to check for changes in the glue records themselves.

	oldInBailiwick, _ := BailiwickNS(zd.ZoneName, oldapex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
	for _, nsname := range oldInBailiwick {
		oldowner, err := zd.GetOwner(nsname)
		if err != nil || oldowner == nil {
			lgDns.Warn("DDCNG: in-bailiwick nameserver has no address records in old zone", "ns", nsname)
			continue
		}
		newowner, err := newzd.ownerForAnalysis(nsname)
		if err != nil || newowner == nil {
			lgDns.Warn("DDCNG: in-bailiwick nameserver has no address records in new zone", "ns", nsname)
			for _, rr := range oldowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs {
				rr.Header().Class = dns.ClassNONE
				dss.ARemoves = append(dss.ARemoves, rr)
			}
			for _, rr := range oldowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs {
				rr.Header().Class = dns.ClassNONE
				dss.AAAARemoves = append(dss.AAAARemoves, rr)
			}
			continue
		}
		diff, adds, removes := core.RRsetDiffer(nsname, newowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs, oldowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs, dns.TypeA, zd.Logger, Globals.Verbose, Globals.Debug)
		if diff {
			dss.AAdds = append(dss.AAdds, adds...)
			dss.ARemoves = append(dss.ARemoves, removes...)
			dss.InSync = false
		}
		diff, adds, removes = core.RRsetDiffer(nsname, newowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs, oldowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs, dns.TypeAAAA, zd.Logger, Globals.Verbose, Globals.Debug)
		if diff {
			dss.AAAAAdds = append(dss.AAAAAdds, adds...)
			dss.AAAARemoves = append(dss.AAAARemoves, removes...)
			dss.InSync = false
		}
	}

	// Compare KSK DNSKEYs and compute DS diff
	oldkeys := oldapex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs
	newkeys := newapex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs
	if len(oldkeys) > 0 || len(newkeys) > 0 {
		var oldDS, newDS []dns.RR
		for _, rr := range oldkeys {
			if dk, ok := rr.(*dns.DNSKEY); ok {
				if dk.Flags&dns.SEP != 0 {
					if ds := dk.ToDS(dns.SHA256); ds != nil {
						oldDS = append(oldDS, ds)
					}
				}
			}
		}
		for _, rr := range newkeys {
			if dk, ok := rr.(*dns.DNSKEY); ok {
				if dk.Flags&dns.SEP != 0 {
					if ds := dk.ToDS(dns.SHA256); ds != nil {
						newDS = append(newDS, ds)
					}
				}
			}
		}
		dsdiff, dsadds, dsremoves := core.RRsetDiffer(zd.ZoneName, newDS, oldDS, dns.TypeDS, zd.Logger, Globals.Verbose, Globals.Debug)
		if dsdiff {
			dss.DSAdds = append(dss.DSAdds, dsadds...)
			dss.DSRemoves = append(dss.DSRemoves, dsremoves...)
			dss.NewDS = newDS
			// This set is derived from the published DNSKEY RRset, which is an
			// answer only when it produced something. An empty result here does
			// not mean the child has no DS -- it means this diff found no SEP
			// keys to hash, which is also what a transfer carrying no DNSKEYs
			// looks like. Saying so explicitly keeps replace mode behaving as
			// it did before the flag existed.
			dss.NewDSKnown = len(newDS) > 0
			dss.InSync = false
		}
	}

	if dss.InSync {
		fmt.Printf("Old delegation data is identical to new. No update needed.\n")
		return false, dss, nil
	}

	return true, dss, nil
}

func (zd *ZoneData) DnskeysChanged(newzd *ZoneData) (bool, DelegationSyncStatus, error) {
	var dss = DelegationSyncStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
		InSync:   true,
	}
	var differ bool

	oldapex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		if errors.Is(err, ErrZoneNotReady) {
			lgDns.Debug("DnskeysChanged: old zone not ready (initial load), reporting DNSKEYs changed", "zone", zd.ZoneName)
			return true, dss, nil
		}
		return false, dss, fmt.Errorf("error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}
	if oldapex == nil {
		lgDns.Debug("DnskeysChanged: old apexdata was nil, this is the initial zone load", "zone", zd.ZoneName)
		return true, dss, nil // on initial load, we always return true, dss, nil as we don't know that the DNSKEYs have changed
	}

	oldkeys, err := zd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, dss, err
	}
	newkeys, err := newzd.rrsetForAnalysis(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, dss, err
	}

	differ, dss.DNSKEYAdds, dss.DNSKEYRemoves = core.RRsetDiffer(zd.ZoneName, newkeys.RRs, oldkeys.RRs, dns.TypeDNSKEY, zd.Logger, Globals.Verbose, Globals.Debug)
	if differ {
		dss.Time = time.Now()
		dss.InSync = false

		// Compute DS diff from KSK changes
		var oldDS, newDS []dns.RR
		for _, rr := range oldkeys.RRs {
			if dk, ok := rr.(*dns.DNSKEY); ok {
				if dk.Flags&dns.SEP != 0 {
					if ds := dk.ToDS(dns.SHA256); ds != nil {
						oldDS = append(oldDS, ds)
					}
				}
			}
		}
		for _, rr := range newkeys.RRs {
			if dk, ok := rr.(*dns.DNSKEY); ok {
				if dk.Flags&dns.SEP != 0 {
					if ds := dk.ToDS(dns.SHA256); ds != nil {
						newDS = append(newDS, ds)
					}
				}
			}
		}
		_, dss.DSAdds, dss.DSRemoves = core.RRsetDiffer(zd.ZoneName, newDS, oldDS, dns.TypeDS, zd.Logger, Globals.Verbose, Globals.Debug)
		dss.NewDS = newDS
		// Same as above: derived from published keys, so an answer only when
		// non-empty.
		dss.NewDSKnown = len(newDS) > 0
	}

	return differ, dss, nil
}

func (zd *ZoneData) DnskeysChangedNG(newzd *ZoneData) (bool, error) {
	var differ bool

	oldapex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		if errors.Is(err, ErrZoneNotReady) {
			lgDns.Debug("DnskeysChangedNG: old zone not ready (initial load), reporting DNSKEYs changed", "zone", zd.ZoneName)
			return true, nil
		}
		return false, fmt.Errorf("error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}
	if oldapex == nil {
		lgDns.Debug("DnskeysChangedNG: old apexdata was nil (initial load), reporting DNSKEYs changed", "zone", zd.ZoneName)
		return true, nil
	}

	oldkeys, err := zd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, err
	}
	// An incoming zone with no apex has no DNSKEY RRset either, but that is a
	// broken transfer rather than a zone that unsigned itself. Without this the
	// "DNSKEYs removed" branch below fires for any signed zone whose transfer
	// arrived empty, and the proxy tells the parent to withdraw the DS.
	newapex, err := newzd.ownerForAnalysis(zd.ZoneName)
	if err != nil {
		return false, fmt.Errorf("error from newzd.ownerForAnalysis(%s): %v", zd.ZoneName, err)
	}
	if newapex == nil {
		lgDns.Warn("DnskeysChangedNG: no apex in the incoming zone; treating as no DNSKEY change",
			"zone", zd.ZoneName)
		return false, nil
	}

	newkeys, err := newzd.rrsetForAnalysis(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, err
	}

	// Handle case where zone has no DNSKEY records (unsigned zone)
	if oldkeys == nil && newkeys == nil {
		// No DNSKEYs in either version - no change
		return false, nil
	}
	if oldkeys == nil && newkeys != nil {
		// DNSKEYs added (zone became signed)
		lgDns.Info("DnskeysChanged: DNSKEYs added", "zone", zd.ZoneName, "count", len(newkeys.RRs))
		return true, nil
	}
	if oldkeys != nil && newkeys == nil {
		// DNSKEYs removed (zone became unsigned)
		lgDns.Info("DnskeysChanged: DNSKEYs removed", "zone", zd.ZoneName, "count", len(oldkeys.RRs))
		return true, nil
	}

	lgDns.Debug("DnskeysChanged: comparing keys", "newkeys", newkeys.RRs, "oldkeys", oldkeys.RRs)
	differ, _, _ = core.RRsetDiffer(zd.ZoneName, newkeys.RRs, oldkeys.RRs, dns.TypeDNSKEY, zd.Logger, Globals.Verbose, Globals.Debug)
	return differ, nil
}


// rolloverOwnsDS reports whether the rollover engine currently owns this zone's
// DS RRset, in which case the delegation-sync comparison must not touch it.
//
// The test is the rollover PHASE, not the RolloverInProgress flag. The flag is
// set only by AtomicRollover, which is one of two ways the engine comes to push
// a DS. The other is the idle branch's steady-state pipeline maintenance: when
// the target DS set differs from what has been submitted it arms
// pending-parent-push directly, and pushes on the next tick, with the flag
// never set at all. Gating on the flag alone therefore left open exactly the
// window this check exists to close -- the engine sends a DS for a key that is
// still `created`, the comparison below derives the child's set from keys that
// warrant one, does not find it, and reports the just-sent DS for removal.
//
// Any phase other than idle means the engine has DS work in hand:
// pending-child-publish and pending-child-withdraw bracket the push,
// pending-parent-push and pending-parent-observe are the push and its
// confirmation, and parent-push-softfail is a push being retried. The flag is
// still consulted as well, so a zone mid-swap is covered even if its phase is
// momentarily idle.
//
// An absent row, an empty phase or an unreadable keystore all mean "not
// rolling". That matches every other reader of this state, and the failure it
// risks is the behaviour that exists today, whereas guessing "rolling" would
// silently freeze DS synchronisation for a zone that is not rolling at all.
//
// Suppression is logged each time: a rollover that dies without returning the
// zone to idle would otherwise stop DS synchronisation indefinitely with
// nothing said about why.
func (zd *ZoneData) rolloverOwnsDS() bool {
	if zd == nil || zd.KeyDB == nil {
		return false
	}
	row, err := LoadRolloverZoneRow(zd.KeyDB, zd.ZoneName)
	if err != nil {
		lgDns.Warn("AnalyseZoneDelegation: could not read rollover state; treating the zone as not rolling",
			"zone", zd.ZoneName, "err", err)
		return false
	}
	if row == nil {
		return false
	}
	phaseBusy := row.RolloverPhase != "" && row.RolloverPhase != rolloverPhaseIdle
	if !row.RolloverInProgress && !phaseBusy {
		return false
	}
	lgDns.Info("AnalyseZoneDelegation: rollover engine owns the DS RRset for this zone; leaving it alone",
		"zone", zd.ZoneName, "phase", row.RolloverPhase, "in_progress", row.RolloverInProgress)
	return true
}
