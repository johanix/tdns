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

	// resp.Parent = zd.Parent

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
			lgDns.Warn("error from AuthQuery for A glue", "server", pserver, "ns", child_inb, "err", err)
		}
		gluediff, adds, removes := core.RRsetDiffer(ns, child_a_glue, parent_a_glue,
			dns.TypeA, zd.Logger, Globals.Verbose, Globals.Debug)
		// log.Printf("AnalyseZoneDelegation: Zone %s: A RRsetDiffer: %v InSync: %v", zd.ZoneName, differ, resp.InSync)
		if gluediff {
			resp.InSync = false
			resp.AAdds = append(resp.AAdds, adds...)
			resp.ARemoves = append(resp.ARemoves, removes...)
		}

		child_aaaa_glue := owner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs
		parent_aaaa_glue, err := AuthQuery(ns, pserver, dns.TypeAAAA)
		if err != nil {
			lgDns.Warn("error from AuthQuery for AAAA glue", "server", pserver, "ns", child_inb, "err", err)
		}
		differ, adds, removes = core.RRsetDiffer(ns, child_aaaa_glue, parent_aaaa_glue,
			dns.TypeAAAA, zd.Logger, Globals.Verbose, Globals.Debug)
		// log.Printf("AnalyseZoneDelegation: Zone %s: AAAA RRsetDiffer: %v InSync: %v", zd.ZoneName, differ, resp.InSync)
		if differ {
			resp.InSync = false
			resp.AAAAAdds = append(resp.AAAAAdds, adds...)
			resp.AAAARemoves = append(resp.AAAARemoves, removes...)
		}
	}
	// 4. If NS RRsets differ, then also compare glue for parent in-bailiwick nameservers

	return resp, nil
}

// Only used from CLI (tdns-cli ddns sync)
// Returns unsynched bool, adds, removes []dns.RR, error

// XXX: This requires lots of recursive queries and does not take advantage of the zonedata struct
//      in tdnsd most likely having cached most of this information. Since the only reason for
//      the tdns-cli tool is to interact with tdnsd, it really should leverage from that rather
//      than just do everything in the CLI.

func ChildDelegationDataUnsynched(zone, pzone, childpri, parpri string) (bool, []dns.RR, []dns.RR, error) {

	var differ bool
	var adds, removes []dns.RR

	if viper.GetBool("childsync.update-ns") {
		differ, adds, removes = ComputeRRDiff(childpri, parpri,
			Globals.Zonename, dns.TypeNS)
	} else {
		fmt.Printf("*** Note: configured NOT to update NS RRset.\n")
	}

	child_ns_inb, parent_ns_inb := ComputeBailiwickNS(childpri, parpri,
		Globals.Zonename)
	for _, ns := range child_ns_inb {
		fmt.Printf("Child in-bailiwick NS: %s\n", ns)
	}
	for _, ns := range parent_ns_inb {
		fmt.Printf("Parent in-bailiwick NS: %s\n", ns)
	}

	for _, ns := range child_ns_inb {
		if viper.GetBool("childsync.update-a") {
			fmt.Printf("Comparing A glue for child NS %s:\n", ns)
			gluediff, a_glue_adds, a_glue_removes := ComputeRRDiff(childpri,
				parpri, ns, dns.TypeA)
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
			gluediff, aaaa_glue_adds, aaaa_glue_removes := ComputeRRDiff(childpri,
				parpri, ns, dns.TypeAAAA)
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

	newapex, err := newzd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, dss, fmt.Errorf("error from newzd.GetOwner(%s): %v", zd.ZoneName, err)
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
			nsowner, err := newzd.GetOwner(nsrr.Ns)
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

	for _, ns := range oldapex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs {
		if nsrr, ok := ns.(*dns.NS); ok {
			oldowner, err := zd.GetOwner(nsrr.Ns)
			if err != nil || oldowner == nil {
				lgDns.Warn("DDCNG: nameserver has no address records in old zone", "ns", nsrr.Ns)
				// TODO: We should add all address records found in the new version of the zone.
				continue
			}
			newowner, err := newzd.GetOwner(nsrr.Ns)
			if err != nil || newowner == nil {
				lgDns.Warn("DDCNG: nameserver has no address records in new zone", "ns", nsrr.Ns)
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
			// dump.P(newowner.RRtypes[dns.TypeA])
			// dump.P(oldowner.RRtypes[dns.TypeA])
			diff, adds, removes := core.RRsetDiffer(nsrr.Ns, newowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs, oldowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs, dns.TypeA, zd.Logger, Globals.Verbose, Globals.Debug)
			if diff {
				dss.AAdds = append(dss.AAdds, adds...)
				dss.ARemoves = append(dss.ARemoves, removes...)
				dss.InSync = false
			}
			diff, adds, removes = core.RRsetDiffer(nsrr.Ns, newowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs, oldowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs, dns.TypeAAAA, zd.Logger, Globals.Verbose, Globals.Debug)
			if diff {
				dss.AAAAAdds = append(dss.AAAAAdds, adds...)
				dss.AAAARemoves = append(dss.AAAARemoves, removes...)
				dss.InSync = false
			}
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
	newkeys, err := newzd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, dss, err
	}

	differ, dss.DNSKEYAdds, dss.DNSKEYRemoves = core.RRsetDiffer(zd.ZoneName, newkeys.RRs, oldkeys.RRs, dns.TypeDNSKEY, zd.Logger, Globals.Verbose, Globals.Debug)
	if differ {
		dss.Time = time.Now()
		dss.InSync = false
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
	newkeys, err := newzd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
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
