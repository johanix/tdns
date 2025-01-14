/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"fmt"
	"log"
	"time"

	"github.com/gookit/goutil/dump"
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
func (zd *ZoneData) AnalyseZoneDelegation() (DelegationSyncStatus, error) {
	var resp = DelegationSyncStatus{
		ZoneName: zd.ZoneName,
		Time:     time.Now(),
	}

	err := zd.FetchParentData()
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
			log.Printf("Error from AuthQuery(%s, %s, NS): %v", pserver, zd.ZoneName, err)
			continue
		}

		if len(p_nsrrs) == 0 {
			log.Printf("Empty respone to AuthQuery(%s, %s, NS)", pserver, zd.ZoneName)
			continue
		}

		// We have a response, no need to talk to rest of parent servers
		break
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return resp, err
	}

	differ, adds, removes := RRsetDiffer(zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs,
		p_nsrrs, dns.TypeNS, zd.Logger)
	resp.InSync = !differ
	// log.Printf("AnalyseZoneDelegation: Zone %s: NS RRsetDiffer: %v InSync: %v", zd.ZoneName, differ, resp.InSync)

	if len(adds) > 0 {
		//		var tmp []dns.NS
		for _, rr := range adds {
			resp.NsAdds = append(resp.NsAdds, rr)
		}
		//		resp.NsAdds = tmp
	}

	if len(removes) > 0 {
		//		var tmp []dns.NS
		for _, rr := range removes {
			resp.NsRemoves = append(resp.NsRemoves, rr)
		}
		//		resp.NsRemoves = tmp
	}

	// 2. Compute the names of the in-bailiwick subset of nameservers
	child_inb, _ := BailiwickNS(zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
	// parent_inb, _ := BailiwickNS(zd.ZoneName, apex.RRtypes[dns.TypeNS].RRs)

	// 3. Compare A and AAAA glue for in child in-bailiwick nameservers
	for _, ns := range child_inb {
		owner, err := zd.GetOwner(ns)
		if err != nil {
			log.Printf("Error from zd.GetOwner(%s): %v", ns, err)
		}
		child_a_glue := owner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs
		parent_a_glue, err := AuthQuery(ns, pserver, dns.TypeA)
		if err != nil {
			log.Printf("Error from AuthQuery(%s, %s, A): %v", pserver, child_inb, err)
		}
		gluediff, adds, removes := RRsetDiffer(ns, child_a_glue, parent_a_glue,
			dns.TypeA, zd.Logger)
		// log.Printf("AnalyseZoneDelegation: Zone %s: A RRsetDiffer: %v InSync: %v", zd.ZoneName, differ, resp.InSync)
		if gluediff {
			resp.InSync = false
			if len(adds) > 0 {
				for _, rr := range adds {
					resp.AAdds = append(resp.AAdds, rr)
				}
			}

			if len(removes) > 0 {
				for _, rr := range removes {
					resp.ARemoves = append(resp.ARemoves, rr)
				}
			}
		}

		child_aaaa_glue := owner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs
		parent_aaaa_glue, err := AuthQuery(ns, pserver, dns.TypeAAAA)
		if err != nil {
			log.Printf("Error from AuthQuery(%s, %s, AAAA): %v", pserver, child_inb, err)
		}
		differ, adds, removes = RRsetDiffer(ns, child_aaaa_glue, parent_aaaa_glue,
			dns.TypeAAAA, zd.Logger)
		// log.Printf("AnalyseZoneDelegation: Zone %s: AAAA RRsetDiffer: %v InSync: %v", zd.ZoneName, differ, resp.InSync)
		if differ {
			resp.InSync = false
			if len(adds) > 0 {
				for _, rr := range adds {
					resp.AAAAAdds = append(resp.AAAAAdds, rr)
				}
			}

			if len(removes) > 0 {
				for _, rr := range removes {
					resp.AAAARemoves = append(resp.AAAARemoves, rr)
				}
			}
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
				for _, rr := range a_glue_removes {
					removes = append(removes, rr)
				}
				for _, rr := range a_glue_adds {
					adds = append(adds, rr)
				}
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
				for _, rr := range aaaa_glue_removes {
					removes = append(removes, rr)
				}
				for _, rr := range aaaa_glue_adds {
					adds = append(adds, rr)
				}
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

// XXX: FIXME: This is old code that no longer works. At least the viper.Get* things are broken.
func (zd *ZoneData) xxxDelegationDataChanged(newzd *ZoneData) (bool, []dns.RR, []dns.RR, DelegationSyncStatus, error) {
	var resp = DelegationSyncStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
		InSync:   true,
	}

	Globals.Zonename = zd.ZoneName

	var nsdiff, fakeolddata bool
	var adds, removes []dns.RR

	oldapex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, []dns.RR{}, []dns.RR{}, resp,
			fmt.Errorf("Error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	if oldapex == nil {
		if !viper.GetBool("childsync.sync-on-boot") {
			zd.Logger.Printf("DelDataChanged: Zone %s old apexdata was nil. Claiming this is a non-change.",
				zd.ZoneName)
			return false, []dns.RR{}, []dns.RR{}, resp, nil
		}
		zd.Logger.Printf("Zone %s delegation sync-on-boot: faking empty old apex data", zd.ZoneName)
		fakeolddata = true
		oldapex = &OwnerData{
			Name:    zd.ZoneName,
			RRtypes: NewRRTypeStore(),
		}
		oldapex.RRtypes.Set(dns.TypeNS, RRset{})
		oldapex.RRtypes.Set(dns.TypeA, RRset{})
		oldapex.RRtypes.Set(dns.TypeAAAA, RRset{})
	}

	newapex, err := newzd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, []dns.RR{}, []dns.RR{}, resp,
			fmt.Errorf("Error from newzd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	// XXX: Should we remove all the policy checks here and just report on whether stuff is in sync or not?
	// XXX: Once we know the status we can make a policy decision.
	if viper.GetBool("childsync.update-ns") {
		nsdiff, adds, removes = RRsetDiffer(zd.ZoneName, newapex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs,
			oldapex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs, dns.TypeNS, zd.Logger)
		resp.InSync = !nsdiff
	} else {
		zd.Logger.Printf("*** Note: configured NOT to update NS RRset.\n")
	}

	if len(adds) > 0 {
		resp.NsAdds = append(resp.NsAdds, adds...)
	}

	if len(removes) > 0 {
		resp.NsRemoves = append(resp.NsRemoves, removes...)
	}

	//	Compute the names of the in-bailiwick subset of nameservers
	new_ns_inb, _ := BailiwickNS(zd.ZoneName, newapex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
	old_ns_inb, _ := BailiwickNS(zd.ZoneName, oldapex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
	for _, ns := range new_ns_inb {
		zd.Logger.Printf("New in-bailiwick NS: %s\n", ns)
	}
	for _, ns := range old_ns_inb {
		zd.Logger.Printf("Old in-bailiwick NS: %s\n", ns)
	}

	var oldowner *OwnerData
	for _, ns := range new_ns_inb {
		if fakeolddata {
			oldowner = oldapex
		} else {
			oldowner, err = zd.GetOwner(ns)
			if err != nil {
				zd.Logger.Printf("Error from zd.GetOwner(%s): %v", ns, err)
				return false, []dns.RR{}, []dns.RR{}, resp, fmt.Errorf("Error from zd.GetOwner(%s): %v", ns, err)
			}
		}

		// When adding a new nameserver to the NS RRset any in-bailiwick glue needs to be added, even though
		// the actual A and AAAA RRs for the glue have not changed. I.e. the change is the the address records
		// are now glue.
		ns_is_new_nameserver := true
		for _, oldns := range old_ns_inb {
			if ns == oldns {
				ns_is_new_nameserver = false
				break
			}
		}
		log.Printf("*** %s: ns_is_new_nameserver: %v", ns, ns_is_new_nameserver)

		newowner, err := newzd.GetOwner(ns)
		if err != nil {
			zd.Logger.Printf("Error from newzd.GetOwner(%s): %v", ns, err)
			return false, []dns.RR{}, []dns.RR{}, resp, fmt.Errorf("Error from newzd.GetOwner(%s): %v", ns, err)
		}

		if viper.GetBool("childsync.update-a") {
			zd.Logger.Printf("Comparing A glue for new NS %s:\n", ns)

			log.Printf("newowner.RRtypes[A]:\n")
			dump.P(newowner.RRtypes.GetOnlyRRSet(dns.TypeA))
			log.Printf("oldowner.RRtypes[A]:\n")
			dump.P(oldowner.RRtypes.GetOnlyRRSet(dns.TypeA))
			gluediff, a_glue_adds, a_glue_removes := RRsetDiffer(ns,
				newowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs,
				oldowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs,
				dns.TypeA, zd.Logger)
			if gluediff {
				resp.InSync = false
				resp.ARemoves = append(resp.ARemoves, a_glue_removes...)
				resp.AAdds = append(resp.AAdds, a_glue_adds...)
			} else if ns_is_new_nameserver {
				// When adding a new nameserver to the NS RRset, all its addresses become glue,
				// regardless of whether the changed or not.
				resp.InSync = false
				resp.AAdds = append(resp.AAdds, newowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs...)
			}
		} else {
			zd.Logger.Printf("*** Note: configured NOT to update A glue.\n")
		}

		if viper.GetBool("childsync.update-aaaa") {
			zd.Logger.Printf("Comparing AAAA glue for new NS %s:\n", ns)
			gluediff, aaaa_glue_adds, aaaa_glue_removes := RRsetDiffer(ns,
				newowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs,
				oldowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs,
				dns.TypeAAAA, zd.Logger)
			if gluediff {
				//				differ = true
				resp.InSync = false
				resp.AAAARemoves = append(resp.AAAARemoves, aaaa_glue_removes...)
				resp.AAAAAdds = append(resp.AAAAAdds, aaaa_glue_adds...)
			} else if ns_is_new_nameserver {
				// When adding a new nameserver to the NS RRset, all its addresses become glue,
				// regardless of whether the changed or not.
				resp.InSync = false
				resp.AAAAAdds = append(resp.AAAAAdds, newowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs...)

			}
		} else {
			fmt.Printf("*** Note: configured NOT to update AAAA glue.\n")
		}
	}

	// dump.P(resp)

	//if !differ {
	if resp.InSync {
		fmt.Printf("Old delegation data is identical to new. No update needed.\n")
		return false, []dns.RR{}, []dns.RR{}, resp, nil
	}

	return true, adds, removes, resp, nil
}

// Let's try to modernize this.
func (zd *ZoneData) DelegationDataChangedNG(newzd *ZoneData) (bool, DelegationSyncStatus, error) {
	log.Printf("*** Enter DDCNG(%s)", newzd.ZoneName)
	var dss = DelegationSyncStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
		InSync:   true,
	}

	oldapex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, dss, fmt.Errorf("Error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}
	if oldapex == nil {
		log.Printf("DDCNG: Zone %s old apexdata was nil. This is the initial zone load.", zd.ZoneName)
		return false, dss, nil
	}

	newapex, err := newzd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, dss, fmt.Errorf("Error from newzd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	log.Printf("*** oldapex.RRtypes[dns.TypeNS]:")
	// dump.P(oldapex.RRtypes[dns.TypeNS])
	log.Printf("*** newapex.RRtypes[dns.TypeNS]:")
	// dump.P(newapex.RRtypes[dns.TypeNS])

	var nsdiff bool

	nsdiff, dss.NsAdds, dss.NsRemoves = RRsetDiffer(zd.ZoneName, newapex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs,
		oldapex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs, dns.TypeNS, zd.Logger)

	dss.InSync = !nsdiff

	for _, ns := range dss.NsRemoves {
		log.Printf("DDCNG: Removed NS: %s", ns.String())
		if nsrr, ok := ns.(*dns.NS); ok {
			nsowner, err := zd.GetOwner(nsrr.Ns)
			if err != nil {
				log.Printf("DDCNG: Error: nsname %s of NS %s has no RRs", nsrr.Ns, nsrr.String())
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
		log.Printf("DDCNG: Added NS: %s", ns.String())
		if nsrr, ok := ns.(*dns.NS); ok {
			nsowner, err := newzd.GetOwner(nsrr.Ns)
			if err != nil {
				log.Printf("DDCNG: Error: nsname %s of NS %s has no RRs", nsrr.Ns, nsrr.String())
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
				log.Printf("DDCNG: Error: Nameserver %s has no address records in old zone", nsrr.Ns)
				// TODO: We should add all address records found in the new version of the zone.
				continue
			}
			newowner, err := newzd.GetOwner(nsrr.Ns)
			if err != nil || newowner == nil {
				log.Printf("DDCNG: Error: Nameserver %s has no address records in new zone", nsrr.Ns)
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
			diff, adds, removes := RRsetDiffer(nsrr.Ns, newowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs, oldowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs, dns.TypeA, zd.Logger)
			if diff {
				for _, rr := range adds {
					dss.AAdds = append(dss.AAdds, rr)
				}
				for _, rr := range removes {
					dss.ARemoves = append(dss.ARemoves, rr)
				}
				dss.InSync = false
			}
			diff, adds, removes = RRsetDiffer(nsrr.Ns, newowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs, oldowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs, dns.TypeAAAA, zd.Logger)
			if diff {
				for _, rr := range adds {
					dss.AAAAAdds = append(dss.AAAAAdds, rr)
				}
				for _, rr := range removes {
					dss.AAAARemoves = append(dss.AAAARemoves, rr)
				}
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
		return false, dss, fmt.Errorf("Error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}
	if oldapex == nil {
		log.Printf("DDCNG: Zone %s old apexdata was nil. This is the initial zone load.", zd.ZoneName)
		return false, dss, nil // on initial load, we always return false, nil, nil as we don't know that the DNSKEYs have changed
	}

	oldkeys, err := zd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, dss, err
	}
	newkeys, err := newzd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, dss, err
	}

	differ, dss.DNSKEYAdds, dss.DNSKEYRemoves = RRsetDiffer(zd.ZoneName, newkeys.RRs, oldkeys.RRs, dns.TypeDNSKEY, zd.Logger)
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
		return false, fmt.Errorf("Error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	if oldapex == nil {
		log.Printf("DnskeysChanged: Zone %s old apexdata was nil. This is the initial zone load.", zd.ZoneName)
		return true, nil // on initial load, we always return false, nil, nil as we don't know that the DNSKEYs have changed
	}

	oldkeys, err := zd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, err
	}
	newkeys, err := newzd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, err
	}

	differ, _, _ = RRsetDiffer(zd.ZoneName, newkeys.RRs, oldkeys.RRs, dns.TypeDNSKEY, zd.Logger)
	return differ, nil
}

func (zd *ZoneData) MsignerChanged(newzd *ZoneData) (bool, *MusicSyncStatus, error) {
	var mss = MusicSyncStatus{
		ZoneName: zd.ZoneName,
		Msg:      "No change",
		Error:    false,
		ErrorMsg: "",
		Status:   true,
	}
	var differ bool

	oldapex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, nil, fmt.Errorf("Error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	newmsigner, err := newzd.GetRRset(zd.ZoneName, TypeMSIGNER)
	if err != nil {
		return false, nil, err
	}

	if oldapex == nil {
		log.Printf("MsignerChanged: Zone %s old apexdata was nil. This is the initial zone load.", zd.ZoneName)
		mss.MsignerAdds = newmsigner.RRs
		return true, &mss, nil // on initial load, we always return true, nil, nil to force a reset of the MSIGNER group
	}

	oldmsigner, err := zd.GetRRset(zd.ZoneName, TypeMSIGNER)
	if err != nil {
		return false, nil, err
	}

	differ, mss.MsignerAdds, mss.MsignerRemoves = RRsetDiffer(zd.ZoneName, newmsigner.RRs, oldmsigner.RRs, TypeMSIGNER, zd.Logger)
	return differ, &mss, nil
}
