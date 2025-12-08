/*
 * (c) Copyright Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"fmt"
	"log"
	"strings"

	core "github.com/johanix/tdns/tdns/core"
	"github.com/miekg/dns"
)

func NSInBailiwick(zone string, ns *dns.NS) bool {
	return strings.HasSuffix(ns.Ns, zone)
}

func (scanner *Scanner) CheckCSYNC(sr ScanRequest, cdd *ChildDelegationData) (*ChildDelegationData, error) {
	zone := sr.ChildZone

	verbose := scanner.Verbose
	// debug := scanner.Debug

	lg := log.Default()

	csync_rrset, err := scanner.AuthQueryNG(zone, zone, dns.TypeCSYNC, "tcp")
	if err != nil {
		return nil, fmt.Errorf("CheckCSYNC: Zone %s: error from AuthQueryNG: %v", zone, err)
	}
	if len(csync_rrset.RRs) == 0 {
		lg.Printf("CheckCSYNC: Zone %s: no CSYNC RR found. Terminating scan.", zone)
		return nil, nil
	}

	// csyncrr := csync_rrs[0].(*dns.CSYNC)
	var csyncrr *dns.CSYNC

	for _, rr := range csync_rrset.RRs {
		switch rr := rr.(type) {
		case *dns.CSYNC:
			csyncrr = rr
		case *dns.RRSIG:
			continue
		}
	}

	immediate := (csyncrr.Flags & 0x01) == 1
	usesoamin := (csyncrr.Flags & 0x02) == 2

	// Ensure that NS comes first.
	csynctypes := []uint16{dns.TypeNS} // Must ensure that we do NS first!
	tmp := csyncrr.TypeBitMap
	for _, t := range tmp {
		if t == dns.TypeNS {
			continue
		}
		csynctypes = append(csynctypes, t)
	}
	// lg.Printf("Zone %s: CSYNC type bitmap: %v", zone, csynctypes)

	if verbose {
		lg.Printf("Zone %s CSYNC flags: immediate=%v usesoamin=%v RR types=%v", zone, immediate, usesoamin, csynctypes)
	}

	// 2: Is this a CSYNC that we have already analysed (i.e. same minsoa)?
	if scanner.ZoneCSYNCKnown(zone, csyncrr) {
		if verbose {
			lg.Printf("Zone %s CSYNC with minsoa=%d is already analyzed", zone, csyncrr.Serial)
		}
		return nil, nil
	}

	// Here we should do the following (according to RFC7477):
	// 1. Query for the child SOA over TCP
	// 2. Query for the child CSYNC over TCP
	// 3. Analyze the changes (if any)
	// 4. Query for the child SOA again over TCP
	// If start_SOA and end_SOA differ then abort.

	// XXX: TODO: Use TCP

	//	soa_rrset, _, err := AuthDNSQuery(zone, scanner.IMR, dns.TypeSOA, lg,
	//		false, scanner.Verbose, scanner.Debug)

	soa_rrset, err := scanner.AuthQueryNG(zone, zone, dns.TypeSOA, "tcp")
	if err != nil {
		return nil, fmt.Errorf("zone %s: CSYNC analysis: error from AuthQueryNG: %v", zone, err)
	}
	if len(soa_rrset.RRs) == 0 {
		return nil, fmt.Errorf("zone %s: CSYNC analysis: no SOA RR from auth servers. Aborting", zone)
	}
	start_serial := soa_rrset.RRs[0].(*dns.SOA).Serial

	// If we're instructed to look at the MinSOA in the CSYNC RR then ensure that current SOA Serial is greater
	if usesoamin {
		if csyncrr.Serial > start_serial {
			lg.Printf("Zone %s: ignoring CSYNC because UseMinSOA=true, CSYNC Serial=%d > SOA Serial=%d",
				zone, csyncrr.Serial, start_serial)
			return nil, nil
		}
		lg.Printf("Zone %s: analysing CSYNC because UseMinSOA=true, CSYNC Serial=%d <= SOA Serial=%d",
			zone, csyncrr.Serial, start_serial)
	}

	lg.Printf("Zone %s CSYNC with minsoa=%d has not previously been analyzed.", zone, csyncrr.Serial)
	lg.Printf("Zone %s: Proceeding with new CSYNC analysis.", zone)

	//	csync_rrset, _, err = AuthDNSQuery(zone, scanner.IMR, dns.TypeCSYNC, lg,
	//		false, scanner.Verbose, scanner.Debug)
	csync_rrset, err = scanner.AuthQueryNG(zone, zone, dns.TypeCSYNC, "tcp")
	if err != nil {
		return nil, fmt.Errorf("zone %s: CSYNC analysis: error from AuthQueryNG: %v", zone, err)
	}
	if len(csync_rrset.RRs) == 0 {
		return nil, fmt.Errorf("zone %s: CSYNC analysis: no CSYNC RR from auth servers. Aborting", zone)
	}

	var nib_ns []*dns.NS // nib_ns == new_in_bailiwick_ns :-)
	var new_nsrrset, new_v4glue, new_v6glue []dns.RR
	var nschanged, v4changed, v6changed bool

	// XXX: TODO: If NS not present in bitmap, must initialize to old value.
	for _, t := range csynctypes {
		// switch dns.TypeToString[t] {
		switch t {
		case dns.TypeNS:
			new_nsrrset, nschanged, err = scanner.CsyncAnalyzeNS(zone, cdd)
			if err != nil {
				return nil, err
			}
			for _, ns := range new_nsrrset {
				switch ns := ns.(type) {
				case *dns.NS:
					if NSInBailiwick(zone, ns) {
						nib_ns = append(nib_ns, ns)
					}

				case *dns.RRSIG:

				}
			}
		case dns.TypeA:
			new_v4glue, v4changed, err = scanner.CsyncAnalyzeA(zone, nib_ns, cdd)
			if err != nil {
				lg.Printf("Zone %s: error analyzing v4 glue: %v. %d new v4 glue RRs. Changed v4 glue: %v", zone, err, len(new_v4glue), v4changed)
				// return err
			}
		case dns.TypeAAAA:
			new_v6glue, v6changed, err = scanner.CsyncAnalyzeAAAA(zone, nib_ns, cdd)
			if err != nil {
				lg.Printf("Zone %s: error analyzing v6 glue: %v. %d new v6 glue RRs. Changed v6 glue: %v", zone, err, len(new_v6glue), v6changed)
				// return err
			}
		default:
			lg.Printf("Unknown RR type in %s CSYNC bitmap: %d (%s)", zone, t, dns.TypeToString[t])
		}
	}

	//	soa_rrset, _, err = AuthDNSQuery(zone, scanner.IMR, dns.TypeSOA, lg,
	//		false, scanner.Verbose, scanner.Debug)
	soa_rrset, err = scanner.AuthQueryNG(zone, zone, dns.TypeSOA, "tcp")
	if err != nil {
		return nil, fmt.Errorf("zone %s: CSYNC analysis: error from AuthQueryNG: %v", zone, err)
	}
	if len(soa_rrset.RRs) == 0 {
		return nil, fmt.Errorf("zone %s: CSYNC analysis: no SOA RR from auth servers. Aborting", zone)
	}
	end_serial := soa_rrset.RRs[0].(*dns.SOA).Serial

	if start_serial != end_serial {
		return nil, fmt.Errorf("zone %s: CSYNC analysis: SOA changed during analysis. Aborting (but will try again later)", zone)
	}
	lg.Printf("Zone %s CSYNC analysis: SOA stable during analysis. Continuing with DB update.", zone)

	//	lg.Printf("Changes: NS=%v (%v),\nv4 glue=%v (%v),\nv6 glue=%v (%v)",
	//		nschanged, new_nsrrset, v4changed,
	//		new_v4glue, v6changed, new_v6glue)

	delupdate := nschanged || v4changed || v6changed

	new_cdd := ChildDelegationData{
		DelHasChanged: delupdate,
		NS_rrs:        new_nsrrset,
		A_glue:        new_v4glue,
		AAAA_glue:     new_v6glue,
	}

	//	if nschanged {
	//		scanner.UpdatePendingChildData(zone, "csync", dns.TypeNS, new_nsrrset, true, verbose, debug, lg)
	//		delupdate = true
	//		owner, err := pzd.GetOwner(zone)
	//		if err != nil {
	//			lg.Printf("Zone %s: error getting owner: %v", zone, err)
	//		}
	//		owner.RRtypes[dns.TypeNS] = RRset{RRs: new_nsrrset}
	//		// pzd.Children[zone].NS_rrs = new_nsrrset
	//	}

	// if v4changed {
	//		scanner.UpdatePendingChildData(zone, "csync", dns.TypeA, new_v4glue, true, verbose, debug, lg)
	//		delupdate = true
	//		ownerMap := make(map[string][]dns.RR)
	//		for _, glue := range new_v4glue {
	//			ownerName := glue.Header().Name
	//			ownerMap[ownerName] = append(ownerMap[ownerName], glue)
	//		}

	//	for ownerName, glueRecords := range ownerMap {
	//		owner, err := pzd.GetOwner(ownerName)
	//		if err != nil {
	//			lg.Printf("Zone %s: error getting owner: %v", ownerName, err)
	//		}
	//		owner.RRtypes[dns.TypeA] = RRset{RRs: glueRecords}
	//	}
	// pzd.Children[zone].A_glue = new_v4glue
	// }

	//	if v6changed {
	//		scanner.UpdatePendingChildData(zone, "csync", dns.TypeAAAA, new_v6glue, true, verbose, debug, lg)
	//		delupdate = true
	//		ownerMap := make(map[string][]dns.RR)
	//		for _, glue := range new_v6glue {
	//			ownerName := glue.Header().Name
	//			ownerMap[ownerName] = append(ownerMap[ownerName], glue)
	//		}

	//		for ownerName, glueRecords := range ownerMap {
	//			owner, err := pzd.GetOwner(ownerName)
	//		if err != nil {
	//			lg.Printf("Zone %s: error getting owner: %v", ownerName, err)
	//		}
	//		owner.RRtypes[dns.TypeAAAA] = RRset{RRs: glueRecords}
	//	}
	// pzd.Children[zone].AAAA_glue = new_v6glue
	// }

	if !delupdate {
		lg.Printf("Zone %s: CSYNC analysis: no change from current delegation information. Terminating.", zone)
		return &new_cdd, nil
	}

	// if we get this far the minsoa of this CSYNC has been analyzed
	err = scanner.UpdateCsyncStatus(zone, csyncrr)
	if err != nil {
		lg.Printf("Error from UpdateCsyncStatus(%s): %v", csyncrr.String(), err)
	}

	if immediate {
		lg.Printf("Zone %s CSYNC has immediate flag set, committing pending update now.", zone)
		//		scanner.LabDB.CommitPendingChildDataNG(zone, scanner.IMR, "csync", "del",
		//			verbose, debug, lg)
	} else {
		lg.Printf("Zone %s CSYNC does not have immediate flag set, but right now we only support immediate updates.", zone)
	}

	KnownCsyncMinSOAs[zone] = csyncrr.Serial
	return &new_cdd, nil
}

func (scanner *Scanner) CsyncAnalyzeA(zone string, new_nsrrs []*dns.NS, cdd *ChildDelegationData) ([]dns.RR, bool, error) {

	log.Printf("CsyncAnalyzeA: zone %s, new_nsrrs %v", zone, new_nsrrs)
	// cur_v4glue, err := scanner.LabDB.FetchChildDataFromDB(zone, dns.TypeA)
	// cur_v4glue := pzd.Children[zone].A_glue
	cur_v4glue := cdd.A_glue

	scanner.Log["CSYNC"].Printf("*** CsyncAnalyzeA: current v4 glue: %v", cur_v4glue)

	// According to RFC7477 we should do the following:
	// 1. For each nameserver in the NS RRset (as analysed by CsyncAnalyzeNS)
	//    figure out if the nameserver is in bailiwick or not.
	// 2. For each nameserver that is in bailiwick, get authenticated
	//    responses from auth servers to current contents of the A RRset.
	// 3. Compare this set of RRs to the current contents in the delegation
	//    table and decide if there is any change.

	// XXX: Need to get validated responses from zone auth servers. Either
	//      query the auth servers and do validation ourselves (preferable)
	//      or get response from both auth servers and recursive. If latter
	//      is validated and response is identical, then all is ok.

	// For now we do the latter.

	var new_v4glue = []dns.RR{}

	for _, ns := range new_nsrrs {
		//		nsv4addrs, validated, err := AuthDNSQuery(ns.Ns, scanner.IMR, dns.TypeA, scanner.Log["CSYNC"], false, scanner.Verbose, scanner.Debug)
		// nsv4addrs, validated, err := pzd.LookupAndValidateRRset(ns.Ns, dns.TypeA, scanner.Verbose)

		// XXX: This is where we sould do validation. But for now we're cheating.
		validated := true
		nsv4addrs, err := scanner.AuthQueryNG(zone, ns.Ns, dns.TypeA, "tcp")
		if err != nil {
			return []dns.RR{}, false,
				fmt.Errorf("error looking up %s A. Aborting", ns.Ns)
		}
		if !validated {
			return []dns.RR{}, false,
				fmt.Errorf("%s A RRset not validated. Aborting", ns.Ns)
		}
		new_v4glue = append(new_v4glue, nsv4addrs.RRs...)
	}

	//	if !RRsetsAreEqual(zone, new_v4glue, cur_v4glue, "A", scanner.Log["CSYNC"],
	if changed, _, _ := core.RRsetDiffer(zone, new_v4glue, cur_v4glue, dns.TypeA, scanner.Log["CSYNC"], scanner.Verbose, scanner.Debug); changed {
		if scanner.Verbose {
			scanner.Log["CSYNC"].Printf("Zone %s: IPv4 glue has changed. DB update needed.", zone)
		}
		return new_v4glue, true, nil
	}

	if scanner.Verbose {
		scanner.Log["CSYNC"].Printf("Zone %s: IPv4 glue is unchanged.", zone)
	}
	return []dns.RR{}, false, nil
}

func (scanner *Scanner) CsyncAnalyzeAAAA(zone string, new_nsrrs []*dns.NS, cdd *ChildDelegationData) ([]dns.RR, bool, error) {
	//func (scanner *Scanner) CsyncAnalyzeAAAA(zone string, new_nsrrs []*dns.NS, pzd *ZoneData) (*RRset, bool, error) {
	log.Printf("CsyncAnalyzeAAAA: zone %s, new_nsrrs %v", zone, new_nsrrs)
	// cur_v6glue := pzd.Children[zone].AAAA_glue
	cur_v6glue := cdd.AAAA_glue

	scanner.Log["CSYNC"].Printf("*** CsyncAnalyzeAAAA: current v6 glue: %v", cur_v6glue)

	// According to RFC7477 we should do the following:
	// 1. For each nameserver in the NS RRset (as analysed by CsyncAnalyzeNS)
	//    figure out if the nameserver is in bailiwick or not.
	// 2. For each nameserver that is in bailiwick, get authenticated
	//    responses from auth servers to current contents of the A RRset.
	// 3. Compare this set of RRs to the current contents in the delegation
	//    table and decide if there is any change.

	// XXX: Need to get validated responses from zone auth servers. Either
	//      query the auth servers and do validation ourselves (preferable)
	//      or get response from both auth servers and recursive. If latter
	//      is validated and response is identical, then all is ok.

	// For now we do the latter.

	var new_v6glue = []dns.RR{}
	// var new_v6glue = &RRset{}
	for _, ns := range new_nsrrs {
		//		nsv6addrs, validated, err := AuthDNSQuery(ns.Ns, scanner.IMR, dns.TypeAAAA, scanner.Log["CSYNC"], false, scanner.Verbose, scanner.Debug)
		// nsv6addrs, validated, err := pzd.LookupAndValidateRRset(ns.Ns, dns.TypeAAAA, scanner.Verbose)
		// XXX: This is where we sould do validation. But for now we're cheating.
		validated := true
		nsv6addrs, err := scanner.AuthQueryNG(zone, ns.Ns, dns.TypeAAAA, "tcp")
		if err != nil {
			return []dns.RR{}, false,
				fmt.Errorf("error looking up %s AAAA. Aborting", ns.Ns)
		}
		if !validated {
			return []dns.RR{}, false,
				fmt.Errorf("%s AAAA RRset not validated. Aborting", ns.Ns)
		}
		new_v6glue = append(new_v6glue, nsv6addrs.RRs...)
	}

	if changed, _, _ := core.RRsetDiffer(zone, new_v6glue, cur_v6glue, dns.TypeAAAA, scanner.Log["CSYNC"], scanner.Verbose, scanner.Debug); changed {
		if scanner.Verbose {
			scanner.Log["CSYNC"].Printf("Zone %s: IPv6 glue has changed. DB update needed.", zone)
		}
		return new_v6glue, true, nil
	}

	if scanner.Verbose {
		scanner.Log["CSYNC"].Printf("Zone %s: IPv6 glue is unchanged.", zone)
	}
	return []dns.RR{}, false, nil
}

// Returns: new_rrs, changed=true, error
func (scanner *Scanner) CsyncAnalyzeNS(zone string, cdd *ChildDelegationData) ([]dns.RR, bool, error) {
	log.Printf("CsyncAnalyzeNS: zone %s", zone)

	// cur_NSrrs := pzd.Children[zone].NS_rrs
	cur_NSrrs := cdd.NS_rrs

	scanner.Log["CSYNC"].Printf("*** CsyncAnalyzeNS: current NS RRset: %v", cur_NSrrs)

	// XXX: Need to get validated response from zone auth servers. Either
	//      query the auth servers and do validation ourselves (preferable)
	//      or get response from both auth servers and recursive. If latter
	//      is validated and response is identical, then all is ok.

	// For now we do the latter.

	// new_rrs, validated, err := AuthDNSQuery(zone, scanner.IMR, dns.TypeNS, scanner.Log["CSYNC"], false, scanner.Verbose, scanner.Debug)
	// new_rrs, validated, err := pzd.LookupAndValidateRRset(zone, dns.TypeNS, scanner.Verbose)
	validated := true
	new_rrs, err := scanner.AuthQueryNG(zone, zone, dns.TypeNS, "tcp")
	if err != nil {
		scanner.Log["CSYNC"].Printf("Error from RecursiveDNSQuery(%s) to imr <internal>: %v",
			zone, err)
		return []dns.RR{}, false, err
	}

	if !validated {
		return []dns.RR{}, false,
			fmt.Errorf("zone %s CSYNC analysis: New NS RRset not authenticated. Aborting", zone)
	}

	if changed, _, _ := core.RRsetDiffer(zone, new_rrs.RRs, cur_NSrrs, dns.TypeNS, scanner.Log["CSYNC"], scanner.Verbose, scanner.Debug); changed {
		if scanner.Verbose {
			scanner.Log["CSYNC"].Printf("Zone %s: NS RRset has changed. DB update needed.", zone)
		}
		return new_rrs.RRs, true, nil // change
	}

	if scanner.Verbose {
		scanner.Log["CSYNC"].Printf("Zone %s: NS RRset is unchanged.", zone)
	}
	return cur_NSrrs, false, nil // no change
}

// Check the minsoa in this CSYNC against the minsoa in the possible
// already stored CSYNC in the CsyncStatus table. If not found or old min_soa
// is lower, then update table.
var KnownCsyncMinSOAs = map[string]uint32{}

func (scanner *Scanner) ZoneCSYNCKnown(zone string, csyncrr *dns.CSYNC) bool {
	log.Printf("ZoneCSYNCKnown: checking if CSYNC for %s is known", zone)
	new_minsoa := csyncrr.Serial
	var old_minsoa uint32
	var ok bool

	if old_minsoa, ok = KnownCsyncMinSOAs[zone]; !ok {
		// This CSYNC is not previously known
		return false
	} else {
		return old_minsoa > new_minsoa
	}
	// unreachable: return true
}

func (scanner *Scanner) UpdateCsyncStatus(zone string, csyncrr *dns.CSYNC) error {
	scanner.Log["CSYNC"].Printf("UpdateCsyncStatus: Updating zone %s CSYNC status, new MinSOA=%d",
		zone, csyncrr.Serial)

	// const UCSsql = `
	//	      	     INSERT OR IGNORE
	//	      	     INTO CsyncStatus(child, minsoa, flags, immediate, useminsoa, rrtypes, rrtype, rr, lastupdate)
	//	      	     VALUES (?,?,?,?,?,?,?,?,?)`

	// immediate := (csyncrr.Flags & 0x01) == 1
	// usesoamin := (csyncrr.Flags & 0x02) == 2
	// csynctypes := TypeBitMapToString(csyncrr.TypeBitMap)

	//	_, err := scanner.LabDB.Exec(UCSsql, zone, csyncrr.Serial, csyncrr.Flags, immediate,
	//		usesoamin, csynctypes, "CSYNC", csyncrr.String(), time.Now())
	//	if err != nil {
	//		scanner.Log["CSYNC"].Printf("UpdateCsyncStatus: Error from ldb.Exec(%s): %v", UCSsql, err)
	//		return err
	//	}
	return nil
}

func TypeBitMapToString(tbm []uint16) string {
	types := []string{}
	for _, v := range tbm {
		types = append(types, dns.TypeToString[v])
	}
	return strings.Join(types, ",")
}
