package fsm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

var FsmLeaveParentDsSynced = music.FSMTransition{
	Description: "Wait for parent to pick up CDS/CDNSKEYs and update it's DS (criteria), then remove CDS/CDNSKEYs from all signers and STOP (action)",

	MermaidPreCondDesc:  "Wait for parent to pick up CDS/CDNSKEYs and update the DS record(s)",
	MermaidActionDesc:   "Remove CDS/CDNSKEYs from all signers",
	MermaidPostCondDesc: "Verify that all CDS/CDNSKEYs have been removed",

	PreCondition:  LeaveParentDsSyncedPreCondition,
	Action:        LeaveParentDsSyncedAction,
	PostCondition: LeaveVerifyCDSRemoval,
}

// LeaveParentDsSyncedPreCondition verifies that the DS records on the parent match the CDS RRs on the remaining signers in the signergroup
func LeaveParentDsSyncedPreCondition(z *music.Zone) bool {
	cdsmap := make(map[string]*dns.CDS)

	log.Printf("%s: Verifying that DSes in parent are up to date compared to signers CDSes", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("LeaveParentDsSyncedPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	leavingSignerName := z.FSMSigner // Issue #34: Static leaving signer until metadata is in place
	if leavingSignerName == "" {
		log.Fatalf("Leaving signer name for zone %s unset.", z.Name)
	}

	// https://github.com/DNSSEC-Provisioning/music/issues/130, testing to remove the leaving signer from the signermap. /rog
	// this may not be obvious to the casual observer
	log.Printf("leave_add_cds: %s SignerMap: %v\n", z.Name, z.SGroup.SignerMap)
	log.Printf("remove %v from SignerMap %v: for %v", leavingSignerName, z.SGroup.SignerMap, z.SGroup.Name)
	delete(z.SGroup.SignerMap, leavingSignerName)
	if _, member := z.SGroup.SignerMap[leavingSignerName]; member {
		log.Fatalf("Signer %s is still a member of group %s", leavingSignerName, z.SGroup.SignerMap)
	}

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeCDS)

		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":"+s.Port)

		if err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to fetch CDSes from %s: %s", s.Name, err))
			return false
		}

		for _, a := range r.Answer {
			cds, ok := a.(*dns.CDS)
			if !ok {
				continue
			}

			cdsmap[fmt.Sprintf("%d %d %d %s", cds.KeyTag, cds.Algorithm, cds.DigestType, cds.Digest)] = cds
		}
	}

	parentAddress, err := z.GetParentAddressOrStop()
	if err != nil {
		return false // stop-reason set in GetParentAddressOrStop()
	}

	m := new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeDS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, parentAddress)
	if err != nil {
		z.SetStopReason(fmt.Sprintf("Unable to fetch DSes from parent: %s", err))
		return false
	}
	for _, a := range r.Answer {
		ds, ok := a.(*dns.DS)
		if !ok {
			continue
		}

		if _, ok := cdsmap[fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)]; !ok {
			z.SetStopReason(fmt.Sprintf("Parent DS found that is not in any signer: %d %d %d %s",
				ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest))
			return false
		}
	}

	log.Printf("%s: Parent is up-to-date with it's DS records", z.Name)
	return true
}

// LeaveParentDsSyncedAction takes no action since we are leaving the CDS/CDNSKEY RRs in place. XXX TODO: We need to look at this
func LeaveParentDsSyncedAction(z *music.Zone) bool {
	log.Printf("LeaveParentDsSyncedAction: zone %s : No action since we are leaving the CDS records on the signers", z.Name)
	return true
}

// LeaveVerifyCDSRemoval takes no action since we are leaving the CDS/CDNSKEY RRs in place. XXX TODO: We need to look at this
func LeaveVerifyCDSRemoval(zone *music.Zone) bool {
	log.Printf("LeaveVerifyCDSRemoval: zone %s : No PostCondtion since we are leaving the CDS records on the signers", zone.Name)
	return true
}

// The code below is on "Pause" until we figure out what we want to do with https://github.com/DNSSEC-Provisioning/music/issues/96
/*
func LeaveParentDsSyncedAction(z *music.Zone) bool {
	log.Printf("%s: Removing CDS/CDNSKEY record sets", z.Name)

	if z.ZoneType == "debug" {
	   log.Printf("LeaveParentDsSyncedAction: zone %s (DEBUG) is automatically ok", z.Name)
	   return true
	}

	cds := new(dns.CDS)
	cds.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 0}

	ccds := new(dns.CDNSKEY)
	ccds.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCDNSKEY, Class: dns.ClassINET, Ttl: 0}

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.RemoveRRset(signer, z.Name, z.Name,
			[][]dns.RR{[]dns.RR{cds}, []dns.RR{ccds}}); err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to remove CDS/CDNSKEY record sets from %s: %s",
							    signer.Name, err))
			return false
		}
		log.Printf("%s: Removed CDS/CDNSKEY record sets from %s successfully", z.Name, signer.Name)
	}

	return true

	// TODO: remove state/metadata around leaving signer
	//       tables: zone_dnskeys, zone_nses
}

// LeaveVerifyCDSRemoval Verifies that the CDS/CDNSKEY Records have been removed
func LeaveVerifyCDSRemoval(zone *music.Zone) bool {
	if zone.ZoneType == "debug" {
		log.Printf("LeaveVerifyCDSRemoval: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}

	var signerNames []string
	rrTypes := []uint16{dns.TypeCDS, dns.TypeCDNSKEY}
	for _, rrType := range rrTypes {
		for signerName, signer := range zone.SGroup.SignerMap {
			updater := music.GetUpdater(signer.Method)
			rrSet, err := updater.FetchRRset(signer, zone.Name, zone.Name, rrType)
			if err != nil {
				zone.SetStopReason(fmt.Sprintf("Couldn't Fetch %s RRset from %s\n", dns.TypeToString[rrType], signerName))
			}
			if len(rrSet) > 0 {
				signerNames = append(signerNames, signerName)
			}
		}
		if len(signerNames) > 0 {
			zone.SetStopReason(fmt.Sprintf("%s records still exist on %v", dns.TypeToString[rrType], signerNames))
			return false
		}
	}
	return true
}
*/
