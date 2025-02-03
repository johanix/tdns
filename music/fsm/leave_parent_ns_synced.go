package fsm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

var FsmLeaveParentNsSynced = music.FSMTransition{
	Description: "Wait for parent to pick up CSYNC and update it's NS records (criteria), then remove CSYNC from all signers (action)",

	MermaidPreCondDesc:  "Wait for parent to pick up CSYNC and update the NS records",
	MermaidActionDesc:   "Remove CSYNC records from all signers",
	MermaidPostCondDesc: "Verify that all CSYNC records have been removed",

	PreCondition:  LeaveParentNsSyncedPreCondition,
	Action:        LeaveParentNsSyncedAction,
	PostCondition: LeaveParentNsSyncedPostCondition,
}

// LeaveParentNsSyncedPreCondition verifies that NS records in parent are in synced with the remaining signers in the signergroup.
func LeaveParentNsSyncedPreCondition(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveParentNsSyncedPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	sg := z.SignerGroup()
	if sg == nil {
		log.Fatalf("Zone %s in process %s not attached to any signer group.", z.Name, z.FSM)
	}

	leavingSignerName := z.FSMSigner // Issue #34: Static leaving signer until metadata is in place
	if leavingSignerName == "" {
		log.Fatalf("Leaving signer name for zone %s unset.", z.Name)
	}

	// Need to get signer to remove records for it also, since it's not part of zone SignerMap anymore
	leavingSigner, err := z.MusicDB.GetSignerByName(nil, leavingSignerName, false) // not apisafe
	if err != nil {
		z.SetStopReason(fmt.Sprintf("Unable to get leaving signer %s: %s", leavingSignerName, err))
		return false
	}

	// https://github.com/DNSSEC-Provisioning/music/issues/130, testing to remove the leaving signer from the signermap. /rog
	// this may not be obvious to the casual observer
	log.Printf("leave_parent_ns_synced: %s SignerMap: %v\n", z.Name, z.SGroup.SignerMap)
	log.Printf("remove %v from SignerMap %v: for %v", leavingSignerName, sg.SignerMap, sg.Name)
	delete(z.SGroup.SignerMap, leavingSignerName)
	if _, member := z.SGroup.SignerMap[leavingSignerName]; member {
		log.Fatalf("Signer %s is still a member of group %s", leavingSignerName, z.SGroup.SignerMap)
	}

	nses := make(map[string][]*dns.NS)

	log.Printf("%s: Verifying that NSes are in sync in the parent", z.Name)

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeNS)
		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":"+s.Port)
		if err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to fetch NSes from %s: %s", s.Name, err))
			return false
		}

		nses[s.Name] = []*dns.NS{}

		for _, a := range r.Answer {
			ns, ok := a.(*dns.NS)
			if !ok {
				continue
			}

			nses[s.Name] = append(nses[s.Name], ns)
		}
	}

	m := new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeNS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, leavingSigner.Address+":"+leavingSigner.Port)
	if err != nil {
		z.SetStopReason(fmt.Sprintf("Unable to fetch NSes from %s: %s", leavingSigner.Name, err))
		return false
	}

	nses[leavingSigner.Name] = []*dns.NS{}

	for _, a := range r.Answer {
		ns, ok := a.(*dns.NS)
		if !ok {
			continue
		}

		nses[leavingSigner.Name] = append(nses[leavingSigner.Name], ns)
	}

	// Map all known NSes
	nsmap := make(map[string]*dns.NS)
	for _, rrs := range nses {
		for _, rr := range rrs {
			nsmap[rr.Ns] = rr
		}
	}

	parentAddress, err := z.GetParentAddressOrStop()
	if err != nil {
		return false // stop-reason set in GetParentAddressOrStop()
	}

	m = new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeNS)
	c = new(dns.Client)
	r, _, err = c.Exchange(m, parentAddress)
	if err != nil {
		z.SetStopReason(fmt.Sprintf("Unable to fetch NSes from parent: %s", err))
		return false
	}

	for _, a := range r.Ns {
		ns, ok := a.(*dns.NS)
		if !ok {
			continue
		}

		if _, ok := nsmap[ns.Ns]; !ok {
			z.SetStopReason(fmt.Sprintf("NS %s still exists in parent", ns.Ns))
			return false
		}
	}

	log.Printf("%s: Parent NSes are up-to-date", z.Name)
	return true
}

// LeaveParentNsSyncedAction removes the CSYNC RRs from the remaining signers in the signergroup.
func LeaveParentNsSyncedAction(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveParentNsSyncedAction: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	sg := z.SignerGroup()
	if sg == nil {
		log.Fatalf("Zone %s in process %s not attached to any signer group.", z.Name, z.FSM)
	}

	leavingSignerName := z.FSMSigner // Issue #34: Static leaving signer until metadata is in place
	if leavingSignerName == "" {
		log.Fatalf("Leaving signer name for zone %s unset.", z.Name)
	}

	// Need to get signer to remove records for it also, since it's not part of zone SignerMap anymore
	// or is it?? it is not ! so the SGroup.SignerMap in signerops and the z.SGroup.SignerMap is two seperate maps, /rog

	leavingSigner, err := z.MusicDB.GetSignerByName(nil, leavingSignerName, false) // not apisafe
	if err != nil {
		z.SetStopReason(fmt.Sprintf("Unable to get leaving signer %s: %s", leavingSignerName, err))
		return false
	}

	// https://github.com/DNSSEC-Provisioning/music/issues/130, testing to remove the leaving signer from the signermap. /rog
	// this may not be obvious to the casual observer
	log.Printf("leave_parent_ns_synced: %s SignerMap: %v\n", z.Name, z.SGroup.SignerMap)
	log.Printf("remove %v from SignerMap %v: for %v", leavingSignerName, sg.SignerMap, sg.Name)
	delete(z.SGroup.SignerMap, leavingSignerName)
	if _, member := z.SGroup.SignerMap[leavingSignerName]; member {
		log.Fatalf("Signer %s is still a member of group %s", leavingSignerName, z.SGroup.SignerMap)
	}

	log.Printf("%s: Removing CSYNC record sets", z.Name)

	csync := new(dns.CSYNC)
	csync.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: 0}

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.RemoveRRset(signer, z.Name, z.Name,
			[][]dns.RR{[]dns.RR{csync}}); err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to remove CSYNC record sets from %s: %s",
				signer.Name, err))
			return false
		}
		log.Printf("%s: Removed CSYNC record sets from %s successfully", z.Name, signer.Name)
	}

	updater := music.GetUpdater(leavingSigner.Method)
	if err := updater.RemoveRRset(leavingSigner, z.Name, z.Name, [][]dns.RR{[]dns.RR{csync}}); err != nil {
		z.SetStopReason(fmt.Sprintf("Unable to remove CSYNC record sets from %s: %s",
			leavingSigner.Name, err))
		return false
	}
	log.Printf("%s: Removed CSYNC record sets from %s successfully", z.Name, leavingSigner.Name)

	return true
}

// LeaveParentNsSyncedPostCondition confirms there are no CSYNC records on the remaining signers in the signergroup.
func LeaveParentNsSyncedPostCondition(zone *music.Zone) bool {
	if zone.ZoneType == "debug" {
		log.Printf("LeaveParentNsSyncedPostCondition: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}

	var signerNames []string
	for signerName, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		rrSet, err := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeCSYNC)
		if err != nil {
			zone.SetStopReason(fmt.Sprintf("Couldn't CSYNC FetchRRset from %s\n", signerName))
		}
		if len(rrSet) > 0 {
			signerNames = append(signerNames, signerName)
		}
	}
	if len(signerNames) > 0 {
		zone.SetStopReason(fmt.Sprintf("CSYNC records still exist on %v", signerNames))
		return false
	}
	return true
}
