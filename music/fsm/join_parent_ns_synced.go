package fsm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

var FsmJoinParentNsSynced = music.FSMTransition{
	Description: "Wait for parent to pick up CSYNC and update it's NS records (criteria), then remove CSYNC from all signers and STOP (action)",

	MermaidPreCondDesc:  "Verify that parent has published updated NS RRset",
	MermaidActionDesc:   "Remove CSYNC RR from all signers",
	MermaidPostCondDesc: "Verify that CSYNC has been removed from all signers",

	PreCondition:  JoinParentNsSyncedPreCondition,
	Action:        JoinParentNsSyncedAction,
	PostCondition: JoinParentNsSyncedPostCondition, // XXX TODO: is the same as LeaveParentNsSyncedConfirmCsyncRemoval. Consolidate
}

// JoinParentNsSyncedPreCondition confirms that the NS RRs for the signergroup have been synced to the parent.
func JoinParentNsSyncedPreCondition(z *music.Zone) bool {
	nses := make(map[string][]*dns.NS)

	log.Printf("%s: Verifying that NSes are in sync in the parent", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("JoinParentNsSyncedPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeNS)
		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":"+s.Port)
		if err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to fetch NSes from %s: %s",
				s.Name, err))
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

	// Map all known NSes
	nsmap := make(map[string]*dns.NS)
	for _, rrs := range nses {
		for _, rr := range rrs {
			nsmap[rr.Ns] = rr
		}
	}

	parentAddress, err := z.GetParentAddressOrStop()
	if err != nil {
		return false // stop-reason defined in GetParentAddressOrStop()
	}

	m := new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeNS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, parentAddress)
	if err != nil {
		z.SetStopReason(fmt.Sprintf("Unable to fetch NSes from parent: %s", err))
		return false
	}

	for _, a := range r.Ns {
		ns, ok := a.(*dns.NS)
		if !ok {
			continue
		}

		delete(nsmap, ns.Ns)
	}

	if len(nsmap) > 0 {
		missing_ns := []string{}
		for ns, _ := range nsmap {
			missing_ns = append(missing_ns, ns)
		}
		z.SetStopReason(fmt.Sprintf("Missing NS in parent: %v", missing_ns))
		return false
	}

	log.Printf("%s: Parent NSes are up-to-date", z.Name)
	return true
}

// JoinParentNsSyncedAction removes the CSYNC RRs from the signers in the signergroup.
func JoinParentNsSyncedAction(z *music.Zone) bool {
	log.Printf("%s: Removing CSYNC record sets", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("JoinParentNsSyncedAction: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

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

	return true
}

// JoinParentNsSyncedPostCondition confirms that the CSYNC records have been removed from the signers in the signergroup.
func JoinParentNsSyncedPostCondition(zone *music.Zone) bool {
	if zone.ZoneType == "debug" {
		log.Printf("JoinParentNsSyncedPostCondition: zone %s (DEBUG) is automatically ok", zone.Name)
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
