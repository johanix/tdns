package fsm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

var FsmJoinParentDsSynced = music.FSMTransition{
	Description: "Wait for parent to pick up CDS/CDNSKEYs and update it's DS (criteria), then remove CDS/CDNSKEYs from all signers (action)",

	MermaidPreCondDesc:  "Verify that parent DS RRset is updated",
	MermaidActionDesc:   "Remove all CDS/CDNSKEYs",
	MermaidPostCondDesc: "Verify that all CDS/CDNSKEYs are removed",

	PreCondition:  JoinParentDsSyncedPreCondition,
	Action:        JoinParentDsSyncedAction,
	PostCondition: VerifyCdsRemoved,
}

// JoinParentDsSyncedPreCondition compares the DS RRs in the parent zone to the signers CDS RRs.
func JoinParentDsSyncedPreCondition(z *music.Zone) bool {
	cdses := make(map[string][]*dns.CDS)

	log.Printf("%s: Verifying that DSes in parent are up to date compared to signers CDSes", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("JoinParentDsSyncedPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeCDS)

		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":"+s.Port) // TODO: add DnsAddress or solve this in a better way

		if err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to fetch CDSes from %s: %s",
				s.Name, err))
			return false
		}

		cdses[s.Name] = []*dns.CDS{}
		for _, a := range r.Answer {
			cds, ok := a.(*dns.CDS)
			if !ok {
				continue
			}

			log.Printf("%s: Signer %s CDS found: %d %d %d %s", z.Name,
				s.Name, cds.KeyTag, cds.Algorithm, cds.DigestType, cds.Digest)
			cdses[s.Name] = append(cdses[s.Name], cds)
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
	dses := []*dns.DS{}
	removedses := make(map[string]*dns.DS)
	for _, a := range r.Answer {
		ds, ok := a.(*dns.DS)
		if !ok {
			continue
		}

		log.Printf("%s: Parent DS found: %d %d %d %s", z.Name, ds.KeyTag,
			ds.Algorithm, ds.DigestType, ds.Digest)
		dses = append(dses, ds)
	}

	parent_up_to_date := true

	cdsmap := make(map[string]*dns.CDS)
	for _, keys := range cdses {
		for _, key := range keys {
			cdsmap[fmt.Sprintf("%d %d %d %s", key.KeyTag, key.Algorithm,
				key.DigestType, key.Digest)] = key
			delete(removedses, fmt.Sprintf("%d %d %d %s", key.KeyTag, key.Algorithm, key.DigestType, key.Digest))
		}
	}
	for _, ds := range dses {
		delete(cdsmap, fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest))
	}
	for _, cds := range cdsmap {
		// log.Printf("%s: Missing DS for CDS: %d %d %d %s", z.Name, cds.KeyTag, cds.Algorithm, cds.DigestType, cds.Digest)
		z.SetStopReason(fmt.Sprintf("Missing DS for CDS: %d", cds.KeyTag))
		parent_up_to_date = false
	}
	for _, ds := range removedses {
		// log.Printf("%s: Unknown DS: %d %d %d %s", z.Name, ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
		z.SetStopReason(fmt.Sprintf("Unknown DS: %d", ds.KeyTag))
		parent_up_to_date = false // TODO: should unknown DS be allowed?
	}

	if !parent_up_to_date {
		return false // stop-reason defined above
	}

	log.Printf("%s: DS records in parent are up-to-date", z.Name)
	return true
}

// JoinParentDsSyncedAction removes the CDS/CDSNSKEY records from the signers in the signergroup.
func JoinParentDsSyncedAction(z *music.Zone) bool {
	log.Printf("%s: Removing CDS/CDNSKEY record sets", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("JoinParentDsSyncedAction: zone %s (DEBUG) is automatically ok",
			z.Name)
		return true
	}

	cds := new(dns.CDS)
	cds.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 0}

	ccds := new(dns.CDNSKEY)
	ccds.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCDNSKEY, Class: dns.ClassINET, Ttl: 0}

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.RemoveRRset(signer, z.Name, z.Name, [][]dns.RR{[]dns.RR{cds},
			[]dns.RR{ccds}}); err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to remove CDS/CDNSKEY record sets from %s: %s", signer.Name, err))
			return false
		}
		log.Printf("%s: Removed CDS/CDNSKEY record sets from %s successfully", z.Name, signer.Name)
	}
	return true
}

// VerifyCdsRemoved confirms that the CDS/CDNSKEY RRs have been removed from the signers in the signergroup.
func VerifyCdsRemoved(z *music.Zone) bool {
	log.Printf("%s: Verify that CDS/CDNSKEY RRsets have been removed", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("VerifyCdsRemoved: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		err, cdsrrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeCDS)
		if err != nil {
			log.Printf("Error from FetchRRset: %v\n", err)
		}

		if len(cdsrrs) > 0 {
			z.SetStopReason(fmt.Sprintf("CDS RRset still published by %s\n",
				signer.Name))
			return false
		}
		err, cdnskeyrrs := updater.FetchRRset(signer, z.Name, z.Name,
			dns.TypeCDNSKEY)
		if err != nil {
			log.Printf("Error from FetchRRset: %v\n", err)
		}

		if len(cdnskeyrrs) > 0 {
			z.SetStopReason(fmt.Sprintf("CDNSKEY RRset still published by %s\n",
				signer.Name))
			return false
		}
	}
	return true
}
