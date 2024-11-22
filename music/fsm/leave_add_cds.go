package fsm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

var FsmLeaveAddCDS = music.FSMTransition{
	Description: "Once all DNSKEYs are correct in all signers (criteria), build CDS/CDNSKEYs RRset and push to all signers (action)",

	MermaidPreCondDesc:  "TEXT",
	MermaidActionDesc:   "TEXT",
	MermaidPostCondDesc: "TEXT",

	PreCondition:  LeaveAddCDSPreCondition,
	Action:        LeaveAddCDSAction,
	PostCondition: LeaveCDSVerify,
}

// LeaveAddCDSPreCondition calculate the relevant DNSKEYS for the signergroup and verify that the signers are correct.
func LeaveAddCDSPreCondition(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveAddCdsPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
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
	// or is it?? it is not ! so the SGroup.SignerMap in signerops and the z.SGroup.SignerMap is two seperate maps,
	leavingSigner, err := z.MusicDB.GetSignerByName(nil, leavingSignerName, false) // not apisafe
	if err != nil {
		z.SetStopReason(fmt.Sprintf("Unable to get leaving signer %s: %s", leavingSignerName, err))
		return false
	}

	// https://github.com/DNSSEC-Provisioning/music/issues/130, testing to remove the leaving signer from the signermap. /rog
	// this may not be obvious to the casual observer
	log.Printf("leave_add_cds: %s SignerMap: %v\n", z.Name, z.SGroup.SignerMap)
	log.Printf("remove %v from SignerMap %v: for %v", leavingSignerName, sg.SignerMap, sg.Name)
	delete(z.SGroup.SignerMap, leavingSignerName)
	if _, member := z.SGroup.SignerMap[leavingSignerName]; member {
		log.Fatalf("Signer %s is still a member of group %s", leavingSignerName, z.SGroup.SignerMap)
	}

	log.Printf("%s: Verifying that leaving signer %s DNSKEYs has been removed from all signers",
		z.Name, leavingSigner.Name)

	const sqlq = "SELECT dnskey FROM zone_dnskeys WHERE zone = ? AND signer = ?"

	rows, err := z.MusicDB.Query(sqlq, z.Name, leavingSigner.Name)
	if err != nil {
		log.Printf("%s: mdb.Query(%s) failed: %s", z.Name, sqlq, err)
		return false
	}

	dnskeys := make(map[string]bool)

	var dnskey string
	for rows.Next() {
		if err = rows.Scan(&dnskey); err != nil {
			log.Printf("%s: Rows.Scan() failed: %s", z.Name, err)
			return false
		}

		dnskeys[dnskey] = true
	}

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeDNSKEY)
		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":"+s.Port)
		if err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to fetch DNSKEYs from %s: %s", s.Name, err))
			return false
		}

		for _, a := range r.Answer {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if _, ok := dnskeys[fmt.Sprintf("%d-%d-%s", dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey)]; ok {
				z.SetStopReason(fmt.Sprintf("DNSKEY %s still exists in signer %s",
					dnskey.PublicKey, s.Name))
				return false
			}
		}
	}

	return true
}

// LeaveAddCDSAction creates the CDS/CDNSKEY RRs and adds them to the remaining signers in the signergroup.
func LeaveAddCDSAction(z *music.Zone) bool {
	log.Printf("%s: Creating CDS/CDNSKEY record sets", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("LeaveAddCdsAction: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	cdses := []dns.RR{}
	cdnskeys := []dns.RR{}

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
		log.Printf("#### leave add cds signer to check: %+v\n ", s)
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeDNSKEY)

		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":"+s.Port)

		if err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to fetch DNSKEYs from %s: %s", s.Name, err))
			return false
		}

		for _, a := range r.Answer {
			log.Printf("#### leave add cds dnskey response %+v\n ", a)
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if f := dnskey.Flags & 0x101; f == 257 {
				cdses = append(cdses, dnskey.ToDS(dns.SHA256).ToCDS())
				cdnskeys = append(cdnskeys, dnskey.ToCDNSKEY())
			}
		}
	}

	// Create CDS/CDNSKEY records sets
	log.Printf("leave_add_cds: %s SignerMap: %v\n", z.Name, z.SGroup.SignerMap)
	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.Update(signer, z.Name, z.Name,
			&[][]dns.RR{cdses, cdnskeys}, nil); err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to update %s with CDS/CDNSKEY record sets: %s",
				signer.Name, err))
			return false
		}
		log.Printf("%s: Update %s successfully with CDS/CDNSKEY record sets", z.Name, signer.Name)
	}

	return true
}

// LeaveCDSVerify Verifies that the CDS/CDNSKEY RRs are published and in sync on the remaining signers in the signergroup.
func LeaveCDSVerify(zone *music.Zone) bool {
	if zone.ZoneType == "debug" {
		log.Printf("LeaveCDSVerify: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}
	matches := true
	rrTypes := []uint16{dns.TypeCDS, dns.TypeCDNSKEY}
	for _, rrType := range rrTypes {
		synced := music.SignerRRsetEqual(zone, rrType)
		if !synced {
			matches = false
		}
	}
	return matches
}
