/*
 *
 */

package fsm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

var FsmJoinAddCDS = music.FSMTransition{
	Description: "Once all DNSKEYs are present in all signers (criteria), build CDS/CDNSKEYs RRset and push to all signers (action)",

	MermaidPreCondDesc:  "Verify that all DNSKEYs are present on all signers",
	MermaidActionDesc:   "Compute and publish CDS/CDNSKEY RRsets on all signers",
	MermaidPostCondDesc: "Verify that all CDS/CDNSKEY RRs are published",

	PreCondition:  JoinAddCdsPreCondition,
	Action:        JoinAddCdsAction,
	PostCondition: VerifyCdsPublished,
}

// JoinAddCdsPreCondition collects DNSKEYS from all signers and verifies that the RRsets match.
func JoinAddCdsPreCondition(zone *music.Zone) bool {
	if zone.ZoneType == "debug" {
		log.Printf("JoinAddCdsPreCondition: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}

	if music.SignerRRsetEqual(zone, dns.TypeDNSKEY) {
		log.Printf("[JoinAddCdsPreCondition] All DNSKEYS synced.")
		return true
	} else {
		log.Printf("[JoinAddCdsPreCondition] All DNSKEYS not synced.")
		return false
	}
}

// JoinAddCdsAction creates the CDS/CDNSKEY RRs and adds them to all signers in the signergroup.
func JoinAddCdsAction(zone *music.Zone) bool {
	log.Printf("[JoinAddCDSAction] zone struct: \n %v \n", zone)
	log.Printf("%s: Creating CDS/CDNSKEY record sets", zone.Name)

	if zone.ZoneType == "debug" {
		log.Printf("JoinAddCdsAction: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}

	// Get DNSKEYS from all the signers.
	// TODO: Figure out how we can just get the keys from when we got them earlier.
	dnskeyMap := make(map[uint16]*dns.DNSKEY)
	for _, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		log.Printf("[JoinAddCdsAction]\t Using FetchRRset interface[DNSKEY]\n")
		rrs, err := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		for _, a := range rrs {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if f := dnskey.Flags & 0x101; f == 257 {
				dnskeyMap[dnskey.KeyTag()] = dnskey
			}
		}
	}

	var cdses, cdnskeys []dns.RR
	for _, dnskey := range dnskeyMap {
		cdses = append(cdses, dnskey.ToDS(dns.SHA256).ToCDS())
		cdses = append(cdses, dnskey.ToDS(dns.SHA384).ToCDS())
		cdnskeys = append(cdnskeys, dnskey.ToCDNSKEY())
	}

	// Publish CDS/CDNSKEY RRsets
	for _, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.Update(signer, zone.Name, zone.Name,
			&[][]dns.RR{cdses, cdnskeys}, nil); err != nil {
			_, err = zone.SetStopReason(fmt.Sprintf("Unable to update %s with CDS/CDNSKEY record sets: %s",
				signer.Name, err))
			if err != nil {
				log.Printf("Could not set stop reason: Unable to update %s with CDS/CDNSKEY rrset: %s",
					signer.Name, err)
			}
			return false
		}
		log.Printf("%s: Update %s successfully with CDS/CDNSKEY record sets",
			zone.Name, signer.Name)
	}
	return true
}

// VerifyCdsPublished verifies that the CDS/CDNSKEY RRs are published and in sync across all signers in the signergroup.
func VerifyCdsPublished(zone *music.Zone) bool {
	log.Printf("Verifying Publication of CDS/CDNSKEY record sets for %s", zone.Name)

	if zone.ZoneType == "debug" {
		log.Printf("VerifyCdsPublished: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}

	cdsFromKSK := map[uint16]*dns.CDS{}     // cdsFromKSK: map of CDS RRs created from all KSKs from all signers
	cdsFromSigners := map[uint16]*dns.CDS{} // cdsFromSigners: map of all CDS RRs found by querying all signers

	cdnskeyFromKSK := map[uint16]*dns.CDNSKEY{}
	cdnskeyFromSigners := map[uint16]*dns.CDNSKEY{}

	// Fetch DNSKEYS
	for _, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		log.Printf("VerifyCdsPublished: %s Using FetchRRset interface\n", zone.Name)
		rrSet, err := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		// Create CDS/CDNSKEY RRsets
		for _, a := range rrSet {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if f := dnskey.Flags & 0x101; f == 257 {
				cdsFromKSK[dnskey.KeyTag()] = dnskey.ToDS(dns.SHA256).ToCDS()
				cdnskeyFromKSK[dnskey.KeyTag()] = dnskey.ToCDNSKEY()
			}
		}
	}
	var keyids []uint16
	for k, _ := range cdsFromKSK {
		keyids = append(keyids, k)
	}
	log.Printf("Verify Publication of CDS: there are KSKs at the signers with the following keytags: %v\n", keyids)

	// Compare DNSKEYs to published CDS/CDNSKEY RRsets.
	for _, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		cdsRRset, err := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeCDS)
		if err != nil {
			_, err = zone.SetStopReason(fmt.Sprintf("Unable to fetch CDS RRset from %s: %v", signer.Name, err))
			return false
		}
		cdnskeyRRset, err := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeCDNSKEY)
		if err != nil {
			_, err = zone.SetStopReason(fmt.Sprintf("Unable to fetch CDNSKEY RRset from %s: %v",
				signer.Name, err))
			return false
		}

		for _, rr := range cdsRRset {
			cdsRR, ok := rr.(*dns.CDS)
			if !ok {
				continue
			}
			cdsFromSigners[cdsRR.KeyTag] = cdsRR
			if _, exist := cdsFromKSK[cdsRR.KeyTag]; !exist {
				_, err = zone.SetStopReason(fmt.Sprintf("CDS RR with keyid=%d published by signer %s should not exist", cdsRR.KeyTag, signer.Name))
				return false
			}
		}
		for _, cdsRR := range cdsFromKSK {
			if _, exist := cdsFromSigners[cdsRR.KeyTag]; !exist {
				_, err = zone.SetStopReason(fmt.Sprintf("CDS RR with keyid=%d should be published by %s, but is not",
					cdsRR.KeyTag, signer.Name))
				return false
			}
		}

		for _, rr := range cdnskeyRRset {
			cdnskeyRR, ok := rr.(*dns.CDNSKEY)
			if !ok {
				continue
			}
			keyTag := cdnskeyRR.KeyTag()
			cdnskeyFromSigners[keyTag] = cdnskeyRR
			if _, exist := cdnskeyFromKSK[keyTag]; !exist {
				_, err = zone.SetStopReason(fmt.Sprintf("CDNSKEY RR with keyid=%d published by %s should not exist",
					keyTag, signer.Name))
				return false
			}
		}
		for _, cdnskeyRR := range cdnskeyFromKSK {
			keyTag := cdnskeyRR.KeyTag()
			if _, exist := cdnskeyFromSigners[keyTag]; !exist {
				_, err = zone.SetStopReason(fmt.Sprintf("CDNSKEY RR with keyid=%d should be published by %s, but is not",
					keyTag, signer.Name))
				return false
			}
		}
	}

	return true
}
