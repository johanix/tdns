package fsm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

// Transition SIGNERS-UNSYNCHED --> DNSKEYS-SYNCHED:

// PRE-CONDITION (aka CRITERIA): None
// ACTION: get all ZSKs for all signers included in the DNSKEY RRset on all signers
// POST-CONDITION: verify that all ZSKs are included in all DNSKEY RRsets on all signers

var FsmJoinSyncDnskeys = music.FSMTransition{
	Description:         "First step when joining, this transistion has no criteria and will sync DNSKEYs between all signers (action)",
	MermaidPreCondDesc:  "",
	MermaidActionDesc:   "Update all signer DNSKEY RRsets with all ZSKs",
	MermaidPostCondDesc: "Verify that all ZSKs are published in signer DNSKEY RRsets",
	PreCondition:        func(z *music.Zone) bool { return true },
	Action:              JoinSyncDnskeys,
	PostCondition:       VerifyDnskeysSynched,
}

// XXX: Is it always true that the PostCondition for one action is equal to the PreCondition
//      for the next action? I think so. I.e. this implementation (VerifyDnskeysSynched) is
//      extremely similar to the JoinAddCdsPreCondition function that is the PreCondition for
//      the next step (adding CDS/CDNSKEYs).

// JoinSyncDnskeys synchronizes all DNSKEY RRs between the signers in the signergroup.
func JoinSyncDnskeys(z *music.Zone) bool {
	dnskeys := make(map[string][]*dns.DNSKEY)

	log.Printf("JoinSyncDnskeys: %s: Syncing DNSKEYs in group %s", z.Name, z.SGroup.Name)

	if z.ZoneType == "debug" {
		log.Printf("JoinSyncDnskeys: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	signer_dnskeys := make(map[string][]string)

	for _, s := range z.SGroup.SignerMap {
		log.Printf("JoinSyncDnskeys: signer: %s\n", s.Name)
		updater := music.GetUpdater(s.Method)
		log.Printf("JoinSyncDnskeys: Using FetchRRset interface:\n")
		rrs, err := updater.FetchRRset(s, z.Name, z.Name, dns.TypeDNSKEY)
		if err != nil {
			_, err = z.SetStopReason(err.Error())
			return false
		}

		dnskeys[s.Name] = []*dns.DNSKEY{}
		signer_dnskeys[s.Name] = []string{}

		//		const sqlq = "INSERT OR IGNORE INTO zone_dnskeys (zone, dnskey, signer) VALUES (?, ?, ?)"
		for _, a := range rrs {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			dnskeys[s.Name] = append(dnskeys[s.Name], dnskey)

			if f := dnskey.Flags & 0x101; f == 256 || f == 257 {
				//				res, err := z.MusicDB.Exec(sqlq, z.Name, fmt.Sprintf("%d-%d-%s",
				//					dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey), s.Name)
				signer_dnskeys[s.Name] = append(signer_dnskeys[s.Name], fmt.Sprintf("%d-%d-%s",
					dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey))
				//				if err != nil {
				//					log.Printf("JoinSyncDnskeys: %s: Statement execute failed: %s",
				//						z.Name, err)
				//					return false
				//				}
				//				rows, _ := res.RowsAffected()
				//				if rows > 0 {
				//					log.Printf("JoinSyncDnskeys: %s: Origin for %s set to %s",
				//						z.Name, dnskey.PublicKey, s.Name)
				//				}
			}
		}

		if len(dnskeys[s.Name]) == 1 {
			log.Printf("JoinSyncDnskeys: %s: Fetched DNSKEYs from %s:", z.Name, s.Name)
			for _, k := range dnskeys[s.Name] {
				log.Printf("%s: - %d (CSK) %s...", z.Name, int(k.KeyTag()), k.PublicKey[:20])
			}
		} else if len(dnskeys[s.Name]) > 1 {
			log.Printf("JoinSyncDnskeys: %s: Fetched DNSKEYs from %s:", z.Name, s.Name)
			for _, k := range dnskeys[s.Name] {
				if f := k.Flags & 0x101; f == 256 {
					log.Printf("%s: - %d (ZSK) %s...", z.Name, int(k.KeyTag()), k.PublicKey[:20])
				} else {
					log.Printf("%s: - %d (KSK) %s...", z.Name, int(k.KeyTag()), k.PublicKey[:20])
				}
			}
		} else {
			log.Printf("JoinSyncDnskeys: %s: No DNSKEYs found in %s", z.Name, s.Name)
		}
	}

	z.SetSignerDnskeys(signer_dnskeys) // replaces the sql stuff above

	// for each signer, check every other_signer if it's missing signer's DNSKEYs
	keysToSync := map[string][]dns.RR{}
	for signer, keys := range dnskeys {
		for _, key := range keys {
			//if f := key.Flags & 0x101; f == 256 { // only process ZSK's
			for other_signer, other_keys := range dnskeys {
				if other_signer == signer {
					continue
				}

				found := false
				for _, other_key := range other_keys {
					if other_key.PublicKey == key.PublicKey {
						// if other_key.Protocol != key.Protocol {
						//     *output = append(*output, fmt.Sprintf("Found DNSKEY in %s but missmatch Protocol: %s", other_signer, key.PublicKey))
						//     break
						// }
						// if other_key.Algorithm != key.Algorithm {
						//     *output = append(*output, fmt.Sprintf("Found DNSKEY in %s but missmatch Protocol: %s", other_signer, key.PublicKey))
						//     break
						// }
						found = true
						break
					}
				}

				if !found {
					if _, ok := keysToSync[other_signer]; !ok {
						keysToSync[other_signer] = []dns.RR{}
					}
					keysToSync[other_signer] = append(keysToSync[other_signer], key)
					log.Printf("JoinSyncDnskeys: %s: Added %s's DNSKEY %s to %s", z.Name, signer, key.PublicKey, other_signer)
				} else {
					log.Printf("JoinSyncDnskeys: %s: %s's DNSKEY %s already exists in %s", z.Name, signer, key.PublicKey, other_signer)
				}
			}
			//	}
		}
	}

	for signer, keys := range keysToSync {
		s := z.SGroup.SignerMap[signer]
		updater := music.GetUpdater(s.Method)
		if err := updater.Update(s, z.Name, z.Name,
			&[][]dns.RR{keys}, nil); err != nil {
			// TODO: use stringtojoin on keysToSync
			//log.Printf("%s: Unable to update %s with new DNSKEYs %v: %s", z.Name, signer, keysToSync, err)
			z.SetStopReason(fmt.Sprintf("%s: Unable to update %s with new DNSKEYs %v: %s", z.Name, signer, keysToSync, err))
			return false
		}
	}

	return true
}

// VerifyDnskeysSynched confirms that all the DNSKEY RR's are synced across all signers in the signergroup.
func VerifyDnskeysSynched(zone *music.Zone) bool {
	if zone.ZoneType == "debug" {
		log.Printf("JoinSyncDnskeysPostCondition: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}

	if music.SignerRRsetEqual(zone, dns.TypeDNSKEY) {
		log.Printf("[JoinSyncDnskeysPostCondition] All DNSKEYS synced")
		return true
	} else {
		log.Printf("[JoinSyncDnskeysPostCondition] All DNSKEYS not synced")
		return false
	}
}
