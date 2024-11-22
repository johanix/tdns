package fsm

import (
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

var zoneWaitDs map[string]time.Time // Issue #34: using local store for now

func init() {
	zoneWaitDs = make(map[string]time.Time)
}

var FsmJoinNsSynced = music.FSMTransition{
	Description: "Wait enough time for parent DS records to propagate (criteria), then sync NS records between all signers (action)",

	MermaidPreCondDesc:  "Wait for DS to propagate",
	MermaidActionDesc:   "Sync NS RRsets between all signers",
	MermaidPostCondDesc: "Verify that NS RRsets are in sync",

	PreCondition:  JoinWaitDsPreCondition,
	Action:        JoinSyncNs,
	PostCondition: JoinSyncNSPostCondition, // XXX TODO: This is also the precondition for the next state. Consolidate
}

// JoinWaitDsPreCondition calculates a waiting period for DS propagation and then waits.
func JoinWaitDsPreCondition(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("JoinWaitDsPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	if until, ok := zoneWaitDs[z.Name]; ok {
		if time.Now().Before(until) {
			z.SetStopReason(fmt.Sprintf("Waiting until %s (%s)", until.String(),
				time.Until(until).String()))
			return false
		}
		log.Printf("%s: Waited enough for DS, pre-condition fullfilled", z.Name)
		delete(zoneWaitDs, z.Name)
		return true
	}

	log.Printf("JoinWaitDsPreCondition: %s: Fetching DNSKEYs and DSes to calculate DS wait until", z.Name)

	var ttl uint32

	for _, signer := range z.SGroup.SignerMap {

		updater := music.GetUpdater(signer.Method)
		err, rrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("JoinWaitDsPreCondition: Error from updater.FetchRRset: %v\n", err)
		}

		for _, a := range rrs {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if dnskey.Header().Ttl > ttl {
				ttl = dnskey.Header().Ttl
			}
		}
	}

	parentAddress, err := z.GetParentAddressOrStop()
	if err != nil {
		return false // stop-reason defined in GetParenAddressOrStop()
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

		if ds.Header().Ttl > ttl {
			ttl = ds.Header().Ttl
		}
	}

	// until := time.Now().Add((time.Duration(ttl*2) * time.Second))
	// TODO: static wait time to enable faster testing
	until := time.Now().Add((time.Duration(5) * time.Second))

	zoneWaitDs[z.Name] = until
	// XXX: this rather needs a z.SetDelayReasonAndTime(...)
	z.SetStopReason(fmt.Sprintf("Largest TTL found was %d, waiting until %s (%s)", ttl,
		until.String(), time.Until(until).String()))
	return false
}

// JoinSyncNs synchronizes all NS RRs between the signers in the signergroup.
func JoinSyncNs(z *music.Zone) bool {
	log.Printf("JoinSyncNs: %s: Fetch all NS records from all signers", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("JoinSyncNs: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	nses := make(map[string][]*dns.NS)
	signer_nsnames := make(map[string][]string)

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		log.Printf("JoinSyncNs: Using FetchRRset interface:\n")
		err, rrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeNS)
		if err != nil {
			z.SetStopReason(err.Error())
			return false
		}

		nses[signer.Name] = []*dns.NS{}
		signer_nsnames[signer.Name] = []string{}

//		const sqlq = "INSERT OR IGNORE INTO zone_nses (zone, ns, signer) VALUES (?, ?, ?)"

		for _, a := range rrs {
			ns, ok := a.(*dns.NS)
			if !ok {
				continue
			}

			nses[signer.Name] = append(nses[signer.Name], ns)
			signer_nsnames[signer.Name] = append(signer_nsnames[signer.Name], ns.Ns)

			// XXX: Should wrap this in a transaction
//			res, err := z.MusicDB.Exec(sqlq, z.Name, ns.Ns, signer.Name)
//			if err != nil {
//				log.Printf("%s: db.Exec (%s) failed: %s", z.Name, sqlq, err)
//				return false
//			}
//			rows, _ := res.RowsAffected()
//			if rows > 0 {
//				log.Printf("%s: Origin for %s set to %s", z.Name, ns.Ns, signer.Name)
//			}
		}
	}
	z.SetSignerNsNames(signer_nsnames) // replaces the SQL stuff above

	log.Printf("%s: Creating NS record sets", z.Name)

	// Map all known NSes
	nsmap := make(map[string]*dns.NS)
	for _, rrs := range nses {
		for _, rr := range rrs {
			nsmap[rr.Ns] = rr
		}
	}
	// Create RRset for insert
	nsset := []dns.RR{}
	for _, rr := range nsmap {
		log.Printf("[JoinSyncNs] adding %v to nsset\n", rr)
		nsset = append(nsset, rr)
	}

	// TODO: is this needed here also?
	//       Old code made sure the configured NS for each signer was added
	// for _, signer := range signers {
	//     ns := Config.Get("signer-ns:"+signer, "")
	//     if ns == "" {
	//         continue
	//     }
	//     if _, ok := nsmap[ns]; !ok {
	//         rr := new(dns.NS)
	//         rr.Hdr = dns.RR_Header{Name: args[0], Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: uint32(ttl)}
	//         rr.Ns = ns
	//         nsset = append(nsset, rr)
	//     }
	// }

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.Update(signer, z.Name, z.Name, &[][]dns.RR{nsset}, nil); err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to update %s with NS record sets: %s", signer.Name, err))
			return false
		}
		log.Printf("%s: Update %s successfully with NS record sets", z.Name, signer.Name)
	}

	// XXX: What should we do here? If we don't do the state transition
	//      then the delete is wrong.
	// z.StateTransition(FsmStateParentDsSynced, FsmStateDsPropagated)
	// The delete has moved to the true-branch of the PreCondition.
	// delete(zoneWaitDs, z.Name)
	return true
}

// JoinSyncNSPostCondition confirms that the NS RRs are synced across all the signers in the signergroup.
func JoinSyncNSPostCondition(z *music.Zone) bool {
	nses := make(map[string][]*dns.NS)

	log.Printf("%s: Verifying that NSes are in sync in group %s", z.Name, z.SGroup.Name)

	if z.ZoneType == "debug" {
		log.Printf("JoinAddCsyncPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	for _, s := range z.SGroup.SignerMap {
		updater := music.GetUpdater(s.Method)
		err, rrs := updater.FetchRRset(s, z.Name, z.Name, dns.TypeNS)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
			// XXX: johani: is it meaningful to continue here? why not just return false?
		}

		nses[s.Name] = []*dns.NS{}

		for _, a := range rrs {
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
	nsset := []*dns.NS{}
	for _, rr := range nsmap {
		nsset = append(nsset, rr)
	}

	group_nses_synced := true
	for signer, keys := range nses {
		for _, ns := range nsset {
			found := false
			for _, key := range keys {
				if ns.Ns == key.Ns {
					found = true
					break
				}
			}
			if !found {
				z.SetStopReason(fmt.Sprintf("NS %s is missing in signer %s", ns.Ns, signer))
				group_nses_synced = false
			}
		}
	}

	if !group_nses_synced {
		return false // stop-reason defined above
	}

	log.Printf("%s: All NSes synced between all signers", z.Name)
	return true
}
