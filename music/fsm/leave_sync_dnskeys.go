package fsm

import (
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

var FsmLeaveSyncDnskeys = music.FSMTransition{
	Description: "Once NSes has been propagated (NO criteria), remove DNSKEYs that originated from the leaving signer (Action)",

	MermaidPreCondDesc:  "todo",
	MermaidActionDesc:   "Remove DNSKEYs that originated with the leaving signer",
	MermaidPostCondDesc: "Verify that DNSKEYs for remaining signers are in sync",

	PreCondition:  LeaveSyncDnskeysPreCondition,
	Action:        LeaveSyncDnskeysAction,
	PostCondition: LeaveSyncDnskeysVerify,
}

// LeaveSyncDnskeysPreCondition calculates a waiting period for NS propagation and then waits.
func LeaveSyncDnskeysPreCondition(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveSyncDnskeysPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	if until, ok := zoneWaitNs[z.Name]; ok {
		if time.Now().Before(until) {
			// XXX: Here we need z.SetDelayReason(reason, duration)
			z.SetStopReason(fmt.Sprintf("%s: Waiting until %s (%s)", z.Name, until.String(), time.Until(until).String()))
			log.Printf("%s: Waiting until %s (%s)", z.Name, until.String(), time.Until(until).String())
			return false
		}
		log.Printf("%s: Waited enough for NS, critera fullfilled", z.Name)
		delete(zoneWaitNs, z.Name)
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

	var ttl uint32

	log.Printf("%s: Fetching NSes to calculate NS wait until", z.Name)

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeNS)
		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":"+s.Port)
		if err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to fetch NSes from %s: %s", s.Name, err))
			return false
		}

		for _, a := range r.Answer {
			ns, ok := a.(*dns.NS)
			if !ok {
				continue
			}

			if ns.Header().Ttl > ttl {
				ttl = ns.Header().Ttl
			}
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

	for _, a := range r.Answer {
		ns, ok := a.(*dns.NS)
		if !ok {
			continue
		}

		if ns.Header().Ttl > ttl {
			ttl = ns.Header().Ttl
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

		if ns.Header().Ttl > ttl {
			ttl = ns.Header().Ttl
		}
	}

	// until := time.Now().Add((time.Duration(ttl*2) * time.Second))
	// TODO: static wait time to enable faster testing
	until := time.Now().Add((time.Duration(5) * time.Second))

	log.Printf("%s: Largest TTL found was %d, waiting until %s (%s)", z.Name, ttl, until.String(), time.Until(until).String())

	// XXX: Here we need the z.SetDelayReason()
	zoneWaitNs[z.Name] = until
	z.SetStopReason(fmt.Sprintf("%s: Waiting until %s (%s)", z.Name, until.String(), time.Until(until).String()))
	return false
}

// LeaveSyncDnskeysAction synchronizes all DNSKEY RRs between the remaining signers in the signergroup.
func LeaveSyncDnskeysAction(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveSyncDnskeysAction: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	sg := z.SignerGroup()
	if sg == nil {
		log.Fatalf("Zone %s in process %s not attached to any signer group.", z.Name, z.FSM)
	}

	leavingSignerName := z.FSMSigner // Issue #34: Static leaving signer until metadata is in place
	if leavingSignerName == "" {
		log.Fatalf("Leaving signer name in for zone %s unset.", z.Name)
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
	log.Printf("leave_sync_dnskeys: %s SignerMap: %v\n", z.Name, z.SGroup.SignerMap)
	log.Printf("remove %v from SignerMap %v: for %v", leavingSignerName, sg.SignerMap, sg.Name)
	delete(z.SGroup.SignerMap, leavingSignerName)
	if _, member := z.SGroup.SignerMap[leavingSignerName]; member {
		log.Fatalf("Signer %s is still a member of group %s", leavingSignerName, z.SGroup.SignerMap)
	}

	log.Printf("%s: Removing DNSKEYs originating from leaving signer %s", z.Name, leavingSigner.Name)

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

		rem := []dns.RR{}

		for _, a := range r.Answer {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if _, ok := dnskeys[fmt.Sprintf("%d-%d-%s", dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey)]; ok {
				rem = append(rem, dnskey)
			}
		}

		if len(rem) > 0 {
			updater := music.GetUpdater(s.Method)
			if err := updater.Update(s, z.Name, z.Name, nil, &[][]dns.RR{rem}); err != nil {
				z.SetStopReason(fmt.Sprintf("Unable to remove DNSKEYs from %s: %s",
					s.Name, err))
				return false
			}
			log.Printf("%s: Removed DNSKEYs from %s successfully", z.Name, s.Name)
		}
	}

	return true
}

// LeaveSyncDnskeysVerify confirms that all the DNSKEY RR's are synced across all signers in the signergroup.
func LeaveSyncDnskeysVerify(zone *music.Zone) bool {
	if zone.ZoneType == "debug" {
		log.Printf("LeaveSyncDnskeysPostCondition: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}

	if music.SignerRRsetEqual(zone, dns.TypeDNSKEY) {
		log.Printf("[LeaveSyncDnskeysPostCondition] DNSKEYS synced")
		return true
	} else {
		log.Printf("[LeaveSyncDnskeysPostCondition] DNSKEYS not synced")
		return false
	}
}
