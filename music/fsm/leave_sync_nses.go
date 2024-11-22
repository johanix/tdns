package fsm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

var FsmLeaveSyncNses = music.FSMTransition{
	Description: "First step when leaving, this transistion has no critera and will remove NSes that originated from the leaving signer (Action)",

	MermaidPreCondDesc:  "None",
	MermaidActionDesc:   "Remove NS records that only belong to the leaving signer",
	MermaidPostCondDesc: "Verify that NS records have been removed from zone",

	PreCondition:  LeaveSyncNsesPreCondition,
	Action:        LeaveSyncNsesAction,
	PostCondition: LeaveSyncNsesPostCondition,
}

// LeaveSyncNsesPreCondition is an automatic true. XXX TODO: Should we have a control function before we start the removal
// process? /rog
func LeaveSyncNsesPreCondition(z *music.Zone) bool {
	return true
}

// LeaveSyncNsesAction calculates which NS RRs should be removed from the signergroup NS RRs and removes them.
func LeaveSyncNsesAction(zone *music.Zone) bool {
	log.Printf("Removing leaving signer: %s NSes", zone.FSMSigner)
	leavingSignerName := zone.FSMSigner // TODO: Discuss with Johan naming of FSMSigner
	if zone.SGroup == nil {
		log.Fatalf("Zone %s in process %s not attached to any signer group.", zone.Name, zone.FSM)
	}
	rogDebug := false
	if rogDebug { // TODO: Remove Debug code once ready for merge and I know how this works.
		leavingSignerName := zone.FSMSigner
		if leavingSignerName == "" {
			log.Fatalf("Leaving signer name for zone %s unset.", zone.Name)
		}
		leavingSigner, err := zone.MusicDB.GetSignerByName(nil, leavingSignerName, false) // not apisafe
		if err != nil {
			zone.SetStopReason(fmt.Sprintf("Unable to get leaving signer %s: %s", leavingSigner.Name, err))
			return false
		}
		// Testing difference between signergroup.signermap and zone.signergroup.signermap
		signerGroup := zone.SignerGroup()
		var testsg *music.SignerGroup
		if testsg, err = zone.MusicDB.GetSignerGroup(nil, signerGroup.Name, false); err != nil { // not apisafe
			return false
		}

		log.Printf("leaving signer: %v", &leavingSigner)
		log.Printf("leaving signername: %s", leavingSignerName)
		log.Printf("signergroup signermap: %v", testsg.SignerMap)
		log.Printf("zone signergroup signermap: %v", zone.SGroup.SignerMap)
	}

	const sqlq = "SELECT ns FROM zone_nses WHERE zone = ? AND signer = ?"
	rows, err := zone.MusicDB.Query(sqlq, zone.Name, leavingSignerName)
	if err != nil {
		log.Printf("%s: mdb.Query(%s) failed: %s", zone.Name, sqlq, err)
		return false
	}
	var nsToRemove []dns.RR
	var ns string
	for rows.Next() {
		if err = rows.Scan(&ns); err != nil {
			log.Printf("%s: Rows.Scan() failed: %s", zone.Name, err)
			return false
		}

		rr := new(dns.NS)
		rr.Hdr = dns.RR_Header{Name: zone.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 0}
		rr.Ns = ns
		nsToRemove = append(nsToRemove, rr)
	}
	log.Printf("NSes to remove: %v", nsToRemove)

	for _, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.Update(signer, zone.Name, zone.Name, nil, &[][]dns.RR{nsToRemove}); err != nil {
			zone.SetStopReason(fmt.Sprintf("Unable to remove NSes from %s: %s", signer.Name, err))
			return false
		}
		log.Printf("%s: Removed NSes from %s successfully", zone.Name, signer.Name)
	}

	return true
}

// LeaveSyncNsesPostCondition checks that the NS RRs on the signers in the signergroup are in sync.
func LeaveSyncNsesPostCondition(zone *music.Zone) bool {
	log.Printf("Verify NSes verify that NSes are in sync")
	if zone.ZoneType == "debug" {
		log.Printf("LeaveSyncNsesPostCondition: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}
	return music.SignerRRsetEqual(zone, dns.TypeNS)
}
