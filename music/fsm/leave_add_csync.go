package fsm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
)

var FsmLeaveAddCsync = music.FSMTransition{
	Description: "Once all NS are correct in all signers (criteria), build CSYNC record and push to all signers (action)",

	MermaidPreCondDesc:  "Wait for all NS RRsets to be in sync in all signers",
	MermaidActionDesc:   "Create and publish CSYNC record in all signers",
	MermaidPostCondDesc: "Verify that the CSYNC record has been removed everywhere",

	PreCondition:  LeaveAddCsyncPreCondition,
	Action:        LeaveAddCsyncAction,
	PostCondition: LeaveVerifyCsyncPublished,
}

// LeaveAddCsyncPreCondition confirms that the leaving signer NS RRs is not configured on the remaining signers in the signergroup.
func LeaveAddCsyncPreCondition(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveAddCsyncPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	sg := z.SignerGroup()
	if sg == nil {
		log.Fatalf("Zone %s in process %s not attached to any signer group.", z.Name, z.FSM)
	}

	log.Printf("LeaveAddCsyncPreCondition: z: %v", z)

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
	log.Printf("leave_add_csync: %s SignerMap: %v\n", z.Name, z.SGroup.SignerMap)
	log.Printf("remove %v from SignerMap %v: for %v", leavingSignerName, sg.SignerMap, sg.Name)
	delete(z.SGroup.SignerMap, leavingSignerName)
	if _, member := z.SGroup.SignerMap[leavingSignerName]; member {
		log.Fatalf("Signer %s is still a member of group %s", leavingSignerName, z.SGroup.SignerMap)
	}

	nses := make(map[string]bool)

	const sqlq = "SELECT ns FROM zone_nses WHERE zone = ? AND signer = ?"

	// XXX: Should wrap this in a transaction
	rows, err := z.MusicDB.Query(sqlq, z.Name, leavingSigner.Name)
	if err != nil {
		log.Printf("%s: mdb.Query(%s) failed: %s", z.Name, sqlq, err)
		return false
	}

	var ns string
	for rows.Next() {
		if err = rows.Scan(&ns); err != nil {
			log.Printf("%s: Rows.Scan() failed: %s", z.Name, err)
			return false
		}

		nses[ns] = true
	}

	log.Printf("%s: Verifying that leaving signer %s NSes has been removed from all signers", z.Name, leavingSigner.Name)

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

			if _, ok := nses[ns.Ns]; ok {
				z.SetStopReason(fmt.Sprintf("NS %s still exists in signer %s", ns.Ns, s.Name))
				return false
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

		if _, ok := nses[ns.Ns]; ok {
			z.SetStopReason(fmt.Sprintf("NS %s still exists in signer %s",
				ns.Ns, leavingSigner.Name))
			return false
		}
	}

	log.Printf("%s: All NSes of leaving signer has been removed", z.Name)
	return true
}

// LeaveAddCsyncAction creates and adds the CSYNC record to the remaining signers in the signergroup.
func LeaveAddCsyncAction(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveAddCsyncAction: zone %s (DEBUG) is automatically ok", z.Name)
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
	log.Printf("leave_add_csync: %s SignerMap: %v\n", z.Name, z.SGroup.SignerMap)
	log.Printf("remove %v from SignerMap %v: for %v", leavingSignerName, sg.SignerMap, sg.Name)
	delete(z.SGroup.SignerMap, leavingSignerName)
	if _, member := z.SGroup.SignerMap[leavingSignerName]; member {
		log.Fatalf("Signer %s is still a member of group %s", leavingSignerName, z.SGroup.SignerMap)
	}

	ttl := 300
	z.CSYNC = new(dns.CSYNC)
	z.CSYNC.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: uint32(ttl), Rdlength: uint16(12)}
	z.CSYNC.Serial = 1
	z.CSYNC.Flags = 1
	z.CSYNC.TypeBitMap = []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA}

	for _, signer := range z.SGroup.SignerMap {
		// check if there is any CSYNC records if there are remove them before adding a csync record
		updater := music.GetUpdater(signer.Method)
		err, csyncrrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeCSYNC)
		if err != nil {
			err, _ = z.SetStopReason(fmt.Sprintf("Unable to fetch CSYNC RRset from %s: %v", signer.Name, err))
			return false
		}
		if len(csyncrrs) != 0 {
			if err := updater.RemoveRRset(signer, z.Name, z.Name,
				[][]dns.RR{[]dns.RR{z.CSYNC}}); err != nil {
				z.SetStopReason(fmt.Sprintf("Unable to remove CSYNC record sets from %s: %s",
					signer.Name, err))
				return false
			}
			log.Printf("%s: Removed CSYNC record sets from %s successfully", z.Name, signer.Name)
		}

		log.Printf("%s: Creating CSYNC record sets", z.Name)

		if err := updater.Update(signer, z.Name, z.Name,
			&[][]dns.RR{[]dns.RR{z.CSYNC}}, nil); err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to update %s with CSYNC record sets: %s",
				signer.Name, err))
			return false
		}
		log.Printf("%s: Update %s successfully with CSYNC record sets", z.Name, signer.Name)
	}

	updater := music.GetUpdater(leavingSigner.Method)
	err, csyncrrs := updater.FetchRRset(leavingSigner, z.Name, z.Name, dns.TypeCSYNC)
	if err != nil {
		err, _ = z.SetStopReason(fmt.Sprintf("Unable to fetch CSYNC RRset from %s: %v", leavingSigner.Name, err))
		return false
	}
	if len(csyncrrs) != 0 {
		if err := updater.RemoveRRset(leavingSigner, z.Name, z.Name,
			[][]dns.RR{[]dns.RR{z.CSYNC}}); err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to remove CSYNC record sets from %s: %s",
				leavingSigner.Name, err))
			return false
		}
		log.Printf("%s: Removed CSYNC record sets from %s successfully", z.Name, leavingSigner.Name)
	}

	if err := updater.Update(leavingSigner, z.Name, z.Name,
		&[][]dns.RR{[]dns.RR{z.CSYNC}}, nil); err != nil {
		z.SetStopReason(fmt.Sprintf("Unable to update %s with CSYNC record sets: %s",
			leavingSigner.Name, err))
		return false
	}
	log.Printf("%s: Update %s successfully with CSYNC record sets", z.Name, leavingSigner.Name)

	return true
}

// LeaveVerifyCsyncPublished confirms that the CSYNC records are published on the remaining signers in the singergroup.
func LeaveVerifyCsyncPublished(z *music.Zone) bool {
	log.Printf("Verifying Publication of CSYNC record sets for %s", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("LeaveVerifyCsyncPublished: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	csynclist := []*dns.CSYNC{}

	// get all csync records from all the remaining signers in the SignerGroup
	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		err, csyncrrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeCSYNC)
		if err != nil {
			err, _ = z.SetStopReason(fmt.Sprintf("Unable to fetch CSYNC RRset from %s: %v", signer.Name, err))
			return false
		}
		switch len(csyncrrs) {
		case 0:
			log.Printf("csyncrrs is %d long", len(csyncrrs))
			z.SetStopReason(fmt.Sprintf("No CSYNC RRset returned from %s", signer.Name))
			return false
		case 1:
			log.Printf("csyncrrs is %d long", len(csyncrrs))
			csynclist = append(csynclist, csyncrrs[0].(*dns.CSYNC))
		default:
			log.Printf("csyncrrs is %d long", len(csyncrrs))
			z.SetStopReason(fmt.Sprintf("Multiple CSYNC RRset returned from %s", signer.Name))
			return false
		}
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

	updater := music.GetUpdater(leavingSigner.Method)
	err, csyncrrs := updater.FetchRRset(leavingSigner, z.Name, z.Name, dns.TypeCSYNC)
	if err != nil {
		err, _ = z.SetStopReason(fmt.Sprintf("Unable to fetch CSYNC RRset from %s: %v", leavingSigner.Name, err))
		return false
	}
	switch len(csyncrrs) {
	case 0:
		log.Printf("csyncrrs is %d long", len(csyncrrs))
		z.SetStopReason(fmt.Sprintf("No CSYNC RRset returned from %s", leavingSigner.Name))
		return false
	case 1:
		log.Printf("csyncrrs is %d long", len(csyncrrs))
		csynclist = append(csynclist, csyncrrs[0].(*dns.CSYNC))
	default:
		log.Printf("csyncrrs is %d long", len(csyncrrs))
		z.SetStopReason(fmt.Sprintf("Multiple CSYNC RRset returned from %s", leavingSigner.Name))
		return false
	}

	// compare that the CSYNC records are the same as the created CSYNC
	for _, csyncrr := range csynclist {
		if !dns.IsDuplicate(csyncrr, z.CSYNC) {
			z.SetStopReason(fmt.Sprintf("CSYNC records are not identical"))
			return false
		}
	}
	return true
}
