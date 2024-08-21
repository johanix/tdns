/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"sync"

	//	"github.com/gookit/goutil/dump"
	"github.com/miekg/dns"
)

type UpdateRequest struct {
	Cmd       string
	ZoneName  string
	Adds      []dns.RR
	Removes   []dns.RR
	Actions   []dns.RR // The Update section from the dns.Msg
	Validated bool     // Signature over update msg is validated
	Trusted   bool     // Content of update is trusted (via validation or policy)
	Status    *UpdateStatus
}

func SprintUpdates(actions []dns.RR) string {
	var buf string
	for _, rr := range actions {
		switch rr.Header().Class {
		case dns.ClassNONE:
			buf += fmt.Sprintf("DELETE:       %s\n", rr.String())
		case dns.ClassANY:
			buf += fmt.Sprintf("DELETE RRset: %s\n", rr.String())
		case dns.ClassINET:
			buf += fmt.Sprintf("ADD:   %s\n", rr.String())
		default:
			buf += fmt.Sprintf("UNKNOWN CLASS %s\n", rr.String())
		}
	}
	return buf
}

func (kdb *KeyDB) UpdaterEngine(stopchan chan struct{}) error {
	updateq := kdb.UpdateQ
	var ur UpdateRequest

	log.Printf("Updater: starting")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			case ur = <-updateq:
				zd, ok := Zones.Get(ur.ZoneName)
				if !ok {
					log.Printf("Updater: Request for update is missing a zonename. Ignored.")
					continue
				}
				switch ur.Cmd {
				case "CHILD-UPDATE":
					// This is the case where a DNS UPDATE contains updates to child delegation information.
					// Either we are the primary (in which case we have the ability to directly modify the contents of the zone),
					// or we are a secondary (i.e. we are an agent) in which case we have the ability to record the changes in the DB).
					log.Printf("Updater: Request for update of child delegation data for zone %s (%d actions).", ur.ZoneName, len(ur.Actions))
					log.Printf("Updater: Actions:\n%s", SprintUpdates(ur.Actions))
					if zd.Options["allow-child-update"] {
						switch zd.ZoneType {
						case Primary:
							err := zd.ApplyChildUpdateToZoneData(ur)
							if err != nil {
								log.Printf("Error from ApplyUpdateToZoneData: %v", err)
							}
						case Secondary:
							err := kdb.ApplyChildUpdateToDB(ur)
							if err != nil {
								log.Printf("Error from ApplyChildUpdateToDB: %v", err)
							}
						}
					}

				case "ZONE-UPDATE":
					// This is the case where a DNS UPDATE contains updates to authoritative data in the zone
					// (i.e. not child delegation information).
					log.Printf("Updater: Request for update of authoritative data for zone %s (%d actions).", ur.ZoneName, len(ur.Actions))
					log.Printf("Updater: Actions:\n%s", SprintUpdates(ur.Actions))
					if zd.Options["allow-update"] {
						dss, err := zd.ZoneUpdateChangesDelegationData(ur)
						if err != nil {
							log.Printf("Error from ZoneUpdateChangesDelegationData: %v", err)
						}
						if zd.Options["delegation-sync-child"] && !dss.InSync {
							zd.DelegationSyncCh <- DelegationSyncRequest{
								Command:    "SYNC-DELEGATION",
								ZoneName:   zd.ZoneName,
								ZoneData:   zd,
								SyncStatus: dss,
								// XXX: *NOT* pupulating the Adds and Removes here, using the dss data
							}
						}

						switch zd.ZoneType {
						case Primary:
							_, err := zd.ApplyZoneUpdateToZoneData(ur)
							if err != nil {
								log.Printf("Error from ApplyUpdateToZoneData: %v", err)
							}

						case Secondary:
							err := kdb.ApplyZoneUpdateToDB(ur)
							if err != nil {
								log.Printf("Error from ApplyUpdateToDB: %v", err)
							}
						}
					}

				case "TRUSTSTORE-UPDATE":
					log.Printf("Updater: Request for update to SIG(0) TrustStore for zone %s (%d actions).", ur.ZoneName, len(ur.Actions))
					log.Printf("Updater: Actions:\n%s", SprintUpdates(ur.Actions))
					tx, err := kdb.Begin("UpdaterEngine")
					if err != nil {
						log.Printf("Error from kdb.Begin(): %v", err)
					}
					for _, rr := range ur.Actions {
						if keyrr, ok := rr.(*dns.KEY); ok {
							tppost := TruststorePost{
								SubCommand: "add",
								Src:        "child-update",
								Keyname:    keyrr.Header().Name,
								Keyid:      int(keyrr.KeyTag()),
								KeyRR:      rr.String(),
								Validated:  ur.Validated,
								Trusted:    ur.Trusted,
							}

							_, err := kdb.Sig0TrustMgmt(tx, tppost)
							if err != nil {
								log.Printf("Error from kdb.Sig0TrustMgmt(): %v", err)
							}
						} else {
							log.Printf("Updater: Error: TRUSTSTORE-UPDATE: not a KEY rr: %s", rr.String())
						}
					}
					err = tx.Commit()
					if err != nil {
						log.Printf("Error from tx.Commit(): %v", err)
					}
				default:
					log.Printf("Unknown command: '%s'. Ignoring.", ur.Cmd)
				}
			}
		}
	}()
	wg.Wait()

	log.Println("Updater: terminating")
	return nil
}

// 1. Sort actions so that all removes come first.
// 2. To delete an RRset, only owner + rrtype is needed
// 3. To delete an exact RR we need owner, rrtype and the rr.String(). Problem is if
//    the TTL is not correct. Therefore we should always store RRs with TTL=0

func (kdb *KeyDB) ApplyChildUpdateToDB(ur UpdateRequest) error {
	const (
		addkeysql = `
INSERT OR REPLACE INTO ChildSig0Keys (owner, keyid, validated, trusted, keyrr) VALUES (?, ?, ?, ?)`
		adddelsql = `
INSERT OR REPLACE INTO ChildDelegationData (owner, rrtype, rr) VALUES (?, ?, ?)`
		// delkeyrrsql    = `DELETE FROM ChildSig0Keys WHERE owner=? AND keyid=? AND rr=?`
		deldelrrsql = `DELETE FROM ChildDelegationData WHERE owner=? AND rrtype=? AND rr=?`
		// delkeyrrsetsql = `DELETE FROM ChildSig0Keys WHERE owner=? AND rrtype=?`
		deldelrrsetsql = `DELETE FROM ChildDelegationData WHERE owner=? AND rrtype=?`
	)

	tx, err := kdb.Begin("ApplyChildUpdateToDB")
	if err != nil {
		return err
	}

	defer func() {
		if err == nil {
			err1 := tx.Commit()
			if err1 != nil {
				log.Printf("ApplyChildUpdateToDB: tx.Commit() error=%v", err1)
			}
		} else {
			log.Printf("ApplyChildUpdateToDB: Error: %v. Rollback.", err)
			err1 := tx.Rollback()
			if err1 != nil {
				log.Printf("ApplyChildUpdateToDB: tx.Rollback() error=%v", err1)
			}
		}
	}()

	for _, rr := range ur.Actions {
		class := rr.Header().Class
		owner := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 0
		rrcopy.Header().Class = dns.ClassINET

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			log.Printf("ApplyChildUpdateToDB: Remove RR: %s %s %s", owner, rrtypestr, rrcopy.String())
			_, err := tx.Exec(deldelrrsql, owner, rrtypestr, rrcopy.String())
			if err != nil {
				log.Printf("Error from tx.Exec(%s, %s, %s): %v", deldelrrsql, owner, rrcopy.String(), err)
				return err
			}
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			log.Printf("ApplyChildUpdateToDB: Remove RRset: %s", rr.String())
			_, err := tx.Exec(deldelrrsetsql, owner, rrtypestr)
			if err != nil {
				log.Printf("Error from tx.Exec(%s, %s, %s): %v", deldelrrsetsql, owner, rrtypestr, err)
				return err
			}
			continue

		case dns.ClassINET:
			// Do nothing here, all adds are handled in the next section.

		default:
			log.Printf("ApplyChildUpdateToDB: Error: unknown class: %s", rr.String())
			continue
		}

		sqlcmd := adddelsql
		if rrtype == dns.TypeKEY {
			sqlcmd = addkeysql
		}

		switch rrtype {
		case dns.TypeKEY:
			key := rr.(*dns.KEY)
			keyid := key.KeyTag()
			log.Printf("ApplyChildUpdateToDB: Add KEY with keyid=%d", keyid)
			_, err := tx.Exec(sqlcmd, owner, keyid, ur.Validated, ur.Trusted, rrcopy.String())
			if err != nil {
				log.Printf("Error from kdb.Exec(%s): %v", sqlcmd, err)
				return err
			}
		case dns.TypeNS, dns.TypeA, dns.TypeAAAA:
			log.Printf("ApplyChildUpdateToDB: Add %s with RR=%s", rrtypestr, rrcopy.String())
			_, err := tx.Exec(sqlcmd, owner, rrtype, rrcopy.String())
			if err != nil {
				log.Printf("Error from kdb.Exec(%s): %v", sqlcmd, err)
				return err
			}
		default:
			log.Printf("ApplyChildUpdateToDB: Error: request to add %s RR", rrtypestr)
		}
	}

	return nil
}

func (zd *ZoneData) ApplyChildUpdateToZoneData(ur UpdateRequest) error {

	zd.mu.Lock()
	defer func() {
		zd.mu.Unlock()
		zd.BumpSerial()
	}()

	for _, rr := range ur.Actions {
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 3600
		rrcopy.Header().Class = dns.ClassINET

		// XXX: The logic here is a bit involved. If this is a delete then it is ~ok that the owner doesn't exist.
		// If it is an add then it is not ok, and then the owner must be created.

		owner, err := zd.GetOwner(ownerName)
		if err != nil {
			log.Printf("Warning: ApplyChildUpdateToZoneData: owner name %s is unknown", ownerName)
			if class == dns.ClassNONE || class == dns.ClassANY {
				// If this is a delete then it is ok that the owner doesn't exist.
				continue
			}
		}
		if owner == nil {
			owner = &OwnerData{
				Name:    ownerName,
				RRtypes: make(map[uint16]RRset),
			}
			zd.AddOwner(owner)
			zd.Options["dirty"] = true
		}

		rrset, exists := owner.RRtypes[rrtype]
		if !exists {
			log.Printf("Warning: ApplyUpdateToZoneData: owner name %s has no RRset of type %s", ownerName, rrtypestr)
			if class == dns.ClassNONE || class == dns.ClassANY {
				// If this is a delete then it is ok that the RRset doesn't exist.
				continue
			}
			rrset = RRset{
				RRs:    []dns.RR{},
				RRSIGs: []dns.RR{},
			}
		}

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			log.Printf("ApplyUpdateToZoneData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			rrset.RemoveRR(rrcopy) // Cannot remove rr, because it is in the wrong class.
			if len(rrset.RRs) == 0 {
				delete(owner.RRtypes, rrtype)
			} else {
				owner.RRtypes[rrtype] = rrset
			}
			zd.Options["dirty"] = true
			log.Printf("ApplyUpdateToZoneData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			log.Printf("ApplyUpdateToZoneData: Remove RRset: %s", rr.String())
			delete(owner.RRtypes, rrtype)
			zd.Options["dirty"] = true
			continue

		case dns.ClassINET:
			// Do nothing here, all adds are handled in the next section.
		default:
			log.Printf("ApplyUpdate: Error: unknown class: %s", rr.String())
			continue
		}

		if _, ok := zd.UpdatePolicy.Child.RRtypes[rrtype]; !ok {
			log.Printf("ApplyChildUpdateToZoneData: Error: request to add %s RR, which is denied in policy", rrtypestr)
			continue
		}

		dup := false
		for _, oldrr := range rrset.RRs {
			if dns.IsDuplicate(oldrr, rrcopy) {
				log.Printf("ApplyUpdateToZoneData: NOT adding duplicate %s record with RR=%s", rrtypestr, rrcopy.String())
				dup = true
				break
			}
		}
		if !dup {
			log.Printf("ApplyChildUpdateToZoneData: Adding %s record with RR=%s", rrtypestr, rrcopy.String())
			rrset.RRs = append(rrset.RRs, rrcopy)
			rrset.RRSIGs = []dns.RR{}
			zd.Options["dirty"] = true
		}
		owner.RRtypes[rrtype] = rrset
		// log.Printf("ApplyUpdateToZoneData: Add %s with RR=%s", rrtypestr, rrcopy.String())
		// log.Printf("ApplyUpdateToZoneData: %s[%s]=%v", owner.Name, rrtypestr, owner.RRtypes[rrtype])
		// dump.P(owner.RRtypes[rrtype])
		zd.Options["dirty"] = true
		continue
	}

	return nil
}

func (zd *ZoneData) ApplyZoneUpdateToZoneData(ur UpdateRequest) (bool, error) {

	zd.mu.Lock()
	defer func() {
		zd.mu.Unlock()
		zd.BumpSerial()
	}()

	for _, rr := range ur.Actions {
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 3600
		rrcopy.Header().Class = dns.ClassINET

		// XXX: The logic here is a bit involved. If this is a delete then it is ~ok that the owner doesn't exist.
		// If it is an add then it is not ok, and then the owner must be created.

		owner, err := zd.GetOwner(ownerName)
		if err != nil {
			log.Printf("Warning: ApplyZoneUpdateToZoneData: owner name %s is unknown", ownerName)
			if class == dns.ClassNONE || class == dns.ClassANY {
				continue
			}
		}
		if owner == nil {
			owner = &OwnerData{
				Name:    ownerName,
				RRtypes: make(map[uint16]RRset),
			}
			zd.AddOwner(owner)
			zd.Options["dirty"] = true
		}

		rrset, exists := owner.RRtypes[rrtype]
		if !exists {
			log.Printf("Warning: ApplyUpdateToZoneData: owner name %s has no RRset of type %s", ownerName, rrtypestr)
			if class == dns.ClassNONE || class == dns.ClassANY {
				continue
			}
			rrset = RRset{
				RRs:    []dns.RR{},
				RRSIGs: []dns.RR{},
			}
		}

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			rrset.RemoveRR(rrcopy) // Cannot remove rr, because it is in the wrong class.
			if len(rrset.RRs) == 0 {
				delete(owner.RRtypes, rrtype)
			} else {
				owner.RRtypes[rrtype] = rrset
			}
			zd.Options["dirty"] = true
			log.Printf("ApplyUpdateToZoneData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			delete(owner.RRtypes, rrtype)
			zd.Options["dirty"] = true
			log.Printf("ApplyUpdateToZoneData: Remove RRset: %s", rr.String())
			continue

		case dns.ClassINET:
		default:
			log.Printf("ApplyUpdate: Error: unknown class: %s", rr.String())
		}

		if _, ok := zd.UpdatePolicy.Zone.RRtypes[rrtype]; !ok {
			log.Printf("ApplyUpdateToZoneData: Error: request to add %s RR, which is denied by policy", rrtypestr)
			continue
		}

		dup := false
		for _, oldrr := range rrset.RRs {
			if dns.IsDuplicate(oldrr, rrcopy) {
				log.Printf("ApplyUpdateToZoneData: NOT adding duplicate %s record with RR=%s", rrtypestr, rrcopy.String())
				dup = true
				break
			}
		}
		if !dup {
			log.Printf("ApplyUpdateToZoneData: Adding %s record with RR=%s", rrtypestr, rrcopy.String())
			rrset.RRs = append(rrset.RRs, rrcopy)
			rrset.RRSIGs = []dns.RR{} // XXX: The RRset changed, so any old RRSIGs are now invalid.
		}
		owner.RRtypes[rrtype] = rrset
		zd.Options["dirty"] = true
		continue
	}

	return zd.Options["dirty"], nil
}

func (kdb *KeyDB) ApplyZoneUpdateToDB(ur UpdateRequest) error {
	return nil // placeholder
}

// ZoneUpdateChangesDelegationData returns a DelegationSyncStatus that describes the changes to the delegation data
// for the zone (if any). It does not update the zone data.

// XXX: The data in dss is not quite complete. We catch changes to the NS RRset, and changes to glue
// for the in-bailiwick nameservers. But we don't catch that we should remove glue for a nameserver that is
// no longer in the NS RRset, nor that we should add glue for a nameserver that is newly in the NS RRset.
// But it's a start.

func (zd *ZoneData) ZoneUpdateChangesDelegationData(ur UpdateRequest) (DelegationSyncStatus, error) {
	var dss = DelegationSyncStatus{
		ZoneName: zd.ZoneName,
		InSync:   true,
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return dss, err
	}
	bns, err := BailiwickNS(zd.ZoneName, apex.RRtypes[dns.TypeNS].RRs)
	if err != nil {
		return dss, err
	}

	for _, rr := range ur.Actions {
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 3600
		rrcopy.Header().Class = dns.ClassINET

		// XXX: The logic here is a bit involved. If this is a delete then it is ~ok that the owner doesn't exist.
		// If it is an add then it is not ok, and then the owner must be created.

		owner, err := zd.GetOwner(ownerName)
		if err != nil {
			log.Printf("Warning: ApplyZoneUpdateToZoneData: owner name %s is unknown", ownerName)
			if class == dns.ClassNONE || class == dns.ClassANY {
				continue
			}
		}
		if owner == nil {
			owner = &OwnerData{
				Name:    ownerName,
				RRtypes: make(map[uint16]RRset),
			}
			zd.AddOwner(owner)
		}

		if ownerName == zd.ZoneName && rrtype == dns.TypeNS {
			dss.InSync = false
			return dss, nil
		}

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			log.Printf("UpdateChangesDelegationData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())

			// Is this a change to the NS RRset?
			if ownerName == zd.ZoneName && rrtype == dns.TypeNS {
				dss.InSync = false
				dss.NsRemoves = append(dss.NsRemoves, rrcopy)
			}
			// Is this a change to glue for a nameserver?
			for _, nsname := range bns {
				if nsname == ownerName {
					if rrtype == dns.TypeA {
						dss.InSync = false
						dss.ARemoves = append(dss.ARemoves, rrcopy)
					} else if rrtype == dns.TypeAAAA {
						dss.InSync = false
						dss.AAAARemoves = append(dss.AAAARemoves, rrcopy)
					}
				}
			}
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			log.Printf("UpdateChangesDelegationData: Remove RRset: %s", rr.String())
			if ownerName == zd.ZoneName && rrtype == dns.TypeNS {
				dss.InSync = false
				dss.NsRemoves = append(dss.NsRemoves, rrcopy)
			}
			for _, nsname := range bns {
				if nsname == ownerName {
					if rrtype == dns.TypeA {
						dss.InSync = false
						dss.ARemoves = append(dss.ARemoves, rrcopy)
					} else if rrtype == dns.TypeAAAA {
						dss.InSync = false
						dss.AAAARemoves = append(dss.AAAARemoves, rrcopy)
					}
				}
			}
			continue

		case dns.ClassINET:
		default:
			log.Printf("UpdateChangesDelegationData: Error: unknown class: %s", rr.String())
		}

		if _, ok := zd.UpdatePolicy.Zone.RRtypes[rrtype]; !ok {
			log.Printf("UpdateChangesDelegationData: Error: request to add %s RR, which is denied by policy", rrtypestr)
			continue
		}

		dup := false
		if rrset, exists := owner.RRtypes[rrtype]; exists {
			for _, oldrr := range rrset.RRs {
				if dns.IsDuplicate(oldrr, rrcopy) {
					log.Printf("UpdateChangesDelegationData: NOT adding duplicate %s record with RR=%s", rrtypestr, rrcopy.String())
					dup = true
					break
				}
			}
		}

		if !dup {
			log.Printf("UpdateChangesDelegationData: Adding %s record with RR=%s", rrtypestr, rrcopy.String())
			// Is this a change to the NS RRset?
			if ownerName == zd.ZoneName && rrtype == dns.TypeNS {
				dss.InSync = false
				dss.NsAdds = append(dss.NsAdds, rrcopy)
			}
			// Iterate over all in-bailiwick nameservers to see if this is an add to the glue for a nameserver.
			for _, nsname := range bns {
				if nsname == ownerName {
					if rrtype == dns.TypeA {
						dss.InSync = false
						dss.AAdds = append(dss.AAdds, rrcopy)
					} else if rrtype == dns.TypeAAAA {
						dss.InSync = false
						dss.AAAAAdds = append(dss.AAAAAdds, rrcopy)
					}
				}
			}
		}
	}

	return dss, nil
}
