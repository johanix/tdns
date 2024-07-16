/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	//        "fmt"
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
					if ur.ZoneName == "" {
						log.Printf("Updater: Request for update is missing a zonename. Ignored.")
						continue
					} else {
						//	XXX: Here we do have the option of modifying the direct contents of the zone. Assuming the
						// zone is a primary zone, and has a policy that allows updates and we're able to write the
						// resulting updated zone back to disk...
						log.Printf("Updater: Request for update %d actions.", len(ur.Actions))
						err := kdb.ApplyChildUpdateToDB(ur)
						if err != nil {
							log.Printf("Error from ApplyChildUpdateToDB: %v", err)
						}
						err = zd.ApplyChildUpdateToZoneData(ur)
						if err != nil {
							log.Printf("Error from ApplyUpdateToZoneData: %v", err)
						}
					}
				case "ZONE-UPDATE":
					if ur.ZoneName == "" {
						log.Printf("Updater: Request for update is missing a zonename. Ignored.")
						continue
					} else {
						//	XXX: Here we do have the option of modifying the direct contents of the zone. Assuming the
						// zone is a primary zone, and has a policy that allows updates and we're able to write the
						// resulting updated zone back to disk...
						log.Printf("Updater: Request for update %d actions.", len(ur.Actions))
						// err := kdb.ApplyZoneUpdateToDB(ur)
						// if err != nil {
						// 	log.Printf("Error from ApplyChildUpdateToDB: %v", err)
						// }
						err := zd.ApplyZoneUpdateToZoneData(ur)
						if err != nil {
							log.Printf("Error from ApplyUpdateToZoneData: %v", err)
						}
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
		delkeyrrsql    = `DELETE FROM ChildSig0Keys WHERE owner=? AND keyid=? AND rr=?`
		deldelrrsql    = `DELETE FROM ChildDelegationData WHERE owner=? AND rrtype=? AND rr=?`
		delkeyrrsetsql = `DELETE FROM ChildSig0Keys WHERE owner=? AND rrtype=?`
		deldelrrsetsql = `DELETE FROM ChildDelegationData WHERE owner=? AND rrtype=?`
	)

	tx, err := kdb.Begin("ApplyUpdateToDB")
	if err != nil {
		return err
	}

	defer func() {
		if err == nil {
			err1 := tx.Commit()
			if err1 != nil {
				log.Printf("ApplyUpdateToDB: tx.Commit() error=%v", err1)
			}
		} else {
			log.Printf("ApplyUpdateToDB: Error: %v. Rollback.", err)
			err1 := tx.Rollback()
			if err1 != nil {
				log.Printf("ApplyUpdateToDB: tx.Rollback() error=%v", err1)
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
			sqlcmd := deldelrrsql
			if rrtype == dns.TypeKEY {
				sqlcmd = delkeyrrsql
			}
			log.Printf("ApplyUpdateToDB: Remove RR: %s %s %s",
				owner, rrtypestr, rrcopy.String())
			_, err := tx.Exec(sqlcmd, owner, rrtypestr, rrcopy.String())
			if err != nil {
				log.Printf("Error from tx.Exec(%s, %s, %s): %v",
					sqlcmd, owner, rrcopy.String(), err)
				return err
			}

		case dns.ClassANY:
			// ClassANY: Remove RRset
			log.Printf("ApplyUpdateToDB: Remove RRset: %s", rr.String())
			sqlcmd := deldelrrsetsql
			if rrtype == dns.TypeKEY {
				sqlcmd = delkeyrrsetsql
			}
			_, err := tx.Exec(sqlcmd, owner, rrtypestr)
			if err != nil {
				log.Printf("Error from tx.Exec(%s, %s, %s): %v", sqlcmd, owner, rrtypestr, err)
				return err
			}

		case dns.ClassINET:
			// log.Printf("ApplyUpdateToDB: Add RR: %s", req.String())
		default:
			log.Printf("ApplyUpdateToDB: Error: unknown class: %s", rr.String())
		}

		sqlcmd := adddelsql
		if rrtype == dns.TypeKEY {
			sqlcmd = addkeysql
		}

		switch rrtype {
		case dns.TypeKEY:
			key := rr.(*dns.KEY)
			keyid := key.KeyTag()
			log.Printf("ApplyUpdateToDB: Add KEY with keyid=%d", keyid)
			_, err := tx.Exec(sqlcmd, owner, keyid, ur.Validated, ur.Trusted, rrcopy.String())
			if err != nil {
				log.Printf("Error from kdb.Exec(%s): %v", sqlcmd, err)
				return err
			}
		case dns.TypeNS, dns.TypeA, dns.TypeAAAA:
			log.Printf("ApplyUpdateToDB: Add %s with RR=%s", rrtypestr, rrcopy.String())
			_, err := tx.Exec(sqlcmd, owner, rrtype, rrcopy.String())
			if err != nil {
				log.Printf("Error from kdb.Exec(%s): %v", sqlcmd, err)
				return err
			}
		default:
			log.Printf("ApplyUpdateToDB: Error: request to add %s RR", rrtypestr)
		}
	}

	return nil
}

func (zd *ZoneData) ApplyChildUpdateToZoneData(ur UpdateRequest) error {
	zd, ok := Zones.Get(ur.ZoneName)
	if !ok {
		return fmt.Errorf("ApplyChildUpdateToZoneData: zone %s is unknown", ur.ZoneName)
	}

	// dump.P(zd)
	// dump.P(ur.Actions)

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

		// dump.P(owner)

		//		if owner == nil {
		//			owner = &tdns.OwnerData{
		//				Name:    ownerName,
		//				RRtypes: make(map[uint16]RRset),
		//			}
		//		}

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

		// dump.P(owner.RRtypes)

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			log.Printf("ApplyUpdateToZoneData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			// dump.P(rrset)
			log.Printf("ApplyUpdateToZoneData: Removed RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			rrset.RemoveRR(rrcopy) // Cannot remove rr, because it is in the wrong class.
			// dump.P(rrset)
			if len(rrset.RRs) == 0 {
				delete(owner.RRtypes, rrtype)
			} else {
				owner.RRtypes[rrtype] = rrset
			}
			log.Printf("ApplyUpdateToZoneData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			log.Printf("ApplyUpdateToZoneData: Remove RRset: %s", rr.String())
			delete(owner.RRtypes, rrtype)
			continue

		case dns.ClassINET:
			// log.Printf("ApplyUpdate: Add RR: %s", req.String())
		default:
			log.Printf("ApplyUpdate: Error: unknown class: %s", rr.String())
		}

		if _, ok := zd.UpdatePolicy.Child.RRtypes[rrtype]; !ok {
			log.Printf("ApplyChildUpdateToZoneData: Error: request to add %s RR, which is denied in policy", rrtypestr)
			continue
		}

		//		switch rrtype {
		// case dns.TypeNS, dns.TypeA, dns.TypeAAAA:
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
		}
		owner.RRtypes[rrtype] = rrset
		// log.Printf("ApplyUpdateToZoneData: Add %s with RR=%s", rrtypestr, rrcopy.String())
		// log.Printf("ApplyUpdateToZoneData: %s[%s]=%v", owner.Name, rrtypestr, owner.RRtypes[rrtype])
		// dump.P(owner.RRtypes[rrtype])
		continue
		// default:
		// 	log.Printf("ApplyChildUpdateToZoneData: Error: request to add %s RR", rrtypestr)
		// }
	}

	return nil
}

func (zd *ZoneData) ApplyZoneUpdateToZoneData(ur UpdateRequest) error {
	zd, ok := Zones.Get(ur.ZoneName)
	if !ok {
		return fmt.Errorf("ApplyZoneUpdateToZoneData: zone %s is unknown", ur.ZoneName)
	}

	// dump.P(zd)
	// dump.P(ur.Actions)

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

		// dump.P(owner)

		//		if owner == nil {
		//			owner = &tdns.OwnerData{
		//				Name:    ownerName,
		//				RRtypes: make(map[uint16]RRset),
		//			}
		//		}

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

		// dump.P(owner.RRtypes)

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			log.Printf("ApplyUpdateToZoneData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			// dump.P(rrset)
			log.Printf("ApplyUpdateToZoneData: Removed RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			rrset.RemoveRR(rrcopy) // Cannot remove rr, because it is in the wrong class.
			// dump.P(rrset)
			if len(rrset.RRs) == 0 {
				delete(owner.RRtypes, rrtype)
			} else {
				owner.RRtypes[rrtype] = rrset
			}
			log.Printf("ApplyUpdateToZoneData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			log.Printf("ApplyUpdateToZoneData: Remove RRset: %s", rr.String())
			delete(owner.RRtypes, rrtype)
			continue

		case dns.ClassINET:
			// log.Printf("ApplyUpdate: Add RR: %s", req.String())
		default:
			log.Printf("ApplyUpdate: Error: unknown class: %s", rr.String())
		}

		if _, ok := zd.UpdatePolicy.Zone.RRtypes[rrtype]; !ok {
			log.Printf("ApplyUpdateToZoneData: Error: request to add %s RR, which is denied in policy", rrtypestr)
			continue
		}

		//switch rrtype {
		//case dns.TypeNS, dns.TypeA, dns.TypeAAAA:
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
			rrset.RRSIGs = []dns.RR{}
		}
		owner.RRtypes[rrtype] = rrset
		// log.Printf("ApplyUpdateToZoneData: Add %s with RR=%s", rrtypestr, rrcopy.String())
		// log.Printf("ApplyUpdateToZoneData: %s[%s]=%v", owner.Name, rrtypestr, owner.RRtypes[rrtype])
		// dump.P(owner.RRtypes[rrtype])
		continue
		// default:
		//			log.Printf("ApplyUpdateToZoneData: Error: request to add %s RR", rrtypestr)
		// }
	}

	return nil
}
