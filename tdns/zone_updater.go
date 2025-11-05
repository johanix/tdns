/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/gookit/goutil/dump"

	"github.com/miekg/dns"
)

type UpdateRequest struct {
	Cmd            string
	UpdateType     string // "DSYNC", "KEY", ...
	ZoneName       string
	Adds           []dns.RR
	Removes        []dns.RR
	Actions        []dns.RR // The Update section from the dns.Msg
	Validated      bool     // Signature over update msg is validated
	Trusted        bool     // Content of update is trusted (via validation or policy)
	InternalUpdate bool     // Internal update, not a DNS UPDATE from the outside
	Status         *UpdateStatus
	Description    string
	PreCondition   func() bool
	Action         func() error
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

type DeferredUpdate struct {
	Cmd          string
	ZoneName     string
	AddTime      time.Time
	Description  string
	PreCondition func() bool
	Action       func() error
}

func (kdb *KeyDB) ZoneUpdaterEngine(ctx context.Context, stopchan chan struct{}) error {
	updateq := kdb.UpdateQ

	var ur UpdateRequest

	log.Printf("ZoneUpdater: starting")
	var wg sync.WaitGroup
	wg.Add(1)
    go func() {
		for ur = range updateq {
			log.Printf("ZoneUpdater: Received update request on queue: %+v", updateq)
			if ur.Cmd == "PING" {
				log.Printf("ZoneUpdater: PING received. PONG!")
				continue
			}
			zd, ok := Zones.Get(ur.ZoneName)
			if !ok {
				log.Printf("ZoneUpdater: Cmd=%s: Zone name \"%s\" in request for update is unknown. Ignored update: %+v", ur.Cmd, ur.ZoneName, ur)
				log.Printf("ZoneUpdater: Current list of known zones: %v", Zones.Keys())
				continue
			}

			switch ur.Cmd {
			case "DEFERRED-UPDATE":
				log.Printf("ZoneUpdater: Error: Received deferred update \"%s\" (should be sent to DeferredUpdaterEngine)", ur.Description)
				continue

			case "CHILD-UPDATE":
				// This is the case where a DNS UPDATE contains updates to child delegation information.
				// Either we are the primary (in which case we have the ability to directly modify the contents of the zone),
				// or we are a secondary (i.e. we are an agent) in which case we have the ability to record the changes in the DB).
				log.Printf("ZoneUpdater: Request for update of child delegation data for zone %s (%d actions).", ur.ZoneName, len(ur.Actions))
				log.Printf("ZoneUpdater: CHILD-UPDATE Actions:\n%s", SprintUpdates(ur.Actions))
				if zd.Options[OptAllowChildUpdates] {
					var updated bool
					var err error

					switch zd.ZoneType {
					case Primary:
						updated, err = zd.ApplyChildUpdateToZoneData(ur, kdb)
						if err != nil {
							log.Printf("ZoneUpdater: Error from ApplyUpdateToZoneData: %v", err)
						}
					case Secondary:
						err := kdb.ApplyChildUpdateToDB(ur)
						if err != nil {
							log.Printf("ZoneUpdater: Error from ApplyChildUpdateToDB: %v", err)
						}
					}
					if updated {
						zd.Options[OptDirty] = true
					}
				}

			case "ZONE-UPDATE":
				// This is the case where a DNS UPDATE contains updates to authoritative data in the zone
				// (i.e. not child delegation information).
				log.Printf("ZoneUpdater: Request for update of authoritative data for zone %s (%d actions).", ur.ZoneName, len(ur.Actions))
				log.Printf("ZoneUpdater: ZONE-UPDATE Actions:\n%s", SprintUpdates(ur.Actions))
				if zd.Options[OptAllowUpdates] {
					dss, err := zd.ZoneUpdateChangesDelegationDataNG(ur)
					if err != nil {
						log.Printf("Error from ZoneUpdateChangesDelegationData: %v", err)
					}
					log.Printf("ZoneUpdater: dss.InSync: %t", dss.InSync)

					if zd.Options[OptDelSyncChild] && !dss.InSync {
						log.Printf("ZoneUpdater: Zone %s has delegation sync enabled and is out of sync. Sending SYNC-DELEGATION request. len(zd.DelegationSyncQ): %d", zd.ZoneName, len(zd.DelegationSyncQ))
						zd.DelegationSyncQ <- DelegationSyncRequest{
							Command:    "SYNC-DELEGATION",
							ZoneName:   zd.ZoneName,
							ZoneData:   zd,
							SyncStatus: dss,
							// XXX: *NOT* populating the Adds and Removes here, using the dss data
						}
					}

					var updated bool

					switch zd.ZoneType {
					case Primary:
						updated, err = zd.ApplyZoneUpdateToZoneData(ur, kdb)
						if err != nil {
							log.Printf("ZoneUpdater: Error from ApplyUpdateToZoneData: %v", err)
						}

					case Secondary:
						err := kdb.ApplyZoneUpdateToDB(ur)
						if err != nil {
							log.Printf("ZoneUpdater: Error from ApplyUpdateToDB: %v", err)
						}
					}
					if updated && !ur.InternalUpdate {
						log.Printf("ZoneUpdater: Zone %s was updated. Setting dirty flag.", zd.ZoneName)
						zd.Options[OptDirty] = true
					}
				} else {
					log.Printf("ZoneUpdater: Zone %s has updates disallowed", zd.ZoneName)
				}
				log.Printf("ZoneUpdater: ZONE-UPDATE done")

			case "TRUSTSTORE-UPDATE":
				log.Printf("ZoneUpdater: Request for update to SIG(0) TrustStore for zone %s (%d actions).", ur.ZoneName, len(ur.Actions))
				log.Printf("ZoneUpdater: TRUSTSTORE-UPDATE Actions:\n%s", SprintUpdates(ur.Actions))
				tx, err := kdb.Begin("UpdaterEngine")
				if err != nil {
					log.Printf("Error from kdb.Begin(): %v", err)
				}
				for _, rr := range ur.Actions {
					var subcommand string
					switch rr.Header().Class {
					case dns.ClassINET:
						subcommand = "add"
					case dns.ClassNONE:
						subcommand = "delete"
					case dns.ClassANY:
						log.Printf("ZoneUpdater: Error: TRUSTSTORE-UPDATE: RR has class ANY. Delete RRset is not supported. Ignored.")
						continue
					default:
						log.Printf("ZoneUpdater: Error: TRUSTSTORE-UPDATE: RR has unknown class: %s. Ignored.", rr.String())
						continue
					}

					if keyrr, ok := rr.(*dns.KEY); ok {
						tppost := TruststorePost{
							SubCommand: subcommand,
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
						log.Printf("ZoneUpdater: Error: TRUSTSTORE-UPDATE: not a KEY rr: %s", rr.String())
					}
				}
				err = tx.Commit()
				if err != nil {
					log.Printf("Error from tx.Commit(): %v", err)
				}
			default:
				log.Printf("Unknown command: '%s'. Ignoring.", ur.Cmd)
			}
			log.Printf("ZoneUpdater: Request for update of type %s is completed.", ur.Cmd)
		}
	}()
	wg.Wait()

	log.Println("ZoneUpdater: terminating")
	return nil
}

func (kdb *KeyDB) DeferredUpdaterEngine(ctx context.Context, stopchan chan struct{}) error {
	deferredq := kdb.DeferredUpdateQ

	var deferredUpdates []DeferredUpdate

	var runQueueTicker = time.NewTicker(10 * time.Second)

	var du DeferredUpdate

	log.Printf("DeferredUpdater: starting")
	var wg sync.WaitGroup
	wg.Add(1)
    go func() {
		for {
			select {
            case <-ctx.Done():
                log.Printf("DeferredUpdater: context cancelled")
                return
			case du = <-deferredq:
				log.Printf("DeferredUpdater: Received update request on queue: %+v", deferredq)
				if du.Cmd == "PING" {
					log.Printf("DeferredUpdater: PING received. PONG!")
					continue
				}
				_, ok := Zones.Get(du.ZoneName)
				if !ok && du.Cmd != "DEFERRED-UPDATE" {
					log.Printf("DeferredUpdater: Cmd=%s: Zone name \"%s\" in request for update is unknown. Ignored update: %+v", du.Cmd, du.ZoneName, du)
					log.Printf("DeferredUpdater: Current list of known zones: %v", Zones.Keys())
					continue
				}

				switch du.Cmd {
				case "DEFERRED-UPDATE":
					// If the PreCondition is true, we execute the Action immediately, otherwise we defer execution an add it to the deferredUpdates queue.
					if du.PreCondition() {
						log.Printf("DeferredUpdater: PreCondition is true for deferred update \"%s\". Executing immediately.", du.Description)
						err := du.Action()
						if err != nil {
							log.Printf("DeferredUpdater: Error return from deferred update %q action: %v", du.Description, err)
						}
					} else {
						log.Printf("DeferredUpdater: PreCondition is false for deferred update \"%s\". Deferring execution.", du.Description)
						du := DeferredUpdate{
							Description:  du.Description,
							PreCondition: du.PreCondition,
							Action:       du.Action,
							AddTime:      time.Now(),
						}
						deferredUpdates = append(deferredUpdates, du)
					}
					continue

				default:
					log.Printf("Unknown command: '%s'. Ignoring.", du.Cmd)
				}
				log.Printf("DeferredUpdater: Request for update of type %s is completed.", du.Cmd)

			case <-runQueueTicker.C:
				if len(deferredUpdates) == 0 {
					continue
				}

				log.Printf("DeferredUpdater: running deferred updates queue (%d items).", len(deferredUpdates))
				for i := 0; i < len(deferredUpdates); {
					du := deferredUpdates[i]
					log.Printf("DeferredUpdater: running deferred update \"%s\"", du.Description)
					ok := du.PreCondition()
					if ok {
						log.Printf("DeferredUpdater: PreCondition is true. Executing deferred update \"%s\"", du.Description)
						err := du.Action()
						if err != nil {
							log.Printf("DeferredUpdater: Error from deferred update action: %v", err)
							i++
						} else {
							log.Printf("DeferredUpdater: Deferred update \"%s\" executed successfully.", du.Description)
							// Remove the item from deferredUpdates queue
							deferredUpdates = append(deferredUpdates[:i], deferredUpdates[i+1:]...)
						}
					} else {
						log.Printf("DeferredUpdater: Deferred update \"%s\" not executed because precondition failed.", du.Description)
						i++
					}
				}
			}
		}
	}()
	wg.Wait()

	log.Println("DeferredUpdater: terminating")
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

func (zd *ZoneData) ApplyChildUpdateToZoneData(ur UpdateRequest, kdb *KeyDB) (bool, error) {

	log.Printf("ApplyChildUpdateToZoneData: %v", ur)

	zd.mu.Lock()
	defer func() {
		zd.mu.Unlock()
		zd.BumpSerial()
	}()

	var updated bool

	for _, rr := range ur.Actions {
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 3600
		rrcopy.Header().Class = dns.ClassINET

		// First check whether this update is allowed by the update-policy.
		if _, ok := zd.UpdatePolicy.Child.RRtypes[rrtype]; !ok {
			log.Printf("ApplyChildUpdateToZoneData: Error: request to add %s RR, which is denied in policy", rrtypestr)
			continue
		}

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
				RRtypes: NewRRTypeStore(),
			}
			zd.AddOwner(owner)
			updated = true
			// zd.Options["dirty"] = true
		}

		rrset, exists := owner.RRtypes.Get(rrtype)
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
				owner.RRtypes.Delete(rrtype)
			} else {
				owner.RRtypes.Set(rrtype, rrset)
			}
			updated = true
			// zd.Options["dirty"] = true
			log.Printf("ApplyUpdateToZoneData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			log.Printf("ApplyUpdateToZoneData: Remove RRset: %s", rr.String())
			owner.RRtypes.Delete(rrtype)
			updated = true
			// zd.Options["dirty"] = true
			continue

		case dns.ClassINET:
			// Do nothing here, all adds are handled in the next section.
		default:
			log.Printf("ApplyUpdate: Error: unknown class: %s", rr.String())
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
			updated = true
			zd.Options[OptDirty] = true
		}
		owner.RRtypes.Set(rrtype, rrset)
		// log.Printf("ApplyUpdateToZoneData: Add %s with RR=%s", rrtypestr, rrcopy.String())
		// log.Printf("ApplyUpdateToZoneData: %s[%s]=%v", owner.Name, rrtypestr, owner.RRtypes[rrtype])
		// dump.P(owner.RRtypes[rrtype])
		updated = true
		// zd.Options["dirty"] = true
		continue
	}

	log.Printf("ApplyChildUpdateToZoneData done: updated=%t", updated)

	return updated, nil
}

func (zd *ZoneData) ApplyZoneUpdateToZoneData(ur UpdateRequest, kdb *KeyDB) (bool, error) {

	// dump.P(ur)
	// log.Printf("**** ApplyZoneUpdateToZoneData: ur=%+v", ur)

	zd.mu.Lock()
	defer func() {
		zd.mu.Unlock()
		zd.BumpSerial()
	}()

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil && zd.Options[OptOnlineSigning] {
		return false, err
	}
	if len(dak.KSKs) == 0 && zd.Options[OptOnlineSigning] {
		return false, fmt.Errorf("zone %s has no active KSKs and online-signing is enabled. zone update is rejected", zd.ZoneName)
	}

	var updated bool

	for _, rr := range ur.Actions {
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 3600
		rrcopy.Header().Class = dns.ClassINET

		// First check whether this update is allowed by the update-policy.
		_, ok := zd.UpdatePolicy.Zone.RRtypes[rrtype]
		if !ok && !ur.InternalUpdate {
			log.Printf("ZoneUpdateChangesDelegationData: Error: request to add %s RR, which is denied by policy", rrtypestr)
			continue
		}

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
				RRtypes: NewRRTypeStore(),
			}
			zd.AddOwner(owner)
			updated = true
			// zd.Options["dirty"] = true
		}

		rrset, exists := owner.RRtypes.Get(rrtype)
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
				owner.RRtypes.Delete(rrtype)
			} else {
				zd.SignRRset(&rrset, ownerName, dak, true)
				owner.RRtypes.Set(rrtype, rrset)
			}
			updated = true
			// zd.Options["dirty"] = true
			log.Printf("ApplyUpdateToZoneData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			owner.RRtypes.Delete(rrtype)
			// XXX: As long as we don't maintain any NSEC chain removing a complete RRset should not require any resigning.
			updated = true
			// zd.Options["dirty"] = true
			log.Printf("ApplyUpdateToZoneData: Remove RRset: %s", rr.String())
			continue

		case dns.ClassINET:
		default:
			log.Printf("ApplyUpdate: Error: unknown class: %s", rr.String())
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
			// rrset.RRSIGs = []dns.RR{} // XXX: The RRset changed, so any old RRSIGs are now invalid.
			zd.SignRRset(&rrset, zd.ZoneName, dak, true)
			updated = true
			// zd.Options["dirty"] = true
		}

		owner.RRtypes.Set(rrtype, rrset)
		updated = true
		// zd.Options["dirty"] = true
		continue
	}

	log.Printf("**** ApplyZoneUpdateToZoneData done: updated=%t", updated)

	return updated, nil
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
	log.Printf("*** Enter ZoneUpdateChangesDelegationData(). ur:\n%+v", ur)
	var dss = DelegationSyncStatus{
		ZoneName: zd.ZoneName,
		Time:     time.Now(),
		InSync:   true,
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return dss, err
	}
	bns, err := BailiwickNS(zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
	if err != nil {
		return dss, err
	}

	for _, rr := range ur.Actions {
		log.Printf("ZoneUpdateChangesDelegationData: checking action: %s", rr.String())
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 3600
		rrcopy.Header().Class = dns.ClassINET

		// First check whether this update is allowed by the update-policy.
		_, ok := zd.UpdatePolicy.Zone.RRtypes[rrtype]
		if !ok && !ur.InternalUpdate {
			log.Printf("ZoneUpdateChangesDelegationData: Error: request to add %s RR, which is denied by policy", rrtypestr)
			continue
		}

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
				RRtypes: NewRRTypeStore(),
			}
			zd.AddOwner(owner) // XXX: This is not ok, as we're not holding the lock here. But this function should die.
		}

		if ownerName == zd.ZoneName && rrtype == dns.TypeNS {
			dss.InSync = false
			// return dss, nil
		}

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			log.Printf("ZoneUpdateChangesDelegationData: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())

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
			log.Printf("ZoneUpdateChangesDelegationData: Remove RRset: %s", rr.String())
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
			log.Printf("ZoneUpdateChangesDelegationData: Class is INET, this is an ADD: %s", rr.String())
		default:
			log.Printf("ZoneUpdateChangesDelegationData: Error: unknown class: %s", rr.String())
		}

		dup := false
		if rrset, exists := owner.RRtypes.Get(rrtype); exists {
			for _, oldrr := range rrset.RRs {
				if dns.IsDuplicate(oldrr, rrcopy) {
					log.Printf("ZoneUpdateChangesDelegationData: NOT adding duplicate %s record with RR=%s", rrtypestr, rrcopy.String())
					dup = true
					break
				}
			}
		}

		if !dup {
			log.Printf("ZoneUpdateChangesDelegationData: Adding %s record with RR=%s", rrtypestr, rrcopy.String())
			// Is this a change to the NS RRset?
			if ownerName == zd.ZoneName && rrtype == dns.TypeNS {
				dss.InSync = false
				dss.NsAdds = append(dss.NsAdds, rrcopy)
			}
			// Iterate over all in-bailiwick nameservers to see if this is an add to the glue for a nameserver.
			for _, nsname := range bns {
				log.Printf("ZoneUpdateChangesDelegationData: checking %s", nsname)
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

	dump.P(dss)
	return dss, nil
}

// New attempt at this elusive function. This may actually be correct now. I.e. the list of action in ddata.Actions
// is the complete set of actions that should be sent to the parent.

func (zd *ZoneData) ZoneUpdateChangesDelegationDataNG(ur UpdateRequest) (DelegationSyncStatus, error) {
	// log.Printf("*** Enter ZUCDDNGNG(). ur:\n%+v", ur)
	var dss = DelegationSyncStatus{
		ZoneName: zd.ZoneName,
		Time:     time.Now(),
		InSync:   true,
	}

	defer func() {
		// log.Printf("********* ZUCDDNGNG: returning")
	}()

	ddata, err := zd.DelegationData()
	if err != nil {
		return dss, err
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return dss, err
	}
	bns, err := BailiwickNS(zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
	if err != nil {
		return dss, err
	}

	// We must sort the ur.Actions to ensure that any NS actions come first (so that possible glue actions
	// have an NS to refer to.

	var new_bns []string

	var actions []dns.RR
	for _, rr := range ur.Actions {
		if rr.Header().Rrtype == dns.TypeNS {
			actions = append(actions, rr)
			if rr.Header().Name == zd.ZoneName {
				new_bns = append(new_bns, rr.Header().Name)
			}
		}
	}
	for _, rr := range ur.Actions {
		if rr.Header().Rrtype != dns.TypeNS {
			actions = append(actions, rr)
		}
	}

	for _, rr := range actions {
		// log.Printf("ZUCDDNG: checking action: %s", rr.String())
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		if rrtype != dns.TypeNS && rrtype != dns.TypeA && rrtype != dns.TypeAAAA {
			//log.Printf("ZUCDDNG: Update does not affect delegation data: %s", rrtypestr)
			continue
		}

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 3600
		// Why did we modify the class here?
		// rrcopy.Header().Class = dns.ClassINET

		// XXX: This is the wrong place for this check. These things should be already sorted out during the approval phase.
		// XXX: But we keep it here until the approval code is updated.
		// First check whether this update is allowed by the update-policy.
		_, ok := zd.UpdatePolicy.Zone.RRtypes[rrtype]
		if !ok && !ur.InternalUpdate {
			// log.Printf("ZUCDDNG: Error: request to add %s RR, which is denied by policy", rrtypestr)
			continue
		}

		if ownerName == zd.ZoneName && rrtype == dns.TypeNS {
			dss.InSync = false
			// return dss, nil
		}

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			//log.Printf("ZUCDDNG: Remove RR: %s %s %s", ownerName, rrtypestr, rrcopy.String())

			// Is this a change to the NS RRset?
			if ownerName == zd.ZoneName && rrtype == dns.TypeNS {
				dss.InSync = false
				dss.NsRemoves = append(dss.NsRemoves, rrcopy)
				ddata.Actions = append(ddata.Actions, rrcopy)
				ddata.RemovedNS.RRs = append(ddata.RemovedNS.RRs, rrcopy)
				//log.Printf("ZUCDDNG: Removed NS: %s; now we need to remove any glue", rrcopy.String())
				if nsrr, ok := rr.(*dns.NS); ok {
					nsowner, err := zd.GetOwner(nsrr.Ns)
					if err != nil {
						log.Printf("ZUCDDNG: Error: nsname %s of NS %s has no RRs", nsrr.Ns, nsrr.String())
					} else if nsowner != nil { // nsowner != nil if the NS is in bailiwick
						if a_rrset, exists := nsowner.RRtypes.Get(dns.TypeA); exists {
							for _, rr := range a_rrset.RRs {
								rr.Header().Class = dns.ClassNONE
								dss.ARemoves = append(dss.ARemoves, rr)
								ddata.Actions = append(ddata.Actions, rr)
							}
						}
						if aaaa_rrset, exists := nsowner.RRtypes.Get(dns.TypeAAAA); exists {
							for _, rr := range aaaa_rrset.RRs {
								rr.Header().Class = dns.ClassNONE
								dss.AAAARemoves = append(dss.AAAARemoves, rr)
								ddata.Actions = append(ddata.Actions, rr)
							}
						}
					}
				}
			}
			// Is this a change to glue for a nameserver?
			for _, nsname := range ddata.BailiwickNS {
				if nsname == ownerName {
					if rrtype == dns.TypeA {
						dss.InSync = false
						dss.ARemoves = append(dss.ARemoves, rrcopy)
						ddata.Actions = append(ddata.Actions, rrcopy)
					} else if rrtype == dns.TypeAAAA {
						dss.InSync = false
						dss.AAAARemoves = append(dss.AAAARemoves, rrcopy)
						ddata.Actions = append(ddata.Actions, rrcopy)
					}
				}
			}
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset.
			//log.Printf("ZUCDDNG: Remove RRset: %s", rr.String())
			switch rrtype {
			case dns.TypeNS:
				if ownerName == zd.ZoneName {
					// XXX: It must not be allowed to remove the *entire* NS RRset for a zone.
					// XXX: This should have been caught during approval. But here we are and we
					// XXX: will complain, but ignore this update
					// log.Printf("Error: update contains a REMOVE for the entire zone NS RRset. This is illegal and ignored.")
				}

			case dns.TypeA:
				for _, nsname := range bns {
					if nsname == ownerName {
						dss.InSync = false
						dss.ARemoves = append(dss.ARemoves, rrcopy)
						ddata.Actions = append(ddata.Actions, rrcopy)
					}
				}

			case dns.TypeAAAA:
				for _, nsname := range bns {
					if nsname == ownerName {
						dss.InSync = false
						dss.AAAARemoves = append(dss.AAAARemoves, rrcopy)
						ddata.Actions = append(ddata.Actions, rrcopy)
					}
				}
			}
			continue

		case dns.ClassINET:
		default:
			//log.Printf("ZUCDDNG: Error: unknown class: %s", rr.String())
			continue
		}

		// Here we know that the actions has class == ClassINET
		//log.Printf("ZUCDDNG: Class is INET, this is an ADD: %s", rr.String())

		dup := false
		switch rrtype {
		case dns.TypeNS:
			if ownerName == zd.ZoneName {
				for _, rr := range ddata.CurrentNS.RRs {
					if dns.IsDuplicate(rr, rrcopy) {
						// log.Printf("ZUCDDNG: NOT adding duplicate %s record with RR=%s", rrtypestr, rrcopy.String())
						dup = true
						break
					}
				}
				if !dup {
					dss.InSync = false
					dss.NsAdds = append(dss.NsAdds, rrcopy)
					ddata.AddedNS.RRs = append(ddata.AddedNS.RRs, rrcopy)
					ddata.Actions = append(ddata.Actions, rrcopy)
					// XXX: This is a new NS. Now we must locate any existing address RRs for this name.
					if nsrr, ok := rr.(*dns.NS); ok {
						//log.Printf("ZUCDDNG: fetching owner for NS: %+v", nsrr.Ns)
						nsowner, err := zd.GetOwner(nsrr.Ns)
						if err != nil || nsowner == nil {
							// log.Printf("ZUCDDNG: Error: owner %s of NS %s is unknown", nsrr.Ns, nsrr.String())
						} else {
							// log.Printf("ZUCDDNG: nsowner: %+v", nsowner)
							if a_rrset, exists := nsowner.RRtypes.Get(dns.TypeA); exists {
								for _, rr := range a_rrset.RRs {
									dss.AAdds = append(dss.AAdds, rr)
									ddata.Actions = append(ddata.Actions, rr)
								}
							}
							if aaaa_rrset, exists := nsowner.RRtypes.Get(dns.TypeAAAA); exists {
								for _, rr := range aaaa_rrset.RRs {
									dss.AAAAAdds = append(dss.AAAAAdds, rr)
									ddata.Actions = append(ddata.Actions, rr)
								}
							}
						}
						// It is also possible that glue for the new NS is present later in the update.
						for _, action := range actions {
							if action.Header().Name == nsrr.Ns {
								if action.Header().Rrtype == dns.TypeA {
									// log.Printf("ZUCDDNG: adding glue for new NS %s from later in the update: %s", nsrr.Ns, action.String())
									dss.AAdds = append(dss.AAdds, action)
									ddata.Actions = append(ddata.Actions, action)
								} else if action.Header().Rrtype == dns.TypeAAAA {
									// log.Printf("ZUCDDNG: adding glue for new NS %s from later in the update: %s", nsrr.Ns, action.String())
									dss.AAAAAdds = append(dss.AAAAAdds, action)
									ddata.Actions = append(ddata.Actions, action)
								}
							}
						}
					}
				}
			} else {
				// log.Printf("ZUCDDNG: Error: zone update tries to modify child delegation.")
			}

		case dns.TypeA:
			// XXX: There are two cases: adding a new A to a current or new NS and adding an A to an NS
			// that is being removed. Only the first case modifies the delegation.
			if oldglue, exist := ddata.A_glue[ownerName]; exist {
				for _, arr := range oldglue.RRs {
					if dns.IsDuplicate(arr, rrcopy) {
						// log.Printf("ZUCDDNG: NOT adding duplicate %s record with RR=%s", rrtypestr, rrcopy.String())
						dup = true
						break
					}
				}
				if !dup {
					dss.InSync = false
					dss.AAdds = append(dss.AAdds, rrcopy)
					ddata.Actions = append(ddata.Actions, rrcopy)
				}
			} else if slices.Contains(new_bns, ownerName) {
				// This is glue for a new NS that is being added.
				dss.InSync = false
				dss.AAdds = append(dss.AAdds, rrcopy)
				ddata.Actions = append(ddata.Actions, rrcopy)
			}

		case dns.TypeAAAA:
			// XXX: There are two cases: adding a new A to a current or new NS and adding an A to an NS
			// that is being removed. Only the first case modifies the delegation.
			if oldglue, exist := ddata.AAAA_glue[ownerName]; exist {
				for _, aaaa_rr := range oldglue.RRs {
					if dns.IsDuplicate(aaaa_rr, rrcopy) {
						// log.Printf("ZUCDDNG: NOT adding duplicate %s record with RR=%s", rrtypestr, rrcopy.String())
						dup = true
						break
					}
				}
				if !dup {
					dss.InSync = false
					dss.AAAAAdds = append(dss.AAAAAdds, rrcopy)
					ddata.Actions = append(ddata.Actions, rrcopy)
				}
			} else if slices.Contains(new_bns, ownerName) {
				// This is glue for a new NS that is being added.
				dss.InSync = false
				dss.AAAAAdds = append(dss.AAAAAdds, rrcopy)
				ddata.Actions = append(ddata.Actions, rrcopy)
			}

		default:
			log.Printf("ZUCDDNG: Error: RR type: %s should not get here: %s", rrtypestr, rr.String())
		}
	}

	if zd.ZoneName == "child.test.net." {
		log.Printf("ZUCDDNG: ddata:\n%+v", ddata)
		log.Printf("ZUCDDNG: ddata.Actions:\n%s", SprintUpdates(ddata.Actions))
	}
	// dump.P(ddata)
	// dump.P(dss)
	return dss, nil
}
