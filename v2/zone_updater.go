/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"slices"
	"time"

	core "github.com/johanix/tdns/v2/core"
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

func (kdb *KeyDB) ZoneUpdaterEngine(ctx context.Context) error {
	updateq := kdb.UpdateQ

	lg.Info("ZoneUpdater starting")
	for {
		select {
		case <-ctx.Done():
			lg.Info("ZoneUpdater: context cancelled")
			lg.Info("ZoneUpdater: terminating")
			return nil
		case ur, ok := <-updateq:
			if !ok {
				lg.Info("ZoneUpdater: updateq closed")
				lg.Info("ZoneUpdater: terminating")
				return nil
			}
			lg.Debug("ZoneUpdater received update request")
			if ur.Cmd == "PING" {
				lg.Debug("ZoneUpdater: PING received, PONG!")
				continue
			}
			zd, ok := Zones.Get(ur.ZoneName)
			if !ok {
				lg.Warn("ZoneUpdater: unknown zone in update request, ignoring", "cmd", ur.Cmd, "zone", ur.ZoneName)
				lg.Debug("ZoneUpdater: known zones", "zones", Zones.Keys())
				continue
			}

			switch ur.Cmd {
			case "DEFERRED-UPDATE":
				lg.Error("ZoneUpdater: received deferred update on wrong queue", "description", ur.Description)
				continue

			case "CHILD-UPDATE":
				// Child delegation data update: dispatch to the configured DelegationBackend.
				lg.Debug("ZoneUpdater: CHILD-UPDATE request", "zone", ur.ZoneName, "actions", len(ur.Actions))
				lg.Debug("ZoneUpdater: CHILD-UPDATE actions detail", "actions", SprintUpdates(ur.Actions))
				if zd.Options[OptAllowChildUpdates] {
					if zd.DelegationBackend != nil {
						err := zd.DelegationBackend.ApplyChildUpdate(ur.ZoneName, ur)
						if err != nil {
							lg.Error("ZoneUpdater: DelegationBackend.ApplyChildUpdate failed",
								"backend", zd.DelegationBackend.Name(), "error", err)
						} else {
							lg.Info("ZoneUpdater: CHILD-UPDATE applied",
								"zone", ur.ZoneName, "backend", zd.DelegationBackend.Name())
							zd.Options[OptDirty] = true
						}
					} else {
						// Fallback: no backend configured, use legacy dispatch
						var updated bool
						var err error

						switch zd.ZoneType {
						case Primary:
							updated, err = zd.ApplyChildUpdateToZoneData(ur, kdb)
							if err != nil {
								lg.Error("ZoneUpdater: ApplyChildUpdateToZoneData failed", "error", err)
							}
						case Secondary:
							err = kdb.ApplyChildUpdateToDB(ur)
							if err != nil {
								lg.Error("ZoneUpdater: ApplyChildUpdateToDB failed", "error", err)
							}
						}
						if updated {
							zd.Options[OptDirty] = true
						}
					}
				}

			case "ZONE-UPDATE":
				// This is the case where a DNS UPDATE contains updates to authoritative data in the zone
				// (i.e. not child delegation information).
				lg.Info("ZoneUpdater: ZONE-UPDATE request", "zone", ur.ZoneName, "actions", len(ur.Actions))
				lg.Debug("ZoneUpdater: ZONE-UPDATE actions detail", "actions", SprintUpdates(ur.Actions))
				if zd.Options[OptAllowUpdates] || ur.InternalUpdate {
					// Delegation sync checks only apply to external updates
					if !ur.InternalUpdate {
						dss, err := zd.ZoneUpdateChangesDelegationDataNG(ur)
						if err != nil {
							lg.Error("ZoneUpdateChangesDelegationData failed", "error", err)
						}
						lg.Debug("ZoneUpdater: delegation sync status", "inSync", dss.InSync)

						if zd.Options[OptDelSyncChild] && !dss.InSync {
							lg.Debug("ZoneUpdater: delegation out of sync, sending SYNC-DELEGATION", "zone", zd.ZoneName, "queueLen", len(zd.DelegationSyncQ))
							zd.DelegationSyncQ <- DelegationSyncRequest{
								Command:    "SYNC-DELEGATION",
								ZoneName:   zd.ZoneName,
								ZoneData:   zd,
								SyncStatus: dss,
							}
							if err := zd.PublishCsyncRR(); err != nil {
								lg.Error("ZoneUpdater: error publishing CSYNC", "zone", zd.ZoneName, "err", err)
							} else {
								lg.Debug("ZoneUpdater: published CSYNC proactively", "zone", zd.ZoneName)
							}
						}
					}

					var updated bool
					var err error

					switch zd.ZoneType {
					case Primary:
						updated, err = zd.ApplyZoneUpdateToZoneData(ur, kdb)
						if err != nil {
							lg.Error("ZoneUpdater: ApplyZoneUpdateToZoneData failed", "error", err)
						}

					case Secondary:
						err := kdb.ApplyZoneUpdateToDB(ur)
						if err != nil {
							lg.Error("ZoneUpdater: ApplyZoneUpdateToDB failed", "error", err)
						}
					}
					if updated && !ur.InternalUpdate {
						lg.Debug("ZoneUpdater: zone updated, setting dirty flag", "zone", zd.ZoneName)
						zd.Options[OptDirty] = true
					}
				} else {
					lg.Warn("ZoneUpdater: updates disallowed for zone, dropping ZONE-UPDATE", "zone", zd.ZoneName)
				}
				lg.Debug("ZoneUpdater: ZONE-UPDATE done")

			case "TRUSTSTORE-UPDATE":
				lg.Debug("ZoneUpdater: TRUSTSTORE-UPDATE request", "zone", ur.ZoneName, "actions", len(ur.Actions))
				lg.Debug("ZoneUpdater: TRUSTSTORE-UPDATE actions detail", "actions", SprintUpdates(ur.Actions))
				tx, err := kdb.Begin("UpdaterEngine")
				if err != nil {
					lg.Error("kdb.Begin failed", "error", err)
				}
				type pendingVerification struct {
					childZone string
					keyid     uint16
					keyRR     string
				}
				var toVerify []pendingVerification
				for _, rr := range ur.Actions {
					var subcommand string
					switch rr.Header().Class {
					case dns.ClassINET:
						subcommand = "add"
					case dns.ClassNONE:
						subcommand = "delete"
					case dns.ClassANY:
						lg.Error("ZoneUpdater: TRUSTSTORE-UPDATE: class ANY (delete RRset) not supported, ignoring")
						continue
					default:
						lg.Error("ZoneUpdater: TRUSTSTORE-UPDATE: unknown class, ignoring", "rr", rr.String())
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
							lg.Error("kdb.Sig0TrustMgmt failed", "error", err)
						}

						// Queue untrusted child-update adds for async verification.
						if subcommand == "add" && !ur.Trusted {
							toVerify = append(toVerify, pendingVerification{
								childZone: keyrr.Header().Name,
								keyid:     uint16(keyrr.KeyTag()),
								keyRR:     rr.String(),
							})
						}
					} else {
						lg.Error("ZoneUpdater: TRUSTSTORE-UPDATE: not a KEY RR", "rr", rr.String())
					}
				}
				err = tx.Commit()
				if err != nil {
					lg.Error("tx.Commit failed", "error", err)
				}

				// Trigger async DNS verification for newly stored untrusted child keys.
				for _, pv := range toVerify {
					lg.Info("ZoneUpdater: triggering child key verification",
						"zone", pv.childZone, "keyid", pv.keyid)
					kdb.TriggerChildKeyVerification(pv.childZone, pv.keyid, pv.keyRR)
				}
			default:
				lg.Error("ZoneUpdater: unknown command, ignoring", "cmd", ur.Cmd)
			}
			lg.Info("ZoneUpdater: update request completed", "type", ur.Cmd)
		}
	}
}

func (kdb *KeyDB) DeferredUpdaterEngine(ctx context.Context) error {
	deferredq := kdb.DeferredUpdateQ

	var deferredUpdates []DeferredUpdate

	var runQueueTicker = time.NewTicker(10 * time.Second)

	lg.Info("DeferredUpdater starting")
	defer runQueueTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			lg.Info("DeferredUpdater: context cancelled")
			lg.Info("DeferredUpdater: terminating")
			return nil
		case du, ok := <-deferredq:
			if !ok {
				lg.Info("DeferredUpdater: deferredq closed")
				lg.Info("DeferredUpdater: terminating")
				return nil
			}
			lg.Debug("DeferredUpdater received update request")
			if du.Cmd == "PING" {
				lg.Debug("DeferredUpdater: PING received, PONG!")
				continue
			}
			_, ok = Zones.Get(du.ZoneName)
			if !ok && du.Cmd != "DEFERRED-UPDATE" {
				lg.Warn("DeferredUpdater: unknown zone in update request, ignoring", "cmd", du.Cmd, "zone", du.ZoneName)
				lg.Debug("DeferredUpdater: known zones", "zones", Zones.Keys())
				continue
			}

			switch du.Cmd {
			case "DEFERRED-UPDATE":
				// If the PreCondition is true, we execute the Action immediately, otherwise we defer execution an add it to the deferredUpdates queue.
				if du.PreCondition() {
					lg.Debug("DeferredUpdater: precondition true, executing immediately", "description", du.Description)
					err := du.Action()
					if err != nil {
						lg.Error("DeferredUpdater: deferred update action failed", "description", du.Description, "error", err)
					}
				} else {
					lg.Debug("DeferredUpdater: precondition false, deferring execution", "description", du.Description)
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
				lg.Error("DeferredUpdater: unknown command, ignoring", "cmd", du.Cmd)
			}
			lg.Info("DeferredUpdater: update request completed", "type", du.Cmd)

		case <-runQueueTicker.C:
			if len(deferredUpdates) == 0 {
				continue
			}

			lg.Debug("DeferredUpdater: running deferred updates queue", "items", len(deferredUpdates))
			for i := 0; i < len(deferredUpdates); {
				du := deferredUpdates[i]
				lg.Debug("DeferredUpdater: running deferred update", "description", du.Description)
				ok := du.PreCondition()
				if ok {
					lg.Debug("DeferredUpdater: precondition true, executing", "description", du.Description)
					err := du.Action()
					if err != nil {
						lg.Error("DeferredUpdater: deferred update action failed", "description", du.Description, "error", err)
						i++
					} else {
						lg.Info("DeferredUpdater: deferred update executed successfully", "description", du.Description)
						// Remove the item from deferredUpdates queue
						deferredUpdates = append(deferredUpdates[:i], deferredUpdates[i+1:]...)
					}
				} else {
					lg.Debug("DeferredUpdater: precondition failed, skipping", "description", du.Description)
					i++
				}
			}
		}
	}
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
				lg.Error("ApplyChildUpdateToDB: tx.Commit failed", "error", err1)
			}
		} else {
			lg.Error("ApplyChildUpdateToDB: rolling back", "error", err)
			err1 := tx.Rollback()
			if err1 != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Rollback failed", "error", err1)
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
			lg.Debug("ApplyChildUpdateToDB: Remove RR", "owner", owner, "rrtype", rrtypestr, "rr", rrcopy.String())
			_, err := tx.Exec(deldelrrsql, owner, rrtypestr, rrcopy.String())
			if err != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Exec failed", "sql", deldelrrsql, "owner", owner, "error", err)
				return err
			}
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			lg.Debug("ApplyChildUpdateToDB: Remove RRset", "rr", rr.String())
			_, err := tx.Exec(deldelrrsetsql, owner, rrtypestr)
			if err != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Exec failed", "sql", deldelrrsetsql, "owner", owner, "rrtype", rrtypestr, "error", err)
				return err
			}
			continue

		case dns.ClassINET:
			// Do nothing here, all adds are handled in the next section.

		default:
			lg.Error("ApplyChildUpdateToDB: unknown class", "rr", rr.String())
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
			lg.Debug("ApplyChildUpdateToDB: Add KEY", "keyid", keyid)
			_, err := tx.Exec(sqlcmd, owner, keyid, ur.Validated, ur.Trusted, rrcopy.String())
			if err != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Exec failed", "sql", sqlcmd, "error", err)
				return err
			}
		case dns.TypeNS, dns.TypeA, dns.TypeAAAA:
			lg.Debug("ApplyChildUpdateToDB: Add RR", "rrtype", rrtypestr, "rr", rrcopy.String())
			_, err := tx.Exec(sqlcmd, owner, rrtype, rrcopy.String())
			if err != nil {
				lg.Error("ApplyChildUpdateToDB: tx.Exec failed", "sql", sqlcmd, "error", err)
				return err
			}
		default:
			lg.Error("ApplyChildUpdateToDB: unsupported RR type for add", "rrtype", rrtypestr)
		}
	}

	return nil
}

func (zd *ZoneData) ApplyChildUpdateToZoneData(ur UpdateRequest, kdb *KeyDB) (bool, error) {

	lg.Debug("ApplyChildUpdateToZoneData", "request", fmt.Sprintf("%+v", ur))

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
		rrcopy.Header().Ttl = zd.UpdatePolicy.Child.TTL
		rrcopy.Header().Class = dns.ClassINET

		// First check whether this update is allowed by the update-policy.
		if _, ok := zd.UpdatePolicy.Child.RRtypes[rrtype]; !ok {
			lg.Error("ApplyChildUpdateToZoneData: RR type denied by policy", "rrtype", rrtypestr)
			continue
		}

		// XXX: The logic here is a bit involved. If this is a delete then it is ~ok that the owner doesn't exist.
		// If it is an add then it is not ok, and then the owner must be created.

		owner, err := zd.GetOwner(ownerName)
		if err != nil {
			lg.Warn("ApplyChildUpdateToZoneData: unknown owner name", "owner", ownerName)
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
			lg.Warn("ApplyChildUpdateToZoneData: no RRset for owner", "owner", ownerName, "rrtype", rrtypestr)
			if class == dns.ClassNONE || class == dns.ClassANY {
				// If this is a delete then it is ok that the RRset doesn't exist.
				continue
			}
			rrset = core.RRset{
				RRs:    []dns.RR{},
				RRSIGs: []dns.RR{},
			}
		}

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			lg.Debug("ApplyChildUpdateToZoneData: Remove RR", "owner", ownerName, "rrtype", rrtypestr, "rr", rrcopy.String())
			rrset.RemoveRR(rrcopy, Globals.Verbose, Globals.Debug) // Cannot remove rr, because it is in the wrong class.
			if len(rrset.RRs) == 0 {
				owner.RRtypes.Delete(rrtype)
			} else {
				owner.RRtypes.Set(rrtype, rrset)
			}
			updated = true
			// zd.Options["dirty"] = true
			lg.Debug("ApplyChildUpdateToZoneData: Remove RR done", "owner", ownerName, "rrtype", rrtypestr)
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			lg.Debug("ApplyChildUpdateToZoneData: Remove RRset", "rr", rr.String())
			owner.RRtypes.Delete(rrtype)
			updated = true
			// zd.Options["dirty"] = true
			continue

		case dns.ClassINET:
			// Do nothing here, all adds are handled in the next section.
		default:
			lg.Error("ApplyChildUpdateToZoneData: unknown class", "rr", rr.String())
			continue
		}

		dup := false
		for _, oldrr := range rrset.RRs {
			if dns.IsDuplicate(oldrr, rrcopy) {
				lg.Debug("ApplyChildUpdateToZoneData: not adding duplicate", "rrtype", rrtypestr, "rr", rrcopy.String())
				dup = true
				break
			}
		}
		if !dup {
			lg.Debug("ApplyChildUpdateToZoneData: adding RR", "rrtype", rrtypestr, "rr", rrcopy.String())
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

	lg.Debug("ApplyChildUpdateToZoneData done", "updated", updated)

	return updated, nil
}

func (zd *ZoneData) ApplyZoneUpdateToZoneData(ur UpdateRequest, kdb *KeyDB) (bool, error) {

	// dump.P(ur)
	// log.Printf("**** ApplyZoneUpdateToZoneData: ur=%+v", ur)

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil && (zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]) && (err != nil || dak == nil || len(dak.KSKs) == 0) {
		lg.Debug("ApplyZoneUpdateToZoneData: GetDnssecKeys failed, attempting to ensure keys exist", "zone", zd.ZoneName)
		// Try to ensure active keys exist (will generate if needed)
		dak, err = zd.ensureActiveDnssecKeys(kdb)
		if err != nil {
			lg.Error("ApplyZoneUpdateToZoneData: failed to ensure active DNSSEC keys", "zone", zd.ZoneName, "error", err)
			return false, err
		}
		if dak == nil || len(dak.KSKs) == 0 {
			lg.Error("ApplyZoneUpdateToZoneData: still no active KSKs after ensureActiveDnssecKeys", "zone", zd.ZoneName)
			return false, fmt.Errorf("zone %s has no active KSKs and online-signing is enabled. zone update is rejected", zd.ZoneName)
		}
	}

	var updated bool

	zd.mu.Lock()
	defer func() {
		zd.mu.Unlock()
		zd.BumpSerial()
	}()

	lg.Debug("ApplyZoneUpdateToZoneData: processing actions", "zone", zd.ZoneName, "count", len(ur.Actions))
	for _, rr := range ur.Actions {
		class := rr.Header().Class
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = zd.UpdatePolicy.Zone.TTL
		rrcopy.Header().Class = dns.ClassINET

		// First check whether this update is allowed by the update-policy.
		_, ok := zd.UpdatePolicy.Zone.RRtypes[rrtype]
		if !ok && !ur.InternalUpdate {
			lg.Error("ApplyZoneUpdateToZoneData: RR type denied by policy", "rrtype", rrtypestr)
			continue
		}

		// XXX: The logic here is a bit involved. If this is a delete then it is ~ok that the owner doesn't exist.
		// If it is an add then it is not ok, and then the owner must be created.

		owner, err := zd.GetOwner(ownerName)
		if err != nil {
			lg.Warn("ApplyZoneUpdateToZoneData: unknown owner name", "owner", ownerName)
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
			lg.Warn("ApplyZoneUpdateToZoneData: no RRset for owner", "owner", ownerName, "rrtype", rrtypestr)
			if class == dns.ClassNONE || class == dns.ClassANY {
				continue
			}
			rrset = core.RRset{
				RRs:    []dns.RR{},
				RRSIGs: []dns.RR{},
			}
		}

		switch class {
		case dns.ClassNONE:
			// ClassNONE: Remove exact RR
			rrset.RemoveRR(rrcopy, Globals.Verbose, Globals.Debug) // Cannot remove rr, because it is in the wrong class.
			if len(rrset.RRs) == 0 {
				owner.RRtypes.Delete(rrtype)
			} else {
				_, err := zd.SignRRset(&rrset, ownerName, dak, true)
				if err != nil {
					lg.Error("ApplyZoneUpdateToZoneData: signing failed after RR removal", "rrtype", rrtypestr, "owner", ownerName, "error", err)
					// Continue anyway - the record is still added, just not signed
				}
				owner.RRtypes.Set(rrtype, rrset)
			}
			updated = true
			// zd.Options["dirty"] = true
			lg.Debug("ApplyZoneUpdateToZoneData: Remove RR", "owner", ownerName, "rrtype", rrtypestr, "rr", rrcopy.String())
			continue

		case dns.ClassANY:
			// ClassANY: Remove RRset
			owner.RRtypes.Delete(rrtype)
			// XXX: As long as we don't maintain any NSEC chain removing a complete RRset should not require any resigning.
			updated = true
			// zd.Options["dirty"] = true
			lg.Debug("ApplyZoneUpdateToZoneData: Remove RRset", "rr", rr.String())
			continue

		case dns.ClassINET:
		default:
			lg.Error("ApplyZoneUpdateToZoneData: unknown class", "rr", rr.String())
		}

		dup := false
		for _, oldrr := range rrset.RRs {
			if dns.IsDuplicate(oldrr, rrcopy) {
				lg.Debug("ApplyZoneUpdateToZoneData: not adding duplicate", "rrtype", rrtypestr, "rr", rrcopy.String())
				dup = true
				break
			}
		}

		if !dup {
			lg.Debug("ApplyZoneUpdateToZoneData: adding RR", "rrtype", rrtypestr, "rr", rrcopy.String())
			rrset.RRs = append(rrset.RRs, rrcopy)
			// rrset.RRSIGs = []dns.RR{} // XXX: The RRset changed, so any old RRSIGs are now invalid.
			_, err = zd.SignRRset(&rrset, ownerName, dak, true)
			if err != nil {
				lg.Error("ApplyZoneUpdateToZoneData: signing failed after RR add", "rrtype", rrtypestr, "owner", ownerName, "error", err)
				// Continue anyway - the record is still added, just not signed
			}
			updated = true
			// zd.Options["dirty"] = true
		}

		owner.RRtypes.Set(rrtype, rrset)
		updated = true
		// zd.Options["dirty"] = true
		continue
	}

	lg.Debug("ApplyZoneUpdateToZoneData done", "updated", updated)

	return updated, nil
}

func (kdb *KeyDB) ApplyZoneUpdateToDB(ur UpdateRequest) error {
	return nil // placeholder
}

// ZoneUpdateChangesDelegationDataNG: the list of actions in ddata.Actions
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

		if rrtype != dns.TypeNS && rrtype != dns.TypeA && rrtype != dns.TypeAAAA && rrtype != dns.TypeDNSKEY {
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
						lg.Error("ZUCDDNG: NS owner has no RRs", "nsname", nsrr.Ns, "ns", nsrr.String())
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
			// Is this a KSK DNSKEY removal?
			if ownerName == zd.ZoneName && rrtype == dns.TypeDNSKEY {
				if dk, ok := rr.(*dns.DNSKEY); ok {
					if dk.Flags&dns.SEP != 0 {
						dss.InSync = false
						dss.DNSKEYRemoves = append(dss.DNSKEYRemoves, rrcopy)
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

			case dns.TypeDNSKEY:
				if ownerName == zd.ZoneName {
					// Removing entire DNSKEY RRset — all KSKs removed
					dss.InSync = false
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

		case dns.TypeDNSKEY:
			if ownerName == zd.ZoneName {
				if dk, ok := rr.(*dns.DNSKEY); ok {
					if dk.Flags&dns.SEP != 0 {
						dss.InSync = false
						dss.DNSKEYAdds = append(dss.DNSKEYAdds, rrcopy)
					}
				}
			}

		default:
			lg.Error("ZUCDDNG: unexpected RR type", "rrtype", rrtypestr, "rr", rr.String())
		}
	}

	lg.Debug("ZUCDDNG delegation data", "zone", zd.ZoneName, "ddata", fmt.Sprintf("%+v", ddata))
	lg.Debug("ZUCDDNG delegation actions", "zone", zd.ZoneName, "actions", SprintUpdates(ddata.Actions))

	computeNewNSFromCurrent(&dss, ddata.CurrentNS.RRs)
	err = computeNewGlue(&dss, zd.ZoneName, ddata)
	if err != nil {
		return dss, err
	}
	computeNewDS(&dss, zd)

	return dss, nil
}

// computeNewNSFromCurrent computes the complete new NS RRset for replace
// mode by starting from the current NS RRset and applying the adds/removes
// from dss.
func computeNewNSFromCurrent(dss *DelegationSyncStatus, currentNS []dns.RR) {
	dss.NewNS = make([]dns.RR, 0, len(currentNS))
	for _, rr := range currentNS {
		dss.NewNS = append(dss.NewNS, dns.Copy(rr))
	}

	for _, remove := range dss.NsRemoves {
		for i := len(dss.NewNS) - 1; i >= 0; i-- {
			if dns.IsDuplicate(dss.NewNS[i], remove) {
				dss.NewNS = append(dss.NewNS[:i], dss.NewNS[i+1:]...)
				break
			}
		}
	}

	for _, add := range dss.NsAdds {
		dup := false
		for _, existing := range dss.NewNS {
			if dns.IsDuplicate(existing, add) {
				dup = true
				break
			}
		}
		if !dup {
			rrcopy := dns.Copy(add)
			rrcopy.Header().Ttl = 3600
			rrcopy.Header().Class = dns.ClassINET
			dss.NewNS = append(dss.NewNS, rrcopy)
		}
	}
}

// computeNewGlue computes the complete new A and AAAA glue records for
// replace mode. It builds maps of current glue, applies adds/removes,
// and collects glue for in-bailiwick NS names from the new NS RRset.
func computeNewGlue(dss *DelegationSyncStatus, zoneName string, ddata *DelegationData) error {
	new_bailiwick_ns, err := BailiwickNS(zoneName, dss.NewNS)
	if err != nil {
		lg.Error("computeNewGlue: failed to compute bailiwick NS", "error", err)
		return err
	}

	current_a_glue := make(map[string][]dns.RR)
	current_aaaa_glue := make(map[string][]dns.RR)
	for nsname, rrset := range ddata.A_glue {
		current_a_glue[nsname] = make([]dns.RR, len(rrset.RRs))
		for i, rr := range rrset.RRs {
			current_a_glue[nsname][i] = dns.Copy(rr)
		}
	}
	for nsname, rrset := range ddata.AAAA_glue {
		current_aaaa_glue[nsname] = make([]dns.RR, len(rrset.RRs))
		for i, rr := range rrset.RRs {
			current_aaaa_glue[nsname][i] = dns.Copy(rr)
		}
	}

	// Apply removes to current glue
	for _, remove := range dss.ARemoves {
		nsname := remove.Header().Name
		if glue, exists := current_a_glue[nsname]; exists {
			for i := len(glue) - 1; i >= 0; i-- {
				if dns.IsDuplicate(glue[i], remove) {
					glue = append(glue[:i], glue[i+1:]...)
					current_a_glue[nsname] = glue
					break
				}
			}
		}
	}
	for _, remove := range dss.AAAARemoves {
		nsname := remove.Header().Name
		if glue, exists := current_aaaa_glue[nsname]; exists {
			for i := len(glue) - 1; i >= 0; i-- {
				if dns.IsDuplicate(glue[i], remove) {
					glue = append(glue[:i], glue[i+1:]...)
					current_aaaa_glue[nsname] = glue
					break
				}
			}
		}
	}

	// Apply adds to current glue
	for _, add := range dss.AAdds {
		nsname := add.Header().Name
		if slices.Contains(new_bailiwick_ns, nsname) {
			if glue, exists := current_a_glue[nsname]; exists {
				dup := false
				for _, existing := range glue {
					if dns.IsDuplicate(existing, add) {
						dup = true
						break
					}
				}
				if !dup {
					rrcopy := dns.Copy(add)
					rrcopy.Header().Ttl = 3600
					rrcopy.Header().Class = dns.ClassINET
					current_a_glue[nsname] = append(current_a_glue[nsname], rrcopy)
				}
			} else {
				rrcopy := dns.Copy(add)
				rrcopy.Header().Ttl = 3600
				rrcopy.Header().Class = dns.ClassINET
				current_a_glue[nsname] = []dns.RR{rrcopy}
			}
		}
	}
	for _, add := range dss.AAAAAdds {
		nsname := add.Header().Name
		if slices.Contains(new_bailiwick_ns, nsname) {
			if glue, exists := current_aaaa_glue[nsname]; exists {
				dup := false
				for _, existing := range glue {
					if dns.IsDuplicate(existing, add) {
						dup = true
						break
					}
				}
				if !dup {
					rrcopy := dns.Copy(add)
					rrcopy.Header().Ttl = 3600
					rrcopy.Header().Class = dns.ClassINET
					current_aaaa_glue[nsname] = append(current_aaaa_glue[nsname], rrcopy)
				}
			} else {
				rrcopy := dns.Copy(add)
				rrcopy.Header().Ttl = 3600
				rrcopy.Header().Class = dns.ClassINET
				current_aaaa_glue[nsname] = []dns.RR{rrcopy}
			}
		}
	}

	// Collect all glue records for the new bailiwick NS
	dss.NewA = []dns.RR{}
	dss.NewAAAA = []dns.RR{}
	for _, nsname := range new_bailiwick_ns {
		if glue, exists := current_a_glue[nsname]; exists {
			for _, rr := range glue {
				dss.NewA = append(dss.NewA, dns.Copy(rr))
			}
		}
		if glue, exists := current_aaaa_glue[nsname]; exists {
			for _, rr := range glue {
				dss.NewAAAA = append(dss.NewAAAA, dns.Copy(rr))
			}
		}
	}

	return nil
}

// computeNewDS computes the complete new DS RRset for replace mode
// by deriving DS records from the current KSK DNSKEYs in the zone.
func computeNewDS(dss *DelegationSyncStatus, zd *ZoneData) {
	if len(dss.DNSKEYAdds) == 0 && len(dss.DNSKEYRemoves) == 0 {
		return
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return
	}

	var newDS []dns.RR
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
		if dk, ok := rr.(*dns.DNSKEY); ok {
			if dk.Flags&dns.SEP != 0 {
				if ds := dk.ToDS(dns.SHA256); ds != nil {
					newDS = append(newDS, ds)
				}
			}
		}
	}
	dss.NewDS = newDS
}
