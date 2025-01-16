/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

func (z *Zone) SignerGroup() *SignerGroup {
	return z.SGroup
}

func (mdb *MusicDB) AddZone(tx *sql.Tx, z *Zone, group string, enginecheck chan EngineCheck) (string, error) {

	fmt.Printf("AddZone: Zone: %v group: '%s'", z, group)

	if tx == nil {
		panic("tx=nil")
	}
	//	var tx *sql.Tx
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("AddZone: Error from mdb.StartTransaction(): %v\n", err)
	//		return "fail", err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	fqdn := dns.Fqdn(z.Name)
	dbzone, _, err := mdb.GetZone(tx, fqdn)
	if err != nil {
		return "", err
	}
	if dbzone.Exists {
		return "", fmt.Errorf("zone %s already present in MuSiC system", fqdn)
	}

	const sqlq = `
INSERT INTO zones(name, zonetype, state, statestamp, fsm, fsmmode)
VALUES (?, ?, ?, datetime('now'), ?, ?)`

	_, err = tx.Exec(sqlq, fqdn, z.ZoneType, "", "", z.FSMMode)
	if CheckSQLError("AddZone", sqlq, err, false) {
		return "", err
	}

	if group != "" {
		fmt.Printf("AddGroup: the zone %s has the signergroup %s specified so we set that too\n", z.Name, group)
		dbzone, _, err := mdb.GetZone(tx, z.Name)
		if err != nil {
			return "", err
		}

		_, err = mdb.ZoneJoinGroup(tx, dbzone, group, enginecheck) // we know that the zone exist
		if err != nil {
			return fmt.Sprintf(
				"Zone %s was added, but failed to attach to signer group %s.", fqdn, group), err
		} else {
			return fmt.Sprintf(
				"Zone %s was added and immediately attached to signer group %s.", fqdn, group), err
		}
	}
	return fmt.Sprintf("Zone %s was added but is not yet attached to any signer group.",
		fqdn), nil
}

func (mdb *MusicDB) UpdateZone(tx *sql.Tx, dbzone, uz *Zone, enginecheck chan EngineCheck) (string, error) {
	log.Printf("UpdateZone: zone: %v", uz)

	if tx == nil {
		panic("tx=nil")
	}
	//	var tx *sql.Tx
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("UpdateZone: Error from mdb.StartTransaction(): %v\n", err)
	//		return "fail", err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	if uz.ZoneType != "" {
		dbzone.ZoneType = uz.ZoneType
	}

	if uz.FSMMode != "" {
		dbzone.FSMMode = uz.FSMMode
	}

	const sqlq = "UPDATE zones SET zonetype=?, fsmmode=? WHERE name=?"

	_, err := tx.Exec(sqlq, dbzone.ZoneType, dbzone.FSMMode, dbzone.Name)
	if CheckSQLError("UpdateZone", sqlq, err, false) {
		return "", err
	}

	if uz.FSMMode == "auto" {
		enginecheck <- EngineCheck{ZoneName: dbzone.Name}
	}

	return fmt.Sprintf("Zone %s updated.", dbzone.Name), nil
}

func (mdb *MusicDB) DeleteZone(tx *sql.Tx, z *Zone) (string, error) {
	if !z.Exists {
		return "", fmt.Errorf("zone %s not present in MuSiC system", z.Name)
	}

	if tx == nil {
		panic("tx=nil")
	}
	sg := z.SignerGroup()
	if sg != nil {
		_, err := mdb.ZoneLeaveGroup(tx, z, sg.Name)
		if err != nil {
			log.Printf("DeleteZone: Error from ZoneLeaveGroup(%s, %s): %v", z.Name, sg.Name, err)
			return fmt.Sprintf("Failed to delete zone '%s'. Error leaving group: %v", z.Name, err), err
		}
	}

	_, err := tx.Exec("DELETE FROM zones WHERE name=?", z.Name)
	if err != nil {
		fmt.Printf("DeleteZone: Error from tx.Exec: %v\n", err)
		return fmt.Sprintf("Failed to delete zone '%s'", z.Name), err
	}

	_, err = tx.Exec("DELETE FROM records WHERE zone=?", z.Name)
	if err != nil {
		log.Printf("DeleteZone: Error from tx.Exec: %v\n", err)
		return fmt.Sprintf("Failed to delete zone '%s'", z.Name), err
	}

	_, err = tx.Exec("DELETE FROM metadata WHERE zone=?", z.Name)
	if err != nil {
		log.Printf("DeleteZone: Error from tx.Exec: %v\n", err)
		return fmt.Sprintf("Failed to delete zone '%s'", z.Name), err
	}

	deletemsg := fmt.Sprintf("Zone %s deleted.", z.Name)
	processcomplete, msg, err := mdb.CheckIfProcessComplete(tx, sg)
	if err != nil {
		return fmt.Sprintf("Error from CheckIfProcessComplete(): %v", err), err
	}
	if processcomplete {
		return deletemsg + "\n" + msg, nil
	}
	return deletemsg, nil
}

func (z *Zone) SetStopReason(value string) (string, error) {
	mdb := z.MusicDB

	mdb.StopReasonCache[z.Name] = value

	mdb.UpdateC <- DBUpdate{
		Type:  "STOPREASON",
		Zone:  z.Name,
		Key:   "stop-reason",
		Value: value,
	}

	log.Printf("%s: %s\n", z.Name, value)
	return fmt.Sprintf("Zone %s stop-reason documented as '%s'", z.Name, value), nil
}

func (z *Zone) SetSignerNsNames(ns_names map[string][]string) (string, error) {
	mdb := z.MusicDB

	mdb.UpdateC <- DBUpdate{
		Type:          "INSERT-ZONE-NS",
		Zone:          z.Name,
		SignerNsNames: ns_names,
	}

	log.Printf("%s: Inserted new NS names for %d signers", z.Name, len(ns_names))
	return fmt.Sprintf("Zone %s signer NS names updated", z.Name), nil
}

func (z *Zone) SetSignerDnskeys(signer_dnskeys map[string][]string) (string, error) {
	mdb := z.MusicDB

	mdb.UpdateC <- DBUpdate{
		Type:          "INSERT-ZONE-DNSKEYS",
		Zone:          z.Name,
		SignerDNSKEYs: signer_dnskeys,
	}

	log.Printf("%s: Inserted new DNSKEYs for %d signers", z.Name, len(signer_dnskeys))
	return fmt.Sprintf("Zone %s signer DNSKEYs updated", z.Name), nil
}

// XXX: SetDelayReason is not yet in use, but is needed for the wait-for-parent-ds stuff
func (z *Zone) SetDelayReason(tx *sql.Tx, value string, delay time.Duration) (string, error) {
	mdb := z.MusicDB

	if tx == nil {
		panic("tx=nil")
	}
	// 	localtx, tx, err := mdb.StartTransaction(tx)
	// 	if err != nil {
	// 		log.Printf("SetDelayReason: Error from mdb.StartTransaction(): %v\n", err)
	// 		return "fail", err
	// 	}
	// 	defer mdb.CloseTransaction(localtx, tx, err)

	msg, err := mdb.ZoneSetMeta(tx, z, "delay-reason", value)
	if err != nil {
		return msg, err
	}

	const sqlq = "UPDATE zones SET fsmstatus='delayed' WHERE name=?"

	_, err = tx.Exec(sqlq, z.Name)
	if err != nil {
		log.Fatalf("DocumentStop: Error from tx.Exec(%s): %v", sqlq, err)
	}
	log.Printf("%s\n", value)
	return msg, err
}

func (mdb *MusicDB) ZoneSetMeta(tx *sql.Tx, z *Zone, key, value string) (string, error) {
	if !z.Exists {
		return "", fmt.Errorf("zone %s not present in MuSiC system", z.Name)
	}

	if tx == nil {
		panic("tx=nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("ZoneSetMeta: Error from mdb.StartTransaction(): %v\n", err)
	//		return "fail", err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlq = "INSERT OR REPLACE INTO metadata (zone, key, time, value) VALUES (?, ?, datetime('now'), ?)"
	_, err := tx.Exec(sqlq, z.Name, key, value)
	if CheckSQLError("ZoneSetMeta", sqlq, err, false) {
		return "", err
	}

	const sqlq2 = "UPDATE zones SET zonetype=? WHERE name=?"

	_, err = tx.Exec(sqlq2, z.ZoneType, z.Name)
	if CheckSQLError("ZoneSetMeta", sqlq2, err, false) {
		return "", err
	}

	return fmt.Sprintf("Zone %s metadata '%s' updated to be '%s'",
		z.Name, key, value), nil
}

/*
rog: This is replaced by *MusicDB GetStopReason allow some time and test and then remove.
func (mdb *MusicDB) ZoneGetMeta(tx *sql.Tx, z *Zone, key string) (string, error) {
	if !z.Exists {
		return "", fmt.Errorf("Zone %s not present in MuSiC system.", z.Name)
	}

	if tx == nil { panic("tx=nil") }
//	localtx, tx, err := mdb.StartTransaction(tx)
//	if err != nil {
// 		log.Printf("ZoneGetMeta: Error from mdb.StartTransaction(): %v\n", err)
// 		return "fail", err
// 	}
// 	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlq = "SELECT value FROM metadata WHERE zone=? AND key=?"

	row := tx.QueryRow(sqlq, z.Name, key)
	if CheckSQLError("ZoneGetMeta", sqlq, err, false) {
		return "", err
	}

	var value string
	switch err = row.Scan(&value); err {
	case sql.ErrNoRows:
		return "", err
	case nil:
		return value, nil
	}
	return "", nil
}
*/

func (z *Zone) StateTransition(tx *sql.Tx, from, to string) error {
	mdb := z.MusicDB
	fsm := z.FSM

	log.Printf("$$$ ROG -> Starting StateTransition with %v as tx", tx)

	if tx == nil {
		panic("tx=nil")
	}
	fmt.Printf("This is %s StateTransition(%s-->%s) in process %s\n", z.Name, from, to, fsm)
	if fsm == "" {
		return fmt.Errorf("zone %s is not currently in any ongoing process", z.Name)
	}

	if z.State != from {
		return fmt.Errorf("StateTransition: Error: zone %s is in state '%s'. Should be '%s'",
			z.Name, z.State, from)
	}

	// XXX: This should not be needed anymore, but leaving it until we know new stop is robust.
	if from == FsmStateStop && to == FsmStateStop {
		log.Printf("StateTransition: terminal state reached. Exiting process.\n")
		to = "---"
		fsm = "---"
	}

	log.Printf("$$$ ROG -> updating DB  with %v as tx, to status: %s, fsm: %s, zone: %s", tx, to, fsm, z.Name)
	_, err := tx.Exec("UPDATE zones SET state=?, fsm=?, fsmstatus=? WHERE name=?", to, fsm, "", z.Name)
	if err != nil {
		log.Printf("$$$ StateTransition: Error from tx.Exec(): %v\n", err)
		return err
	}
	_, err = mdb.ZoneSetMeta(tx, z, "stop-reason", "") // remove old stop-reason if there
	if err != nil {
		log.Printf("StateTransition: Error from ZoneSetMeta: %v\n", err)
		return err
	}
	// XXX TODO: this is not correct it should only trigger if we have no error
	log.Printf("Zone %s transitioned from %s to %s in process %s", z.Name, from, to, fsm)
	return nil
	//}
}

func (mdb *MusicDB) ApiGetZone(tx *sql.Tx, zonename string) (*Zone, bool, error) {
	zone, exists, err := mdb.GetZone(tx, zonename)
	if err != nil {
		return nil, false, err
	}
	zone.MusicDB = nil
	zone.SGroup = nil // another one
	return zone, exists, nil
}

func (mdb *MusicDB) GetZone(tx *sql.Tx, zonename string) (*Zone, bool, error) {

	if tx == nil {
		panic("tx=nil")
	}
	// 	localtx, tx, err := mdb.StartTransaction(tx)
	// 	if err != nil {
	// 		log.Printf("GetZone: Error from mdb.StartTransaction(): %v\n", err)
	// 		// return err, "fail"
	// 		return nil, false, err
	// 	}
	// 	defer mdb.CloseTransaction(localtx, tx, err)

	const qsql = `
SELECT name, zonetype, state, fsmmode, COALESCE(statestamp, datetime('now')) AS timestamp,
       fsm, fsmsigner, COALESCE(sgroup, '') AS signergroup
FROM zones WHERE name=?`

	row := tx.QueryRow(qsql, zonename)

	var name, zonetype, state, fsmmode, timestamp, fsm, fsmsigner, signergroup string
	switch err := row.Scan(&name, &zonetype, &state, &fsmmode, &timestamp,
		&fsm, &fsmsigner, &signergroup); err {
	case sql.ErrNoRows:
		// fmt.Printf("GetZone: Zone \"%s\" does not exist\n", zonename)
		return &Zone{
			Name:   zonename,
			Exists: false,
		}, false, nil // not an error

	case nil:
		t, err := time.Parse(layout, timestamp)
		if err != nil {
			log.Fatal("GetZone: Error from time.Parse():", err)
			return nil, false, err
		}

		sg, err := mdb.GetSignerGroup(tx, signergroup, false) // not apisafe
		if err != nil {
			return nil, false, err
		}

		nexttransitions := mdb.FSMlist[fsm].States[state].Next
		next := map[string]bool{}
		for k := range nexttransitions {
			next[k] = true
		}

		return &Zone{
			Name:       name,
			Exists:     true,
			ZoneType:   zonetype,
			State:      state,
			FSMMode:    fsmmode,
			Statestamp: t,
			NextState:  next,
			FSM:        fsm,
			FSMSigner:  fsmsigner, // is this still used for anything?
			SGroup:     sg,
			SGname:     sg.Name,
			MusicDB:    mdb, // can not be json encoded, i.e. not used in API
		}, true, nil

	default:
		log.Fatalf("GetZone: error from row.Scan(): name=%s, err=%v", zonename, err)
	}
	return &Zone{
		Name:   zonename,
		Exists: false,
	}, false, nil
}

func (mdb *MusicDB) GetSignerGroupZones(tx *sql.Tx, sg *SignerGroup) ([]*Zone, error) {
	var zones = []*Zone{}

	if tx == nil {
		panic("tx=nil")
	}
	// 	localtx, tx, err := mdb.StartTransaction(tx)
	// 	if err != nil {
	// 		log.Printf("GetSignerGroup: Error from mdb.StartTransaction(): %v\n", err)
	// 		return zones, err
	// 	}
	// 	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlq = `
SELECT name, state, COALESCE(statestamp, datetime('now')) AS timestamp, fsm FROM zones WHERE sgroup=?`

	rows, err := tx.Query(sqlq, sg.Name)
	if err != nil {
		log.Printf("GetSignerGroupZones: Error from SQL query: %v", err)
		return zones, err
	}
	defer rows.Close()

	if CheckSQLError("GetSignerGroupZones", sqlq, err, false) {
		log.Printf("GetSignerGroupZones: Error from SQL query: %v", err)
		return zones, err
	} else {
		rowcounter := 0
		var name, state, fsm, timestamp string
		for rows.Next() {
			err := rows.Scan(&name, &state, &timestamp, &fsm)
			if err != nil {
				log.Fatal("GetSignerGroupZones: Error from rows.Next():", err)
			}

			t, err := time.Parse(layout, timestamp)
			if err != nil {
				log.Fatal("GetSignerGroupZones: Error from time.Parse():", err)
			}

			zones = append(zones, &Zone{
				Name:       name,
				Exists:     true,
				State:      state,
				Statestamp: t,
				FSM:        fsm,
				SGroup:     sg,
				MusicDB:    mdb,
			})
			rowcounter++
		}
	}
	return zones, nil
}

// When a zone joins a signer group it could be that the signer group
// is in a state of transition (incoming or departing signer). In that
// case, shouldn't the new zone immediately also enter that process?

// Or, perhaps the new zone should enter the "add-signer" process
// regardless of the state of the signer group? I.e. from the POV of the
// zone, "joining" the signer group (that has signers) by definition
// causes signers to be added (for that zone).

// Current thinking: it should not be possible to enter (or leave) a
// signer group that is in an add-signer or remove-signer process. The
// problem with that is that // if a zone joining then automatically
// enters the add-signer process, then we "lock" the signer group until
// the new zone is in sync. That seems... bad.

// So perhaps the new zone going through "add-signer" is different
// from the entire signer group going through "add-signer"? In that case,
// perhaps the right thing is to "lock" the signer group when the entire
// group enters a proceess (and unlock when all zones are done)

func (mdb *MusicDB) ZoneJoinGroup(tx *sql.Tx, dbzone *Zone, g string,
	enginecheck chan EngineCheck) (string, error) {
	var group *SignerGroup
	var err error

	if tx == nil {
		panic("tx=nil")
	}

	if !dbzone.Exists {
		return "", fmt.Errorf("Zone %s unknown", dbzone.Name)
	}

	if group, err = mdb.GetSignerGroup(tx, g, false); err != nil { // not apisafe
		return "", err
	}

	sg := dbzone.SignerGroup()

	// must test for existence of sg, as after AddZone() it is still nil
	if sg != nil && sg.Name != "" {
		return "", fmt.Errorf("zone %s already assigned to signer group %s",
			dbzone.Name, sg.Name)
	}

	// Is the signer group locked (because of being in a process
	// that precludes zones joining or leaving)?
	if group.Locked {
		return "", fmt.Errorf("signer group %s locked from zones joining or leaving due to ongoing '%s' process",
			group.Name, group.CurrentProcess)

	}

	// 	localtx, tx, err := mdb.StartTransaction(tx)
	// 	if err != nil {
	// 		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	// 		return "fail", err
	// 	}
	// 	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlq = "UPDATE zones SET sgroup=? WHERE name=?"

	_, err = tx.Exec(sqlq, g, dbzone.Name)
	if CheckSQLError("JoinGroup", sqlq, err, false) {
		return fmt.Sprintf("Error from tx.Exec(%s): %v", sqlq, err), err
	}

	dbzone, _, err = mdb.GetZone(tx, dbzone.Name)
	if err != nil {
		return fmt.Sprintf("Error from mdb.GetZone(%s): %v", dbzone.Name, err), err
	}

	// If the new zone is not already in a process then we put it in the
	// VerifyZoneInSyncProcess as a method of ensuring that it is in sync.
	// This process is currently a no-op, but doesn't have to be.
	if dbzone.FSM == "" || dbzone.FSM == "---" {
		msg, err := mdb.ZoneAttachFsm(tx, dbzone, SignerJoinGroupProcess,
			"all", false) // false=no preempting
		if err != nil {
			return msg, err
		}

		enginecheck <- EngineCheck{ZoneName: dbzone.Name}
		return fmt.Sprintf(
			"Zone %s has joined signer group %s and started the process '%s'.",
			dbzone.Name, g, SignerJoinGroupProcess), nil
	}

	enginecheck <- EngineCheck{ZoneName: dbzone.Name}
	return fmt.Sprintf(
		`Zone %s has joined signer group %s but could not start the process '%s'
as the zone is already in process '%s'. Problematic.`, dbzone.Name,
		g, SignerJoinGroupProcess, dbzone.FSM), nil
}

// Leaving a signer group is different from joining in the sense that
// if the group is locked (due to ongoing process) a zone cannot join at
// all, but it is always possible to leave. Apart from being a basic
// observation of the zone owners right to always decide what it wants to
// do it is also a "safe" mechanism, as part of the point with MUSIC and
// the multi-signer mechanism in general is that every single state in every
// process is a stable and fully functioning state. I.e regarless of where
// a zone may decide to jump ship it will not be dangrous to eith the child,
// nor the signer group if this occurs.

func (mdb *MusicDB) ZoneLeaveGroup(tx *sql.Tx, dbzone *Zone, g string) (string, error) {
	if !dbzone.Exists {
		return "", fmt.Errorf("Zone %s unknown", dbzone.Name)
	}

	if tx == nil {
		panic("tx=nil")
	}

	if _, err := mdb.GetSignerGroup(tx, g, false); err != nil { // not apisafe
		return "", err
	}

	sg := dbzone.SignerGroup()

	if sg.Name != g {
		return "", fmt.Errorf("Zone %s is not assigned to signer group %s",
			dbzone.Name, g)
	}

	const sqlq = "UPDATE zones SET sgroup='', state='', fsm='' WHERE name=?"

	_, err := tx.Exec(sqlq, dbzone.Name)
	if CheckSQLError("ZoneLeaveGroup", sqlq, err, false) {
		return "", err
	}

	// -------
	leavemsg := fmt.Sprintf("Zone %s has left the signer group %s.", dbzone.Name, sg.Name)
	processcomplete, msg, err := mdb.CheckIfProcessComplete(tx, sg)
	if err != nil {
		return fmt.Sprintf("Error from CheckIfProcessComplete(): %v", err), err
	}
	if processcomplete {
		return leavemsg + "\n" + msg, nil
	}
	return leavemsg, nil
}

const (
	layout = "2006-01-02 15:04:05"
)

func (mdb *MusicDB) ListZones(tx *sql.Tx) (map[string]Zone, error) {
	var zl = make(map[string]Zone, 10)

	if tx == nil {
		panic("tx=nil")
	}

	const sqlq = `
SELECT name, zonetype, state, fsm, fsmmode, fsmstatus,
  COALESCE(statestamp, datetime('now')) AS timestamp,
  COALESCE(sgroup, '') AS signergroup
FROM zones`

	rows, err := tx.Query(sqlq)
	if err != nil {
		log.Printf("ListZones: Error from db query: %v", err)
	}
	defer rows.Close()

	if CheckSQLError("ListZones", sqlq, err, false) {
		return zl, err
	} else {
		rowcounter := 0
		var name, zonetype, state, fsm, fsmmode, fsmstatus string
		var timestamp string
		var signergroup, stopreason string
		for rows.Next() {
			err := rows.Scan(&name, &zonetype, &state, &fsm, &fsmmode,
				&fsmstatus, &timestamp, &signergroup)
			fmt.Printf("ListZones: name=%s type=%s, state=%s fsm=%s, fsmmode=%s group='%s'\n", name, zonetype, state, fsm, fsmmode, signergroup)
			if err != nil {
				log.Fatal("ListZones: Error from rows.Next():", err)
			}
			t, err := time.Parse(layout, timestamp)
			if err != nil {
				log.Fatal("ListZones: Error from time.Parse():", err)
			}

			sg := &SignerGroup{}
			if signergroup != "" {
				sg, err = mdb.GetSignerGroup(tx, signergroup, true) // apisafe
				if err != nil {
					return zl, err
				}
			} else {
				sg.Name = signergroup
			}

			nexttransitions := mdb.FSMlist[fsm].States[state].Next
			next := map[string]bool{}
			for k := range nexttransitions {
				next[k] = true
			}

			tz := Zone{
				Name:       name,
				Exists:     true,
				ZoneType:   zonetype,
				State:      state,
				FSMMode:    fsmmode,
				FSMStatus:  fsmstatus,
				Statestamp: t,
				NextState:  next,
				FSM:        fsm,
				SGroup:     sg,
				SGname:     sg.Name,
			}

			if fsmstatus == "blocked" {
				stopreason, _, err = mdb.GetStopReason(tx, &tz)
				if err != nil {
					return zl, err
				}
				log.Printf("ListZones: zone %s is blocked. reason: '%s'", name, stopreason)
				tz.StopReason = stopreason
			}
			zl[name] = tz

			rowcounter++
		}
		// fmt.Printf("ListZones: rowcounter: %d zonemap: %v\n", rowcounter, zl)
	}

	return zl, nil
}
