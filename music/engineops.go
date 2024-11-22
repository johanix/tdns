/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	"log"
	"strings"
)

const (
	AutoZones = `
SELECT name, zonetype, fsm, fsmsigner, fsmstatus
FROM zones WHERE fsmmode='auto' AND fsm != '' AND fsmstatus != 'blocked'`
	AllAutoZones = `
SELECT name, zonetype, fsm, fsmsigner, fsmstatus
FROM zones WHERE fsmmode='auto' AND fsm != ''`
)

// PushZones: Try to move all "auto" zones forward through their respective processes until they
//            hit a stop.
//
// Note that we also need to add management for:
// (a) trying stopped zones, but less frequently, as they may have become unwedged
// (b)

func (mdb *MusicDB) PushZones(tx *sql.Tx, checkzones map[string]bool, checkall bool) ([]Zone, error) {
	var zones []Zone
	var err error

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return zones, err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	sqlq := AutoZones
	if checkall {
		sqlq = AllAutoZones
	}

	rows, err := tx.Query(sqlq)
	if err != nil {
		log.Printf("PushZones: Error from tx.Query(%s): %v", sqlq, err)
		return zones, err
	}
	defer rows.Close()

	if CheckSQLError("PushZones", AutoZones, err, false) {
		return zones, err
	} else {
		var name, zonetype, fsm, fsmsigner, fsmstatus string
		for rows.Next() {
			err := rows.Scan(&name, &zonetype, &fsm, &fsmsigner, &fsmstatus)
			if err != nil {
				log.Fatalf("PushZones: Error from rows.Scan: %v", err)
			}

			z := Zone{Name: name, FSMStatus: fsmstatus}

			if len(checkzones) == 0 {
				zones = append(zones, z)
			} else {
				if checkzones[name] {
					zones = append(zones, z)
				}
			}
		}
	}

	var tmperr error
	if len(zones) > 0 {
		zonelist := []string{}
		for _, z := range zones {
			zonelist = append(zonelist, z.Name)
		}

		log.Printf("PushZones: will push on these zones: %v", strings.Join(zonelist, " "))
		for _, z := range zones {
			if z.FSMStatus == "delayed" {
				log.Printf("PushZones: zone %s is delayed until %v. Leaving for now.",
					z.Name, "time-when zone-has-waited-long-enough")
			} else {
				tmperr = mdb.PushZone(z)
				if err == nil {
					err = tmperr // save first error encountered
				}
			}
		}
	}
	return zones, err
}

func (mdb *MusicDB) PushZone(z Zone) error {
	tx, err := mdb.StartTransactionNG()
	if err != nil {
		log.Printf("PushZone: Error from mdb.StartTransactionNG(): %v\n", err)
		return err
	}
	defer mdb.CloseTransactionNG(tx, err)

	dbzone, _, err := mdb.GetZone(tx, z.Name)
	if err != nil {
		return err
	}
	success, _, _ := mdb.ZoneStepFsm(tx, dbzone, "")
	oldstate := dbzone.State
	if success {
		dbzone, _, err := mdb.GetZone(tx, z.Name)
		if err != nil {
			return err
		}
		log.Printf("PushZone: successfully transitioned zone '%s' from '%s' to '%s'",
			z.Name, oldstate, dbzone.State)
	} else {
		log.Printf("PushZone: failed to transition zone '%s' from state '%s'",
			z.Name, oldstate)
	}
	return nil
}
