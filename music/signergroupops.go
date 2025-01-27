/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func (mdb *MusicDB) AddSignerGroup(tx *sql.Tx, sg string) (string, error) {
	fmt.Printf("AddSignerGroup(%s)\n", sg)

	if sg == "" {
		return "", errors.New("Signer group without name cannot be created")
	}

	if tx == nil {
		panic("tx=nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("AddSignerGroup: Error from mdb.StartTransaction(): %v\n", err)
	//		return "fail", err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	_, err := mdb.GetSignerGroup(tx, sg, false)
	if err == nil {
		return fmt.Sprintf("Signergroup %s already exists.", sg), err
	}

	const addcmd = "INSERT OR REPLACE INTO signergroups(name) VALUES (?)"

	_, err = tx.Exec(addcmd, sg)

	if CheckSQLError("AddSignerGroup", addcmd, err, false) {
		return fmt.Sprintf("Signergroup %s not created. Reason: %v", sg, err), err
	}
	return fmt.Sprintf("Signergroup %s created.", sg), nil
}

func (mdb *MusicDB) GetSignerGroup(tx *sql.Tx, sg string, apisafe bool) (*SignerGroup, error) {
	if sg == "" {
		return &SignerGroup{}, nil // A non-existent signergroup is not an error
	}

	if tx == nil {
		panic("tx=nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	//		return nil, err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlq = `
SELECT name, locked, COALESCE(curprocess, '') AS curp, COALESCE(pendadd, '') AS padd,
COALESCE(pendremove, '') AS prem FROM signergroups WHERE name=?`

	row := tx.QueryRow(sqlq, sg)

	var sqllocked int
	var err error
	var name, curprocess, pendadd, pendremove string
	switch err = row.Scan(&name, &sqllocked, &curprocess, &pendadd, &pendremove); err {
	case sql.ErrNoRows:
		fmt.Printf("GetSignerGroup: Signer group \"%s\" does not exist\n", sg)
		return &SignerGroup{}, fmt.Errorf("GetSignerGroup: Signer group \"%s\" does not exist", sg)
	case nil:
		sm, err := mdb.GetGroupSigners(tx, name, apisafe)
		if err != nil {
			return nil, err
		}
		dbref := mdb
		if apisafe {
			dbref = nil
		}

		sg := SignerGroup{
			Name:            name,
			Locked:          sqllocked == 1,
			CurrentProcess:  curprocess,
			PendingAddition: pendadd,
			PendingRemoval:  pendremove,
			SignerMap:       sm,
			DB:              dbref,
		}

		zones, _ := mdb.GetSignerGroupZones(tx, &sg)
		pzones := 0
		for _, z := range zones {
			if z.FSM != "" {
				pzones++
			}
		}
		sg.NumZones = len(zones)
		sg.NumProcessZones = pzones
		return &sg, nil

	default:
		log.Fatalf("GetSignerGroup: error from row.Scan(): name=%s, err=%v", sg, err)
	}
	return &SignerGroup{}, err
}

// DeleteSignerGroup: it is always possible to delete a signer group.
// * If there are signers that are part of the signer group then they are thrown out.
// * If there are zones that are part of the signer group, then they are thrown out.
// Obviously, deleting a signer
// group is a major change that should not be undertaken lightly, but at the same time it is
// more or less the only tool we have to force a cleanup if or when stuff has gotten seriously
// out of whack.

func (mdb *MusicDB) DeleteSignerGroup(tx *sql.Tx, group string) (string, error) {

	if tx == nil {
		panic("tx=nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("DeleteSignerGroup: Error from mdb.StartTransaction(): %v\n", err)
	//		return "fail", err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	_, err := mdb.GetSignerGroup(tx, group, false)
	if err != nil {
		return fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err), err
	}

	const sqlq = "DELETE FROM signergroups WHERE name=?"

	_, err = tx.Exec(sqlq, group)
	if CheckSQLError("DeleteSignerGroup", sqlq, err, false) {
		return fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err), err
	}

	const sqlq2 = "DELETE FROM group_signers WHERE name=?"

	_, err = tx.Exec(sqlq2, group)
	if CheckSQLError("DeleteSignerGroup", sqlq2, err, false) {
		return fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err), err
	}

	const sqlq3 = "UPDATE zones SET sgroup='' WHERE sgroup=?"

	_, err = tx.Exec(sqlq3, group)
	if CheckSQLError("DeleteSignerGroup", sqlq3, err, false) {
		return fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err), err
	}

	return fmt.Sprintf("Signergroup %s deleted. Any zones or signers in signergroup were detached.", group),
		nil
}

func (mdb *MusicDB) ListSignerGroups(tx *sql.Tx) (map[string]SignerGroup, error) {
	var sgl = make(map[string]SignerGroup, 2)

	if tx == nil {
		panic("tx=nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	//		return sgl, err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlq = `
SELECT name, COALESCE(curprocess, '') AS curp, COALESCE (pendadd, '') AS padd,
COALESCE(pendremove, '') AS prem, locked FROM signergroups`

	rows, err := tx.Query(sqlq)
	if CheckSQLError("ListSignerGroups", sqlq, err, false) {
		return sgl, err
	} else {
		var name, curp, pendadd, pendrem string
		var sqllocked int
		for rows.Next() {
			err := rows.Scan(&name, &curp, &pendadd, &pendrem, &sqllocked)
			if err != nil {
				return nil, fmt.Errorf("ListSignerGroups: Error from rows.Next(): %v", err)
			}
			sgl[name] = SignerGroup{
				Name:            name,
				Locked:          sqllocked == 1,
				CurrentProcess:  curp,
				PendingAddition: pendadd,
				PendingRemoval:  pendrem,
			}
		}
	}
	rows.Close()

	for sgname, sg := range sgl {
		const sqlq2 = "SELECT COALESCE (signer, '') AS signer2 FROM group_signers WHERE name=?"
		rows, err := tx.Query(sqlq2, sgname)
		if err != nil {
			log.Printf("ListSignerGroups: Error from tx.Query: %v", err)
			return sgl, err
		}
		defer rows.Close()

		var signer string
		var zones = []*Zone{}
		signers := map[string]*Signer{}
		for rows.Next() {
			err := rows.Scan(&signer)
			if err != nil {
				return nil, fmt.Errorf("ListSignerGroups: Error from rows.Next(): %v", err)
			}
			if signer == "" { // There may be rows with signer=="" (if group created w/o signers)
				continue
			}
			s, err := mdb.GetSignerByName(tx, signer, true) // apisafe
			if err != nil {
				return nil, fmt.Errorf("ListSignerGroups: Error from GetSigner: %v", err)
			} else {
				signers[signer] = s
			}
		}
		zones, err = mdb.GetSignerGroupZones(tx, &sg)
		if err != nil {
			return sgl, err
		}

		pzones := 0
		for _, z := range zones {
			if z.FSM != "" {
				pzones++
			}
		}

		sg.SignerMap = signers
		sg.NumZones = len(zones)
		sg.NumProcessZones = pzones
		sgl[sgname] = sg
	}

	fmt.Printf("ListSignerGroup(): %v\n", sgl)
	return sgl, nil
}

func (sg *SignerGroup) PopulateSigners(tx *sql.Tx) error {
	mdb := sg.DB

	if tx == nil {
		panic("tx=nil")
	}
	// 	localtx, tx, err := mdb.StartTransaction(tx)
	// 	if err != nil {
	// 		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	// 		return err
	// 	}
	// 	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlcmd = "SELECT name FROM signers WHERE sgroup=?"

	rows, err := tx.Query(sqlcmd, sg.Name)
	if err != nil {
		log.Printf("PopulateSigners: Error from tx.Query: %v", err)
		return err
	}
	defer rows.Close()

	var name string
	signers := map[string]*Signer{}
	for rows.Next() {
		err := rows.Scan(&name)
		if err != nil {
			return fmt.Errorf("PopulateSigners: Error from rows.Next(): %v", err)
		} else {
			s, err := mdb.GetSignerByName(tx, name, false) // not apisafe
			if err != nil {
				return fmt.Errorf("PopulateSigners: Error from GetSigner: %v", err)
			} else {
				signers[name] = s
				fmt.Printf("LSG: found signer obj for %s: %v\n", name, s)
			}
		}
	}
	sg.SignerMap = signers
	return nil
}

func (mdb *MusicDB) GetGroupSigners(tx *sql.Tx, name string, apisafe bool) (map[string]*Signer, error) {

	if tx == nil {
		panic("tx=nil")
	}
	// 	localtx, tx, err := mdb.StartTransaction(tx)
	// 	if err != nil {
	// 		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	// 		return nil, err
	// 	}
	// 	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlq = "SELECT COALESCE (signer, '') AS signer2 FROM group_signers WHERE name=?"

	rows, err := tx.Query(sqlq, name)
	if err != nil {
		log.Printf("GetGroupSigners: Error from tx.Query: %v", err)
		return nil, err
	}
	defer rows.Close()

	signers := map[string]*Signer{}

	var signer string
	for rows.Next() {
		err := rows.Scan(&signer)
		if err != nil {
			return nil, fmt.Errorf("GetGroupSigners: Error from rows.Next(): %v", err)
		}
		if signer == "" {
			continue // This does happen, not a problem
		}
		s, err := mdb.GetSignerByName(tx, signer, apisafe)
		if err != nil {
			return nil, fmt.Errorf("GGS: Error from GetSigner: %v", err)
		} else {
			signers[signer] = s
		}
	}
	return signers, nil
}

func (mdb *MusicDB) GetGroupSignersNG(tx *sql.Tx, name string, apisafe bool) (map[string]*Signer, error) {

	if tx == nil {
		panic("tx=nil")
	}
	// 	localtx, tx, err := mdb.StartTransaction(tx)
	// 	if err != nil {
	// 		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	// 		return nil, err
	// 	}
	// 	defer mdb.CloseTransaction(localtx, tx, err)

	signers := map[string]*Signer{}

	const sqlq = "SELECT signer FROM group_signers WHERE name=?"

	rows, err := tx.Query(sqlq, name)
	if err != nil {
		log.Printf("GetGroupSignersNG: Error from tx.Query: %v", err)
		return nil, err
	}
	defer rows.Close()

	var signername string
	for rows.Next() {
		err := rows.Scan(&signername)
		if err != nil {
			return nil, fmt.Errorf("GetGroupSigners: Error from rows.Next(): %v", err)
		} else {
			s, err := mdb.GetSignerByName(tx, name, apisafe)
			if err != nil {
				log.Fatalf("GGS: Error from GetSigner: %v", err)
			} else {
				signers[signername] = s
			}
		}
	}
	return signers, nil
}

// XXX: Todo: in the wrap up of a REMOVE-SIGNER the signer in PendingRemoval should be physically
//
//	removed from the signer group.
func (mdb *MusicDB) CheckIfProcessComplete(tx *sql.Tx, sg *SignerGroup) (bool, string, error) {
	var msg string

	if tx == nil {
		panic("tx=nil")
	}
	// 	localtx, tx, err := mdb.StartTransaction(tx)
	// 	if err != nil {
	// 		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	// 		return false, err.Error(), err
	// 	}
	// 	defer mdb.CloseTransaction(localtx, tx, err)

	zones, _ := mdb.GetSignerGroupZones(tx, sg)
	pzones := 0
	for _, z := range zones {
		if z.FSM != "" {
			pzones++
		}
	}

	if len(zones) == 0 || pzones == 0 {
		log.Printf("Signer group %s: process '%s' is now complete. Unlocking group.",
			sg.Name, sg.CurrentProcess)

		var sqlq string
		cp := sg.CurrentProcess
		pr := sg.PendingRemoval
		if cp == SignerJoinGroupProcess {
			sqlq = "UPDATE signergroups SET locked=0, curprocess='', pendadd='' WHERE name=?"
		} else if cp == SignerLeaveGroupProcess {
			sqlq = "UPDATE signergroups SET locked=0, curprocess='', pendremove='' WHERE name=?"
		} else if cp == "" { // curprocess is "" for zones in verify-zone-sync
			sqlq = "UPDATE signergroups SET locked=0, curprocess='', pendremove='' WHERE name=?"
		} else {
			log.Fatalf("CheckIfProcessIsComplete: Unknown process: %s. Terminating.", cp)
		}

		_, err := tx.Exec(sqlq, sg.Name)
		if err != nil {
			log.Printf("CheckIfProcessIsComplete: Error from tx.Exec(%s): %v", sqlq, err)
			return false, fmt.Sprintf("Error from tx.Exec(%s): %v", sqlq, err), err
		}

		if cp == SignerLeaveGroupProcess {
			sqlq = "DELETE FROM group_signers WHERE name=? AND signer=?"
			_, err = tx.Exec(sqlq, sg.Name, pr)
			if err != nil {
				log.Printf("CheckIfProcessIsComplete: Error from tx.Exec(%s): %v",
					sqlq, err)
				return false, fmt.Sprintf("Error from tx.Exec(%s): %v", sqlq, err), err
			}
		}

		return true, msg, nil
	}
	return false, "", nil // not an error
}
