/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func (s *Signer) MusicDB() *MusicDB {
	return s.DB
}

func (mdb *MusicDB) AddSigner(tx *sql.Tx, dbsigner *Signer, group string) (string, error) {
	var err error
	msg := fmt.Sprintf("Failed to add new signer %s.", dbsigner.Name)

	if tx == nil {
		panic("tx == nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("AddSigner: Error from mdb.StartTransaction(): %v\n", err)
	//		return msg, err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	if dbsigner.Exists {
		return "", fmt.Errorf("signer %s already present in system",
			dbsigner.Name)
	}

	updatermap := ListUpdaters()
	_, ok := updatermap[dbsigner.Method]

	if !ok {
		return "", fmt.Errorf(
			"unknown signer method: %s. Known methods are: %v", dbsigner.Method, updatermap)
	}

	if dbsigner.Method == "ddns" || dbsigner.Method == "rlddns" {
		if dbsigner.Auth.TSIGKey != "" {
			dbsigner.AuthStr = fmt.Sprintf("%s:%s:%s", dbsigner.Auth.TSIGAlg,
				dbsigner.Auth.TSIGName, dbsigner.Auth.TSIGKey)
		}
	}

	const sqlq = `
	INSERT INTO signers(name, method, auth, addr, port, usetcp, usetsig) VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.Exec(sqlq, dbsigner.Name, dbsigner.Method,
		dbsigner.AuthStr, dbsigner.Address, dbsigner.Port, dbsigner.UseTcp, dbsigner.UseTSIG)
	if err != nil {
		log.Printf("AddSigner: failure: %s, %s, %s, %s, %s, %t, %t\n",
			dbsigner.Name, dbsigner.Method, dbsigner.AuthStr,
			dbsigner.Address, dbsigner.Port, dbsigner.UseTcp, dbsigner.UseTSIG)
		return msg, err
	}

	if group != "" {
		log.Printf("AddSigner: signer %s has the signergroup %s specified so we set that too\n",
			dbsigner.Name, group)
		dbsigner, err := mdb.GetSigner(tx, dbsigner, false) // no need for apisafe
		if err != nil {
			return msg, err
		}

		_, err = mdb.SignerJoinGroup(tx, dbsigner, group) // we know that the signer exist
		if err != nil {
			return fmt.Sprintf("AddSigner: Error joinging new signer %s to group %s: %v",
				dbsigner.Name, group, err), err
		}
		return fmt.Sprintf("Signer %s was added and immediately attached to signer group %s.",
			dbsigner.Name, group), nil
	}

	log.Printf("AddSigner: success: %s, %s, %s, %s, %s\n", dbsigner.Name,
		dbsigner.Method, dbsigner.AuthStr, dbsigner.Address, dbsigner.Port)
	return fmt.Sprintf("New signer %s successfully added.", dbsigner.Name), nil
}

func (mdb *MusicDB) UpdateSigner(tx *sql.Tx, dbsigner *Signer, us Signer) (string, error) {
	var err error
	if !dbsigner.Exists {
		return "", fmt.Errorf("signer %s not present in system",
			dbsigner.Name)
	}

	if tx == nil {
		panic("tx == nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	//		return fmt.Sprintf("UpdateSigner: Error from mdb.StartTransaction(): %v", err), err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	updatermap := ListUpdaters()
	_, ok := updatermap[dbsigner.Method]
	if !ok {
		return "", fmt.Errorf("unknown signer method: %s. Known methods are: %v",
			dbsigner.Method, updatermap)
	}

	if us.Method != "" {
		dbsigner.Method = us.Method

		if us.Auth.TSIGKey != "" { // only possible to update auth data together with method
			dbsigner.Auth = us.Auth
			dbsigner.AuthStr = fmt.Sprintf("%s:%s:%s", us.Auth.TSIGAlg, us.Auth.TSIGName, us.Auth.TSIGKey)
		}
	}

	if us.Address != "" {
		dbsigner.Address = us.Address
	}

	if us.Port != "" {
		dbsigner.Port = us.Port
	}

	// Cannot check for existence of a bool value by whether it is true or not
	dbsigner.UseTcp = us.UseTcp
	dbsigner.UseTSIG = us.UseTSIG

	const sqlq = "UPDATE signers SET method=?, auth=?, addr=?, port=?, usetcp=?, usetsig=? WHERE name =?"

	_, err = tx.Exec(sqlq, dbsigner.Method, dbsigner.AuthStr, dbsigner.Address, dbsigner.Port,
		dbsigner.UseTcp, dbsigner.UseTSIG, dbsigner.Name)
	if err != nil {
		log.Printf("UpdateSigner: Error from tx.Exec(%s): %v\n", sqlq, err)
		return fmt.Sprintf("UpdateSigner: Error from tx.Exec: %v", err), err
	}

	log.Printf("UpdateSigner: success: %s, %s, %s, %s, %s\n", dbsigner.Name,
		dbsigner.Method, dbsigner.Auth,
		dbsigner.Address, dbsigner.Port)
	return fmt.Sprintf("Signer %s successfully updated.", dbsigner.Name), nil
}

// SignerJoinGroup(): add an already defined signer to an already defined signer group.
//
// Note: this should trigger all zones attached to this signer group to enter
// the "add-signer" process and the signer will be put in the PendingAddition slot until the zones
// are done with that process.

// XXX: I think we have this one more or less correct now.

func (mdb *MusicDB) SignerJoinGroup(tx *sql.Tx, dbsigner *Signer, g string) (string, error) {
	var sg *SignerGroup
	var err error

	if tx == nil {
		panic("tx == nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	//		return "SignerJoinGroup: Error starting transaction", err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	if !dbsigner.Exists {
		return "", fmt.Errorf("signer %s is unknown", dbsigner.Name)
	}

	if sg, err = mdb.GetSignerGroup(tx, g, false); err != nil { // not apisafe
		return "", err
	}

	if _, member := sg.SignerMap[dbsigner.Name]; member {
		return "", fmt.Errorf("Signer %s is already a member of group %s", dbsigner.Name, sg.Name)
	}

	if sg.CurrentProcess != "" {
		return "", fmt.Errorf("signer group %s is currently in the '%s' process and does not accept signer addition",
			sg.Name, sg.CurrentProcess)
	}

	if sg.PendingAddition != "" {
		return "", fmt.Errorf("Signer group %s has signer %s in the PendingAddition slot already",
			sg.Name, sg.PendingAddition)
	}

	if sg.PendingRemoval != "" {
		return "", fmt.Errorf("Signer group %s has signer %s in the PendingRemoval slot, and only one process at a time is possible",
			sg.Name, sg.PendingRemoval)
	}

	// johani: Issue #116
	// if sg.NumProcessZones != 0 {
	//	return fmt.Errorf("Signer group %s has %d zones executing processes and does not accept signer addition.",
	//		sg.Name, sg.NumProcessZones), ""
	// }

	const sqlq = "INSERT OR IGNORE INTO group_signers (name, signer) VALUES (?, ?)"

	_, err = tx.Exec(sqlq, g, dbsigner.Name)
	if CheckSQLError("SignerJoinGroup", sqlq, err, false) {
		return "", err
	}

	log.Printf("SignerJoinGroup: signers in group %s: %v\n", sg.Name, sg.SignerMap)
	if sg, err = mdb.GetSignerGroup(tx, g, false); err != nil { // not apisafe
		return "", err
	}

	// if we now have more than one signer in the signer group it is possible that they
	// are unsynced. Then we must enter the "add-signer" process to get them in sync.
	if len(sg.SignerMap) > 1 {
		zones, err := mdb.GetSignerGroupZones(tx, sg)
		if err != nil {
			return "", err
		}

		if len(zones) == 0 {
			return fmt.Sprintf(
				"Signer %s has joined signer group %s, which now has %d signers but no zones.",
				dbsigner.Name, sg.Name, len(sg.SignerMap)), nil
		}

		// At this stage we know that there are now more than one signer and more than zero
		// zones. Hence we need to enter the add-signer process for all the zones.

		const sqlq2 = "UPDATE signergroups SET curprocess=?, pendadd=?, locked=1 WHERE name=?"

		_, err = tx.Exec(sqlq2, SignerJoinGroupProcess, dbsigner.Name, sg.Name)
		if CheckSQLError("SignerJoinGroup", sqlq2, err, false) {
			return "", err
		}

		// sg.CurrentProcess = SignerJoinGroupProcess
		// sg.PendingAddition = dbsigner.Name
		// XXX: this is inefficient, but I don't think we will have enough
		//      zones in the system for that to be an issue
		for _, z := range zones {
			log.Printf("SignerJoinGroup: calling ZoneAttachFsm(%s, %s, %s)",
				z.Name, SignerJoinGroupProcess, dbsigner.Name)
			msg, err := mdb.ZoneAttachFsm(tx, z, SignerJoinGroupProcess, // we know that z exist
				dbsigner.Name, true) // true=preempt
			if err != nil {
				log.Printf("SJG: Error from ZAF: %v", err)
				return "", err
			}
			log.Printf("SJG: Message from ZAF: %s", msg)
		}
		return fmt.Sprintf(
			"Signer %s has joined signer group %s and %d zones have entered the 'add-signer' process.",
			dbsigner.Name, g, len(zones)), nil
	}
	return fmt.Sprintf(
		"Signer %s has joined signer group %s as the first signer. No zones entered the 'add-signer' process.",
		dbsigner.Name, g), nil
}

// Semantics:
// 1. Check whether there is any other signer already in the signergroup.PendingRemoval state
//    (if so, return error)
// 2. If not, put this signer in sg.PendingRemoval. Keep the signer among the group signers.
// 3. If there are zones connected to this group, put them in the "remove-signer" process
// 4. If there are no zones

// XXX: Note that this function doesn't remove signers from signergroups, it only initiates a process for
//      updating zones so that a future removal may be done safely.

func (mdb *MusicDB) SignerLeaveGroup(tx *sql.Tx, dbsigner *Signer, g string) (string, error) {
	var sg *SignerGroup
	var err error

	if tx == nil {
		panic("tx==nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	//		return "Error starting transaction", err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	if !dbsigner.Exists {
		return "", fmt.Errorf("signer %s is unknown", dbsigner.Name)
	}

	if sg, err = mdb.GetSignerGroup(tx, g, false); err != nil { // not apisafe
		return "", err
	}

	if _, member := sg.SignerMap[dbsigner.Name]; !member {
		return "", fmt.Errorf("Signer %s is not a member of group %s", dbsigner.Name, sg.Name)
	}

	if sg.CurrentProcess != "" {
		return "", fmt.Errorf("signer group %s is currently in the '%s' process and does not accept signer removal",
			sg.Name, sg.CurrentProcess)
	}

	if sg.PendingRemoval != "" {
		return "", fmt.Errorf("Signer group %s has signer %s in the PendingRemoval slot already",
			sg.Name, sg.PendingRemoval)
	}

	if sg.PendingAddition != "" {
		return "", fmt.Errorf("Signer group %s has signer %s in the PendingAddition slot, and only one process at a time is possible",
			sg.Name, sg.PendingAddition)
	}

	// johani: Issue #116
	// if sg.NumProcessZones != 0 {
	//	return fmt.Errorf("Signer group %s has %d zones executing processes and does not accept signer removal.",
	//		sg.Name, sg.NumProcessZones), ""
	// }

	zones, err := mdb.GetSignerGroupZones(tx, sg)
	if err != nil {
		return "", err
	}

	const sqlq = "DELETE FROM group_signers WHERE name=? AND signer=?"

	// If the signer group has no zones attached to it, then it is ok to remove
	// a signer immediately
	if len(zones) == 0 {
		_, err = tx.Exec(sqlq, sg.Name, dbsigner.Name)
		if CheckSQLError("SignerLeaveGroup", sqlq, err, false) {
			return "", err
		}
		return fmt.Sprintf(
			"Signer %s was removed from signer group %s immediately (because the signer group has no zones).",
			dbsigner.Name, g), nil
	}

	// It is not legal to remove the last signer in a signer group with zones
	// (as that would cause rather obvious problems).
	if len(sg.SignerMap) == SignerGroupMinimumSigners {
		return "", fmt.Errorf(
			"the signer group %s has %d zones but only %d signer, %s, which can therefore not be removed",
			sg.Name, len(zones), SignerGroupMinimumSigners, dbsigner.Name)
	}

	const sqlq3 = "UPDATE signergroups SET curprocess=?, pendremove=?, locked=1 WHERE name=?"

	_, err = tx.Exec(sqlq3, SignerLeaveGroupProcess, dbsigner.Name, sg.Name)
	if CheckSQLError("SignerLeaveGroup", sqlq3, err, false) {
		return "", err
	}

	// XXX: this is inefficient, but I don't think we will have enough
	//      zones in the system for that to be an issue
	for _, z := range zones {
		_, err := mdb.ZoneAttachFsm(tx, z, SignerLeaveGroupProcess, // we know that z exist
			dbsigner.Name, true) // true=preempt
		if err != nil {
			return fmt.Sprintf("Failed to attach zone %s to the REMOVE-SIGNER process as signer %s is leaving.",
				z.Name, dbsigner.Name), err
		}
	}

	// https://github.com/DNSSEC-Provisioning/music/issues/130, testing to remove the leaving signer from the signermap. /rog
	log.Printf("remove %v from SignerMap %v: for %v", dbsigner.Name, sg.SignerMap, sg.Name)
	log.Printf("signerops: signer group %+v\n", sg)
	delete(sg.SignerMap, dbsigner.Name)
	if _, member := sg.SignerMap[dbsigner.Name]; member {
		return "", fmt.Errorf("Signer %s is still a member of group %s", dbsigner.Name, sg.Name)
	}

	return fmt.Sprintf(
		"Signer %s is in pending removal from signer group %s and therefore %d zones entered the '%s' process.",
		dbsigner.Name, g, len(zones), SignerLeaveGroupProcess), nil
}

// XXX: It should not be possible to delete a signer that is part of a signer group.
//
//	Full stop.
func (mdb *MusicDB) DeleteSigner(tx *sql.Tx, dbsigner *Signer) (string, error) {

	if tx == nil {
		panic("tx==nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	//		return "fail", err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	sgs := dbsigner.SignerGroups
	if len(sgs) != 0 {
		return "", fmt.Errorf(
			"signer %s can not be deleted as it is part of the signer groups %v",
			dbsigner.Name, sgs)
	}

	const dsql = "DELETE FROM signers WHERE name=?"
	_, err := tx.Exec(dsql, dbsigner.Name)
	if CheckSQLError("DeleteSigner", dsql, err, false) {
		return "", err
	}

	// This should be a no-op, as the signer must not be a member of any group.
	// But we keep it as a GC mechanism in case something has gone wrong.
	const dsql2 = "DELETE FROM group_signers WHERE signer=?"

	_, err = tx.Exec(dsql2, dbsigner.Name)
	if CheckSQLError("DeleteSigner", dsql2, err, false) {
		return "", err
	}
	return fmt.Sprintf("Signer %s deleted.", dbsigner.Name), nil
}

func (mdb *MusicDB) ListSigners(tx *sql.Tx) (map[string]Signer, error) {
	var sl = make(map[string]Signer, 2)

	if tx == nil {
		panic("tx==nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	//	if err != nil {
	//		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
	//		return nil, err
	//	}
	//	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlq = "SELECT name, method, addr, auth, port FROM signers"
	rows, err := tx.Query(sqlq)
	if err != nil {
		log.Printf("ListSigners: Error from tx.Query: %v", err)
		return sl, err
	}
	defer rows.Close()

	var name, method, address, authstr, port string
	for rows.Next() {
		err := rows.Scan(&name, &method, &address, &authstr, &port)
		if err != nil {
			log.Fatal("ListSigners: Error from rows.Next():", err)
		}

		auth := AuthData{}
		authparts := strings.Split(authstr, ":")
		log.Printf("ListSigners: authparts: '%s'", authparts)
		if len(authparts) == 3 {
			auth = AuthData{
				TSIGAlg:  authparts[0],
				TSIGName: authparts[1],
				TSIGKey:  authparts[2],
			}
		}
		s := Signer{
			Name:    name,
			Exists:  true,
			Method:  method,
			Address: address,
			AuthStr: authstr, // AuthDataTmp(auth), // TODO: Issue #28
			Auth:    auth,    // AuthDataTmp(auth), // TODO: Issue #28
			Port:    port,
		}
		sgs, err := mdb.GetSignerGroups(tx, name)
		if err != nil {
			log.Fatalf("mdb.ListSigners: Error from mdb.GetSignerGroups: %v",
				err)
		}
		s.SignerGroups = sgs
		sl[name] = s
	}
	return sl, nil
}

// XXX: not used anymore, should die
// XXX: how is login to API-based signers done w/o this?
func (mdb *MusicDB) SignerLogin(dbsigner *Signer, cliconf *CliConfig, tokvip *viper.Viper) (string, error) {
	switch dbsigner.Method {
	case "ddns":
		return "", fmt.Errorf("signer %s has method=ddns: No login required", dbsigner.Name)

		//	case "desec-api":
		//		api := GetUpdater("desec-api").GetApi()
		//		dlr, err = api.DesecLogin()
		//		if err != nil {
		//			return fmt.Errorf("SignerLogin: error from DesecLogin: %v",
		//				err), ""
		//		}

		//		if dlr.Token != "" {
		//			endtime := dlr.Created.Add(dlr.MaxUnused)
		//			msg = fmt.Sprintf("New token received and stored. It is valid until %v",
		//				endtime.Format("2006-01-02 15:04:05"))
		//		} else {
		//			msg = "Something happened. No token received. Hmm?"
		//		}
	default:
		return "", fmt.Errorf("signer %s has method=%s, which is unknown", dbsigner.Name, dbsigner.Method)
	}
}

// XXX: not used anymore, should die
// XXX: how is login to API-based signers done w/o this?
func (mdb *MusicDB) SignerLogout(dbsigner *Signer, cliconf *CliConfig, tokvip *viper.Viper) (string, error) {
	// var err error
	var msg string

	switch dbsigner.Method {
	case "ddns":
		return "", fmt.Errorf("signer %s has method=ddns: No logout required",
			dbsigner.Name)

		//	case "desec":
		//		err = DesecLogout(cliconf, tokvip)
		//		if err != nil {
		//			return fmt.Errorf("SignerLogout: error from DesecLogout: %v",
		//				err), ""
		//		}
		//		msg = "Logout from deSEC complete."
	}
	return msg, nil
}

func (mdb *MusicDB) SaveSigners(tx *sql.Tx) error {
	_, _ = mdb.ListSigners(tx)

	return nil
}
