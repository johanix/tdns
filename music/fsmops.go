/*
 * Copyright 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

func (mdb *MusicDB) ZoneAttachFsm(tx *sql.Tx, dbzone *Zone, fsm, fsmsigner string,
	preempt bool) (string, error) {

	var msg string

	if tx == nil {
		panic("tx=nil")
	}
	//	localtx, tx, err := mdb.StartTransaction(tx)
	// 	if err != nil {
	// 		log.Printf("ZoneAttachFsm: Error from mdb.StartTransaction(): %v\n", err)
	// 		return "fail", err
	// 	}
	// 	defer mdb.CloseTransaction(localtx, tx, err)

	log.Printf("ZoneAttachFsm: zone: %s fsm: %s fsmsigner: '%s'", dbzone.Name, fsm, fsmsigner)
	if !dbzone.Exists {
		return "", fmt.Errorf("Zone %s unknown", dbzone.Name)
	}

	sgname := dbzone.SignerGroup().Name

	if sgname == "" || sgname == "---" {
		return "", fmt.Errorf("Zone %s not assigned to any signer group, so it can not attach to a process\n",
			dbzone.Name)
	}

	var exist bool
	var process FSM
	if process, exist = mdb.FSMlist[fsm]; !exist {
		return "", fmt.Errorf("Process %s unknown. Sorry.", fsm)
	}

	if dbzone.FSM != "" {
		if preempt {
			msg = fmt.Sprintf("Zone %s was in process '%s', which is now preempted by new process.\n", dbzone.Name, dbzone.FSM)
		} else {
			return "", fmt.Errorf(
				"Zone %s already attached to process %s. Only one process at a time possible.\n",
				dbzone.Name, dbzone.FSM)
		}
	}

	initialstate := process.InitialState

	log.Printf("ZAF: Updating zone %s to fsm=%s, fsmsigner=%s", dbzone.Name, fsm, fsmsigner)

	const sqlq = "UPDATE zones SET fsm=?, fsmsigner=?, state=? WHERE name=?"
	_, err := tx.Exec(sqlq, fsm, fsmsigner, initialstate, dbzone.Name)
	if CheckSQLError("JoinGroup", sqlq, err, false) {
		return msg, err
	}
	return msg + fmt.Sprintf("Zone %s has now started process '%s' in state '%s'.",
		dbzone.Name, fsm, initialstate), nil
}

func (mdb *MusicDB) ZoneDetachFsm(tx *sql.Tx, dbzone *Zone, fsm, fsmsigner string) (string, error) {

	if tx == nil {
		panic("tx=nil")
	}
	if !dbzone.Exists {
		return "", fmt.Errorf("Zone %s unknown", dbzone.Name)
	}

	sgname := dbzone.SignerGroup().Name

	if sgname == "" || sgname == "---" {
		return "", fmt.Errorf("Zone %s not assigned to any signer group, so it can not detach from a process\n",
			dbzone.Name)
	}

	var exist bool
	if _, exist = mdb.FSMlist[fsm]; !exist {
		return "", fmt.Errorf("Process %s unknown. Sorry.", fsm)
	}

	if dbzone.FSM == "" || dbzone.FSM == "---" {
		return "", fmt.Errorf("Zone %s is not attached to any process.\n",
			dbzone.Name)
	}

	if dbzone.FSM != fsm {
		return "", fmt.Errorf(
			"Zone %s should be attached to process %s but is instead attached to %s.\n",
			dbzone.Name, fsm, dbzone.FSM)
	}

	// 	localtx, tx, err := mdb.StartTransaction(tx)
	// 	if err != nil {
	// 		log.Printf("ZoneDetachFsm: Error from mdb.StartTransaction(): %v\n", err)
	// 		return "fail", err
	// 	}
	// 	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlq = "UPDATE zones SET fsm=?, fsmsigner=?, state=? WHERE name=?"

	_, err := tx.Exec(sqlq, "", "", "", dbzone.Name)
	if CheckSQLError("DetachFsm", sqlq, err, false) {
		return "", err
	}
	return fmt.Sprintf("Zone %s has now left process '%s'.",
		dbzone.Name, fsm), nil
}

// XXX: Returning a map[string]Zone just to get rid of an extra call
// to ListZones() was a mistake. Let's simplify.

func (mdb *MusicDB) ZoneStepFsm(tx *sql.Tx, dbzone *Zone, nextstate string) (bool, string, error) {

	log.Printf("$$$ ROG -> starting ZoneStepFsm with %v as tx", tx)
	if tx == nil {
		panic("tx=nil")
	}
	if !dbzone.Exists {
		return false, "", fmt.Errorf("Zone %s unknown", dbzone.Name)
	}

	fsmname := dbzone.FSM

	if fsmname == "" || fsmname == "---" {
		return false, "", fmt.Errorf("Zone %s not attached to any process.", dbzone.Name)
	}

	CurrentFsm := mdb.FSMlist[fsmname]

	state := dbzone.State

	if state == FsmStateStop {
		// 1. Zone leaves process
		// 2. Count of #zones in process in signergroup is decremented
		msg, err := mdb.ZoneDetachFsm(tx, dbzone, fsmname, "")
		if err != nil {
			log.Printf("ZoneStepFsm: Error from ZoneDetachFsm(%s, %s): %v",
				dbzone.Name, fsmname, err)
			return false, "", err
		}

		res, msg2, err := mdb.CheckIfProcessComplete(tx, dbzone.SignerGroup())
		if err != nil {
			// "process complete" is the more important message
			return false, fmt.Sprintf("Error from CheckIfProcessComplete(): %v", err), err
		}
		if res {
			// "process complete" is the more important message
			return true, fmt.Sprintf("%s\n%s", msg, msg2), nil
		}
		return true, msg, nil
	}

	var CurrentState FSMState
	var exist bool
	if CurrentState, exist = CurrentFsm.States[state]; !exist {
		return false, "", fmt.Errorf(
			"Zone state '%s' does not exist in process %s. Terminating.",
			state, dbzone.FSM)
	}

	var transitions []string
	for k, _ := range CurrentState.Next {
		transitions = append(transitions, k)
	}

	// msgtmpl := "Zone %s transitioned to state '%s' in process '%s'."
	// transittmpl := "Zone %s transitioned to state '%s' in process '%s'."
	// notransittmpl := "Zone %s did not transition to state '%s' (post-condition failed)."

	// Only one possible next state: this it the most common case
	if len(CurrentState.Next) == 1 {
		nextname := transitions[0]
		t := CurrentState.Next[nextname]
		log.Printf("$$$ ROG -> Heading into AttempStateTransition with %v as tx", tx)
		success, msg, err := dbzone.AttemptStateTransition(tx, nextname, t)
		// return dbzone.AttemptStateTransition(nextname, t)
		log.Printf("ZoneStepFsm debug: result from AttemptStateTransition: success: %v, err: %v, msg: '%s'\n", success, err, msg)
		return success, msg, err
	}

	// More than one possible next state: this can happen. Right now we can
	// only deal with multiple possible next states when the "right" next state
	// is explicitly specified (via parameter nextstate).
	// In the future it seems like a better approach will be to iterate through
	// all the pre-conditions and execute on the first that returns true.
	// It can be argued that if multiple pre-conditions can be true at the same
	// time then the FSM is buggy (as in not deterministic).
	if len(CurrentState.Next) > 1 {
		if nextstate != "" {
			if _, exist := CurrentState.Next[nextstate]; exist {
				t := CurrentState.Next[nextstate]
				// success, err, msg := dbzone.AttemptStateTransition(tx, nextstate, t)
				return dbzone.AttemptStateTransition(tx, nextstate, t)
			} else {
				return false, "", fmt.Errorf(
					"State '%s' is not a possible next state from '%s'",
					nextstate, state)
			}
		} else {
			return false, "", fmt.Errorf(
				"Multiple possible next states from '%s': [%s] but next state not specified",
				state, strings.Join(transitions, " "))
		}
	}

	// Arriving here equals len(CurrentState.Next) == 0, i.e. you are in a
	// state with no "next" state. If that happens the FSM is likely buggy.
	return false, "", fmt.Errorf(
		"Zero possible next states from '%s': you lose.", state)
}

// pre-condition false ==> return false, nil, "msg": no transit, no error
// pre-cond true + no post-cond ==> return false, error, "msg": no transit, error
// pre-cond true + post-cond false ==> return false, nil, "msg"
// pre-cond true + post-cond true ==> return true, nil, "msg": all ok
func (z *Zone) AttemptStateTransition(tx *sql.Tx, nextstate string,
	t FSMTransition) (bool, string, error) {

	log.Printf("$$$ ROG -> Starting AttempStateTransition with %v as tx", tx)

	if tx == nil {
		panic("tx=nil")
	}

	currentstate := z.State

	log.Printf("AttemptStateTransition: zone '%s' to state '%s'\n", z.Name, nextstate)

	// If pre-condition(aka criteria)==true ==> execute action
	// If post-condition==true ==> change state.
	// If post-condition==false ==> bump hold time
	log.Printf("*** AttemptStateTransition(%s): '%s--->%s': PreCondition",
		z.Name, currentstate, nextstate)
	if t.PreCondition(z) {
		log.Printf("*** AttemptStateTransition(%s): '%s--->%s': PreCondition: true\n",
			z.Name, currentstate, nextstate)
		log.Printf("*** AttemptStateTransition(%s): '%s--->%s': ACTION",
			z.Name, currentstate, nextstate)
		t.Action(z)                 //TODO XXX: catch return value
		if t.PostCondition != nil { //TODO XXX: remove once we have post conditions everywhere.
			log.Printf("*** AttemptStateTransition(%s): '%s--->%s': PostCondition",
				z.Name, currentstate, nextstate)
			postcond := t.PostCondition(z)
			if postcond {
				log.Printf("*** AttemptStateTransition(%s): '%s--->%s': PostCondition: true",
					z.Name, currentstate, nextstate)
				log.Printf("$$$ ROG -> running StateTransition with %v as tx", tx)
				err := z.StateTransition(tx, currentstate, nextstate) // success
				if err != nil {
				   log.Printf("*** AttemptStateTransition(%s): '%s--->%s': Transition failed",
					z.Name, currentstate, nextstate)
				   return false,
				       fmt.Sprintf("Zone %s did not transition from '%s' to '%s'",
						z.Name, currentstate, nextstate), err
				} else {
				  log.Printf("*** AttemptStateTransition(%s): '%s--->%s': Transition complete",
					z.Name, currentstate, nextstate)
				  return true,
					fmt.Sprintf("Zone %s transitioned from '%s' to '%s'",
						z.Name, currentstate, nextstate), nil
				}
			} else {
				stopreason, exist, err := z.MusicDB.GetMeta(tx, z, "stop-reason")
				if err != nil {
					return false, fmt.Sprintf("Error retrieving metadata for zone %s",
						z.Name), err
				}
				if exist {
					stopreason = fmt.Sprintf(" Current stop reason: %s", stopreason)
				}
				return false,
					fmt.Sprintf("Zone %s did not transition from %s to %s.",
						z.Name, currentstate, nextstate), nil
			}

		} else {
			// there is no post-condition
			log.Fatalf("AttemptStateTransition: Error: no PostCondition defined for transition %s --> %s", currentstate, nextstate)
			// obviously, because of the log.Fatalf this return won't happen:
			return false, "", fmt.Errorf("Cannot transition due to lack of definied post-condition for transition %s --> %s", currentstate, nextstate)
		}
	}
	// pre-condition returns false
	stopreason, exist, err := z.MusicDB.GetStopReason(tx, z)
	if err != nil {
		return false, fmt.Sprintf("%s: Error retrieving current stop reason: %v",
			z.Name, stopreason), err

	}
	if exist {
		stopreason = fmt.Sprintf(" Current stop reason: %s", stopreason)
	}

	return false, fmt.Sprintf("%s: PreCondition for '%s' failed.%s\n",
		z.Name, nextstate, stopreason), nil
}

func (mdb *MusicDB) ListProcesses() ([]Process, error, string) {
	var resp []Process
	for name, fsm := range mdb.FSMlist {
		resp = append(resp, Process{
			Name: name,
			Desc: fsm.Desc,
		})
	}
	return resp, nil, ""
}

func (z *Zone) GetParentAddressOrStop() (string, error) {
	var parentAddress string
	var exist bool
	var err error

	if parentAddress, exist, err = z.MusicDB.GetMeta(nil, z, "parentaddr"); err != nil {
		return "", fmt.Errorf("Zone %s: Error retrieving parent address: %v", z.Name, err)
	}

	if !exist {
		z.SetStopReason("No parent-agent address registered")
		return "", fmt.Errorf("Zone %s has no parent address registered", z.Name)
	}
	return parentAddress, nil
}

func GetSortedTransitionKeys(fsm string) ([]string, error) {
	var skeys = []string{}
	return skeys, nil
}

func (mdb *MusicDB) GraphProcess(fsm string) (string, error) {
	var exist bool
	var process FSM

	if process, exist = mdb.FSMlist[fsm]; !exist {
		return "", fmt.Errorf("Process %s unknown. Sorry.", fsm)
	}

	gtype := "flowchart"

	switch gtype {
	case "flowchart":
		return MermaidFlowChart(&process)
	case "statediagram":
		return MermaidStateDiagram(&process)
	}
	return "", nil
}

func MermaidStateDiagram(process *FSM) (string, error) {
	return "", nil
}

func MermaidFlowChart(process *FSM) (string, error) {
	graph := "mermaid\ngraph TD\n"
	statenum := 0
	var stateToId = map[string]string{}

	log.Printf("GraphProcess: graphing process %s\n", process.Name)
	for sn, _ := range process.States {
		stateId := fmt.Sprintf("State%d", statenum)
		graph += fmt.Sprintf("%s(%s)\n", stateId, sn)
		stateToId[sn] = stateId
		statenum++
	}

	log.Printf("GraphProcess: stateToId: %v\n", stateToId)

	statenum = 0
	for sn, st := range process.States {
		var action string
		var criteria string
		for state, nt := range st.Next {
			thisstate := sn
			nextstate := stateToId[state]
			if nt.MermaidCriteriaDesc != "" {
				criteria = "Criteria: " + nt.MermaidCriteriaDesc + "<br/>"
			}
			if nt.MermaidActionDesc != "" {
				action = "Action: " + nt.MermaidActionDesc + "<br/>"
			}
			txt := criteria + action
			if txt != "" && len(txt) > 5 {
				txt = "|" + txt[:len(txt)-5] + "|"
			}
			graph += fmt.Sprintf("%s --> %s %s\n", stateToId[thisstate],
				txt, nextstate)
		}
		statenum++
	}

	log.Printf("GraphProcess: graph: \n%s\n", graph)

	return graph, nil
}
