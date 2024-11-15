/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

const (
 	FsmStateStop             = "stop"	// XXX: Yes, we need to keep this in the music package
)				   		//      because it is referred to from zoneops.go et al

type FSMState struct {
	Next map[string]FSMTransition
}

type FSMTransition struct {
	Description string // used by various things
	Desc        string // used by music-cli process list

	MermaidCriteriaDesc string
	MermaidPreCondDesc  string
	MermaidActionDesc   string
	MermaidPostCondDesc string

	Criteria      func(z *Zone) bool // being replaced by PreCondition
	PreCondition  func(z *Zone) bool
	Action        func(z *Zone) bool
	PostCondition func(z *Zone) bool
}

type FSM struct {
	Name         string
	Type         string // "single-run" | "permanent"
	Desc         string
	InitialState string // zones that enter this process start here
	States       map[string]FSMState
}

