package fsm

import (
	"github.com/johanix/tdns/music"
)

var FsmZoneIsInSync = music.FSMTransition{
	Description: "This is a no-op state transition that always claim that a zone is in sync",

	MermaidPreCondDesc:  "None",
	MermaidActionDesc:   "Do nothing",
	MermaidPostCondDesc: "None",

	PreCondition:  func(z *music.Zone) bool { return true },
	Action:        func(z *music.Zone) bool { return true },
	PostCondition: func(z *music.Zone) bool { return true },
}

