/*
 * Copyright (c) 2024 Rog Murray, roger.murray@internetstiftelsen.se
 */

package mcmd

import (
	"fmt"

	"github.com/johanix/tdns/music"
)

func ZoneStatus() {
	zone := "fluffmunk.se." // must have something, not used
	zr := SendZoneCommand(zone, music.ZonePost{
		Command: "list",
		Zone: music.Zone{
			Name: zone,
		},
	})
	PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	if len(zr.Zones) != 0 {
		PrintZones(zr.Zones, true, "")
	} else {
		fmt.Printf("*** There are 0 zones in the system.\n")
	}
}

func SignerStatus() {
	sr := SendSignerCmd(music.SignerPost{
		Command: "list",
	})
	if len(sr.Signers) != 0 {
		PrintSigners(sr)
	} else {
		fmt.Printf("*** There are 0 signers in the system.\n")
	}
}

func SignerGroupStatus() {
	sgr := SendSignerGroupCmd("none", music.SignerGroupPost{
		Command: "list",
	})
	if len(sgr.SignerGroups) != 0 {
		PrintSignerGroups(sgr)
	} else {
		fmt.Printf("*** There are 0 signers in the system.\n")
	}
}
