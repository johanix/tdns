/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"log"
	"os"

	tdns "github.com/johanix/tdns/tdns"
	cmap "github.com/orcaman/concurrent-map/v2"
)

// var Validate *validator.Validate
var Validate *tdns.CustomValidator

func init() {
	var err error
	// Validate = validator.New()
	Validate, err = tdns.NewCustomValidator()
	if err != nil {
		log.Printf("Error from NewCustomValidator(): %+v", err)
		os.Exit(1)
	}
}

type GlobalStuff struct {
	Sidecars *Sidecars
	// Api         *Api
	Zonename   string
	Signername string
	Sgroupname string
	FSMname    string
	FSMmode    string
	CfgFile    string
}

var Globals = GlobalStuff{
	Sidecars: &Sidecars{
		S: cmap.New[*Sidecar](),
	},
}
