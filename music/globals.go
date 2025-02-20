/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	//	"github.com/johanix/tdns/music"
	"github.com/go-playground/validator/v10"
	cmap "github.com/orcaman/concurrent-map/v2"
)

var Validate *validator.Validate

func init() {
	Validate = validator.New()
}

type GlobalStuff struct {
	MSAs *MSAs
	// Api         *Api
	Zonename   string
	Signername string
	Sgroupname string
	FSMname    string
	FSMmode    string
	CfgFile    string
}

var Globals = GlobalStuff{
	MSAs: &MSAs{
		S: cmap.New[*MSA](),
	},
}
