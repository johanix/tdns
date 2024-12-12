/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	//	"github.com/johanix/tdns/music"
	"github.com/go-playground/validator/v10"
	cmap "github.com/orcaman/concurrent-map/v2"
)

// var CfgFile string

// var Showheaders bool

//var api *Api

// var validate *validator.Validate
var Validate = validator.New()

type GlobalStuff struct {
//	Verbose  bool
//	Debug    bool
	Sidecars *Sidecars
	// Api         *Api
	Zonename    string
	Signername  string
	Sgroupname  string
	FSMname     string
	FSMmode     string
	CfgFile     string
}

var Globals = GlobalStuff{
	Sidecars: &Sidecars{
		S: cmap.New[*Sidecar](),
	},
}
