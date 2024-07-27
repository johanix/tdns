/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	cmap "github.com/orcaman/concurrent-map/v2"
)

type GlobalStuff struct {
	IMR         string
	Verbose     bool
	Debug       bool
	Zonename    string
	ParentZone  string
	Sig0Keyfile string
	Api         *ApiClient
	PingCount   int
	Slurp       bool
}

var Globals = GlobalStuff{
	//	IMR:     "8.8.8.8:53",
	Verbose: false,
	Debug:   false,
}

var Zones = cmap.New[*ZoneData]()
