/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"tdns-lookup/cmd"
	tdns "github.com/johanix/tdns/tdns"
)

func main() {
	tdns.Globals.App.Type = tdns.AppTypeLookup
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate
	cmd.Execute()
}
