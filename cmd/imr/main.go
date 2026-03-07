/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"tdns-imr/cmd"

	tdns "github.com/johanix/tdns/tdns"
)

func main() {
	tdns.Globals.App.Type = tdns.AppTypeImr
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate
	cmd.Execute()
}
