/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	tdns "github.com/johanix/tdns/tdns"
	"tdns-imr/cmd"
)

func main() {
	tdns.Globals.App.Type = tdns.AppTypeImr
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate
	cmd.Execute()
}
