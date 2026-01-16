/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package main

import (
	"dog/cmd"

	tdns "github.com/johanix/tdns/v2"
)

func main() {
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate
	cmd.Execute()
}
