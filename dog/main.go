/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package main

import (
	"dog/cmd"
        tdns "github.com/johanix/tdns/tdns"
//        cli "github.com/johanix/tdns/tdns/cli"
)

func main() {
        tdns.Globals.App.Name = appName
        tdns.Globals.App.Version = appVersion
        tdns.Globals.App.Date = appDate
        cmd.Execute()
}
