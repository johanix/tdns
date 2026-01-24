/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	tdns "github.com/johanix/tdns/v2"
)

func main() {
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate
	Execute()
}
