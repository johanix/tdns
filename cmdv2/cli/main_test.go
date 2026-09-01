/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package main

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// tdns-cli must identify itself to the library, and App.Type is the field that
// matters beyond cosmetics.
//
// Unset it is the zero value, which is no AppType at all: AppTypeAuth starts at
// iota+1. Every branch keyed on AppTypeCli then goes the wrong way, and
// parseZones' is not cosmetic -- it skips zone refresh for the non-zone-serving
// app types, so an unset type falls to the default and terminates with
// "refresh channel is not configured".
//
// Eleven commands across three files set this for themselves to work around
// that. This pins the one place that makes those unnecessary.
func TestInitGlobalsIdentifiesTheBinary(t *testing.T) {
	tdns.Globals.App = tdns.AppDetails{} // zero it, as a fresh process has it

	initGlobals()

	if tdns.Globals.App.Type != tdns.AppTypeCli {
		t.Errorf("App.Type = %d (%q), want AppTypeCli",
			tdns.Globals.App.Type, tdns.AppTypeToString[tdns.Globals.App.Type])
	}
	if tdns.Globals.App.Type == 0 {
		t.Error("App.Type is the zero value: not any AppType, so every" +
			" AppTypeCli branch takes the wrong path")
	}
	if tdns.Globals.App.Name != appName {
		t.Errorf("App.Name = %q, want %q", tdns.Globals.App.Name, appName)
	}
}
