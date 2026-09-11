/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"os"
	"path/filepath"
	"testing"
)

const persistLivenessZone = `persist.example. 3600 IN SOA ns.persist.example. h.persist.example. 7 3600 600 604800 300
persist.example. 3600 IN NS ns.persist.example.
ns.persist.example. 3600 IN A 192.0.2.1
`

// TestADeletedZoneIsNotWrittenBackByTheRefreshThatWasRunning.
//
// A refresh that finishes after its zone was deleted or replaced must not write
// that zone anywhere. The liveness check used to sit on the dynamic-zone arm
// only; a secondary that failed it fell through to the source-file arm -- which
// any non-primary with a Zonefile satisfies -- and wrote the stale data back to
// disk, where the next load would bring it back.
func TestADeletedZoneIsNotWrittenBackByTheRefreshThatWasRunning(t *testing.T) {
	zd := testZone(t, "persist.example.", persistLivenessZone)
	zd.ZoneType = Secondary
	zd.Zonefile = filepath.Join(t.TempDir(), "persist.example.zone")

	// Not registered in Zones, which is what a delete leaves behind: the
	// refresh still holds its pointer, but the zone is gone.
	persistRefreshedZone(zd, zd.ZoneName, zd.generation.Load(), &Config{})

	if _, err := os.Stat(zd.Zonefile); err == nil {
		t.Error("a refresh wrote a deleted zone back to its source file; the next load" +
			" resurrects data the operator removed")
	}
}

// The other half: a zone that is still live keeps being written, or a
// secondary's source file would silently stop tracking its primary.
func TestALiveSecondaryIsStillWrittenToItsSourceFile(t *testing.T) {
	zd := testZone(t, "persist.example.", persistLivenessZone)
	registerZones(t, zd)
	zd.ZoneType = Secondary
	zd.Zonefile = filepath.Join(t.TempDir(), "persist.example.zone")

	persistRefreshedZone(zd, zd.ZoneName, zd.generation.Load(), &Config{})

	if _, err := os.Stat(zd.Zonefile); err != nil {
		t.Errorf("a live secondary's refresh was not written to its source file: %v", err)
	}
}
