/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"os"
	"testing"
)

// The package's tests apply a change and read the zone back as if every
// publish were synchronous (about 130 call sites: ApplyZoneUpdateToZoneData,
// SignZone, Publish, StageBatch, ...). Under the publish gate a change to a
// busy zone waits a cadence. With a zero default cadence no zone is ever busy,
// so the gate publishes in the caller and those tests keep their reading. The
// gate's own tests set a cadence on their zones.
func TestMain(m *testing.M) {
	defaultPublishCadence = 0
	os.Exit(m.Run())
}
