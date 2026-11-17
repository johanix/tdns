/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// johanix/tdns#981, the other half: a zone's Options field is replaced under
// optionsMu, but a store that writes one option into the map the field points
// at (SetOption, the dirty flag) does not replace anything, and a reader
// that indexes that map meets it: a concurrent map read and map write, which
// go test -race reports and which can stop the process. These stores give the
// zone a new map instead, the way SetRuntimeOption does, so that no map a
// reader can hold is ever written.
//
// And a snapshot of the options is the caller's own: a caller that writes it
// (a caller that should not, but could) changes nothing the zone reads.

// snapshotReaders are readers of the options that take a snapshot of them, or
// look at the options the in-place stores write.
var snapshotReaders = []func(zd *ZoneData) bool{
	func(zd *ZoneData) bool {
		anyOn := false
		for _, on := range zd.OptionsSnapshot() {
			anyOn = anyOn || on
		}
		return anyOn
	},
	func(zd *ZoneData) bool { return zd.Option(OptDirty) || zd.Option(OptFrozen) },
	func(zd *ZoneData) bool { return len(zd.asConfiguredOptions()) > 0 },
}

// SetOption, as `zone freeze` and `zone thaw` call it, against the readers.
func TestSetOptionRacesNoReader(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.", Options: map[ZoneOption]bool{OptAllowUpdates: true}}
	stop := readOptionsUntil(t, zd, snapshotReaders...)

	opts := []ZoneOption{OptFrozen, OptDirty, OptInlineSigning, OptMultiProvider, OptModifiedDownstream}
	const rounds = 2000
	for i := 0; i < rounds; i++ {
		zd.SetOption(opts[i%len(opts)], i%2 == 0)
	}
	for _, opt := range opts {
		zd.SetOption(opt, true)
	}
	if reads := stop(); reads == 0 {
		t.Fatal("the readers never ran")
	}
	for _, opt := range opts {
		if !optionOn(zd, opt) {
			t.Errorf("%v reads off after it was set on", opt)
		}
	}
	if !optionOn(zd, OptAllowUpdates) {
		t.Error("an option the zone had was lost")
	}
}

// The dirty flag cleared by writing the zone to its file, against the readers.
func TestWritingTheZoneFileRacesNoReader(t *testing.T) {
	zd := testSnapshotZone(t, ovZone, ovUpstreamZone(40))
	zd.mu.Lock()
	zd.Zonefile = filepath.Join(t.TempDir(), "example.zone")
	zd.CurrentSerial = 40
	zd.Options = map[ZoneOption]bool{OptDirty: true}
	zd.mu.Unlock()
	stop := readOptionsUntil(t, zd, snapshotReaders...)

	const rounds = 100
	for i := 0; i < rounds; i++ {
		// Dirty again, then written out: the second step clears it.
		zd.SetOption(OptDirty, true)
		if _, err := zd.WriteZone(true, true); err != nil {
			stop()
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if reads := stop(); reads == 0 {
		t.Fatal("the readers never ran")
	}
	if optionOn(zd, OptDirty) {
		t.Error("the zone still reads as dirty after it was written to its file")
	}
	if _, err := os.Stat(zd.Zonefile); err != nil {
		t.Errorf("the zone file was not written: %v", err)
	}
}

// A snapshot is a copy. Writing it changes nothing the zone reads, and the
// options the zone had are what OptionsSnapshot and asConfiguredOptions give
// back, with and without suppressed ones.
func TestAnOptionsSnapshotIsACopy(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.", Options: map[ZoneOption]bool{OptAllowUpdates: true}}

	snap := zd.OptionsSnapshot()
	snap[OptFrozen] = true
	delete(snap, OptAllowUpdates)
	if zd.Option(OptFrozen) || !zd.Option(OptAllowUpdates) {
		t.Fatalf("writing a snapshot changed the zone's options: %v", zd.OptionsSnapshot())
	}

	// Nothing suppressed: the zone's own set once, now a copy of it.
	conf := zd.asConfiguredOptions()
	conf[OptFrozen] = true
	delete(conf, OptAllowUpdates)
	if zd.Option(OptFrozen) || !zd.Option(OptAllowUpdates) {
		t.Fatalf("writing asConfiguredOptions' answer changed the zone's options: %v", zd.OptionsSnapshot())
	}

	// Something suppressed: always a new map, and the suppressed one in it.
	zd.SuppressedOptions = map[ZoneOption]bool{OptInlineSigning: true}
	conf = zd.asConfiguredOptions()
	if !conf[OptInlineSigning] || !conf[OptAllowUpdates] {
		t.Fatalf("asConfiguredOptions = %v, want the zone's options and the suppressed one", conf)
	}
	conf[OptFrozen] = true
	if zd.Option(OptFrozen) {
		t.Fatal("writing asConfiguredOptions' answer changed the zone's options")
	}

	// A zone with no options map has none to hand out.
	if got := (&ZoneData{}).OptionsSnapshot(); len(got) != 0 {
		t.Fatalf("a zone with no options gave %v", got)
	}
}

// Callers that write the snapshots they were given, against the readers: with
// the zone's own map handed out, that is a write into a map every reader
// indexes.
func TestWritingASnapshotRacesNoReader(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.", Options: map[ZoneOption]bool{OptAllowUpdates: true}}
	stop := readOptionsUntil(t, zd, snapshotReaders...)

	var wg sync.WaitGroup
	for _, snapshot := range []func() map[ZoneOption]bool{zd.OptionsSnapshot, zd.asConfiguredOptions} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				m := snapshot()
				m[OptFrozen] = i%2 == 0
				m[OptDirty] = i%2 == 1
			}
		}()
	}
	wg.Wait()
	if reads := stop(); reads == 0 {
		t.Fatal("the readers never ran")
	}
	if optionOn(zd, OptFrozen) || optionOn(zd, OptDirty) {
		t.Error("what the callers wrote into their snapshots reached the zone")
	}
}
