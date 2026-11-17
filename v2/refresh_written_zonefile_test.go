/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Tests for #919, for a secondary with a zone file. The refresh engine writes
// such a zone's file after every refresh that changed it (persistRefreshedZone),
// and the next start adopts that file at first bind. The write used to leave
// the journal anchored to the serial received and keep the deltas the file
// holds, so the load from the file refused the journal as an edited file.

// zfVariants are the two kinds of signing secondary outside the journal
// overlay, which journal against their file.
var zfVariants = []struct {
	name  string
	setup func(t *testing.T, zd *ZoneData)
}{
	{"multi-provider", func(t *testing.T, zd *ZoneData) {
		zd.mu.Lock()
		zd.Options[OptMultiProvider] = true
		zd.mu.Unlock()
	}},
	{"not tdns-auth", func(t *testing.T, zd *ZoneData) {
		prev := Globals.App.Type
		Globals.App.Type = AppTypeAgent
		t.Cleanup(func() { Globals.App.Type = prev })
	}},
}

// zfOverlay leaves the zone as ixSigningSecondary makes it: an inline-signing
// secondary on tdns-auth, which is an overlay zone.
func zfOverlay(*testing.T, *ZoneData) {}

// zfLocalTXT is a local change: a record the upstream does not have.
func zfLocalTXT(t *testing.T, n int) dns.RR {
	t.Helper()
	return mustRR(t, fmt.Sprintf("local.example.\t3600\tIN\tTXT\t\"local-%d\"", n))
}

// zfSecondary is a signing secondary at serial 7, set up by setup, with a zone
// file the refresh engine writes.
func zfSecondary(t *testing.T, setup func(*testing.T, *ZoneData)) *ZoneData {
	t.Helper()
	zd := ixSigningSecondary(t, ixApplyZone)
	setup(t, zd)
	zd.Zonefile = filepath.Join(t.TempDir(), "example.zone")
	return zd
}

// zfUpstream serves the upstream's zone at serial for the rest of the test.
func zfUpstream(t *testing.T, serial uint32) string {
	t.Helper()
	_, addr, stop := ixfrTestPrimary(t, ovUpstreamZone(serial))
	t.Cleanup(stop)
	return addr
}

// zfRefresh is one refresh by the refresh engine from the upstream at addr,
// the write of the zone file included.
func zfRefresh(t *testing.T, zd *ZoneData, addr string) {
	t.Helper()
	zfRefreshWith(t, zd, addr, &Config{})
}

func zfRefreshWith(t *testing.T, zd *ZoneData, addr string, conf *Config) {
	t.Helper()
	zd.mu.Lock()
	zd.Upstreams = []PeerConf{{Addr: addr}}
	zd.mu.Unlock()
	updated, err := runZoneRefresh(context.Background(),
		refreshJob{zd: zd, zone: zd.ZoneName, gen: zd.generation.Load()}, conf)
	if err != nil {
		t.Fatalf("runZoneRefresh: %v", err)
	}
	if !updated {
		t.Fatal("precondition: the refresh transferred nothing, so it wrote nothing")
	}
}

// zfFirstBind is a restart up to the first-load replay: a new zone on the same
// keystore, set up as the old one was, which adopts its file at first bind and
// finds the upstream at addr where it was, so nothing is transferred.
func zfFirstBind(t *testing.T, zd *ZoneData, setup func(*testing.T, *ZoneData), addr string) *ZoneData {
	t.Helper()
	return zfFirstBindWith(t, zd, setup, addr, &Config{})
}

func zfFirstBindWith(t *testing.T, zd *ZoneData, setup func(*testing.T, *ZoneData), addr string,
	conf *Config) *ZoneData {
	t.Helper()
	again := ovRestarted(t, zd.KeyDB, zd.DnssecPolicy)
	setup(t, again)
	again.Zonefile = zd.Zonefile
	again.Upstreams = []PeerConf{{Addr: addr}}
	updated, err := again.Refresh(context.Background(), false, false, false, conf)
	if err != nil {
		t.Fatalf("first-bind Refresh: %v", err)
	}
	if updated {
		t.Fatal("precondition: the first bind transferred the zone; it was to load the file")
	}
	if again.publishedSnapshot() == nil {
		t.Fatal("precondition: the first bind did not adopt the zone file")
	}
	return again
}

// zfFileSerial is the serial the journal is anchored to.
func zfFileSerial(zd *ZoneData) uint32 {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.fileSerial
}

// The #919 case for a zone with a file. A refresh writes the file, a change
// is made after it, and the zone restarts from that file with the upstream
// where it was: the journal is replayed over the file, with no ConfigWarning.
func TestRefreshWrittenZoneFileReplaysItsJournalAfterARestart(t *testing.T) {
	for _, v := range zfVariants {
		t.Run(v.name, func(t *testing.T) {
			zd := zfSecondary(t, v.setup)
			if err := ovUpdate(t, zd, zfLocalTXT(t, 1)); err != nil {
				t.Fatalf("local change before the refresh: %v", err)
			}

			addr := zfUpstream(t, 8)
			zfRefresh(t, zd, addr)

			// The file is the zone's file now: the journal is anchored to it,
			// and the delta from before the full transfer, which neither the
			// zone nor the file holds, is gone.
			written := ovServedSerial(t, zd)
			if got := zfFileSerial(zd); got != written {
				t.Errorf("the journal is anchored to serial %d, the file holds serial %d", got, written)
			}
			if j := ovJournal(t, zd); len(j) != 0 {
				t.Errorf("the journal kept deltas the written file covers:%s", ovJournalString(j))
			}

			txt := zfLocalTXT(t, 2)
			if err := ovUpdate(t, zd, txt); err != nil {
				t.Fatalf("local change after the refresh: %v", err)
			}
			if j := ovJournal(t, zd); len(j) != 1 || j[0].FromSerial != written {
				t.Fatalf("the change is not journalled from the file's serial %d:%s",
					written, ovJournalString(j))
			}

			buf := ovCaptureLog(t)
			again := zfFirstBind(t, zd, v.setup, addr)
			replayZoneDeltasOnLoad(again)

			if w := ovConfigWarning(again); w != "" {
				t.Errorf("the first load raised a ConfigWarning: %s", w)
			}
			if strings.Contains(buf.String(), "edited or replaced") {
				t.Error("the load says the zone file was edited or replaced; tdns wrote it")
			}
			if !ovHas(ovServed(t, again, "local.example.", dns.TypeTXT), txt) {
				t.Errorf("the change is not served after the restart; journal:%s",
					ovJournalString(ovJournal(t, again)))
			}
			if n := len(ovJournal(t, again)); n != 1 {
				t.Errorf("the journal holds %d deltas after the replay, want 1", n)
			}
		})
	}
}

// The write after a refresh cannot drop deltas the first load has not yet
// replayed. A first-load completion that fails before its replay (the DNSSEC
// policy did not bind) leaves the zone refreshing on NOTIFY with the journal
// still owed: the write then leaves the journal and its anchor alone, and the
// replay that follows still applies it. Once replayed, the next write drops
// what the file holds as usual.
func TestRefreshWriteKeepsTheJournalUntilTheFirstLoadReplaysIt(t *testing.T) {
	for _, v := range zfVariants {
		t.Run(v.name, func(t *testing.T) {
			zd := zfSecondary(t, v.setup)
			addr := zfUpstream(t, 8)
			zfRefresh(t, zd, addr)
			txt := zfLocalTXT(t, 1)
			if err := ovUpdate(t, zd, txt); err != nil {
				t.Fatalf("local change: %v", err)
			}
			before := ovJournal(t, zd)
			if len(before) != 1 {
				t.Fatalf("precondition: the journal holds %d deltas, want 1", len(before))
			}

			again := zfFirstBind(t, zd, v.setup, addr)
			if !again.journalReplayIsOwed() {
				t.Fatal("the first load does not record that it owes the journal")
			}
			anchor := zfFileSerial(again)
			if ovHas(ovServed(t, again, "local.example.", dns.TypeTXT), txt) {
				t.Fatal("precondition: the change is served before the replay")
			}
			if !serialNewer(ovServedSerial(t, again), before[0].ToSerial) {
				t.Fatalf("precondition: the zone serves serial %d, which does not cover the delta"+
					" to %d, so a drop bounded by it would keep the delta anyway",
					ovServedSerial(t, again), before[0].ToSerial)
			}

			persistRefreshedZone(again, again.ZoneName, again.generation.Load(), &Config{})

			after := ovJournal(t, again)
			if len(after) != 1 || after[0].FromSerial != before[0].FromSerial ||
				after[0].ToSerial != before[0].ToSerial {
				t.Fatalf("the write before the replay changed the journal:\nbefore:%s\nafter:%s",
					ovJournalString(before), ovJournalString(after))
			}
			if got := zfFileSerial(again); got != anchor {
				t.Errorf("the write before the replay moved the journal's anchor from %d to %d",
					anchor, got)
			}

			replayZoneDeltasOnLoad(again)
			if w := ovConfigWarning(again); w != "" {
				t.Errorf("the replay after the write raised a ConfigWarning: %s", w)
			}
			if !ovHas(ovServed(t, again, "local.example.", dns.TypeTXT), txt) {
				t.Error("the change is not served after the replay")
			}
			if again.journalReplayIsOwed() {
				t.Error("the journal is still owed after it was replayed")
			}

			persistRefreshedZone(again, again.ZoneName, again.generation.Load(), &Config{})
			if j := ovJournal(t, again); len(j) != 0 {
				t.Errorf("the write after the replay kept deltas the file holds:%s",
					ovJournalString(j))
			}
			if got, served := zfFileSerial(again), ovServedSerial(t, again); got != served {
				t.Errorf("the write after the replay anchored the journal to %d, the file holds %d",
					got, served)
			}
		})
	}
}

// A journal the first load refused is left for the operator to reconcile: the
// write after a refresh does not drop it on their behalf.
func TestRefreshWriteLeavesARefusedJournal(t *testing.T) {
	zd := zfSecondary(t, zfVariants[0].setup)
	addr := zfUpstream(t, 8)
	zfRefresh(t, zd, addr)
	written := ovServedSerial(t, zd)
	// Rows that do not chain from the file, and that its serial covers.
	ovPlant(t, zd, written-2, written-1, "local.example.\t3600\tIN\tTXT\t\"planted\"")

	again := zfFirstBind(t, zd, zfVariants[0].setup, addr)
	replayZoneDeltasOnLoad(again)
	if w := ovConfigWarning(again); !strings.Contains(w, "could not be replayed") {
		t.Fatalf("precondition: ConfigWarning = %q, want the refusal", w)
	}

	persistRefreshedZone(again, again.ZoneName, again.generation.Load(), &Config{})

	if n := len(ovJournal(t, again)); n != 1 {
		t.Errorf("the journal holds %d deltas after the write, want the 1 refused", n)
	}
}

// An overlay zone keeps its journal across the write after a refresh: it
// holds the zone's own records, applied to every full transfer and to the
// file at the next start.
func TestRefreshWriteKeepsAnOverlayZonesJournal(t *testing.T) {
	zd := zfSecondary(t, zfOverlay)
	cds := ovCDS(t, 1)
	if err := ovPublishCDS(t, zd, cds); err != nil {
		t.Fatalf("CDS publish: %v", err)
	}
	addr := zfUpstream(t, 8)
	zfRefresh(t, zd, addr)

	if n := len(ovJournal(t, zd)); n != 1 {
		t.Fatalf("the overlay zone's journal holds %d deltas after the write, want 1", n)
	}

	again := zfFirstBind(t, zd, zfOverlay, addr)
	replayZoneDeltasOnLoad(again)
	if !ovHas(ovServed(t, again, ovZone, dns.TypeCDS), cds) {
		t.Error("the CDS is not served after a restart from the written file")
	}
	if w := ovConfigWarning(again); w != "" {
		t.Errorf("the first load raised a ConfigWarning: %s", w)
	}
	if n := len(ovJournal(t, again)); n != 1 {
		t.Errorf("the overlay zone's journal holds %d deltas after the restart, want 1", n)
	}
}

// The same, for a zone the refresh writes to the dynamic-zone directory
// (conf.ShouldPersistZone): an API-managed secondary. That write goes through
// WriteDynamicZoneFile, not through the source-file arm, and it is the file
// such a zone adopts at its next start. It is the more common case of the two.

// zfDynamicConf persists API-managed secondaries into a temporary directory.
func zfDynamicConf(t *testing.T) *Config {
	t.Helper()
	conf := &Config{}
	conf.DynamicZones.ZoneDirectory = t.TempDir()
	conf.DynamicZones.Dynamic.Storage = "persistent"
	conf.DynamicZones.Dynamic.Allowed = []string{"secondary"}
	return conf
}

// zfDynamic is setup, and an API-managed zone.
func zfDynamic(setup func(*testing.T, *ZoneData)) func(*testing.T, *ZoneData) {
	return func(t *testing.T, zd *ZoneData) {
		setup(t, zd)
		zd.mu.Lock()
		zd.Options[OptApiManagedZone] = true
		zd.mu.Unlock()
	}
}

// zfDynamicSecondary is zfSecondary with no zone file of its own: the file is
// the one the dynamic-zone directory derives.
func zfDynamicSecondary(t *testing.T, setup func(*testing.T, *ZoneData)) *ZoneData {
	t.Helper()
	zd := ixSigningSecondary(t, ixApplyZone)
	zfDynamic(setup)(t, zd)
	return zd
}

// The #919 case for a dynamic zone. A refresh writes the zone's file in the
// dynamic-zone directory, a change is made after it, and the zone restarts
// from that file with the upstream where it was: the journal is replayed over
// the file, with no ConfigWarning.
func TestRefreshWrittenDynamicZoneFileReplaysItsJournalAfterARestart(t *testing.T) {
	for _, v := range zfVariants {
		t.Run(v.name, func(t *testing.T) {
			conf := zfDynamicConf(t)
			setup := zfDynamic(v.setup)
			zd := zfDynamicSecondary(t, v.setup)
			if err := ovUpdate(t, zd, zfLocalTXT(t, 1)); err != nil {
				t.Fatalf("local change before the refresh: %v", err)
			}

			addr := zfUpstream(t, 8)
			zfRefreshWith(t, zd, addr, conf)
			if _, err := os.Stat(GetDynamicZoneFilePath(zd.ZoneName, conf.DynamicZones.ZoneDirectory)); err != nil {
				t.Fatalf("precondition: the refresh wrote no dynamic zone file: %v", err)
			}

			// The file is the zone's file now: the journal is anchored to it,
			// and the delta from before the full transfer, which neither the
			// zone nor the file holds, is gone.
			written := ovServedSerial(t, zd)
			if got := zfFileSerial(zd); got != written {
				t.Errorf("the journal is anchored to serial %d, the file holds serial %d", got, written)
			}
			if j := ovJournal(t, zd); len(j) != 0 {
				t.Errorf("the journal kept deltas the written file covers:%s", ovJournalString(j))
			}

			txt := zfLocalTXT(t, 2)
			if err := ovUpdate(t, zd, txt); err != nil {
				t.Fatalf("local change after the refresh: %v", err)
			}
			if j := ovJournal(t, zd); len(j) != 1 || j[0].FromSerial != written {
				t.Fatalf("the change is not journalled from the file's serial %d:%s",
					written, ovJournalString(j))
			}

			buf := ovCaptureLog(t)
			again := zfFirstBindWith(t, zd, setup, addr, conf)
			replayZoneDeltasOnLoad(again)

			if w := ovConfigWarning(again); w != "" {
				t.Errorf("the first load raised a ConfigWarning: %s", w)
			}
			if strings.Contains(buf.String(), "edited or replaced") {
				t.Error("the load says the zone file was edited or replaced; tdns wrote it")
			}
			if !ovHas(ovServed(t, again, "local.example.", dns.TypeTXT), txt) {
				t.Errorf("the change is not served after the restart; journal:%s",
					ovJournalString(ovJournal(t, again)))
			}
			if n := len(ovJournal(t, again)); n != 1 {
				t.Errorf("the journal holds %d deltas after the replay, want 1", n)
			}
		})
	}
}

// The write of a dynamic zone is held to the same rule as the write of a
// source file: it leaves the journal and its anchor alone while the first load
// still owes the journal a replay, and drops what the file holds once it has
// been replayed.
func TestRefreshWriteOfADynamicZoneKeepsTheJournalUntilTheFirstLoadReplaysIt(t *testing.T) {
	for _, v := range zfVariants {
		t.Run(v.name, func(t *testing.T) {
			conf := zfDynamicConf(t)
			setup := zfDynamic(v.setup)
			zd := zfDynamicSecondary(t, v.setup)
			addr := zfUpstream(t, 8)
			zfRefreshWith(t, zd, addr, conf)
			txt := zfLocalTXT(t, 1)
			if err := ovUpdate(t, zd, txt); err != nil {
				t.Fatalf("local change: %v", err)
			}
			before := ovJournal(t, zd)
			if len(before) != 1 {
				t.Fatalf("precondition: the journal holds %d deltas, want 1", len(before))
			}

			again := zfFirstBindWith(t, zd, setup, addr, conf)
			if !again.journalReplayIsOwed() {
				t.Fatal("the first load does not record that it owes the journal")
			}
			anchor := zfFileSerial(again)

			persistRefreshedZone(again, again.ZoneName, again.generation.Load(), conf)

			after := ovJournal(t, again)
			if len(after) != 1 || after[0].FromSerial != before[0].FromSerial ||
				after[0].ToSerial != before[0].ToSerial {
				t.Fatalf("the write before the replay changed the journal:\nbefore:%s\nafter:%s",
					ovJournalString(before), ovJournalString(after))
			}
			if got := zfFileSerial(again); got != anchor {
				t.Errorf("the write before the replay moved the journal's anchor from %d to %d",
					anchor, got)
			}

			replayZoneDeltasOnLoad(again)
			if w := ovConfigWarning(again); w != "" {
				t.Errorf("the replay after the write raised a ConfigWarning: %s", w)
			}
			if !ovHas(ovServed(t, again, "local.example.", dns.TypeTXT), txt) {
				t.Error("the change is not served after the replay")
			}

			persistRefreshedZone(again, again.ZoneName, again.generation.Load(), conf)
			if j := ovJournal(t, again); len(j) != 0 {
				t.Errorf("the write after the replay kept deltas the file holds:%s", ovJournalString(j))
			}
			if got, served := zfFileSerial(again), ovServedSerial(t, again); got != served {
				t.Errorf("the write after the replay anchored the journal to %d, the file holds %d",
					got, served)
			}
		})
	}
}

// A dynamic zone whose own file is not the copy the dynamic-zone directory
// holds (a template-expanded primary's can live outside it) is not loaded from
// that copy, so the journal is not anchored to it, and the deltas it holds are
// not dropped: they are not in the file the next start reads.
func TestRefreshWriteOfADynamicCopyThatIsNotTheZonesFileLeavesTheJournal(t *testing.T) {
	conf := zfDynamicConf(t)
	zd := zfDynamicSecondary(t, zfVariants[0].setup)
	zd.Zonefile = filepath.Join(t.TempDir(), "elsewhere.zone")
	if err := ovUpdate(t, zd, zfLocalTXT(t, 1)); err != nil {
		t.Fatalf("local change: %v", err)
	}
	before := ovJournal(t, zd)

	addr := zfUpstream(t, 8)
	zfRefreshWith(t, zd, addr, conf)
	if _, err := os.Stat(GetDynamicZoneFilePath(zd.ZoneName, conf.DynamicZones.ZoneDirectory)); err != nil {
		t.Fatalf("precondition: the refresh wrote no dynamic zone file: %v", err)
	}

	// The transfer anchored the journal to the serial received. The write
	// would have moved it to the serial it wrote.
	if got, written := zfFileSerial(zd), ovServedSerial(t, zd); got == written {
		t.Errorf("the journal is anchored to serial %d, the one written to a file the zone does not"+
			" load from", got)
	}
	if after := ovJournal(t, zd); len(after) != len(before) {
		t.Errorf("the journal went from %d deltas to %d for a file the zone does not load from:%s",
			len(before), len(after), ovJournalString(after))
	}
}

// A zone deleted or replaced while the refresh's write of its file runs does
// not take the journal of the zone that holds its name now: the delete after
// the write is by name. persistRefreshedZone asks whether the zone is live once,
// before the write; the delete asks again.
func TestRefreshWriteLeavesTheJournalOfAZoneReplacedWhileItWasWritten(t *testing.T) {
	for _, tc := range []struct {
		name     string
		whileRun func(zd *ZoneData)
		dropped  bool
	}{
		{"still live", func(*ZoneData) {}, true},
		{"deleted", func(zd *ZoneData) { Zones.Remove(zd.ZoneName) }, false},
		{"replaced", func(zd *ZoneData) {
			Zones.Set(zd.ZoneName, &ZoneData{ZoneName: zd.ZoneName, ZoneType: Secondary})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := zfSecondary(t, zfVariants[0].setup)
			zfRefresh(t, zd, zfUpstream(t, 8))
			// What the zone journals after that write, and the next write holds.
			if err := ovUpdate(t, zd, zfLocalTXT(t, 1)); err != nil {
				t.Fatalf("local change: %v", err)
			}
			if n := len(ovJournal(t, zd)); n != 1 {
				t.Fatalf("precondition: the journal holds %d deltas, want 1", n)
			}
			gen := zd.generation.Load()
			if !zoneStillLive(zd, gen) {
				t.Fatal("precondition: the zone is not live before the write")
			}

			// The write, and the zone going away while it runs.
			_, wrote, err := zd.WriteFileWithSerial(zd.Zonefile)
			if err != nil {
				t.Fatalf("WriteFileWithSerial: %v", err)
			}
			tc.whileRun(zd)
			recordRefreshWrite(zd, gen, zd.Zonefile, wrote)

			n := len(ovJournal(t, zd))
			if tc.dropped && n != 0 {
				t.Errorf("the journal holds %d deltas after a write that holds them, want 0", n)
			}
			if !tc.dropped && n != 1 {
				t.Errorf("the journal holds %d deltas after the zone went away during the write,"+
					" want the 1 that is not this zone's to drop", n)
			}
		})
	}
}
