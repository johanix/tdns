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

// Tests for #919: a signing secondary outside the journal overlay -- a
// multi-provider zone, or a zone of an app other than tdns-auth -- has its
// journal recorded against the copy it received by transfer. At a restart the
// zone is transferred afresh, and once the upstream has moved on the journal
// no longer chains from the serial received.

// btVariants are the two kinds of zone outside the overlay that journal.
var btVariants = []struct {
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

// btLocalTXT is a local change: a record the upstream does not have.
func btLocalTXT(t *testing.T, n int) dns.RR {
	t.Helper()
	return mustRR(t, fmt.Sprintf("local.example.\t3600\tIN\tTXT\t\"local-%d\"", n))
}

// btRestart is a restart stand-in: a new zone on the same keystore, set up as
// the old one was, first loaded by transfer from an upstream at serial, and
// then reconciled with its journal as the first load does.
func btRestart(t *testing.T, zd *ZoneData, setup func(*testing.T, *ZoneData), serial uint32) *ZoneData {
	t.Helper()
	again := ovRestarted(t, zd.KeyDB, zd.DnssecPolicy)
	setup(t, again)
	ovTransfer(t, again, ovUpstreamZone(serial), true)
	replayZoneDeltasOnLoad(again)
	return again
}

// The #919 case. The upstream has moved on: the journal is discarded without
// a ConfigWarning and without blaming a zone file, and a change made after
// that is journalled from the serial received, so it survives the next
// restart.
func TestJournalBehindTransferDiscardedAtLoad(t *testing.T) {
	for _, v := range btVariants {
		t.Run(v.name, func(t *testing.T) {
			zd := ixSigningSecondary(t, ixApplyZone)
			v.setup(t, zd)
			if err := ovUpdate(t, zd, btLocalTXT(t, 1)); err != nil {
				t.Fatalf("local change: %v", err)
			}
			if n := len(ovJournal(t, zd)); n != 1 {
				t.Fatalf("precondition: the journal holds %d deltas, want 1", n)
			}

			buf := ovCaptureLog(t)
			again := btRestart(t, zd, v.setup, 20)

			if w := ovConfigWarning(again); w != "" {
				t.Errorf("the first load raised a ConfigWarning: %s", w)
			}
			if j := ovJournal(t, again); len(j) != 0 {
				t.Errorf("the journal was kept:%s", ovJournalString(j))
			}
			logged := buf.String()
			if strings.Contains(logged, "edited or replaced") {
				t.Error("the load says the zone file was edited or replaced; the zone has no file")
			}
			if !strings.Contains(logged, "deltas were discarded") || !strings.Contains(logged, "local-1") {
				t.Errorf("the discarded change is not in the log:\n%s", logged)
			}

			// A change after the discard chains from the serial received.
			txt := btLocalTXT(t, 2)
			if err := ovUpdate(t, again, txt); err != nil {
				t.Fatalf("local change after the discard: %v", err)
			}
			if j := ovJournal(t, again); len(j) != 1 || j[0].FromSerial != 20 {
				t.Fatalf("the change is not journalled from the received serial 20:%s",
					ovJournalString(j))
			}
			third := btRestart(t, again, v.setup, 20)
			if !ovHas(ovServed(t, third, "local.example.", dns.TypeTXT), txt) {
				t.Errorf("the change is not served after a restart with the upstream unchanged;"+
					" journal:%s", ovJournalString(ovJournal(t, third)))
			}
			if w := ovConfigWarning(third); w != "" {
				t.Errorf("the second restart raised a ConfigWarning: %s", w)
			}
		})
	}
}

// The sequence the discard at load does not reach: a full transfer at runtime,
// a local change after it, and a restart with the upstream unmoved.
//
// The journal recorded before the transfer describes content the transfer has
// replaced. If it stays, the next local change chains from its tail, and at
// the restart the journal begins at a serial that is not the one received: the
// whole journal is discarded, the change made after the transfer with it. And
// the discard alone is not enough. The journal's next delta is anchored to the
// serial received, and the zone counts its own serials: the replacement the
// transfer publishes is one past the serial it served, not the upstream's. An
// upstream that is ahead leaves the first change after the transfer ending
// behind the serial it is anchored to, and it has to publish past it. Both
// upstream positions are here: ahead of the zone, and behind it.
func TestJournalDiscardedByRuntimeFullTransfer(t *testing.T) {
	for _, v := range btVariants {
		for _, x := range []struct {
			name   string
			serial uint32
			force  bool
		}{
			{"upstream ahead, axfr", 20, true},
			{"upstream behind, axfr", 5, true},
			{"upstream ahead, ixfr answered with the whole zone", 20, false},
		} {
			t.Run(v.name+"/"+x.name, func(t *testing.T) {
				zd := ixSigningSecondary(t, ixApplyZone)
				v.setup(t, zd)
				first, second := btLocalTXT(t, 1), btLocalTXT(t, 2)
				if err := ovUpdate(t, zd, first); err != nil {
					t.Fatalf("local change: %v", err)
				}
				if n := len(ovJournal(t, zd)); n != 1 {
					t.Fatalf("precondition: the journal holds %d deltas, want 1", n)
				}

				buf := ovCaptureLog(t)
				servedBefore := ovServedSerial(t, zd)
				ovTransfer(t, zd, ovUpstreamZone(x.serial), x.force)

				if ovHas(ovServed(t, zd, "local.example.", dns.TypeTXT), first) {
					t.Fatal("precondition: the full transfer kept the local change")
				}
				// The zone's own count, not the upstream's.
				if got := ovServedSerial(t, zd); got != servedBefore+1 {
					t.Errorf("served serial %d -> %d: the transfer is published at the zone's"+
						" own next serial, %d", servedBefore, got, servedBefore+1)
				}
				if j := ovJournal(t, zd); len(j) != 0 {
					t.Errorf("the journal recorded against the replaced content was kept:%s",
						ovJournalString(j))
				}
				if logged := buf.String(); !strings.Contains(logged, "deltas were discarded") ||
					!strings.Contains(logged, "local-1") {
					t.Errorf("the discarded change is not in the log:\n%s", logged)
				}
				if w := ovConfigWarning(zd); w != "" {
					t.Errorf("the transfer raised a ConfigWarning: %s", w)
				}

				// The change after the transfer chains from the serial received
				// and runs forward from it.
				if err := ovUpdate(t, zd, second); err != nil {
					t.Fatalf("local change after the transfer: %v", err)
				}
				j := ovJournal(t, zd)
				if len(j) != 1 || j[0].FromSerial != x.serial || !serialNewer(j[0].ToSerial, x.serial) {
					t.Errorf("the change is not journalled forward from the received serial %d:%s",
						x.serial, ovJournalString(j))
				}
				if !ovHas(ovServed(t, zd, "local.example.", dns.TypeTXT), second) {
					t.Fatal("the change is not served")
				}
				if got := ovServedSerial(t, zd); got != j[0].ToSerial {
					t.Errorf("served serial %d, but the journal's delta ends at %d", got, j[0].ToSerial)
				}

				// A restart with the upstream where it was: the change survives.
				again := btRestart(t, zd, v.setup, x.serial)
				if !ovHas(ovServed(t, again, "local.example.", dns.TypeTXT), second) {
					t.Errorf("the change made after the transfer is not served after a restart"+
						" with the upstream unchanged; journal:%s", ovJournalString(ovJournal(t, again)))
				}
				if w := ovConfigWarning(again); w != "" {
					t.Errorf("the restart raised a ConfigWarning: %s", w)
				}
			})
		}
	}
}

// What a full transfer discards is saved beside the zone file, as a purge
// saves it, when the zone has one.
func TestJournalDiscardByTransferSavedBesideZoneFile(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	btVariants[0].setup(t, zd)
	zd.Zonefile = filepath.Join(t.TempDir(), "example.zone")
	if err := ovUpdate(t, zd, btLocalTXT(t, 1)); err != nil {
		t.Fatalf("local change: %v", err)
	}

	ovTransfer(t, zd, ovUpstreamZone(20), true)

	saved, err := os.ReadFile(zd.Zonefile + ".9.purged")
	if err != nil {
		t.Fatalf("the discarded journal was not saved beside the zone file: %v", err)
	}
	if !strings.Contains(string(saved), "local-1") ||
		!strings.Contains(string(saved), "a full transfer replaced the content") {
		t.Errorf("the artefact does not say what was discarded and why:\n%s", saved)
	}
	if j := ovJournal(t, zd); len(j) != 0 {
		t.Errorf("the journal was kept:%s", ovJournalString(j))
	}
}

// When it cannot be saved, nothing is deleted. The transfer is applied all the
// same, since the zone has to follow its upstream, and the zone says that its
// journal could not be discarded.
func TestJournalDiscardByTransferNotSavedKeepsJournalAndWarns(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	btVariants[0].setup(t, zd)
	zd.Zonefile = filepath.Join(t.TempDir(), "no-such-directory", "example.zone")
	first := btLocalTXT(t, 1)
	if err := ovUpdate(t, zd, first); err != nil {
		t.Fatalf("local change: %v", err)
	}

	servedBefore := ovServedSerial(t, zd)
	ovTransfer(t, zd, ovUpstreamZone(20), true)

	if j := ovJournal(t, zd); len(j) != 1 {
		t.Errorf("the journal holds %d deltas, want the 1 that could not be saved:%s",
			len(j), ovJournalString(j))
	}
	if w := ovConfigWarning(zd); !strings.Contains(w, "could not be discarded") {
		t.Errorf("ConfigWarning = %q, want one saying the journal could not be discarded", w)
	}
	if got := ovServedSerial(t, zd); got != servedBefore+1 {
		t.Errorf("served serial %d -> %d: the transfer was not applied", servedBefore, got)
	}
	if ovHas(ovServed(t, zd, "local.example.", dns.TypeTXT), first) {
		t.Error("the transfer kept the local change")
	}
}

// An applied IXFR is not a full transfer: its content is the zone as served,
// local changes included, plus the difference, so the journal is left alone.
func TestJournalKeptByAppliedIxfr(t *testing.T) {
	for _, v := range btVariants {
		t.Run(v.name, func(t *testing.T) {
			authApp(t)
			pzd, addr, stop := ixfrTestPrimary(t, ixApplyZone)
			defer stop()
			// Registered only while its chain is built; see TestIxfrInConvergesViaDelta.
			Zones.Set(ovZone, pzd)
			t.Cleanup(func() { Zones.Remove(ovZone) })
			stageAndPublish(t, pzd, stageAddA(t, pzd, "one.example.", "10.1.0.1"))
			Zones.Remove(ovZone)

			zd := ixSigningSecondary(t, ixApplyZone)
			v.setup(t, zd)
			txt := btLocalTXT(t, 1)
			if err := ovUpdate(t, zd, txt); err != nil {
				t.Fatalf("local change: %v", err)
			}
			outcome, _, err := zd.ixfrTransferIn(context.Background(), PeerConf{Addr: addr},
				zd.IncomingSerial, &Config{})
			if err != nil {
				t.Fatalf("ixfrTransferIn: %v", err)
			}
			if outcome != ixfrDelta {
				t.Fatalf("the upstream answered %s, want a delta", outcome)
			}
			journalBefore := ovJournalString(ovJournal(t, zd))

			ovTransferFrom(t, zd, addr, false)

			if owner, _ := zd.GetOwner("one.example."); owner == nil {
				t.Fatal("one.example. is missing: the delta was not applied")
			}
			if !ovHas(ovServed(t, zd, "local.example.", dns.TypeTXT), txt) {
				t.Error("the local change is gone after an applied IXFR")
			}
			if after := ovJournalString(ovJournal(t, zd)); after != journalBefore {
				t.Errorf("an applied IXFR changed the journal:\nbefore:%s\nafter:%s", journalBefore, after)
			}
		})
	}
}

// The upstream has not moved: the journal chains from the serial received and
// is replayed, as before.
func TestJournalBehindTransferReplayedWhenUpstreamUnchanged(t *testing.T) {
	for _, v := range btVariants {
		t.Run(v.name, func(t *testing.T) {
			zd := ixSigningSecondary(t, ixApplyZone)
			v.setup(t, zd)
			txt := btLocalTXT(t, 1)
			if err := ovUpdate(t, zd, txt); err != nil {
				t.Fatalf("local change: %v", err)
			}

			again := btRestart(t, zd, v.setup, 7)

			if !ovHas(ovServed(t, again, "local.example.", dns.TypeTXT), txt) {
				t.Errorf("the change is not served after the restart; journal:%s",
					ovJournalString(ovJournal(t, again)))
			}
			if n := len(ovJournal(t, again)); n != 1 {
				t.Errorf("the journal holds %d deltas after the replay, want 1", n)
			}
			if w := ovConfigWarning(again); w != "" {
				t.Errorf("the first load raised a ConfigWarning: %s", w)
			}
		})
	}
}

// A zone loaded from its file keeps the refusal: a journal that does not
// chain from the file is kept, and reported.
func TestJournalNotChainingFromFileStillRefused(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	btVariants[0].setup(t, zd)
	ovPlant(t, zd, 3, 5, "local.example.\t3600\tIN\tTXT\t\"planted\"")

	replayZoneDeltasOnLoad(zd)

	if w := ovConfigWarning(zd); !strings.Contains(w, "could not be replayed") {
		t.Errorf("ConfigWarning = %q, want the refusal", w)
	}
	if n := len(ovJournal(t, zd)); n != 1 {
		t.Errorf("the journal holds %d deltas, want the 1 planted", n)
	}
}

// `zone journal status` on a zone whose content came by transfer, holding a
// journal that does not chain from the serial received: it names the transfer,
// not a zone file. A full transfer at runtime discards such a journal, so the
// record is put there the way a record that reached the journal some other way
// would be.
func TestJournalStatusBehindTransfer(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	btVariants[0].setup(t, zd)
	ovTransfer(t, zd, ovUpstreamZone(20), true)
	ovPlant(t, zd, 3, 5, "local.example.\t3600\tIN\tTXT\t\"planted\"")

	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if !info.FromTransfer {
		t.Error("FromTransfer = false after a transfer")
	}
	if info.Replayable {
		t.Error("Replayable = true for a journal that predates the transferred copy")
	}
	if !strings.Contains(info.Diagnosis, "transferred at serial 20") ||
		strings.Contains(info.Diagnosis, "edited or replaced") {
		t.Errorf("Diagnosis does not describe the transfer: %q", info.Diagnosis)
	}
}
