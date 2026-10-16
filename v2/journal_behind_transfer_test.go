/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
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

// `zone journal status` on a running zone after a full transfer from an
// upstream that has moved on: it names the transfer, not a zone file.
func TestJournalStatusBehindTransfer(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	btVariants[0].setup(t, zd)
	if err := ovUpdate(t, zd, btLocalTXT(t, 1)); err != nil {
		t.Fatalf("local change: %v", err)
	}
	ovTransfer(t, zd, ovUpstreamZone(20), true)

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
