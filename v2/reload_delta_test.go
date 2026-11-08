/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"log"
	"os"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #1006: a reload computes the difference from what it replaces.

func reloadText(serial, body string) string {
	return "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. " + serial + " 7200 1800 604800 7200\n" +
		"example.\t3600\tIN\tNS\tns.example.\n" + body
}

func mustReload(t *testing.T, zd *ZoneData, force bool) {
	t.Helper()
	if _, err := zd.Refresh(context.Background(), false, false, force, &Config{}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
}

func servedSerial(zd *ZoneData) uint32 {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.CurrentSerial
}

// rrsetsHold reports whether some RRset in sets holds an RR whose text has all
// of the given substrings.
func rrsetsHold(sets []core.RRset, parts ...string) bool {
	for _, rs := range sets {
		for _, rr := range rs.RRs {
			s, all := rr.String(), true
			for _, p := range parts {
				if !strings.Contains(s, p) {
					all = false
					break
				}
			}
			if all {
				return true
			}
		}
	}
	return false
}

// With ixfr-from-differences, an edit-and-reload becomes one IXFR link holding
// exactly what the edit changed.
func TestReloadWithIxfrFromDifferencesAppendsALink(t *testing.T) {
	zd := reloadZone(t, newTestKeyDB(t), reloadBase)
	zd.SetOption(OptIxfrFromDifferences, true)

	operatorEdit(t, zd, reloadText("101", "www.example.\t3600\tIN\tA\t192.0.2.9\nnew.example.\t300\tIN\tA\t192.0.2.5\n"))
	mustReload(t, zd, false)

	chain := chainOf(zd)
	if len(chain) != 1 {
		t.Fatalf("got %d IXFR links after a reload, want 1", len(chain))
	}
	link := chain[0]
	if link.FromSerial != 100 || link.ToSerial != 101 {
		t.Errorf("link runs %d -> %d, want 100 -> 101", link.FromSerial, link.ToSerial)
	}
	if !rrsetsHold(link.Removed, "www.example.", "192.0.2.1") {
		t.Errorf("the link does not remove the old www A: %v", link.Removed)
	}
	if !rrsetsHold(link.Added, "www.example.", "192.0.2.9") || !rrsetsHold(link.Added, "new.example.", "192.0.2.5") {
		t.Errorf("the link does not add the new records: %v", link.Added)
	}
	if len(link.Removed) != 1 || len(link.Added) != 2 {
		t.Errorf("the link carries more than the edit: removed %v, added %v", link.Removed, link.Added)
	}
	if steps, ok := ixfrDeltaSteps(zd.publishedSnapshot(), 100); !ok || len(steps) != 1 {
		t.Errorf("no IXFR path from 100: ok=%v steps=%d", ok, len(steps))
	}

	// A second edit: a downstream two versions back gets both steps.
	operatorEdit(t, zd, reloadText("102", "www.example.\t3600\tIN\tA\t192.0.2.9\n"))
	mustReload(t, zd, false)
	if steps, ok := ixfrDeltaSteps(zd.publishedSnapshot(), 100); !ok || len(steps) != 2 {
		t.Errorf("no two-step IXFR path from 100: ok=%v steps=%d", ok, len(steps))
	}
}

// Without the option a reload starts a new IXFR epoch, as before.
func TestReloadWithoutTheOptionResetsTheChain(t *testing.T) {
	zd := reloadZone(t, newTestKeyDB(t), reloadBase)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.", "192.0.2.11"))
	if len(chainOf(zd)) != 1 {
		t.Fatal("setup: expected 1 link")
	}
	operatorEdit(t, zd, reloadText("500", "www.example.\t3600\tIN\tA\t192.0.2.9\n"))
	mustReload(t, zd, false)
	if got := len(chainOf(zd)); got != 0 {
		t.Errorf("a reload without ixfr-from-differences kept %d links", got)
	}
}

// A file whose serial is ahead is served at that serial; one that is not gets
// the zone's next serial.
func TestReloadServesTheFilesOwnSerial(t *testing.T) {
	zd := reloadZone(t, newTestKeyDB(t), reloadBase)

	operatorEdit(t, zd, reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.9\n"))
	mustReload(t, zd, false)
	if got := servedSerial(zd); got != 101 {
		t.Errorf("an edit that kept the file's serial is served at %d, want 101", got)
	}

	operatorEdit(t, zd, reloadText("500", "www.example.\t3600\tIN\tA\t192.0.2.10\n"))
	mustReload(t, zd, false)
	if got := servedSerial(zd); got != 500 {
		t.Errorf("a file at serial 500 is served at %d, want 500", got)
	}
}

// A reload whose content is what the zone serves publishes nothing: no new
// serial and no NOTIFY, forced or not.
func TestReloadOfUnchangedContentKeepsTheSerial(t *testing.T) {
	q := withNotifyQ(t, 4)
	zd := reloadZone(t, newTestKeyDB(t), reloadBase)
	zd.Notify = []PeerConf{{Addr: aDownstream}}
	before := zd.publishedSnapshot()

	mustReload(t, zd, true)
	if got := servedSerial(zd); got != 100 {
		t.Errorf("a forced reload of an unchanged file moved the serial to %d", got)
	}
	if zd.publishedSnapshot() != before {
		t.Error("a forced reload of an unchanged file published a new version")
	}

	// Reformatted, reordered and with a TTL style change: the same zone.
	operatorEdit(t, zd, "$TTL 3600\nwww.example.\tIN A 192.0.2.1\n; a comment\n"+
		"example.\tIN SOA ns.example. hostmaster.example. 100 7200 1800 604800 7200\nexample. IN NS ns.example.\n")
	mustReload(t, zd, true)
	if got := servedSerial(zd); got != 100 {
		t.Errorf("a reformatted file moved the serial to %d", got)
	}
	if got := len(q); got != 0 {
		t.Errorf("%d NOTIFYs for reloads that changed nothing", got)
	}

	// And a real change does publish and notify.
	operatorEdit(t, zd, reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.7\n"))
	mustReload(t, zd, false)
	if got := servedSerial(zd); got != 101 {
		t.Errorf("a real edit is served at %d, want 101", got)
	}
	if got := len(q); got != 1 {
		t.Errorf("%d NOTIFYs for one real edit, want 1", got)
	}
}

// A file whose only change is a serial ahead of the served one is served at
// that serial: the operator asked for it, and it is a legal empty IXFR step.
func TestReloadOfASerialOnlyBump(t *testing.T) {
	zd := reloadZone(t, newTestKeyDB(t), reloadBase)
	zd.SetOption(OptIxfrFromDifferences, true)
	operatorEdit(t, zd, strings.Replace(reloadBase, " 100 ", " 200 ", 1))
	mustReload(t, zd, false)
	if got := servedSerial(zd); got != 200 {
		t.Fatalf("a serial-only bump is served at %d, want 200", got)
	}
	chain := chainOf(zd)
	if len(chain) != 1 || len(chain[0].Removed) != 0 || len(chain[0].Added) != 0 {
		t.Errorf("want one empty link, got %+v", chain)
	}
}

// The operator folds the journalled change into the file by hand: the content
// is what is served, so nothing is published, and the journal is emptied.
func TestReloadOfAJournalFoldedIntoTheFile(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)
	if err := apiUpdate(t, zd, kdb, "journal.example. 3600 IN A 10.1.1.1"); err != nil {
		t.Fatalf("the API update failed: %v", err)
	}
	served := servedSerial(zd)

	operatorEdit(t, zd, reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.1\njournal.example.\t3600\tIN\tA\t10.1.1.1\n"))
	mustReload(t, zd, false)
	if got := servedSerial(zd); got != served {
		t.Errorf("folding the journal into the file moved the serial from %d to %d", served, got)
	}
	if !hasARRset(t, zd, "journal.example.") {
		t.Error("the folded record is not served")
	}
	if _, have, err := kdb.LastZoneDeltaSerial(zd.ZoneName); err != nil || have {
		t.Errorf("the journal was not emptied (have=%v, err=%v)", have, err)
	}
}

// restartZone stands up a second ZoneData over the same file and database, as
// a restart does, and loads it.
func restartZone(t *testing.T, zd *ZoneData, kdb *KeyDB) *ZoneData {
	t.Helper()
	fresh := &ZoneData{
		ZoneName:      "example.",
		ZoneStore:     MapZone,
		ZoneType:      Primary,
		Zonefile:      zd.Zonefile,
		Logger:        log.New(os.Stderr, "", 0),
		Options:       map[ZoneOption]bool{OptAllowUpdates: true},
		KeyDB:         kdb,
		UpdatePolicy:  policyAllowing(dns.TypeA, dns.TypeTXT),
		FirstZoneLoad: true,
		Data:          core.NewNameMap[OwnerData](),
	}
	zd.stopPublisher()
	Zones.Set("example.", fresh)
	t.Cleanup(func() { Zones.Remove("example.") })
	t.Cleanup(fresh.stopPublisher)
	if _, err := fresh.Refresh(context.Background(), false, false, false, &Config{}); err != nil {
		t.Fatalf("Refresh after the restart: %v", err)
	}
	fresh.InstallInitialSnapshot()
	return fresh
}

// A restart that loads exactly what was last published serves that serial
// again, even when it is past the file's own.
func TestRestartWithUnchangedContentKeepsTheSerial(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)
	operatorEdit(t, zd, reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.9\n"))
	mustReload(t, zd, false)
	if got := servedSerial(zd); got != 101 {
		t.Fatalf("setup: served %d, want 101", got)
	}

	fresh := restartZone(t, zd, kdb)
	if got := servedSerial(fresh); got != 101 {
		t.Errorf("a restart with nothing changed serves %d, want 101", got)
	}
}

// Anything published after the content the digest describes, or any change
// while the server was down, still lifts the serial past what was published.
func TestRestartAfterAChangeLiftsTheSerial(t *testing.T) {
	t.Run("file changed while down", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := reloadZone(t, kdb, reloadBase)
		operatorEdit(t, zd, reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.9\n"))
		mustReload(t, zd, false)
		operatorEdit(t, zd, reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.8\n"))
		fresh := restartZone(t, zd, kdb)
		if got := servedSerial(fresh); got != 102 {
			t.Errorf("a restart over a changed file serves %d, want 102", got)
		}
	})
	t.Run("published after the reload", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := reloadZone(t, kdb, reloadBase)
		operatorEdit(t, zd, reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.9\n"))
		mustReload(t, zd, false)
		stageAndPublish(t, zd, nil) // a serial bump with no change, as a re-sign makes
		last := servedSerial(zd)
		fresh := restartZone(t, zd, kdb)
		if got := servedSerial(fresh); !serialNewer(got, last) {
			t.Errorf("a restart after a later publish serves %d, not past %d", got, last)
		}
	})
}

func TestAuthoredContentEqual(t *testing.T) {
	build := func(t *testing.T, text string) map[string]*OwnerData {
		t.Helper()
		zd := &ZoneData{ZoneName: "example.", ZoneStore: MapZone, Logger: log.New(os.Stderr, "", 0)}
		if _, _, err := zd.ReadZoneData(text, true); err != nil {
			t.Fatalf("ReadZoneData: %v", err)
		}
		return snapshotMapFromData(zd.Data)
	}
	base := build(t, reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.1\nwww.example.\t3600\tIN\tA\t192.0.2.2\n"))
	cases := []struct {
		name, text string
		equal      bool
	}{
		{"serial only", reloadText("999", "www.example.\t3600\tIN\tA\t192.0.2.1\nwww.example.\t3600\tIN\tA\t192.0.2.2\n"), true},
		{"order", reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.2\nwww.example.\t3600\tIN\tA\t192.0.2.1\n"), true},
		{"TTL", reloadText("100", "www.example.\t300\tIN\tA\t192.0.2.1\nwww.example.\t300\tIN\tA\t192.0.2.2\n"), false},
		{"one record fewer", reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.1\n"), false},
		{"new owner", reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.1\nwww.example.\t3600\tIN\tA\t192.0.2.2\nx.example.\t3600\tIN\tTXT\t\"x\"\n"), false},
		{"SOA timer", strings.Replace(reloadText("100", "www.example.\t3600\tIN\tA\t192.0.2.1\nwww.example.\t3600\tIN\tA\t192.0.2.2\n"), " 7200 1800 ", " 3600 1800 ", 1), false},
	}
	for _, c := range cases {
		other := build(t, c.text)
		if got := authoredContentEqual("example.", base, other, false); got != c.equal {
			t.Errorf("%s: equal = %v, want %v", c.name, got, c.equal)
		}
		digestsEqual := authoredContentDigest("example.", base, false) == authoredContentDigest("example.", other, false)
		if digestsEqual != c.equal {
			t.Errorf("%s: digests equal = %v, want %v", c.name, digestsEqual, c.equal)
		}
	}
}

// The diff stops as soon as it passes its limit.
func TestComputeZoneDeltaBoundedStopsEarly(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < 200; i++ {
		a.WriteString("h" + itoa(i) + ".example.\t3600\tIN\tA\t192.0.2.1\n")
		b.WriteString("h" + itoa(i) + ".example.\t3600\tIN\tA\t192.0.2.2\n")
	}
	build := func(text string) map[string]*OwnerData {
		zd := &ZoneData{ZoneName: "example.", ZoneStore: MapZone, Logger: log.New(os.Stderr, "", 0)}
		if _, _, err := zd.ReadZoneData(reloadText("1", text), true); err != nil {
			t.Fatalf("ReadZoneData: %v", err)
		}
		return snapshotMapFromData(zd.Data)
	}
	oldData, newData := build(a.String()), build(b.String())
	if _, _, est, complete := computeZoneDeltaBounded("example.", oldData, newData, 500); complete || est > 1000 {
		t.Errorf("bounded diff: complete=%v est=%d, want an early stop just past 500", complete, est)
	}
	rem, add, _, complete := computeZoneDeltaBounded("example.", oldData, newData, -1)
	if !complete || len(rem) != 200 || len(add) != 200 {
		t.Errorf("unbounded diff: complete=%v removed=%d added=%d", complete, len(rem), len(add))
	}
}
