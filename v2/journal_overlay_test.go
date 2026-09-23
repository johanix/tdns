/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Tests for docs/2026-09-24-journal-overlay-on-transfer.md, section 8.
//
// The zone under test is an overlay zone (doc 4.1): an inline-signing
// secondary on tdns-auth, with a real keystore, whose upstream is a tdns
// primary on a local port. Its own records are published the way the DS
// engine publishes a CDS: an internal ZONE-UPDATE that deletes the RRset and
// adds the new one (publishCDSAndWait).

const ovZone = "example."

// ovUpstreamZone is the upstream's zone at serial, with extra records.
func ovUpstreamZone(serial uint32, extra ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. %d 7200 1800 604800 7200\n", serial)
	b.WriteString("example.\t3600\tIN\tNS\tns.example.\n")
	b.WriteString("ns.example.\t3600\tIN\tA\t10.0.0.1\n")
	b.WriteString("www.example.\t3600\tIN\tA\t10.0.0.3\n")
	b.WriteString("www.example.\t3600\tIN\tAAAA\t2001:db8::3\n")
	for _, e := range extra {
		b.WriteString(e + "\n")
	}
	return b.String()
}

// ovCDSText is a CDS record at the apex, told apart by n.
func ovCDSText(n int) string {
	return fmt.Sprintf("example.\t3600\tIN\tCDS\t%d 15 2 %064x", 1000+n, n)
}

func ovCDS(t *testing.T, n int) dns.RR {
	t.Helper()
	return mustRR(t, ovCDSText(n))
}

// ovPublishCDS publishes the apex CDS RRset as the DS engine does: delete the
// RRset, add the new one. With no records it withdraws the CDS.
func ovPublishCDS(t *testing.T, zd *ZoneData, cds ...dns.RR) error {
	t.Helper()
	actions := append([]dns.RR{cdsDeleteRR(zd.ZoneName)}, cds...)
	_, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        actions,
		InternalUpdate: true,
	}, zd.KeyDB)
	return err
}

// ovUpdate applies a local change through the zone updater.
func ovUpdate(t *testing.T, zd *ZoneData, actions ...dns.RR) error {
	t.Helper()
	_, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        actions,
		InternalUpdate: true,
	}, zd.KeyDB)
	return err
}

// ovDel is rr as an update-section delete of that one record.
func ovDel(rr dns.RR) dns.RR {
	c := dns.Copy(rr)
	c.Header().Class = dns.ClassNONE
	c.Header().Ttl = 0
	return c
}

// ovTransfer points zd at a fresh upstream serving zoneStr and runs one
// refresh through it. force asks for a full transfer (AXFR); without it the
// secondary asks for IXFR when it can.
func ovTransfer(t *testing.T, zd *ZoneData, zoneStr string, force bool) {
	t.Helper()
	_, addr, stop := ixfrTestPrimary(t, zoneStr)
	defer stop()
	ovTransferFrom(t, zd, addr, force)
}

func ovTransferFrom(t *testing.T, zd *ZoneData, addr string, force bool) {
	t.Helper()
	zd.mu.Lock()
	zd.Upstreams = []PeerConf{{Addr: addr}}
	zd.mu.Unlock()
	if _, err := zd.FetchFromUpstream(context.Background(), false, false, force,
		zd.CollectDynamicRRs(&Config{}), &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}
}

// ovServed is the published RRset of rrtype at owner.
func ovServed(t *testing.T, zd *ZoneData, owner string, rrtype uint16) []dns.RR {
	t.Helper()
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("no published snapshot")
	}
	od := getOwnerFrom(snap, owner)
	if od == nil {
		return nil
	}
	return od.RRtypes.GetOnlyRRSet(rrtype).RRs
}

func ovServedSerial(t *testing.T, zd *ZoneData) uint32 {
	t.Helper()
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("no published snapshot")
	}
	return snap.Serial
}

// ovHas reports whether rrs holds want, TTL aside.
func ovHas(rrs []dns.RR, want dns.RR) bool {
	for _, rr := range rrs {
		if rrKey(rr) == rrKey(want) {
			return true
		}
	}
	return false
}

// ovJournal is the zone's journal, one delta per element.
func ovJournal(t *testing.T, zd *ZoneData) []ZoneDeltaRecord {
	t.Helper()
	deltas, err := zd.KeyDB.LoadZoneDeltas(zd.ZoneName)
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	return deltas
}

func ovJournalString(deltas []ZoneDeltaRecord) string {
	var b strings.Builder
	for _, d := range deltas {
		fmt.Fprintf(&b, "\n  %d -> %d", d.FromSerial, d.ToSerial)
		for _, rr := range d.RRs {
			fmt.Fprintf(&b, "\n    %s %s", rr.Action, rr.RR)
		}
	}
	if b.Len() == 0 {
		return " (empty)"
	}
	return b.String()
}

// ovRestarted is a new zone on kdb, as after a restart: nothing loaded, and
// its first load still to come.
func ovRestarted(t *testing.T, kdb *KeyDB, policy *DnssecPolicy) *ZoneData {
	t.Helper()
	zd := &ZoneData{
		ZoneName:      ovZone,
		ZoneStore:     MapZone,
		ZoneType:      Secondary,
		Logger:        discardLogger(),
		Options:       map[ZoneOption]bool{OptInlineSigning: true},
		KeyDB:         kdb,
		DnssecPolicy:  policy,
		FirstZoneLoad: true,
	}
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
	t.Cleanup(zd.stopPublisher)
	return zd
}

// ovConfigWarning is the zone's ConfigWarning, or "" when it has none.
func ovConfigWarning(zd *ZoneData) string {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if e, ok := zd.Errors[ConfigWarning]; ok {
		return e.Msg
	}
	return ""
}

// T1. A CDS published on an inline-signing secondary survives a full transfer
// from an upstream without one, and the transfer publishes once. Both shapes of
// full transfer: a forced AXFR, and an IXFR request the upstream answers with
// the whole zone (it has no chain to serve from).
func TestJournalOverlayCDSSurvivesFullTransfer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		force bool
	}{
		{"axfr", true},
		{"ixfr answered with the whole zone", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := ixSigningSecondary(t, ixApplyZone)
			cds := ovCDS(t, 1)
			if err := ovPublishCDS(t, zd, cds); err != nil {
				t.Fatalf("CDS publish: %v", err)
			}
			if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), cds) {
				t.Fatal("precondition: the CDS is not served after its publish")
			}

			_, addr, stop := ixfrTestPrimary(t, ovUpstreamZone(20))
			defer stop()
			if !tc.force {
				// What the doc's 4.3 turns on: a whole zone in answer to an
				// IXFR request is a full replacement, not an applied delta.
				outcome, _, err := zd.ixfrTransferIn(context.Background(),
					PeerConf{Addr: addr}, zd.IncomingSerial, &Config{})
				if err != nil {
					t.Fatalf("ixfrTransferIn: %v", err)
				}
				if outcome != ixfrFullZone {
					t.Fatalf("the upstream answered %s, want the whole zone", outcome)
				}
			}

			before := ovServedSerial(t, zd)
			ovTransferFrom(t, zd, addr, tc.force)

			if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), cds) {
				t.Fatalf("the CDS is gone after a full transfer from an upstream without one;"+
					" journal:%s", ovJournalString(ovJournal(t, zd)))
			}
			assertPublishedRRsetVerifies(t, zd, ovZone, dns.TypeCDS)
			if got := ovServedSerial(t, zd); got != before+1 {
				t.Errorf("served serial %d -> %d: the transfer published %d times, want once",
					before, got, got-before)
			}
		})
	}
}

// T2. Restart stand-in: a new zone on the same keystore, first loaded by
// transfer from an upstream that has moved on, serves the CDS, and the load's
// journal step raises no ConfigWarning. L1 is the real restart.
func TestJournalOverlayCDSSurvivesRestart(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	cds := ovCDS(t, 1)
	if err := ovPublishCDS(t, zd, cds); err != nil {
		t.Fatalf("CDS publish: %v", err)
	}

	again := ovRestarted(t, zd.KeyDB, zd.DnssecPolicy)
	ovTransfer(t, again, ovUpstreamZone(20), true)
	replayZoneDeltasOnLoad(again)

	if !ovHas(ovServed(t, again, ovZone, dns.TypeCDS), cds) {
		t.Errorf("after the restart the CDS is not served; journal:%s",
			ovJournalString(ovJournal(t, again)))
	}
	if w := ovConfigWarning(again); w != "" {
		t.Errorf("the first load raised a ConfigWarning: %s", w)
	}
}

// T3. Empty journal, upstream serial ahead of the served one: a local change
// is applied (doc §3, first case).
func TestJournalOverlayLocalChangeWithUpstreamAhead(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	ovTransfer(t, zd, ovUpstreamZone(2026092401), true)
	if n := len(ovJournal(t, zd)); n != 0 {
		t.Fatalf("precondition: the journal holds %d deltas, want none", n)
	}

	cds := ovCDS(t, 1)
	if err := ovPublishCDS(t, zd, cds); err != nil {
		t.Fatalf("CDS publish refused behind an upstream whose serial is ahead: %v", err)
	}
	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), cds) {
		t.Error("the CDS publish returned no error, but the CDS is not served")
	}
}

// T4. Journal tail ahead of the served serial: a local change is applied (doc
// §3, second case). Three CDS publishes leave the tail at 11. The upstream has
// moved on to 8, so the restarted zone's first load serves 8, below the tail.
func TestJournalOverlayLocalChangeWithJournalAhead(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	for i := 1; i <= 3; i++ {
		if err := ovPublishCDS(t, zd, ovCDS(t, i)); err != nil {
			t.Fatalf("CDS publish %d: %v", i, err)
		}
	}

	again := ovRestarted(t, zd.KeyDB, zd.DnssecPolicy)
	ovTransfer(t, again, ovUpstreamZone(8), true)
	replayZoneDeltasOnLoad(again)

	cds := ovCDS(t, 4)
	if err := ovPublishCDS(t, again, cds); err != nil {
		t.Fatalf("CDS publish refused with the journal ahead of the served serial: %v", err)
	}
	if !ovHas(ovServed(t, again, ovZone, dns.TypeCDS), cds) {
		t.Error("the CDS publish returned no error, but the CDS is not served")
	}
}

// ovOneDelta asserts that the journal is exactly one delta ending at the
// served serial, and returns its rows.
func ovOneDelta(t *testing.T, zd *ZoneData) []ZoneDeltaRR {
	t.Helper()
	deltas := ovJournal(t, zd)
	if len(deltas) != 1 {
		t.Fatalf("the journal holds %d deltas, want one; journal:%s",
			len(deltas), ovJournalString(deltas))
	}
	d := deltas[0]
	if served := ovServedSerial(t, zd); d.ToSerial != served || d.FromSerial != served-1 {
		t.Errorf("the delta runs %d -> %d, want %d -> %d (the served serial)",
			d.FromSerial, d.ToSerial, served-1, served)
	}
	return d.RRs
}

// ovRowsAre asserts the rows, in any order.
func ovRowsAre(t *testing.T, rows []ZoneDeltaRR, want ...ZoneDeltaRR) {
	t.Helper()
	key := func(r ZoneDeltaRR) string {
		rr, err := dns.NewRR(r.RR)
		if err != nil {
			t.Fatalf("journal row %q does not parse: %v", r.RR, err)
		}
		return r.Action + " " + rrKey(rr)
	}
	got := map[string]bool{}
	for _, r := range rows {
		got[key(r)] = true
	}
	if len(rows) != len(want) {
		t.Errorf("%d rows, want %d", len(rows), len(want))
	}
	for _, w := range want {
		if !got[key(w)] {
			t.Errorf("no row %s %s", w.Action, w.RR)
		}
	}
}

func ovAdd(rr string) ZoneDeltaRR { return ZoneDeltaRR{Action: ZoneDeltaAdd, RR: rr} }

// ovPlant writes rows into the journal directly, as a record that reached it
// some other way. Its serials only order it after what is already there.
func ovPlant(t *testing.T, zd *ZoneData, from, to uint32, added ...string) {
	t.Helper()
	var rrs []dns.RR
	for _, a := range added {
		rrs = append(rrs, mustRR(t, a))
	}
	if err := zd.KeyDB.PersistZoneDelta(zd.ZoneName, from, to, nil,
		[]core.RRset{{RRs: rrs}}); err != nil {
		t.Fatalf("PersistZoneDelta: %v", err)
	}
}

// ovCaptureLog sends every log line to the returned buffer for the rest of
// the test.
func ovCaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// T5. Net effect: three CDS publishes and one full transfer serve one CDS,
// the last, and leave the journal as one delta holding one add.
func TestJournalOverlayNetEffect(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	for i := 1; i <= 3; i++ {
		if err := ovPublishCDS(t, zd, ovCDS(t, i)); err != nil {
			t.Fatalf("CDS publish %d: %v", i, err)
		}
	}
	ovTransfer(t, zd, ovUpstreamZone(20), true)

	served := ovServed(t, zd, ovZone, dns.TypeCDS)
	if len(served) != 1 || !ovHas(served, ovCDS(t, 3)) {
		t.Errorf("served CDS %v, want only the last one published", served)
	}
	ovRowsAre(t, ovOneDelta(t, zd), ovAdd(ovCDSText(3)))
}

// T6. Only the allowlist is overlaid. The CDS in the journal is; a DNSKEY and
// a KEY the keystore does not hold are not; nor is a local edit of the
// upstream's A record.
func TestJournalOverlayAllowlist(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	cds := ovCDS(t, 1)
	if err := ovPublishCDS(t, zd, cds); err != nil {
		t.Fatalf("CDS publish: %v", err)
	}
	oldA := mustRR(t, "www.example.\t3600\tIN\tA\t10.0.0.3")
	newA := mustRR(t, "www.example.\t3600\tIN\tA\t10.0.0.99")
	if err := ovUpdate(t, zd, ovDel(oldA), newA); err != nil {
		t.Fatalf("local A edit: %v", err)
	}
	const (
		strayDNSKEY = "example.\t3600\tIN\tDNSKEY\t257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
		strayKEY    = "example.\t3600\tIN\tKEY\t256 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
	)
	ovPlant(t, zd, 1000, 1001, strayDNSKEY, strayKEY)

	ovTransfer(t, zd, ovUpstreamZone(20), true)

	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), cds) {
		t.Error("the CDS in the journal was not overlaid")
	}
	if ovHas(ovServed(t, zd, ovZone, dns.TypeDNSKEY), mustRR(t, strayDNSKEY)) {
		t.Error("a DNSKEY from the journal was overlaid; the keystore is the DNSKEY's only source")
	}
	if ovHas(ovServed(t, zd, ovZone, dns.TypeKEY), mustRR(t, strayKEY)) {
		t.Error("a KEY from the journal was overlaid; the keystore is the KEY's only source")
	}
	served := ovServed(t, zd, "www.example.", dns.TypeA)
	if ovHas(served, newA) || !ovHas(served, oldA) {
		t.Errorf("www.example. A is %v after a full transfer, want the upstream's %s alone",
			served, oldA)
	}
}

// T7. The server's copy wins for its own types, and the replaced upstream
// record is logged, once. It does not win for the upstream's own data: a local
// delete of an upstream A record is undone by the next full transfer.
func TestJournalOverlayOwnCopyWins(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	upstreamCDS := ovCDS(t, 9)
	ovTransfer(t, zd, ovUpstreamZone(20, ovCDSText(9)), true)
	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), upstreamCDS) {
		t.Fatal("precondition: the upstream's CDS is not served")
	}
	ours := ovCDS(t, 1)
	if err := ovPublishCDS(t, zd, ours); err != nil {
		t.Fatalf("CDS publish: %v", err)
	}
	wwwA := mustRR(t, "www.example.\t3600\tIN\tA\t10.0.0.3")
	if err := ovUpdate(t, zd, ovDel(wwwA)); err != nil {
		t.Fatalf("local delete of www A: %v", err)
	}

	buf := ovCaptureLog(t)
	ovTransfer(t, zd, ovUpstreamZone(21, ovCDSText(9)), true)

	served := ovServed(t, zd, ovZone, dns.TypeCDS)
	if len(served) != 1 || !ovHas(served, ours) {
		t.Errorf("served CDS %v, want ours alone", served)
	}
	var lines []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, "journal overlay") && strings.Contains(l, "1009 15 2") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 {
		t.Errorf("%d log lines name the upstream CDS the overlay removed, want one:\n%s",
			len(lines), buf.String())
	}
	if !ovHas(ovServed(t, zd, "www.example.", dns.TypeA), wwwA) {
		t.Error("a local delete of an upstream A record survived a full transfer")
	}
}

// T8. Zones that are not overlay zones behave as before: a journalled CDS is
// not overlaid and the journal is left as it was. The primary's reload merge
// and replay are pinned by the zone_reload_reconcile tests.
func TestJournalOverlayOnlyOverlayZones(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, zd *ZoneData)
	}{
		{"plain secondary", func(t *testing.T, zd *ZoneData) {
			zd.mu.Lock()
			zd.Options[OptInlineSigning] = false
			zd.mu.Unlock()
		}},
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := ixSigningSecondary(t, ixApplyZone)
			ovPlant(t, zd, 7, 9, ovCDSText(1))
			tc.setup(t, zd)
			before := ovJournalString(ovJournal(t, zd))

			ovTransfer(t, zd, ovUpstreamZone(20), true)

			if ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), ovCDS(t, 1)) {
				t.Error("a journalled CDS was overlaid on a zone that is not an overlay zone")
			}
			if after := ovJournalString(ovJournal(t, zd)); after != before {
				t.Errorf("the journal changed:\nbefore:%s\nafter:%s", before, after)
			}
		})
	}
}

// T9. An applied IXFR keeps the CDS as today, with no overlay: the journal is
// not compacted, and names the delta did not touch are not re-signed.
func TestJournalOverlayNotOnAppliedIxfr(t *testing.T) {
	authApp(t)
	pzd, addr, stop := ixfrTestPrimary(t, ixApplyZone)
	defer stop()
	// Registered only while its chain is built; see TestIxfrInConvergesViaDelta.
	Zones.Set(ovZone, pzd)
	t.Cleanup(func() { Zones.Remove(ovZone) })
	stageAndPublish(t, pzd, stageAddA(t, pzd, "one.example.", "10.1.0.1"))
	Zones.Remove(ovZone)

	zd := ixSigningSecondary(t, ixApplyZone)
	cds := ovCDS(t, 1)
	if err := ovPublishCDS(t, zd, cds); err != nil {
		t.Fatalf("CDS publish: %v", err)
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
	sigsBefore := fmt.Sprint(getOwnerFrom(zd.publishedSnapshot(), "www.example.").
		RRtypes.GetOnlyRRSet(dns.TypeA).RRSIGs)

	ovTransferFrom(t, zd, addr, false)

	if owner, _ := zd.GetOwner("one.example."); owner == nil {
		t.Fatal("one.example. is missing: the delta was not applied")
	}
	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), cds) {
		t.Error("the CDS is gone after an applied IXFR")
	}
	if after := ovJournalString(ovJournal(t, zd)); after != journalBefore {
		t.Errorf("an applied IXFR changed the journal:\nbefore:%s\nafter:%s", journalBefore, after)
	}
	sigsAfter := fmt.Sprint(getOwnerFrom(zd.publishedSnapshot(), "www.example.").
		RRtypes.GetOnlyRRSet(dns.TypeA).RRSIGs)
	if sigsAfter != sigsBefore {
		t.Error("www.example. A was re-signed by an IXFR that did not touch it")
	}
}

// T10. A persisted copy adopted at first bind already carries the CDS: the
// overlay does not double it, and the load raises no ConfigWarning.
func TestJournalOverlayPersistedCopyAtFirstBind(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	cds := ovCDS(t, 1)
	if err := ovPublishCDS(t, zd, cds); err != nil {
		t.Fatalf("CDS publish: %v", err)
	}

	copyFile := filepath.Join(t.TempDir(), "example.zone")
	if err := os.WriteFile(copyFile, []byte(ovUpstreamZone(20, ovCDSText(1))), 0644); err != nil {
		t.Fatalf("write the persisted copy: %v", err)
	}
	again := ovRestarted(t, zd.KeyDB, zd.DnssecPolicy)
	again.Zonefile = copyFile
	again.adoptPersistedCopyAtFirstBind(context.Background(), false, false,
		again.CollectDynamicRRs(&Config{}), &Config{})
	if again.publishedSnapshot() == nil {
		t.Fatal("the persisted copy was not adopted")
	}
	replayZoneDeltasOnLoad(again)

	if served := ovServed(t, again, ovZone, dns.TypeCDS); len(served) != 1 || !ovHas(served, cds) {
		t.Errorf("served CDS %v, want the one CDS", served)
	}
	if w := ovConfigWarning(again); w != "" {
		t.Errorf("the first load raised a ConfigWarning: %s", w)
	}
}

// T11. Compaction. A net effect with nothing left in it clears the journal;
// rows of other types are dropped from it; and a full transfer whose publish
// is refused leaves the journal as it was.
func TestJournalOverlayCompaction(t *testing.T) {
	t.Run("empty net effect", func(t *testing.T) {
		zd := ixSigningSecondary(t, ixApplyZone)
		if err := ovPublishCDS(t, zd, ovCDS(t, 1)); err != nil {
			t.Fatalf("CDS publish: %v", err)
		}
		if err := ovPublishCDS(t, zd); err != nil {
			t.Fatalf("CDS withdrawal: %v", err)
		}
		ovTransfer(t, zd, ovUpstreamZone(20), true)
		if deltas := ovJournal(t, zd); len(deltas) != 0 {
			t.Errorf("the journal is not empty:%s", ovJournalString(deltas))
		}
	})

	t.Run("other types dropped", func(t *testing.T) {
		zd := ixSigningSecondary(t, ixApplyZone)
		if err := ovUpdate(t, zd, mustRR(t, "new.example.\t3600\tIN\tA\t10.0.0.7")); err != nil {
			t.Fatalf("local add: %v", err)
		}
		if err := ovPublishCDS(t, zd, ovCDS(t, 1)); err != nil {
			t.Fatalf("CDS publish: %v", err)
		}
		ovTransfer(t, zd, ovUpstreamZone(20), true)
		ovRowsAre(t, ovOneDelta(t, zd), ovAdd(ovCDSText(1)))
	})

	t.Run("refused publish", func(t *testing.T) {
		zd := ixSigningSecondary(t, ixApplyZone)
		if err := ovPublishCDS(t, zd, ovCDS(t, 1)); err != nil {
			t.Fatalf("CDS publish: %v", err)
		}
		if err := ovPublishCDS(t, zd, ovCDS(t, 2)); err != nil {
			t.Fatalf("CDS publish: %v", err)
		}
		before := ovJournalString(ovJournal(t, zd))
		served := ovServedSerial(t, zd)
		// Not live: the publish drops the working set and serves on.
		Zones.Remove(ovZone)
		ovTransfer(t, zd, ovUpstreamZone(20), true)
		if got := ovServedSerial(t, zd); got != served {
			t.Fatalf("precondition: the publish was not refused (serial %d -> %d)", served, got)
		}
		if after := ovJournalString(ovJournal(t, zd)); after != before {
			t.Errorf("a refused publish compacted the journal:\nbefore:%s\nafter:%s", before, after)
		}
	})
}

// T12. An add the transfer already has is kept in the compacted journal, and
// the record comes back once the upstream withdraws it.
func TestJournalOverlayKeepsAddTheTransferHas(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	cds := ovCDS(t, 1)
	if err := ovPublishCDS(t, zd, cds); err != nil {
		t.Fatalf("CDS publish: %v", err)
	}

	ovTransfer(t, zd, ovUpstreamZone(20, ovCDSText(1)), true)
	if served := ovServed(t, zd, ovZone, dns.TypeCDS); len(served) != 1 {
		t.Errorf("served CDS %v, want the one CDS", served)
	}
	ovRowsAre(t, ovOneDelta(t, zd), ovAdd(ovCDSText(1)))

	ovTransfer(t, zd, ovUpstreamZone(21), true)
	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), cds) {
		t.Error("the CDS is gone once the upstream withdrew its copy of it")
	}
}

// T13. journal: active: false. Nothing is journalled, so a CDS is lost at a
// full transfer as it always was, and nothing is refused. Rows already in the
// journal when the switch was thrown are still overlaid and compacted: reads
// are not gated (as the replay is not), and compaction rewrites the journal
// as the primary's merge does.
func TestJournalOverlayJournalInactive(t *testing.T) {
	t.Run("nothing journalled", func(t *testing.T) {
		withJournalActive(t, false)
		zd := ixSigningSecondary(t, ixApplyZone)
		if err := ovPublishCDS(t, zd, ovCDS(t, 1)); err != nil {
			t.Fatalf("CDS publish: %v", err)
		}
		ovTransfer(t, zd, ovUpstreamZone(2026092401), true)
		if err := ovPublishCDS(t, zd, ovCDS(t, 2)); err != nil {
			t.Fatalf("CDS publish refused with the journal off: %v", err)
		}
		if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), ovCDS(t, 2)) {
			t.Error("the CDS publish returned no error, but the CDS is not served")
		}
		if deltas := ovJournal(t, zd); len(deltas) != 0 {
			t.Errorf("the journal is not empty:%s", ovJournalString(deltas))
		}
	})

	t.Run("rows from before the switch", func(t *testing.T) {
		zd := ixSigningSecondary(t, ixApplyZone)
		cds := ovCDS(t, 1)
		if err := ovPublishCDS(t, zd, cds); err != nil {
			t.Fatalf("CDS publish: %v", err)
		}
		withJournalActive(t, false)
		ovTransfer(t, zd, ovUpstreamZone(20), true)
		if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), cds) {
			t.Error("a CDS journalled before the switch was not overlaid")
		}
		ovRowsAre(t, ovOneDelta(t, zd), ovAdd(ovCDSText(1)))
	})
}

// Doc 4.6. `zone journal status` describes an overlay zone's journal as
// applied to every transfer, not as a chain from a file; and purge, which
// takes the zone's own records away at the next full transfer, asks for
// --force as it does for a journal that would replay.
func TestJournalOverlayStatusAndPurge(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	if err := ovPublishCDS(t, zd, ovCDS(t, 1)); err != nil {
		t.Fatalf("CDS publish: %v", err)
	}
	ovTransfer(t, zd, ovUpstreamZone(20), true)

	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if !info.Overlay {
		t.Error("JournalInfo does not say the journal is an overlay")
	}
	if !info.Replayable || info.Diagnosis != "" {
		t.Errorf("JournalInfo: replayable %v, diagnosis %q; an overlay is not a chain from a file",
			info.Replayable, info.Diagnosis)
	}

	_, err = zd.JournalPurge(false)
	if err == nil {
		t.Fatal("purge without --force went through on an overlay zone's journal")
	}
	if strings.Contains(err.Error(), "zone sync") {
		t.Errorf("the refusal points at `zone sync`, which a secondary cannot use: %v", err)
	}
	if deltas := ovJournal(t, zd); len(deltas) == 0 {
		t.Fatal("the refused purge emptied the journal")
	}
	if _, err := zd.JournalPurge(true); err != nil {
		t.Fatalf("purge --force: %v", err)
	}
	if deltas := ovJournal(t, zd); len(deltas) != 0 {
		t.Errorf("the journal is not empty after purge --force:%s", ovJournalString(deltas))
	}
}

// `zone write`, and `zone sync` and freeze through it, leave an overlay zone's
// journal alone. A primary's file takes its journalled changes in, so the
// write drops them (TestZoneDeltaDroppedOnWriteZone). An overlay zone's
// journal is not relative to a file, and dropping it would take the zone's own
// records out at the next full transfer.
func TestJournalOverlayZoneWriteKeepsJournal(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	cds := ovCDS(t, 1)
	if err := ovPublishCDS(t, zd, cds); err != nil {
		t.Fatalf("CDS publish: %v", err)
	}
	zd.Zonefile = filepath.Join(t.TempDir(), "example.zone")
	before := ovJournalString(ovJournal(t, zd))

	if _, err := zd.WriteZone(false, true); err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	if after := ovJournalString(ovJournal(t, zd)); after != before {
		t.Errorf("the zone write changed the journal:\nbefore:%s\nafter:%s", before, after)
	}
	ovTransfer(t, zd, ovUpstreamZone(20), true)
	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), cds) {
		t.Error("the CDS is gone at the full transfer after a zone write")
	}
}
