/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Step 4: the remaining publishers behind the gate (design rows 7-9). The
// signing passes, the catalog, the batch API and Publish ask the gate; the
// operator's bump stays immediate and says when a hold stopped it.

// A signing pass on a busy zone does not publish in the caller: its work goes
// out with the gate's next publish, sharing that serial with whatever an
// update staged in the same window.
func TestASigningPassOnABusyZoneGoesOutWithTheNextPublish(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	t.Cleanup(func() { zd.stopPublisher(); zd.joinPublisher() })
	zd.mu.Lock()
	zd.publishCadence = 700 * time.Millisecond
	zd.lastPublish = time.Now()
	zd.mu.Unlock()
	serial := ovServedSerial(t, zd)
	local := ovCDS(t, 5)
	if err := ovUpdate(t, zd, local); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, err := zd.ResignZone(context.Background(), zd.KeyDB); err != nil {
		t.Fatalf("ResignZone: %v", err)
	}
	if got := ovServedSerial(t, zd); got != serial {
		t.Fatalf("the pass published in the caller on a busy zone: serial %d -> %d", serial, got)
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool { return ovServedSerial(t, zd) > serial })
	if got := ovServedSerial(t, zd); got != serial+1 {
		t.Errorf("serial %d -> %d, want one publish carrying the update and the pass", serial, got)
	}
	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), local) {
		t.Error("the update staged before the pass is not served by the publish that carried the pass")
	}
}

// A zone that is not Ready is not rate-limited (rule 5): the first signing of a
// zone that signs publishes in the caller, cadence or not, so a signed zone is
// not Ready a cadence late at start. A guard: it holds before and after step 4.
func TestTheFirstSigningOfASigningZonePublishesAtOnce(t *testing.T) {
	const zone = "firstsign.gate.example."
	zd, id, kdb := newHeldSigningZone(t, zone, nil) // no policy yet: signed or none installs nothing
	stageTxt(t, zd, "a."+zone, "one")
	_ = zd.CommitTx(id)
	if zd.publishedSnapshot() != nil {
		t.Fatal("precondition: the unsigned first content was published")
	}
	zd.mu.Lock()
	zd.publishCadence = 5 * time.Second
	zd.lastPublish = time.Now() // as if a load had just published; the zone is still not Ready
	zd.DnssecPolicy = txTestPolicy()
	zd.mu.Unlock()
	if _, err := zd.SignZone(context.Background(), kdb, false); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	if zd.publishedSnapshot() == nil {
		t.Fatal("the first signing of a zone that is not Ready waited for the gate")
	}
	if !zd.Ready {
		t.Error("the zone is not Ready after its first signing")
	}
}

// A catalog member change on a busy zone is published by the gate, and the
// catalog's file is written after that publish, never ahead of what is served.
func TestACatalogChangeOnABusyZoneWritesItsFileAfterThePublish(t *testing.T) {
	const zone = "catalog.gate.example."
	dir, err := os.MkdirTemp("", "gate-catalog-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// Registered before the zone's cleanup, so that it runs after the
	// publisher has been joined: the deferred persist reads the config.
	prev := Conf.DynamicZones
	Conf.DynamicZones.ZoneDirectory = dir
	Conf.DynamicZones.CatalogZones.Storage = "persistent"
	Conf.DynamicZones.CatalogZones.Allowed = true
	t.Cleanup(func() { Conf.DynamicZones = prev })
	t.Cleanup(func() {
		if zd, ok := Zones.Get(zone); ok {
			zd.stopPublisher()
			zd.joinPublisher()
		}
		Zones.Remove(zone)
		forgetCatalogMembership(zone)
	})
	if err := handleCatalogCreate(zone, &CatalogResponse{}); err != nil {
		t.Fatalf("handleCatalogCreate: %v", err)
	}
	zd, ok := Zones.Get(zone)
	if !ok {
		t.Fatal("the catalog zone is not registered")
	}
	file := filepath.Join(dir, "catalog.gate.example.zone")
	os.Remove(file) // whatever the create wrote; the add must not write before its publish
	zd.mu.Lock()
	zd.publishCadence = 700 * time.Millisecond
	zd.lastPublish = time.Now()
	zd.mu.Unlock()
	serial := zd.publishedSnapshot().Serial
	if err := handleCatalogZoneAdd(zone, "member.example.", nil, &CatalogResponse{}); err != nil {
		t.Fatalf("handleCatalogZoneAdd: %v", err)
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("the catalog's file was written before the publish that carries the member")
	}
	if got := zd.publishedSnapshot().Serial; got != serial {
		t.Fatalf("the regeneration published in the caller on a busy zone: serial %d -> %d", serial, got)
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool { return zd.publishedSnapshot().Serial > serial })
	waitFor(t, 3*time.Second, "the catalog's file after the publish", func() bool {
		b, err := os.ReadFile(file)
		return err == nil && strings.Contains(string(b), "member.example")
	})
}

// A batch on a busy zone reports no new serial: the publish is the gate's to
// make. On an idle zone it publishes in the caller and reports the serial.
func TestABatchOnABusyZoneReportsNoNewSerial(t *testing.T) {
	const zone = "batch.gate.example."
	zd, _ := busyZone(t, zone, 700*time.Millisecond)
	txt := func(owner, text string) core.RRset {
		return core.RRset{Name: owner, RRtype: dns.TypeTXT, Class: dns.ClassINET,
			RRs: []dns.RR{txTestRR(t, owner+` 300 IN TXT "`+text+`"`)}}
	}
	resp, err := zd.StageBatch(func(s Stager) (bool, error) {
		s.SetRRset("b."+zone, txt("b."+zone, "two"))
		return true, nil
	})
	if err != nil {
		t.Fatalf("StageBatch: %v", err)
	}
	if resp.NewSerial != resp.OldSerial {
		t.Fatalf("a batch on a busy zone reported a new serial %d -> %d: it published in the caller", resp.OldSerial, resp.NewSerial)
	}
	if served(zd, "b."+zone, dns.TypeTXT) {
		t.Fatal("the batch's change is served before the gate's publish")
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool { return served(zd, "b."+zone, dns.TypeTXT) })
	time.Sleep(800 * time.Millisecond) // idle again
	resp, err = zd.StageBatch(func(s Stager) (bool, error) {
		s.SetRRset("c."+zone, txt("c."+zone, "three"))
		return true, nil
	})
	if err != nil {
		t.Fatalf("StageBatch: %v", err)
	}
	if resp.NewSerial != resp.OldSerial+1 || !served(zd, "c."+zone, dns.TypeTXT) {
		t.Errorf("a batch on an idle zone: serial %d -> %d, served=%v; want the publish in the caller", resp.OldSerial, resp.NewSerial, served(zd, "c."+zone, dns.TypeTXT))
	}
}

// The operator's bump stays immediate, and on a held zone its response says
// why nothing was published.
func TestABumpOnAHeldZoneSaysSo(t *testing.T) {
	const zone = "heldbump.tx.example."
	zd, _ := newPublishedAutoZone(t, zone)
	id := mustBeginTx(t, zd, 0)
	resp, err := zd.BumpSerial()
	if err != nil {
		t.Fatalf("BumpSerial: %v", err)
	}
	if resp.NewSerial != resp.OldSerial {
		t.Fatal("a bump published through a hold")
	}
	if !strings.Contains(resp.Msg, "held") {
		t.Errorf("the response does not say the zone is held: %q", resp.Msg)
	}
	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	resp, err = zd.BumpSerial()
	if err != nil || resp.NewSerial != resp.OldSerial+1 {
		t.Errorf("after the commit a bump is immediate: serial %d -> %d err=%v", resp.OldSerial, resp.NewSerial, err)
	}
}

// Publish asks the gate for what is staged and bumps nothing of its own: on a
// busy zone the publish is the gate's, on an idle zone it is in the caller,
// and with nothing staged there is nothing to publish.
func TestPublishAsksTheGate(t *testing.T) {
	const zone = "publish.gate.example."
	zd, _ := busyZone(t, zone, 700*time.Millisecond)
	resp, err := zd.Publish()
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if resp.NewSerial != resp.OldSerial {
		t.Fatalf("Publish with nothing staged bumped the serial %d -> %d", resp.OldSerial, resp.NewSerial)
	}
	stageTxt(t, zd, "a."+zone, "one")
	resp, err = zd.Publish()
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if resp.NewSerial != resp.OldSerial {
		t.Fatalf("Publish on a busy zone published in the caller: serial %d -> %d", resp.OldSerial, resp.NewSerial)
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool { return served(zd, "a."+zone, dns.TypeTXT) })
	time.Sleep(800 * time.Millisecond) // idle again
	stageTxt(t, zd, "b."+zone, "two")
	resp, err = zd.Publish()
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if resp.NewSerial != resp.OldSerial+1 || !served(zd, "b."+zone, dns.TypeTXT) {
		t.Errorf("Publish on an idle zone: serial %d -> %d, served=%v; want the publish in the caller", resp.OldSerial, resp.NewSerial, served(zd, "b."+zone, dns.TypeTXT))
	}
}

// A renewal pass on a busy zone takes nothing from the served snapshot: its
// signatures leave with the gate's publish, which renews what it owns, and
// the still-due check and the schedule that read the snapshot after a publish
// wait for the pass that follows it (the step-4 review's C1).
func TestARenewalOnABusyZoneTakesNothingFromTheServedSnapshot(t *testing.T) {
	var logs syncBuffer
	prev := lgSigner
	lgSigner = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lgSigner = prev })
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)
	t.Cleanup(func() { zd.stopPublisher(); zd.joinPublisher() })
	zd.mu.Lock()
	zd.publishCadence = 700 * time.Millisecond
	zd.lastPublish = time.Now()
	zd.mu.Unlock()
	before := zd.publishedSnapshot()
	ageApexSoaSignature(t, zd)

	renewed, err := zd.RenewZoneSignatures(context.Background(), kdb)
	if err != nil {
		t.Fatal(err)
	}
	if renewed == 0 {
		t.Fatal("reported nothing to do while the apex SOA signature was about to expire")
	}
	if zd.publishedSnapshot() != before {
		t.Fatal("the pass published in the caller on a busy zone")
	}
	if strings.Contains(logs.String(), "STILL due") {
		t.Errorf("the pass read the served snapshot before the gate's publish and reported a false error:\n%s", logs.String())
	}
	if _, ok := zd.resignDue(); ok {
		t.Error("a renewal schedule was taken from the snapshot the pass found due")
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool { return zd.publishedSnapshot() != before })
	for _, sig := range getOwnerFrom(zd.publishedSnapshot(), zd.ZoneName).RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs {
		if expiry := time.Unix(int64(sig.(*dns.RRSIG).Expiration), 0); time.Until(expiry) < time.Hour {
			t.Errorf("the apex SOA signature still expires at %s after the gate's publish", expiry.UTC())
		}
	}
}
