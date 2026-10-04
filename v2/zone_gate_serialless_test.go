package tdns

import (
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A serial-less publisher that finds another writer's change queued in the
// working set does not publish it at the served serial: it asks the gate, and
// the change goes out with a serial of its own.
func TestASignalCommitOverAQueuedChangeRidesTheGate(t *testing.T) {
	const zone = "signal.gate.example."
	zd, kdb := busyZone(t, zone, 500*time.Millisecond)
	before := zd.publishedSnapshot().Serial

	ur := txtUpdate(t, zd, "q."+zone, "queued")
	ur.Resp = make(chan ZoneUpdateResult, 1)
	if _, deferred, err := zd.applyZoneUpdate(ur, kdb, nil); err != nil || !deferred {
		t.Fatalf("the update was not deferred on the busy zone: deferred=%v err=%v", deferred, err)
	}

	signal := core.RRset{Name: "_dns.ns." + zone, RRtype: dns.TypeSVCB, Class: dns.ClassINET,
		RRs: []dns.RR{txTestRR(t, "_dns.ns."+zone+" 300 IN SVCB 1 . alpn=dot")}}
	zd.mu.Lock()
	zd.commitTransportSignalLocked(false, "_dns.ns."+zone, signal, "", nil)
	zd.mu.Unlock()

	if zd.publishedSnapshot().Serial != before {
		t.Fatalf("the signal's publish went out in the caller on a busy zone: serial %d -> %d", before, zd.publishedSnapshot().Serial)
	}
	select {
	case res := <-ur.Resp:
		if res.Err != nil {
			t.Fatalf("the queued change was refused by the signal's publish: %v", res.Err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the queued change was never answered")
	}
	if !served(zd, "q."+zone, dns.TypeTXT) || !served(zd, "_dns.ns."+zone, dns.TypeSVCB) {
		t.Fatal("the change or the signal is not served after the gate's publish")
	}
	if got := zd.publishedSnapshot().Serial; got <= before {
		t.Fatalf("the queued change was published at the served serial: %d -> %d", before, got)
	}
}

// On a bare working set the signal's publish stays serial-less.
func TestASignalCommitOnABareWorkingSetIsSerialLess(t *testing.T) {
	const zone = "signal2.gate.example."
	zd, _ := busyZone(t, zone, 500*time.Millisecond)
	before := zd.publishedSnapshot().Serial
	signal := core.RRset{Name: "_dns.ns." + zone, RRtype: dns.TypeSVCB, Class: dns.ClassINET,
		RRs: []dns.RR{txTestRR(t, "_dns.ns."+zone+" 300 IN SVCB 1 . alpn=dot")}}
	zd.mu.Lock()
	bare := zd.workingSet == nil
	zd.ensureWorkingSet()
	zd.commitTransportSignalLocked(bare, "_dns.ns."+zone, signal, "", nil)
	zd.mu.Unlock()
	if !bare {
		t.Fatal("the zone had a working set before the pass")
	}
	if !served(zd, "_dns.ns."+zone, dns.TypeSVCB) {
		t.Fatal("the signal is not served")
	}
	if got := zd.publishedSnapshot().Serial; got != before {
		t.Fatalf("a signal on a bare working set bumped the serial: %d -> %d", before, got)
	}
}

// The dynamic-RR repopulation has the same shape and the same rule.
func TestARepopulationOverAQueuedChangeRidesTheGate(t *testing.T) {
	const zone = "repop.gate.example."
	zd, kdb := busyZone(t, zone, 500*time.Millisecond)
	before := zd.publishedSnapshot().Serial
	ur := txtUpdate(t, zd, "q."+zone, "queued")
	ur.Resp = make(chan ZoneUpdateResult, 1)
	if _, deferred, err := zd.applyZoneUpdate(ur, kdb, nil); err != nil || !deferred {
		t.Fatalf("the update was not deferred on the busy zone: deferred=%v err=%v", deferred, err)
	}
	zd.RepopulateDynamicRRs([]*core.RRset{{Name: "dyn." + zone, RRtype: dns.TypeTXT, Class: dns.ClassINET,
		RRs: []dns.RR{txTestRR(t, "dyn."+zone+` 300 IN TXT "dynamic"`)}}})
	if zd.publishedSnapshot().Serial != before {
		t.Fatal("the repopulation published in the caller on a busy zone")
	}
	select {
	case res := <-ur.Resp:
		if res.Err != nil {
			t.Fatalf("the queued change was refused by the repopulation's publish: %v", res.Err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the queued change was never answered")
	}
	if got := zd.publishedSnapshot().Serial; got <= before || !served(zd, "q."+zone, dns.TypeTXT) {
		t.Fatalf("the queued change was not published with its own serial: %d -> %d", before, got)
	}
}
