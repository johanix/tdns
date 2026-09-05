package tdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// withNotifyQ installs a test NOTIFY queue for the duration of one test.
func withNotifyQ(t *testing.T, depth int) chan NotifyRequest {
	t.Helper()
	prev := Conf.Internal.NotifyQ
	q := make(chan NotifyRequest, depth)
	Conf.Internal.NotifyQ = q
	t.Cleanup(func() { Conf.Internal.NotifyQ = prev })
	return q
}

const aDownstream = "127.0.0.1:5399"

// One published version, one NOTIFY, handed to the Notifier rather than sent
// inline. The inline loop this replaces ran under zd.mu with dns.Exchange, so a
// publish held the zone's lock across network I/O to every downstream.
func TestPublishNotifiesOnceWhenServable(t *testing.T) {
	q := withNotifyQ(t, 4)
	zd := loadIxfrTestZone(t, basicZone)
	zd.Notify = []PeerConf{{Addr: aDownstream}}

	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))

	if got := len(q); got != 1 {
		t.Fatalf("got %d NOTIFYs for one published version, want exactly 1", got)
	}
	req := <-q
	if req.ZoneName != zd.ZoneName {
		t.Errorf("NOTIFY names zone %q, want %q", req.ZoneName, zd.ZoneName)
	}
	if req.RRtype != dns.TypeSOA {
		t.Errorf("NOTIFY rrtype %s, want SOA", dns.TypeToString[req.RRtype])
	}
	if len(req.Targets) != 1 || req.Targets[0] != aDownstream {
		t.Errorf("NOTIFY targets %v, want [%s]", req.Targets, aDownstream)
	}
}

// The load path publishes before InstallInitialSnapshot marks the zone Ready.
// A downstream acting on a NOTIFY about that version is refused on status, so
// telling it about the version only burns its retry budget.
func TestPublishDoesNotNotifyBeforeReady(t *testing.T) {
	q := withNotifyQ(t, 4)
	zd := loadIxfrTestZone(t, basicZone)
	zd.Notify = []PeerConf{{Addr: aDownstream}}
	zd.mu.Lock()
	zd.Ready = false
	zd.mu.Unlock()

	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))

	if got := len(q); got != 0 {
		t.Fatalf("got %d NOTIFYs for a version that is not Ready to be transferred", got)
	}
}

// A signed zone whose policy is not bound yet publishes an unsigned apex SOA --
// the genuine first-load shape, since binding happens post-Ready. ZoneTransferOut
// fail-closes on exactly that, so the NOTIFY must not go out either.
func TestPublishDoesNotNotifyAnUnsignedVersionOfASignedZone(t *testing.T) {
	q := withNotifyQ(t, 4)
	zd := loadIxfrTestZone(t, basicZone)
	makeZoneSigning(t, zd)
	zd.DnssecPolicy = nil // not bound yet: nothing signs the SOA on publish
	zd.Notify = []PeerConf{{Addr: aDownstream}}

	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))

	if got := len(q); got != 0 {
		t.Fatalf("got %d NOTIFYs for an unsigned version of a signed zone; "+
			"ZoneTransferOut would refuse to hand it over", got)
	}
}

// Becoming servable is a snapshot-cutting event in its own right, and on a first
// load whose policy sync backfills it is the ONLY one: the publish that stored
// the snapshot ran pre-Ready and was silent, and a backfill re-signs nothing.
func TestInstallInitialSnapshotNotifiesOnTheReadyTransition(t *testing.T) {
	q := withNotifyQ(t, 4)
	zd := &ZoneData{
		ZoneName: "becomesready.example.",
		Notify:   []PeerConf{{Addr: aDownstream}},
	}
	zd.snapshot.Store(&zoneSnapshot{Serial: 7, SOA: &dns.SOA{Serial: 7}})
	Zones.Set(zd.ZoneName, zd)
	defer Zones.Remove(zd.ZoneName)
	defer zd.stopPublisher()

	zd.InstallInitialSnapshot()

	if !zd.Ready {
		t.Fatal("zone did not become Ready")
	}
	if got := len(q); got != 1 {
		t.Fatalf("got %d NOTIFYs on the Ready transition, want 1: without this "+
			"a backfilled first load serves a new serial nobody is told about", got)
	}
}

// A full queue must drop, not block. The consumer is a single goroutine that
// spends up to 2s per unreachable target, so a blocking send here would stall
// publishes behind it -- while holding zd.mu.
func TestPublishDropsNotifyWhenTheQueueIsFull(t *testing.T) {
	q := withNotifyQ(t, 1)
	q <- NotifyRequest{ZoneName: "occupant."} // fill it

	zd := loadIxfrTestZone(t, basicZone)
	zd.Notify = []PeerConf{{Addr: aDownstream}}

	done := make(chan struct{})
	go func() {
		stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("publish blocked on a full NOTIFY queue, while holding zd.mu")
	}

	if zd.publishedSnapshot() == nil {
		t.Fatal("a dropped NOTIFY must not prevent the publish")
	}
}
