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

// A publish that cannot make the zone servable leaves it not Ready and silent.
// This is the first-load shape: a zone configured to sign, with no keys yet
// because its policy binds post-Ready, publishes its transferred data unsigned
// and must stay invisible until the policy apply signs it.
func TestPublishStaysInvisibleWhenItCannotSign(t *testing.T) {
	q := withNotifyQ(t, 4)
	zd := loadIxfrTestZone(t, basicZone)
	zd.Notify = []PeerConf{{Addr: aDownstream}}
	// Signs its own content, but has nothing to sign with.
	if zd.Options == nil {
		zd.Options = map[ZoneOption]bool{}
	}
	zd.Options[OptOnlineSigning] = true
	zd.KeyDB = nil
	zd.mu.Lock()
	zd.Ready = false
	zd.mu.Unlock()

	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))

	if zd.Ready {
		t.Fatal("a signing zone became Ready on an unsigned snapshot; Ready is the " +
			"whole reason publishing that snapshot is safe")
	}
	if got := len(q); got != 0 {
		t.Fatalf("got %d NOTIFYs for a version no downstream can take", got)
	}
	if rrset := publishedARRset(t, zd, "one.example.test."); len(rrset.RRSIGs) != 0 {
		t.Fatal("nothing should have signed this: there are no keys")
	}
}

// The restart case. Keys exist and the policy is not bound yet -- a process-start
// publish -- and the zone must NOT be signed there.
//
// This test asserted the opposite when it was written, because the design did:
// "skip on unresolvable keys, not on a nil policy pointer" was meant to stop a
// restart being silently skipped. It stopped the skip and introduced something
// worse. Signing under a nil policy gives sigValiditySeconds() == 0, which
// sigLifetime turns into five-minute RRSIGs, so a restart re-signed its whole
// zone into signatures that expired six minutes later and that nothing renewed.
// Observed in the lab, on every record but the SOA -- the SOA escaping because
// it is re-signed on every publish.
//
// The restart is still not skipped. It is deferred by a few steps, to the moment
// the policy binds, which is the same load.
func TestRestartPublishesUnsignedThenSignsWhenThePolicyBinds(t *testing.T) {
	q := withNotifyQ(t, 4)
	zd := loadIxfrTestZone(t, basicZone)
	makeZoneSigning(t, zd)
	policy := zd.DnssecPolicy
	zd.DnssecPolicy = nil // binding is post-Ready: this is every process start
	zd.Notify = []PeerConf{{Addr: aDownstream}}
	zd.mu.Lock()
	zd.Ready = false
	zd.mu.Unlock()

	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))

	if zd.Ready {
		t.Fatal("a zone published before its policy bound became Ready; it is unsigned")
	}
	if got := len(q); got != 0 {
		t.Fatalf("got %d NOTIFYs for an unsigned version", got)
	}
	if soa := zd.publishedSnapshot().Apex.RRtypes.GetOnlyRRSet(dns.TypeSOA); len(soa.RRSIGs) != 0 {
		t.Error("the apex SOA was signed under an unbound policy")
	}

	// The bind, and the signing it enables.
	zd.DnssecPolicy = policy
	signOnceAfterPolicyBind(zd)

	if !zd.Ready {
		t.Fatal("the zone did not become Ready once its policy bound and it was signed")
	}
	soa := zd.publishedSnapshot().Apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(soa.RRSIGs) == 0 {
		t.Fatal("still unsigned after the policy bound")
	}
	sig := soa.RRSIGs[0].(*dns.RRSIG)
	if lifetime := sig.Expiration - sig.Inception; lifetime < 24*3600 {
		t.Fatalf("signature lifetime %ds: still the five-minute nil-policy fallback", lifetime)
	}
	if got := len(q); got != 1 {
		t.Fatalf("got %d NOTIFYs, want exactly 1 -- the publish that made it servable", got)
	}
}

// The Ready gate, from the other side: a zone that signs its own content must
// not become Ready on a snapshot whose apex SOA carries no RRSIG. Ready is what
// makes queries answerable, so publishing an unsigned first snapshot is only
// safe while the flag is false.
func TestInstallInitialSnapshotDoesNotReadyAnUnsignedSigningZone(t *testing.T) {
	q := withNotifyQ(t, 4)
	zd := &ZoneData{
		ZoneName: "unsignedsigner.example.",
		Notify:   []PeerConf{{Addr: aDownstream}},
		Options:  map[ZoneOption]bool{OptOnlineSigning: true},
	}
	zd.snapshot.Store(&zoneSnapshot{Serial: 7, SOA: &dns.SOA{Serial: 7}}) // no signed apex
	Zones.Set(zd.ZoneName, zd)
	defer Zones.Remove(zd.ZoneName)
	defer zd.stopPublisher()

	zd.InstallInitialSnapshot()

	if zd.Ready {
		t.Fatal("a signing zone became Ready on a snapshot with no apex SOA RRSIG")
	}
	if got := len(q); got != 0 {
		t.Fatalf("got %d NOTIFYs for a version that is not servable", got)
	}
}

// An unbound policy with no keys to fall back on is the ordinary first load, not
// a fault: publish unsigned, stay not Ready, record no error. The distinction is
// ErrDnssecPolicyNotBound; any other resolution failure refuses the publish and
// sets DnssecError (TestPublishRefusesAReplacementItCannotSign).
func TestPublishTreatsAnUnboundPolicyAsNotYetRatherThanAFault(t *testing.T) {
	q := withNotifyQ(t, 4)
	zd := loadIxfrTestZone(t, basicZone)
	if zd.Options == nil {
		zd.Options = map[ZoneOption]bool{}
	}
	zd.Options[OptOnlineSigning] = true
	zd.KeyDB = newTestKeyDB(t) // reachable, and empty: no keys to resolve
	zd.DnssecPolicy = nil      // ...and nothing to mint them under
	zd.Notify = []PeerConf{{Addr: aDownstream}}
	zd.mu.Lock()
	zd.Ready = false
	zd.mu.Unlock()

	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))

	if zd.Ready {
		t.Error("became Ready on an unsigned snapshot")
	}
	if got := len(q); got != 0 {
		t.Errorf("got %d NOTIFYs", got)
	}
	if zd.HasError(DnssecError) {
		t.Error("a policy that has not bound yet is not a fault; recording " +
			"DnssecError here would take every brand-new signed zone off the air")
	}
	if zd.publishedSnapshot() == nil {
		t.Error("the publish was refused; it should have gone out unsigned")
	}
}

// Becoming servable is a snapshot-cutting event in its own right, and on a first
// load whose policy sync BACKFILLS it is the only one: the publish that stored
// the snapshot ran pre-Ready and was silent, and a backfill re-signs nothing and
// publishes nothing more.
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
