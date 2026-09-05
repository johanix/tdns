package tdns

import (
	"testing"

	"github.com/miekg/dns"

	core "github.com/johanix/tdns/v2/core"
)

// makeZoneSigning turns a loaded test zone into one that signs its own content:
// an active KSK and ZSK in a fresh KeyDB, online-signing, and a BOUND policy.
// The binding matters -- the publish path deliberately does nothing for a zone
// whose policy is still nil, because binding happens post-Ready and that is what
// keeps first load working.
func makeZoneSigning(t *testing.T, zd *ZoneData) *KeyDB {
	t.Helper()
	kdb := newTestKeyDB(t)
	for _, role := range []string{"KSK", "ZSK"} {
		if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive,
			dns.TypeDNSKEY, dns.ED25519, role, nil); err != nil {
			t.Fatalf("generate %s: %v", role, err)
		}
	}
	if zd.Options == nil {
		zd.Options = map[ZoneOption]bool{}
	}
	zd.Options[OptOnlineSigning] = true
	zd.KeyDB = kdb
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
	}
	return kdb
}

const replacedOwner = "fresh.example.test."

// stageArrivedRRset stages an RRset the way content arriving from a file or an
// upstream does: with no RRSIGs of ours on it.
func stageArrivedRRset(t *testing.T, zd *ZoneData) {
	t.Helper()
	rr := mustRR(t, replacedOwner+" 60 IN A 192.0.2.77")
	zd.stageRRsetLocked(replacedOwner, core.RRset{
		Name: replacedOwner, Class: dns.ClassINET, RRtype: dns.TypeA, RRs: []dns.RR{rr},
	})
}

func publishedARRset(t *testing.T, zd *ZoneData, owner string) core.RRset {
	t.Helper()
	od := getOwnerFrom(zd.publishedSnapshot(), owner)
	if od == nil {
		t.Fatalf("owner %s is not in the published snapshot", owner)
	}
	return od.RRtypes.GetOnlyRRSet(dns.TypeA)
}

// C1. Content that arrives unsigned must be signed BEFORE the snapshot is
// stored, not in a pass afterwards.
//
// Before this, a refresh published the transferred data and SignZone published
// again: for the length of a full signing pass the zone served its answers with
// no RRSIGs, alongside a signed SOA and a signed NSEC chain -- and
// ZoneTransferOut's fail-closed guard let a downstream AXFR it, because that
// guard inspects the SOA. The one-publish assertion below is the other half:
// two publishes for one change is what produced the extra serial and the extra
// NOTIFY.
func TestPublishSignsWholesaleReplacementBeforeTheSwap(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	makeZoneSigning(t, zd)

	before := zd.publishedSnapshot()
	if before == nil {
		t.Fatal("test zone has no published snapshot to start from")
	}

	zd.mu.Lock()
	zd.ensureWorkingSet()
	stageArrivedRRset(t, zd)
	// Exactly what applyRefreshReplacementLocked stages for a zone that signs
	// its own content.
	zd.wsNeedsFullSign = true
	zd.publishWorkingSetLocked(zd.generation.Load(), true)
	leaked := zd.wsNeedsFullSign
	zd.mu.Unlock()

	if leaked {
		t.Error("a successful publish left wsNeedsFullSign set")
	}

	rrset := publishedARRset(t, zd, replacedOwner)
	if len(rrset.RRs) == 0 {
		t.Fatal("the replacement content was not published at all")
	}
	if len(rrset.RRSIGs) == 0 {
		t.Fatal("the published snapshot carries the arrived RRset UNSIGNED: " +
			"a validator asking during this window gets an unsigned answer " +
			"alongside a signed NSEC chain, and a downstream can transfer it")
	}

	if got, want := zd.publishedSnapshot().Serial, before.Serial+1; got != want {
		t.Fatalf("serial %d, want %d: one content change must be ONE publish, "+
			"not a publish followed by a signing publish", got, want)
	}
}

// The incremental paths sign each RRset as they stage it, so publish must not
// walk the whole zone on their behalf: that would make every DDNS update O(zone)
// to re-confirm signatures that are already there. Staged without the flag, what
// was staged is what gets published.
func TestPublishDoesNotFullSignAnIncrementalChange(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	makeZoneSigning(t, zd)

	zd.mu.Lock()
	zd.ensureWorkingSet()
	stageArrivedRRset(t, zd) // no wsNeedsFullSign: an incremental change
	zd.publishLocked(zd.generation.Load())
	zd.mu.Unlock()

	if rrset := publishedARRset(t, zd, replacedOwner); len(rrset.RRSIGs) != 0 {
		t.Fatal("publish ran a full signing pass for an incremental change; " +
			"the staging path owns signing there, and this makes every update O(zone)")
	}
}

// A replacement that cannot be signed must not reach the wire, and must not take
// the zone down either: the previous snapshot is still good and is still being
// served.
func TestPublishRefusesAReplacementItCannotSign(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	makeZoneSigning(t, zd)
	// A refusal the tree produces itself: the zone's active keys are ED25519
	// and the bound policy asks for RSASHA256, which reconcileActiveKeyAlgorithms
	// refuses rather than papers over. Any signing failure would do; this one is
	// in-domain and deterministic.
	withCompleteness(t, CompletenessStrict)
	zd.DnssecPolicy.KSKAlgorithm = dns.RSASHA256
	zd.DnssecPolicy.ZSKAlgorithm = dns.RSASHA256

	before := zd.publishedSnapshot()

	zd.mu.Lock()
	zd.ensureWorkingSet()
	stageArrivedRRset(t, zd)
	zd.wsNeedsFullSign = true
	zd.publishWorkingSetLocked(zd.generation.Load(), true)
	stillFlagged := zd.wsNeedsFullSign
	zd.mu.Unlock()

	if zd.publishedSnapshot() != before {
		t.Fatal("an unsignable replacement was published anyway")
	}
	if !stillFlagged {
		t.Fatal("a refused publish cleared wsNeedsFullSign; the working set is " +
			"still staged, so the next publish would put it on the wire unsigned")
	}
	if zd.CurrentSerial != before.Serial {
		t.Fatalf("serial advanced to %d on a refused publish (was %d)",
			zd.CurrentSerial, before.Serial)
	}
	if !zd.HasError(DnssecPolicyWarning) {
		t.Error("the refusal is invisible: no DnssecPolicyWarning recorded")
	}
	if zd.HasServiceImpactingError() {
		t.Error("a failed re-sign must not take a zone off the air that is still " +
			"serving a perfectly good signed snapshot")
	}
}
