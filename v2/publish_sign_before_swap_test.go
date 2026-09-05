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
		// A real policy sets these, and a policy that does not is its own trap:
		// sigValiditySeconds returns 0 and sigLifetime silently substitutes five
		// minutes, which is the regression these tests exist for.
		SigValidity: PolicySigValidity{Default: 14 * 86400, DNSKEY: 30 * 86400, DS: 14 * 86400},
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
	if !zd.HasError(DnssecError) {
		t.Error("the refusal is invisible: no DnssecError recorded")
	}
	if !zd.HasServiceImpactingError() {
		t.Error("a signed zone that can no longer sign must say so: DnssecError is " +
			"service-impacting, and the alternative is quietly serving an ageing " +
			"snapshot while the operator believes all is well")
	}
}

// An inbound IXFR must sign what its delta touched and nothing else.
//
// The assertion that matters is the second one, not the first. A full pass would
// still produce a correctly signed zone -- SignRRset short-circuits on
// NeedsResigning, so untouched owners keep the valid RRSIGs they arrived with,
// and a signature count would look identical. What a full pass destroys is the
// SHARING: staging an owner goes through cloneOwner, which builds it a fresh
// RRTypeStore, so every owner the pass walks is re-materialised. For a
// two-record delta into a large zone that is the whole zone, which is exactly
// the work materializeForIxfr shares owners to avoid.
func TestPublishSignsOnlyTheOwnersAnIxfrTouched(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	makeZoneSigning(t, zd)

	// Baseline: a fully signed published snapshot to share owners from.
	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.wsNeedsFullSign = true
	zd.publishWorkingSetLocked(zd.generation.Load(), true)
	zd.mu.Unlock()

	before := zd.publishedSnapshot()
	const untouched = "ns.example.test."
	if before.Data[untouched] == nil {
		t.Fatalf("test setup: %s is not in the baseline snapshot", untouched)
	}
	beforeStore := before.Data[untouched].RRtypes

	// A delta that reaches one name, staged the way applyRefreshReplacementLocked
	// stages an ixfrDerived replacement.
	zd.mu.Lock()
	zd.ensureWorkingSet()
	stageArrivedRRset(t, zd)
	zd.wsSignOwners = map[string]bool{replacedOwner: true, zd.ZoneName: true}
	zd.publishWorkingSetLocked(zd.generation.Load(), true)
	zd.mu.Unlock()

	if rrset := publishedARRset(t, zd, replacedOwner); len(rrset.RRSIGs) == 0 {
		t.Fatal("the owner the delta touched was published unsigned")
	}

	after := zd.publishedSnapshot()
	if after.Data[untouched] == nil {
		t.Fatalf("%s vanished from the snapshot", untouched)
	}
	if after.Data[untouched].RRtypes != beforeStore {
		t.Fatal("an owner the delta never touched was re-materialised: the signing " +
			"pass staged it, and stageRRsetLocked clones. At zone scale this is the " +
			"whole point of scoping the pass")
	}
}

// A publish must not sign under an unbound policy.
//
// The regression this pins: signing with zd.DnssecPolicy == nil gives
// sigValiditySeconds() == 0, which sigLifetime turns into a FIVE-MINUTE
// signature lifetime -- and a first load publishes before the policy binds, so
// a whole zone would be signed that way and nothing on the normal path renews
// it. The zone must publish unsigned and stay not Ready instead.
func TestPublishDoesNotSignUnderAnUnboundPolicy(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	makeZoneSigning(t, zd)
	policy := zd.DnssecPolicy
	zd.DnssecPolicy = nil // as at every first load: binding is post-Ready
	zd.mu.Lock()
	zd.Ready = false
	zd.mu.Unlock()

	zd.mu.Lock()
	zd.ensureWorkingSet()
	stageArrivedRRset(t, zd)
	zd.wsNeedsFullSign = true
	zd.publishWorkingSetLocked(zd.generation.Load(), true)
	zd.mu.Unlock()

	if rrset := publishedARRset(t, zd, replacedOwner); len(rrset.RRSIGs) != 0 {
		sig := rrset.RRSIGs[0].(*dns.RRSIG)
		t.Fatalf("signed under an unbound policy: inception %d expiration %d, a %d-second "+
			"lifetime that nothing will renew", sig.Inception, sig.Expiration,
			sig.Expiration-sig.Inception)
	}
	if zd.Ready {
		t.Error("an unsigned snapshot of a signing zone became Ready")
	}

	// And once the policy binds, the zone signs with the policy's own validity.
	zd.DnssecPolicy = policy
	signOnceAfterPolicyBind(zd)

	rrset := publishedARRset(t, zd, replacedOwner)
	if len(rrset.RRSIGs) == 0 {
		t.Fatal("the zone was never signed after its policy bound")
	}
	sig := rrset.RRSIGs[0].(*dns.RRSIG)
	if lifetime := sig.Expiration - sig.Inception; lifetime < 24*3600 {
		t.Fatalf("signature lifetime %ds; the bound policy asks for 14 days, so this "+
			"is still the nil-policy fallback", lifetime)
	}
	if !zd.Ready {
		t.Error("the zone did not become Ready once it was properly signed")
	}
}
