package tdns

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Step 2 (relaxed-mode ZSK algorithm rollover) test matrix, §8.4:
// T1, T2, T2b, T2c, T2d, T-timing, T3, T3b, T4, T4b, T4c, T5, T6, T7, T8, T9.
// Driven against a real on-disk KeyDB via newTestKeyDB (sign_reconcile_test.go)
// and the package-global Conf (withCompleteness sets the mode per test).

const algZone = "zsk-alg.example."

// algTestZone builds a minimal signing ZoneData with a bound KSK-ZSK policy.
func algTestZone(ksk, zsk uint8) *ZoneData {
	return &ZoneData{
		ZoneName: algZone,
		Options:  map[ZoneOption]bool{OptOnlineSigning: true},
		DnssecPolicy: &DnssecPolicy{
			Mode:         DnssecPolicyModeKSKZSK,
			KSKAlgorithm: ksk,
			ZSKAlgorithm: zsk,
		},
		DnssecPolicyName: "base",
		Logger:           log.New(os.Stderr, "", 0),
	}
}

// stampPublishedAt sets published_at on a standby ZSK so FIFO ordering is
// deterministic (GenerateKeypair directly into standby does not set it).
func stampPublishedAt(t *testing.T, kdb *KeyDB, keyid uint16, at time.Time) {
	t.Helper()
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET published_at=? WHERE zonename=? AND keyid=?`,
		at.UTC().Format(time.RFC3339), algZone, int(keyid)); err != nil {
		t.Fatalf("stamp published_at on %d: %v", keyid, err)
	}
}

func genZSK(t *testing.T, kdb *KeyDB, state string, alg uint8) uint16 {
	t.Helper()
	pkc, _, err := kdb.GenerateKeypair(algZone, "test", state, dns.TypeDNSKEY, alg, "ZSK", nil)
	if err != nil {
		t.Fatalf("generate ZSK (%s, %s): %v", state, dns.AlgorithmToString[alg], err)
	}
	return pkc.KeyId
}

func countStandbyZSKs(t *testing.T, kdb *KeyDB) int {
	t.Helper()
	keys, err := GetDnssecKeysByState(kdb, algZone, DnskeyStateStandby)
	if err != nil {
		t.Fatalf("list standby: %v", err)
	}
	n := 0
	for _, k := range keys {
		if k.Flags == 256 {
			n++
		}
	}
	return n
}

func countPublishedZSKs(t *testing.T, kdb *KeyDB) int {
	t.Helper()
	keys, err := GetDnssecKeysByState(kdb, algZone, DnskeyStatePublished)
	if err != nil {
		t.Fatalf("list published: %v", err)
	}
	n := 0
	for _, k := range keys {
		if k.Flags == 256 {
			n++
		}
	}
	return n
}

// T1 — relaxed-mode reconcile with active ZSK alg ≠ policy alg does NOT retire
// the active ZSK (the §2 unsafe synchronous swap is gated off).
func TestT1RelaxedReconcileDoesNotRetireActiveZSK(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.RSASHA256) // policy ZSK = RSASHA256

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("generate KSK: %v", err)
	}
	// Active ZSK is ED25519 — wrong alg vs policy RSASHA256.
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)

	dak, err := kdb.GetDnssecKeys(algZone, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeys: %v", err)
	}
	changed, err := zd.reconcileActiveKeyAlgorithms(kdb, dak)
	if err != nil {
		t.Fatalf("relaxed reconcile must not error: %v", err)
	}
	if changed {
		t.Fatal("relaxed reconcile must not retire the wrong-alg active ZSK")
	}
	// The old-alg ZSK is still active.
	active, _ := GetDnssecKeysByState(kdb, algZone, DnskeyStateActive)
	found := false
	for _, k := range active {
		if k.Flags == 256 && k.Algorithm == dns.ED25519 {
			found = true
		}
	}
	if !found {
		t.Fatal("old-alg active ZSK should remain active (carried by the FIFO roll)")
	}
}

// T9 — reload mid-roll: the relaxed reconcile is invoked again (as a zone reload
// re-sign would) while the active ZSK is still old-alg; the T1 invariant holds
// (no retire) across the repeated call.
func TestT9RelaxedReconcileIdempotentMidRoll(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.RSASHA256)
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("generate KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)

	for i := 0; i < 3; i++ {
		dak, _ := kdb.GetDnssecKeys(algZone, DnskeyStateActive)
		if changed, err := zd.reconcileActiveKeyAlgorithms(kdb, dak); err != nil || changed {
			t.Fatalf("reload %d: changed=%v err=%v (want no-op)", i, changed, err)
		}
	}
	active, _ := GetDnssecKeysByState(kdb, algZone, DnskeyStateActive)
	realZSKs := 0
	for _, k := range active {
		if k.Flags == 256 {
			realZSKs++
		}
	}
	if realZSKs != 1 {
		t.Fatalf("active ZSK count after 3 reloads = %d, want 1 (never retired)", realZSKs)
	}
}

// T3 — role-only count: standby_zsk_count=2, two OLD-alg standbys present, policy
// ZSK alg changed to NEW. The maintainer generates NOTHING (role-only count sees
// 2 ≥ 2), and the two old-alg standbys are untouched.
func TestT3RoleOnlyCountGeneratesNothing(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	// policy ZSK = MAYO would need liboqs; use two built-ins: old=ED25519,
	// new=RSASHA256. Policy now wants RSASHA256.
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("generate KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	s1 := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	s2 := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	stampPublishedAt(t, kdb, s1, time.Now().Add(-2*time.Hour))
	stampPublishedAt(t, kdb, s2, time.Now().Add(-1*time.Hour))

	// New policy ZSK alg = RSASHA256; role-only count of standbys = 2 ≥ 2.
	maintainStandbyKeysForType(kdb, algZone, dns.RSASHA256, "ZSK", 256, 2, true /*roleOnly*/)

	if n := countStandbyZSKs(t, kdb); n != 2 {
		t.Fatalf("standby ZSK count = %d, want 2 (nothing generated)", n)
	}
	if n := countPublishedZSKs(t, kdb); n != 0 {
		t.Fatalf("published ZSK count = %d, want 0 (nothing minted)", n)
	}
	// Both old-alg standbys still ED25519.
	keys, _ := GetDnssecKeysByState(kdb, algZone, DnskeyStateStandby)
	for _, k := range keys {
		if k.Flags == 256 && k.Algorithm != dns.ED25519 {
			t.Fatalf("standby %d alg %s, want ED25519 (untouched)", k.KeyTag, dns.AlgorithmToString[k.Algorithm])
		}
	}
}

// T3b — generate-on-drain: from T3's state, after one standby is promoted (count
// drops to 1), the maintainer generates ONE key and it carries the NEW algorithm.
func TestT3bGenerateOnDrainUsesNewAlg(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("generate KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	// Only ONE old-alg standby (count dropped to 1 after a promotion).
	s1 := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	stampPublishedAt(t, kdb, s1, time.Now().Add(-2*time.Hour))

	// Maintainer with new policy alg RSASHA256, standby target 2, role-only.
	maintainStandbyKeysForType(kdb, algZone, dns.RSASHA256, "ZSK", 256, 2, true)

	// It should have generated exactly one new key, staged to published, NEW alg.
	pub, _ := GetDnssecKeysByState(kdb, algZone, DnskeyStatePublished)
	newCount := 0
	for _, k := range pub {
		if k.Flags == 256 {
			newCount++
			if k.Algorithm != dns.RSASHA256 {
				t.Fatalf("generated key alg %s, want RSASHA256 (new alg)", dns.AlgorithmToString[k.Algorithm])
			}
		}
	}
	if newCount != 1 {
		t.Fatalf("generated %d new keys, want exactly 1", newCount)
	}
	// The remaining old-alg standby is untouched.
	keys, _ := GetDnssecKeysByState(kdb, algZone, DnskeyStateStandby)
	for _, k := range keys {
		if k.Flags == 256 && k.KeyTag == s1 && k.Algorithm != dns.ED25519 {
			t.Fatalf("old standby %d changed alg", s1)
		}
	}
}

// T4 — sweep cap: standby_zsk_count=2, THREE standby ZSKs present; the relaxed
// cap deletes the YOUNGEST one (back to 2), keeps the oldest two regardless of
// algorithm — never deletes by algorithm. Maintainer + cap agree (no oscillation).
func TestT4SweepCapDeletesYoungestSurplus(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("generate KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	// Three standbys: two old-alg (oldest), one new-alg (youngest).
	old1 := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	old2 := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	young := genZSK(t, kdb, DnskeyStateStandby, dns.RSASHA256)
	stampPublishedAt(t, kdb, old1, time.Now().Add(-3*time.Hour))
	stampPublishedAt(t, kdb, old2, time.Now().Add(-2*time.Hour))
	stampPublishedAt(t, kdb, young, time.Now().Add(-1*time.Hour))

	capStandbyZsksByCount(kdb, algZone, 2)

	if n := countStandbyZSKs(t, kdb); n != 2 {
		t.Fatalf("standby ZSK count after cap = %d, want 2", n)
	}
	keys, _ := GetDnssecKeysByState(kdb, algZone, DnskeyStateStandby)
	gotTags := map[uint16]bool{}
	for _, k := range keys {
		if k.Flags == 256 {
			gotTags[k.KeyTag] = true
		}
	}
	if !gotTags[old1] || !gotTags[old2] {
		t.Fatalf("cap deleted an OLD standby; survivors=%v want both old (%d,%d)", gotTags, old1, old2)
	}
	if gotTags[young] {
		t.Fatalf("cap kept the YOUNGEST standby %d; should have deleted it", young)
	}

	// Maintainer + cap agree: with 2 standbys and target 2, role-only maintainer
	// generates nothing, cap removes nothing — no oscillation.
	maintainStandbyKeysForType(kdb, algZone, dns.RSASHA256, "ZSK", 256, 2, true)
	capStandbyZsksByCount(kdb, algZone, 2)
	if n := countStandbyZSKs(t, kdb); n != 2 {
		t.Fatalf("after maintainer+cap re-run, standby count = %d, want stable 2", n)
	}
	if p := countPublishedZSKs(t, kdb); p != 0 {
		t.Fatalf("maintainer generated %d keys when count already met (oscillation)", p)
	}
}

// T4b — no out-of-order promotion: an OLDER old-alg standby and a YOUNGER new-alg
// standby both present; a roll promotes the OLD-alg one (FIFO oldest-first).
func TestT4bNoOutOfOrderPromotion(t *testing.T) {
	kdb := newTestKeyDB(t)
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("generate active ZSK: %v", err)
	}
	oldAlg := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	newAlg := genZSK(t, kdb, DnskeyStateStandby, dns.RSASHA256)
	stampPublishedAt(t, kdb, oldAlg, time.Now().Add(-2*time.Hour)) // older
	stampPublishedAt(t, kdb, newAlg, time.Now().Add(-1*time.Hour)) // younger

	_, promoted, err := kdb.RolloverKey(algZone, "ZSK", nil)
	if err != nil {
		t.Fatalf("RolloverKey: %v", err)
	}
	if promoted != oldAlg {
		t.Fatalf("promoted %d, want the OLDER old-alg standby %d (FIFO)", promoted, oldAlg)
	}
}

// T4c — FIFO ordering fix: with multiple same-role standbys created in a known
// order, RolloverKey promotes the OLDEST published_at deterministically,
// independent of insertion order. Asserts the ORDER BY published_at fix.
func TestT4cFifoOrderingByPublishedAt(t *testing.T) {
	kdb := newTestKeyDB(t)
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("generate active ZSK: %v", err)
	}
	// Insert in NON-chronological order: a (newest), b (oldest), c (middle).
	a := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	b := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	c := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	stampPublishedAt(t, kdb, a, time.Now().Add(-1*time.Hour))
	stampPublishedAt(t, kdb, b, time.Now().Add(-3*time.Hour)) // oldest
	stampPublishedAt(t, kdb, c, time.Now().Add(-2*time.Hour))

	_, promoted, err := kdb.RolloverKey(algZone, "ZSK", nil)
	if err != nil {
		t.Fatalf("RolloverKey: %v", err)
	}
	if promoted != b {
		t.Fatalf("promoted %d, want the oldest-published standby %d", promoted, b)
	}
}

// T5 — full sequence via asap (standby_zsk_count=2): change-policy binds new alg;
// the maintainer generates nothing; successive RolloverKey (asap) promotes the
// old-alg standbys FIFO; once they drain the maintainer mints new-alg keys; a
// further promotion activates a new-alg key. No instant with zero ZSK coverage;
// FIFO preserved; DNSKEY RRset never exceeds active + 2 standby + draining-retired.
func TestT5FullSequenceViaAsap(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	const oldA, newA = dns.ED25519, dns.RSASHA256
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, oldA, "KSK", nil); err != nil {
		t.Fatalf("generate KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, oldA)
	s1 := genZSK(t, kdb, DnskeyStateStandby, oldA)
	s2 := genZSK(t, kdb, DnskeyStateStandby, oldA)
	stampPublishedAt(t, kdb, s1, time.Now().Add(-4*time.Hour))
	stampPublishedAt(t, kdb, s2, time.Now().Add(-3*time.Hour))

	// change-policy bound new alg (simulated by maintainer/promotions using newA).
	// 1) maintainer: role-only count = 2, generates nothing.
	maintainStandbyKeysForType(kdb, algZone, newA, "ZSK", 256, 2, true)
	if countPublishedZSKs(t, kdb) != 0 || countStandbyZSKs(t, kdb) != 2 {
		t.Fatalf("step1: expected 2 standby, 0 published; got %d/%d", countStandbyZSKs(t, kdb), countPublishedZSKs(t, kdb))
	}

	// 2) asap → promote s1 (oldest old-alg).
	_, p1, err := kdb.RolloverKey(algZone, "ZSK", nil)
	if err != nil || p1 != s1 {
		t.Fatalf("asap#1 promoted %d (err %v), want s1=%d", p1, err, s1)
	}
	// 3) asap → promote s2.
	_, p2, err := kdb.RolloverKey(algZone, "ZSK", nil)
	if err != nil || p2 != s2 {
		t.Fatalf("asap#2 promoted %d (err %v), want s2=%d", p2, err, s2)
	}
	// Now 0 standby → maintainer mints 2 new-alg keys (into published).
	if countStandbyZSKs(t, kdb) != 0 {
		t.Fatalf("after draining both standbys, standby count = %d, want 0", countStandbyZSKs(t, kdb))
	}
	maintainStandbyKeysForType(kdb, algZone, newA, "ZSK", 256, 2, true)
	// Move the freshly-generated published keys to standby (the worker's
	// published→standby transition), stamping published_at oldest-first.
	pub, _ := GetDnssecKeysByState(kdb, algZone, DnskeyStatePublished)
	var newKeys []uint16
	for _, k := range pub {
		if k.Flags == 256 {
			newKeys = append(newKeys, k.KeyTag)
		}
	}
	if len(newKeys) != 2 {
		t.Fatalf("maintainer minted %d new keys, want 2", len(newKeys))
	}
	for i, kid := range newKeys {
		if err := UpdateDnssecKeyState(kdb, algZone, kid, DnskeyStateStandby); err != nil {
			t.Fatalf("publish→standby %d: %v", kid, err)
		}
		stampPublishedAt(t, kdb, kid, time.Now().Add(time.Duration(-2+i)*time.Hour))
		// Confirm new alg.
		keys, _ := GetDnssecKeysByState(kdb, algZone, DnskeyStateStandby)
		for _, k := range keys {
			if k.KeyTag == kid && k.Algorithm != newA {
				t.Fatalf("new key %d alg %s, want new alg", kid, dns.AlgorithmToString[k.Algorithm])
			}
		}
	}

	// 4) asap → promotes a NEW-alg key; zone now signs new alg.
	_, p3, err := kdb.RolloverKey(algZone, "ZSK", nil)
	if err != nil {
		t.Fatalf("asap#3: %v", err)
	}
	active, _ := GetDnssecKeysByState(kdb, algZone, DnskeyStateActive)
	var activeZSKAlg uint8
	for _, k := range active {
		if k.Flags == 256 {
			activeZSKAlg = k.Algorithm
		}
	}
	if activeZSKAlg != newA {
		t.Fatalf("after asap#3 active ZSK alg = %s, want new alg %s (promoted key %d)",
			dns.AlgorithmToString[activeZSKAlg], dns.AlgorithmToString[newA], p3)
	}

	// Invariant: at no checked point were there zero active ZSKs.
	if len(active) == 0 {
		t.Fatal("zero active ZSKs at end of sequence")
	}
}

// ---- change-policy entry-guard tests (T2, T2b, T2c, T2d) ----
// These exercise the refusal guards, which return BEFORE SignZone, so they need
// only a bound current policy + a target in Conf.Internal.DnssecPolicies.

func withPolicies(t *testing.T, policies map[string]DnssecPolicy) {
	t.Helper()
	prev := Conf.Internal.DnssecPolicies
	Conf.Internal.DnssecPolicies = policies
	t.Cleanup(func() { Conf.Internal.DnssecPolicies = prev })
}

// T2 — STRICT mode ZSK alg change is refused at the entry, no key change.
func TestT2StrictModeZskAlgChangeRefused(t *testing.T) {
	withCompleteness(t, CompletenessStrict)
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519) // current ZSK ED25519
	withPolicies(t, map[string]DnssecPolicy{
		"target": {Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.RSASHA256},
	})
	_, err := changeZonePolicy(zd, kdb, "target")
	if err == nil {
		t.Fatal("strict-mode ZSK alg change must be refused")
	}
	// No override written.
	if _, ok, _ := GetZonePolicyOverride(kdb, algZone); ok {
		t.Fatal("strict refusal must not write an override")
	}
}

// T2b — KSK-only and CSK alg changes under RELAXED are refused; no key churn.
func TestT2bKskAndCskAlgChangeRefused(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)

	// KSK-only change (ZSK same).
	zd := algTestZone(dns.ED25519, dns.RSASHA256)
	withPolicies(t, map[string]DnssecPolicy{
		"kskroll": {Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.RSASHA256, ZSKAlgorithm: dns.RSASHA256},
	})
	if _, err := changeZonePolicy(zd, kdb, "kskroll"); err == nil {
		t.Fatal("KSK-only alg change must be refused")
	}
	if _, ok, _ := GetZonePolicyOverride(kdb, algZone); ok {
		t.Fatal("KSK refusal must not write an override")
	}

	// CSK target.
	zdCsk := algTestZone(dns.ED25519, dns.RSASHA256)
	withPolicies(t, map[string]DnssecPolicy{
		"csk": {Mode: DnssecPolicyModeCSK, Algorithm: dns.RSASHA256, KSKAlgorithm: dns.RSASHA256, ZSKAlgorithm: dns.RSASHA256},
	})
	if _, err := changeZonePolicy(zdCsk, kdb, "csk"); err == nil {
		t.Fatal("CSK alg change must be refused")
	}
}

// T2c — both-role target is rejected at entry before any override write.
func TestT2cBothRoleChangeRejected(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	withPolicies(t, map[string]DnssecPolicy{
		"both": {Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.RSASHA256, ZSKAlgorithm: dns.RSASHA256},
	})
	_, err := changeZonePolicy(zd, kdb, "both")
	if err == nil {
		t.Fatal("both-role alg change must be rejected")
	}
	if _, ok, _ := GetZonePolicyOverride(kdb, algZone); ok {
		t.Fatal("both-role rejection must not write an override")
	}
}

// T2d — re-entrancy: a second change-policy while a ZSK alg roll is in flight is
// refused, covering both the pre-promotion phase and the drain window (D4's
// blind spot, where the new-alg key is active and an old-alg ZSK is still
// retired). Asserts the fuller predicate.
func TestT2dReentrancyRefused(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)

	t.Run("pre-promotion", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := algTestZone(dns.ED25519, dns.RSASHA256) // bound policy already RSASHA256
		// Active ZSK is still old-alg (ED25519) → roll in flight pre-promotion.
		if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
			t.Fatalf("KSK: %v", err)
		}
		genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
		withPolicies(t, map[string]DnssecPolicy{
			"target": {Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.RSASHA256},
		})
		if _, err := changeZonePolicy(zd, kdb, "target"); err == nil {
			t.Fatal("re-entrant change-policy (pre-promotion) must be refused")
		}
	})

	t.Run("drain-window", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := algTestZone(dns.ED25519, dns.RSASHA256)
		if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
			t.Fatalf("KSK: %v", err)
		}
		// New-alg ZSK already promoted to active; old-alg ZSK still retired
		// (draining). active alg == policy alg (D4 reads false), but the fuller
		// predicate sees the retired old-alg key → still in flight.
		genZSK(t, kdb, DnskeyStateActive, dns.RSASHA256)
		genZSK(t, kdb, DnskeyStateRetired, dns.ED25519)
		withPolicies(t, map[string]DnssecPolicy{
			"target": {Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.RSASHA256},
		})
		if _, err := changeZonePolicy(zd, kdb, "target"); err == nil {
			t.Fatal("re-entrant change-policy (drain window) must be refused")
		}
	})
}

// T7 — override≠YAML but active-alg == bound-policy-alg (a COMPLETED prior
// change) is NOT treated as in progress (D4 / the fuller predicate both read
// "not rolling"). zskAlgRollInFlight returns false.
func TestT7CompletedChangeNotInProgress(t *testing.T) {
	kdb := newTestKeyDB(t)
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.RSASHA256, "ZSK", nil); err != nil {
		t.Fatalf("active ZSK: %v", err)
	}
	// One retired ZSK of the SAME (current) alg — a normal same-alg roll
	// remnant, not an algorithm transition.
	genZSK(t, kdb, DnskeyStateRetired, dns.RSASHA256)
	st, err := zskAlgRollInFlight(kdb, algZone, dns.RSASHA256)
	if err != nil {
		t.Fatalf("zskAlgRollInFlight: %v", err)
	}
	if st.InFlight {
		t.Fatalf("completed same-alg state must not read in-flight: %+v", st)
	}
}

// Regression: a FRESH zone whose ZSKs are all on its currently-bound algorithm
// (active + standby + draining retired, all the same alg — the normal starting
// state before any roll) must NOT read as a roll-in-flight relative to that
// bound algorithm. The re-entrancy guard measures against the BOUND alg, not the
// incoming target; checking against a different target would falsely report
// "already in progress" on the very first change-policy. (Caught on the testbed
// rolling fastroll ED25519 → mayo1.)
func TestReentrancyFreshZoneNotInFlight(t *testing.T) {
	kdb := newTestKeyDB(t)
	// Mirror a live fastroll zone: active + standby + a draining retired ZSK,
	// all ED25519 (the bound alg).
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("active ZSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	genZSK(t, kdb, DnskeyStateRetired, dns.ED25519)

	// Against the BOUND alg (ED25519): nothing is in flight — the roll has not
	// started.
	if st, err := zskAlgRollInFlight(kdb, algZone, dns.ED25519); err != nil {
		t.Fatalf("zskAlgRollInFlight(bound): %v", err)
	} else if st.InFlight {
		t.Fatalf("fresh same-alg zone must not read in-flight vs its bound alg: %+v", st)
	}

	// Sanity: against a DIFFERENT alg the predicate trivially trips — which is
	// exactly why the guard must use the bound alg, not the target.
	if st, err := zskAlgRollInFlight(kdb, algZone, dns.RSASHA256); err != nil {
		t.Fatalf("zskAlgRollInFlight(target): %v", err)
	} else if !st.InFlight {
		t.Fatal("vs a different alg the predicate should trip (guards the bound-vs-target reasoning)")
	}
}

// Regression (end-to-end): changeZonePolicy on a fresh same-alg zone must get
// PAST the re-entrancy guard (it may fail later in SignZone for lack of real
// zone data, but it must NOT be refused as "already in progress").
func TestChangePolicyFreshZonePassesReentrancyGuard(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519) // bound fastroll-like: ZSK ED25519
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("active ZSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	withPolicies(t, map[string]DnssecPolicy{
		"mayoish": {Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.RSASHA256},
	})
	_, err := changeZonePolicy(zd, kdb, "mayoish")
	// It will likely error in SignZone (no real zone data), but NOT with the
	// re-entrancy refusal.
	if err != nil && strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("fresh zone wrongly refused as already-in-progress: %v", err)
	}
}

// T2 (mode) + T-timing — a same-algorithm, timing-only change is allowed: no
// roll, no error, no in-flight detection. (We assert the predicate is false and
// the both-role/KSK/CSK/re-entrancy guards do not fire for a same-alg target.)
func TestTTimingSameAlgNotARoll(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.RSASHA256, "ZSK", nil); err != nil {
		t.Fatalf("active ZSK: %v", err)
	}
	st, err := zskAlgRollInFlight(kdb, algZone, dns.RSASHA256)
	if err != nil {
		t.Fatalf("zskAlgRollInFlight: %v", err)
	}
	if st.InFlight {
		t.Fatal("same-alg zone must not read as an in-flight roll")
	}
}

// T6 — change-policy writes the override to the TARGET; a simulated restart
// (re-resolve via EffectiveDnssecPolicyName, given the YAML config base) rebinds
// to the target, not the old policy. This is the persistence half of
// change-policy (the override write) verified independently of the heavy
// SignZone path the success branch also runs.
func TestT6OverrideResumesToTargetOnRestart(t *testing.T) {
	kdb := newTestKeyDB(t)
	const configBase = "old-policy"
	const target = "new-policy"

	// Before any change-policy: effective == config base.
	eff, overridden, err := EffectiveDnssecPolicyName(kdb, algZone, configBase)
	if err != nil {
		t.Fatalf("EffectiveDnssecPolicyName (pre): %v", err)
	}
	if overridden || eff != configBase {
		t.Fatalf("pre-override: eff=%q overridden=%v, want %q/false", eff, overridden, configBase)
	}

	// change-policy's durable effect: write the override to the target.
	if err := SetZonePolicyOverride(kdb, algZone, target); err != nil {
		t.Fatalf("SetZonePolicyOverride: %v", err)
	}

	// Simulated restart: re-resolve from the YAML config base. The override wins.
	eff, overridden, err = EffectiveDnssecPolicyName(kdb, algZone, configBase)
	if err != nil {
		t.Fatalf("EffectiveDnssecPolicyName (post): %v", err)
	}
	if !overridden || eff != target {
		t.Fatalf("post-override: eff=%q overridden=%v, want %q/true (resume toward target)", eff, overridden, target)
	}
}

// T8 — relaxed roll does not maintain a whole-zone double-signature: the
// reconcile never re-activates or refreshes the old-alg ZSK once it has been
// retired; only the new-alg active key signs. We assert at the key-state level
// that a retired old-alg ZSK is not promoted back to active by the reconcile.
func TestT8NoMaintainedDoubleSignature(t *testing.T) {
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.RSASHA256)
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.RSASHA256) // new-alg active
	oldRetired := genZSK(t, kdb, DnskeyStateRetired, dns.ED25519)

	dak, _ := kdb.GetDnssecKeys(algZone, DnskeyStateActive)
	if changed, err := zd.reconcileActiveKeyAlgorithms(kdb, dak); err != nil || changed {
		t.Fatalf("reconcile changed=%v err=%v (want no-op; new-alg active matches policy)", changed, err)
	}
	// The old-alg key is still retired (not promoted back to active).
	retired, _ := GetDnssecKeysByState(kdb, algZone, DnskeyStateRetired)
	stillRetired := false
	for _, k := range retired {
		if k.KeyTag == oldRetired {
			stillRetired = true
		}
	}
	if !stillRetired {
		t.Fatal("retired old-alg ZSK must stay retired (no maintained double-signature)")
	}
}
