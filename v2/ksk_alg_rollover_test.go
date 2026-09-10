package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// KSK algorithm rollover test matrix
// (docs/2026-09-08-ksk-alg-rollover-implementation-plan.md §8). Driven
// against a real on-disk KeyDB and a real signed zone, with the tick's
// clock injected through RolloverEngineDeps.Now.

const ktAlgZone = "kskalg.example."

const ktAlgZoneText = `kskalg.example.	3600	IN	SOA	ns.kskalg.example. hostmaster.kskalg.example. 1 7200 1800 604800 7200
kskalg.example.	3600	IN	NS	ns.kskalg.example.
ns.kskalg.example.	3600	IN	A	192.0.2.1
www.kskalg.example.	3600	IN	A	192.0.2.2
`

// ktAlgFixture: a signed zone with one active ED25519 KSK (A) and an
// active ZSK, bound to a policy that still wants ED25519. Tests flip
// pol.KSKAlgorithm to simulate the bind change-policy makes.
func ktAlgFixture(t *testing.T, method RolloverMethod) (*ZoneData, *KeyDB, uint16) {
	t.Helper()
	kdb := newTestKeyDB(t)
	pol := ktMultiDSPolicy(dns.ED25519, dns.ED25519)
	pol.Rollover.Method = method
	zd := ktEngineZone(t, kdb, ktAlgZone, ktAlgZoneText, pol)
	a := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	return zd, kdb, a
}

func ktActiveSEPs(t *testing.T, kdb *KeyDB, zone string) []DnssecKeyWithTimestamps {
	t.Helper()
	keys, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	var out []DnssecKeyWithTimestamps
	for _, k := range keys {
		if k.Flags&dns.SEP != 0 {
			out = append(out, k)
		}
	}
	return out
}

func ktCountSEPsInState(t *testing.T, kdb *KeyDB, zone, state string) int {
	t.Helper()
	keys, err := GetDnssecKeysByState(kdb, zone, state)
	if err != nil {
		t.Fatalf("list %s: %v", state, err)
	}
	n := 0
	for _, k := range keys {
		if k.Flags&dns.SEP != 0 {
			n++
		}
	}
	return n
}

func ktTick(t *testing.T, zd *ZoneData, kdb *KeyDB, now time.Time) {
	t.Helper()
	if err := RolloverAutomatedTick(context.Background(), ktDeps(zd, kdb, now)); err != nil {
		t.Fatalf("tick: %v", err)
	}
}

// KT-3 / KT-3b: one tick after the bind mints exactly ONE new-algorithm
// KSK straight into active with full rollover bookkeeping; the
// old-algorithm head is untouched; the zone is parked in
// pending-child-publish with the roll recorded.
func TestKT3SpawnMintsOneNewAlgKSKIntoActive(t *testing.T) {
	zd, kdb, a := ktAlgFixture(t, RolloverMethodMultiDS)
	zd.DnssecPolicy.KSKAlgorithm = dns.RSASHA256 // the bind
	now := time.Now()

	ktTick(t, zd, kdb, now)

	seps := ktActiveSEPs(t, kdb, ktAlgZone)
	if len(seps) != 2 {
		t.Fatalf("active SEP keys after spawn = %d, want 2 (A and B)", len(seps))
	}
	var b uint16
	for _, k := range seps {
		switch {
		case k.KeyTag == a:
			if k.Algorithm != dns.ED25519 {
				t.Fatalf("A's algorithm changed: %s", dns.AlgorithmToString[k.Algorithm])
			}
		case k.Algorithm == dns.RSASHA256:
			b = k.KeyTag
		default:
			t.Fatalf("unexpected active SEP key %d (%s)", k.KeyTag, dns.AlgorithmToString[k.Algorithm])
		}
	}
	if b == 0 {
		t.Fatal("no RSASHA256 KSK minted")
	}
	if n := ktCountSEPsInState(t, kdb, ktAlgZone, DnskeyStateCreated); n != 0 {
		t.Fatalf("spawn minted %d created keys; B must go straight to active", n)
	}

	// KT-3b: bookkeeping on B, and its index follows A's.
	if at, err := RolloverKeyActiveAt(kdb, ktAlgZone, b); err != nil || at == nil {
		t.Fatalf("B active_at: at=%v err=%v", at, err)
	}
	if seq, err := RolloverKeyActiveSeq(kdb, ktAlgZone, b); err != nil || seq < 0 {
		t.Fatalf("B active_seq: seq=%d err=%v", seq, err)
	}
	ia, okA, _ := RolloverIndexForKey(kdb, ktAlgZone, a)
	ib, okB, _ := RolloverIndexForKey(kdb, ktAlgZone, b)
	if !okA || !okB || ib <= ia {
		t.Fatalf("rollover_index A=%d(%v) B=%d(%v); B must follow A", ia, okA, ib, okB)
	}

	row, err := LoadRolloverZoneRow(kdb, ktAlgZone)
	if err != nil || row == nil {
		t.Fatalf("row: %v %v", row, err)
	}
	if !row.RolloverInProgress || row.RolloverPhase != rolloverPhasePendingChildPublish {
		t.Fatalf("after spawn: in_progress=%v phase=%q", row.RolloverInProgress, row.RolloverPhase)
	}
	st := kskAlgRollFromRow(row)
	if st == nil || st.FromAlg != dns.ED25519 || st.ToAlg != dns.RSASHA256 ||
		st.OldHeadKeyID != a || st.NewHeadKeyID != b || st.OldHeadRetireAt != nil {
		t.Fatalf("alg-roll state = %+v", st)
	}

	// A second tick inside the propagation wait changes nothing.
	ktTick(t, zd, kdb, now.Add(time.Second))
	if seps := ktActiveSEPs(t, kdb, ktAlgZone); len(seps) != 2 {
		t.Fatalf("second tick changed the active set: %d keys", len(seps))
	}
	st2, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	if st2 == nil || st2.NewHeadKeyID != b {
		t.Fatalf("second tick disturbed the roll state: %+v", st2)
	}
}

// KT-4: the freeze. Old-algorithm (and stray third-algorithm) pipeline
// members go to removed at spawn; the active head and a retired key are
// left alone; a new-algorithm standby survives.
func TestKT4SpawnFreezesOldAlgorithmPipeline(t *testing.T) {
	zd, kdb, a := ktAlgFixture(t, RolloverMethodMultiDS)
	created := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateCreated, dns.ED25519)
	published := ktGenKSK(t, kdb, ktAlgZone, DnskeyStatePublished, dns.ED25519)
	standby := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateStandby, dns.ED25519)
	stray := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateStandby, dns.ECDSAP256SHA256)
	retired := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateRetired, dns.ED25519)
	newStandby := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateStandby, dns.RSASHA256)
	zd.DnssecPolicy.KSKAlgorithm = dns.RSASHA256

	ktTick(t, zd, kdb, time.Now())

	for _, kid := range []uint16{created, published, standby, stray} {
		if st := ktKeyState(t, kdb, ktAlgZone, kid); st != DnskeyStateRemoved {
			t.Fatalf("key %d should be frozen (removed), is %s", kid, st)
		}
	}
	if st := ktKeyState(t, kdb, ktAlgZone, a); st != DnskeyStateActive {
		t.Fatalf("old head %d must stay active, is %s", a, st)
	}
	if st := ktKeyState(t, kdb, ktAlgZone, retired); st != DnskeyStateRetired {
		t.Fatalf("retired key %d is the withdraw phase's to drain, is %s", retired, st)
	}
	if st := ktKeyState(t, kdb, ktAlgZone, newStandby); st != DnskeyStateStandby {
		t.Fatalf("new-algorithm standby %d must survive the freeze, is %s", newStandby, st)
	}
}

// KT-13: pipeline-fill mints nothing while the roll is in flight (D-8), and
// the multi-DS-only transitions do not select B.
func TestKT13NoPipelineFillDuringAlgRoll(t *testing.T) {
	zd, kdb, _ := ktAlgFixture(t, RolloverMethodMultiDS)
	zd.DnssecPolicy.Rollover.NumDS = 3 // would want two more keys if the fill ran
	zd.DnssecPolicy.KSKAlgorithm = dns.RSASHA256
	now := time.Now()

	ktTick(t, zd, kdb, now)
	before := ktCountSEPsInState(t, kdb, ktAlgZone, DnskeyStateCreated)
	if before != 0 {
		t.Fatalf("the spawn tick minted %d created keys", before)
	}
	for i := 1; i <= 3; i++ {
		ktTick(t, zd, kdb, now.Add(time.Duration(i)*time.Second))
	}
	if n := ktCountSEPsInState(t, kdb, ktAlgZone, DnskeyStateCreated); n != 0 {
		t.Fatalf("pipeline-fill minted %d created keys during the roll", n)
	}

	st, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	ctx := context.Background()
	TransitionRolloverKskDsPublishedToPublished(ctx, &Conf, kdb, now, time.Minute)
	TransitionRolloverKskPublishedToStandby(ctx, &Conf, kdb, now, time.Minute)
	if s := ktKeyState(t, kdb, ktAlgZone, st.NewHeadKeyID); s != DnskeyStateActive {
		t.Fatalf("B moved to %s under the multi-DS transitions", s)
	}
	if s := ktKeyState(t, kdb, ktAlgZone, st.OldHeadKeyID); s != DnskeyStateActive {
		t.Fatalf("A moved to %s under the multi-DS transitions", s)
	}
}

// D-11 at spawn time: a KSK change bound while a ZSK algorithm rollover is
// draining waits; it spawns once the ZSK roll has finished.
func TestKT2dSpawnWaitsForZskAlgRoll(t *testing.T) {
	zd, kdb, a := ktAlgFixture(t, RolloverMethodMultiDS)
	// A draining old-algorithm ZSK: the bound ZSK algorithm is ED25519,
	// so a retired RSASHA256 ZSK reads as an unfinished ZSK transition.
	oldZSK := ktGenZSK(t, kdb, ktAlgZone, DnskeyStateRetired, dns.RSASHA256)
	zd.DnssecPolicy.KSKAlgorithm = dns.RSASHA256
	now := time.Now()

	ktTick(t, zd, kdb, now)
	if seps := ktActiveSEPs(t, kdb, ktAlgZone); len(seps) != 1 || seps[0].KeyTag != a {
		t.Fatalf("spawned while a ZSK roll was draining: %d active SEP keys", len(seps))
	}
	if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st != nil {
		t.Fatalf("roll recorded while a ZSK roll was draining: %+v", st)
	}
	// While it waits, nothing acts on the new algorithm ahead of the spawn:
	// no pipeline-fill, no push armed.
	if n := ktCountSEPsInState(t, kdb, ktAlgZone, DnskeyStateCreated); n != 0 {
		t.Fatalf("pipeline-fill minted %d new-algorithm keys while the spawn was deferred", n)
	}
	if row, _ := LoadRolloverZoneRow(kdb, ktAlgZone); row == nil || row.RolloverPhase != rolloverPhaseIdle {
		t.Fatalf("a push was armed while the spawn was deferred: %+v", row)
	}

	// The ZSK drain finishes; the next tick spawns.
	if err := UpdateDnssecKeyState(kdb, ktAlgZone, oldZSK, DnskeyStateRemoved); err != nil {
		t.Fatalf("remove old ZSK: %v", err)
	}
	ktTick(t, zd, kdb, now.Add(time.Second))
	if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st == nil || st.OldHeadKeyID != a {
		t.Fatalf("expected the roll to spawn once the ZSK drain finished: %+v", st)
	}
}

// The spawn is refused on top of any rollover already in progress, and
// never runs twice.
func TestSpawnRefusedWhileRolloverInProgress(t *testing.T) {
	zd, kdb, a := ktAlgFixture(t, RolloverMethodMultiDS)
	ktSetInProgress(t, kdb, ktAlgZone, true)
	if _, err := SpawnKskAlgRollover(&Conf, kdb, ktAlgZone, dns.ED25519, dns.RSASHA256); err == nil {
		t.Fatal("spawn must refuse while rollover_in_progress is set")
	}
	ktSetInProgress(t, kdb, ktAlgZone, false)
	zd.DnssecPolicy.KSKAlgorithm = dns.RSASHA256
	ktTick(t, zd, kdb, time.Now())
	if _, err := SpawnKskAlgRollover(&Conf, kdb, ktAlgZone, dns.ED25519, dns.RSASHA256); err == nil {
		t.Fatal("a second spawn must refuse (roll already recorded)")
	}
	if seps := ktActiveSEPs(t, kdb, ktAlgZone); len(seps) != 2 {
		t.Fatalf("active SEP keys = %d, want 2", len(seps))
	}
	if st := ktKeyState(t, kdb, ktAlgZone, a); st != DnskeyStateActive {
		t.Fatalf("A is %s", st)
	}
}

// D-4: a method: double-signature zone gets an algorithm roll through the
// same engine, and outside one the tick still does nothing for it.
func TestD4DoubleSignatureZoneSpawnsAlgRoll(t *testing.T) {
	zd, kdb, a := ktAlgFixture(t, RolloverMethodDoubleSignature)
	zd.DnssecPolicy.Rollover.NumDS = 3
	now := time.Now()

	// Same algorithm: the same-alg double-signature cadence is unbuilt; no
	// fill, no roll.
	ktTick(t, zd, kdb, now)
	if n := ktCountSEPsInState(t, kdb, ktAlgZone, DnskeyStateCreated); n != 0 {
		t.Fatalf("double-signature zone got pipeline-fill: %d created keys", n)
	}
	if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st != nil {
		t.Fatalf("no mismatch, yet a roll was recorded: %+v", st)
	}

	zd.DnssecPolicy.KSKAlgorithm = dns.RSASHA256
	ktTick(t, zd, kdb, now.Add(time.Second))
	st, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	if st == nil || st.OldHeadKeyID != a || st.ToAlg != dns.RSASHA256 {
		t.Fatalf("double-signature zone did not spawn the algorithm roll: %+v", st)
	}
	if seps := ktActiveSEPs(t, kdb, ktAlgZone); len(seps) != 2 {
		t.Fatalf("active SEP keys = %d, want 2", len(seps))
	}
}
