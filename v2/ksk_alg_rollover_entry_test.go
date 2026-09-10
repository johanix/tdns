package tdns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Entry layer for the KSK algorithm rollover: the reconcile hand-off
// (KT-1), the change-policy gates (KT-2d), reload mid-roll (KT-9), the
// double-signature itself (KT-16), and the YAML routing predicate.

// ktWithLivePolicies publishes a runtime-config snapshot carrying exactly
// these policies, which is where changeZonePolicy resolves names from.
func ktWithLivePolicies(t *testing.T, policies map[string]DnssecPolicy) {
	t.Helper()
	prev := liveConfig.Load()
	liveConfig.Store(&RuntimeConfig{DnssecPolicies: policies})
	t.Cleanup(func() { liveConfig.Store(prev) })
}

// ktBoundFixture: a signed, registered zone bound to policy "base" (KSK
// ED25519, multi-DS engine) with the target policy "newalg" (KSK
// RSASHA256, same engine) published alongside.
func ktBoundFixture(t *testing.T) (*ZoneData, *KeyDB, uint16) {
	t.Helper()
	withCompleteness(t, CompletenessRelaxed)
	kdb := newTestKeyDB(t)
	base := ktSequencePolicy(RolloverMethodMultiDS)
	base.Name = "base"
	target := *base
	target.Name = "newalg"
	target.KSKAlgorithm = dns.RSASHA256
	ktWithLivePolicies(t, map[string]DnssecPolicy{"base": *base, "newalg": target})

	zd := ktEngineZone(t, kdb, ktAlgZone, ktAlgZoneText, base)
	a := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	return zd, kdb, a
}

// KT-1: with an engine configured, a wrong-algorithm active KSK is neither
// retired nor refused by the reconcile, in both completeness modes.
func TestKT1ReconcileHandsKskMismatchToEngine(t *testing.T) {
	for _, mode := range []string{CompletenessStrict, CompletenessRelaxed} {
		t.Run(mode, func(t *testing.T) {
			withCompleteness(t, mode)
			kdb := newTestKeyDB(t)
			pol := ktMultiDSPolicy(dns.RSASHA256, dns.ED25519) // wants RSASHA256
			zd := &ZoneData{ZoneName: ktAlgZone, Options: map[ZoneOption]bool{OptOnlineSigning: true}, DnssecPolicy: pol}
			a := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519) // has ED25519
			ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
			dak, err := kdb.GetDnssecKeys(ktAlgZone, DnskeyStateActive)
			if err != nil {
				t.Fatalf("GetDnssecKeys: %v", err)
			}
			changed, err := zd.reconcileActiveKeyAlgorithms(kdb, dak)
			if err != nil {
				t.Fatalf("reconcile must hand the mismatch to the engine, not refuse: %v", err)
			}
			if changed {
				t.Fatal("reconcile must not touch keys on a KSK mismatch")
			}
			if st := ktKeyState(t, kdb, ktAlgZone, a); st != DnskeyStateActive {
				t.Fatalf("old-algorithm KSK %d is %s, want active", a, st)
			}
		})
	}
}

// The predicate that routes a YAML rebind through the engine.
func TestKskOnlyAlgChangeWithEngine(t *testing.T) {
	ksz := func(k, z uint8, m RolloverMethod) *DnssecPolicy {
		return &DnssecPolicy{Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: k, ZSKAlgorithm: z, Rollover: RolloverPolicy{Method: m}}
	}
	cases := []struct {
		name        string
		from, to    *DnssecPolicy
		wantCarried bool
	}{
		{"ksk change, engine", ksz(dns.ED25519, dns.ED25519, RolloverMethodNone), ksz(dns.RSASHA256, dns.ED25519, RolloverMethodMultiDS), true},
		{"ksk change, double-signature engine", ksz(dns.ED25519, dns.ED25519, RolloverMethodNone), ksz(dns.RSASHA256, dns.ED25519, RolloverMethodDoubleSignature), true},
		{"ksk change, no engine", ksz(dns.ED25519, dns.ED25519, RolloverMethodNone), ksz(dns.RSASHA256, dns.ED25519, RolloverMethodNone), false},
		{"both roles change", ksz(dns.ED25519, dns.ED25519, RolloverMethodNone), ksz(dns.RSASHA256, dns.RSASHA256, RolloverMethodMultiDS), false},
		{"zsk only", ksz(dns.ED25519, dns.ED25519, RolloverMethodNone), ksz(dns.ED25519, dns.RSASHA256, RolloverMethodMultiDS), false},
		{"csk", &DnssecPolicy{Mode: DnssecPolicyModeCSK, KSKAlgorithm: dns.ED25519}, &DnssecPolicy{Mode: DnssecPolicyModeCSK, KSKAlgorithm: dns.RSASHA256, Rollover: RolloverPolicy{Method: RolloverMethodMultiDS}}, false},
		{"nil", nil, ksz(dns.RSASHA256, dns.ED25519, RolloverMethodMultiDS), false},
	}
	for _, c := range cases {
		if got := kskOnlyAlgChangeWithEngine(c.from, c.to); got != c.wantCarried {
			t.Errorf("%s: carried=%v, want %v", c.name, got, c.wantCarried)
		}
	}
}

// KT-3 proper: change-policy binds, the next tick spawns.
func TestKT3ChangePolicyThenTickSpawns(t *testing.T) {
	zd, kdb, a := ktBoundFixture(t)
	msg, err := changeZonePolicy(context.Background(), zd, kdb, "newalg")
	if err != nil {
		t.Fatalf("change-policy: %v", err)
	}
	if !strings.Contains(msg, "DOUBLE-SIGNATURE") || !strings.Contains(msg, "does NOT perform the roll") {
		t.Fatalf("bind message does not describe the KSK roll: %q", msg)
	}
	if zd.DnssecPolicy.KSKAlgorithm != dns.RSASHA256 {
		t.Fatalf("bound policy KSK algorithm = %s", dns.AlgorithmToString[zd.DnssecPolicy.KSKAlgorithm])
	}
	// The bind's re-sign did not retire A (D-5: the tick spawns, not the bind).
	if st := ktKeyState(t, kdb, ktAlgZone, a); st != DnskeyStateActive {
		t.Fatalf("after bind: A is %s", st)
	}
	if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st != nil {
		t.Fatalf("change-policy must not spawn itself: %+v", st)
	}

	ktTick(t, zd, kdb, time.Now())
	st, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	if st == nil || st.OldHeadKeyID != a || st.FromAlg != dns.ED25519 || st.ToAlg != dns.RSASHA256 {
		t.Fatalf("tick after bind did not spawn: %+v", st)
	}
	if seps := ktActiveSEPs(t, kdb, ktAlgZone); len(seps) != 2 {
		t.Fatalf("active SEP keys = %d, want 2", len(seps))
	}
}

// KT-2d: re-entrancy, four sub-cases, all refused, none writing an override.
func TestKT2dChangePolicyReentrancy(t *testing.T) {
	refused := func(t *testing.T, zd *ZoneData, kdb *KeyDB, pol, want string) {
		t.Helper()
		_, err := changeZonePolicy(context.Background(), zd, kdb, pol)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("change-policy %q: err=%v, want refusal containing %q", pol, err, want)
		}
	}

	t.Run("i-mid-DS-dance", func(t *testing.T) {
		zd, kdb, _ := ktBoundFixture(t)
		if _, err := changeZonePolicy(context.Background(), zd, kdb, "newalg"); err != nil {
			t.Fatalf("first change-policy: %v", err)
		}
		ktTick(t, zd, kdb, time.Now()) // spawn: rollover_in_progress, pending-child-publish
		// A second change-policy (back to base) while the DS dance runs.
		refused(t, zd, kdb, "base", "already in progress")
	})

	t.Run("ii-mid-drain", func(t *testing.T) {
		zd, kdb, a := ktBoundFixture(t)
		if _, err := changeZonePolicy(context.Background(), zd, kdb, "newalg"); err != nil {
			t.Fatalf("first change-policy: %v", err)
		}
		ktTick(t, zd, kdb, time.Now())
		// Fake the confirm: clock stamped, phase withdraw; A still active.
		tx, _ := kdb.Begin("test")
		_ = setKskAlgRollOldHeadRetireAtTx(tx, ktAlgZone, time.Now())
		_ = setRolloverPhaseTx(tx, ktAlgZone, rolloverPhasePendingChildWithdraw)
		_ = tx.Commit()
		if st := ktKeyState(t, kdb, ktAlgZone, a); st != DnskeyStateActive {
			t.Fatalf("A is %s", st)
		}
		refused(t, zd, kdb, "base", "already in progress")
	})

	t.Run("iii-ksk-change-while-zsk-drains", func(t *testing.T) {
		zd, kdb, _ := ktBoundFixture(t)
		// A draining old-algorithm ZSK relative to the bound ZSK algorithm.
		ktGenZSK(t, kdb, ktAlgZone, DnskeyStateRetired, dns.RSASHA256)
		refused(t, zd, kdb, "newalg", "ZSK algorithm rollover is already in progress")
		if _, ok, _ := GetZonePolicyOverride(kdb, ktAlgZone); ok {
			t.Fatal("refusal must not write an override")
		}
	})

	t.Run("iv-zsk-change-while-ksk-drains", func(t *testing.T) {
		zd, kdb, _ := ktBoundFixture(t)
		if _, err := changeZonePolicy(context.Background(), zd, kdb, "newalg"); err != nil {
			t.Fatalf("first change-policy: %v", err)
		}
		ktTick(t, zd, kdb, time.Now())
		zskTarget := *zd.DnssecPolicy
		zskTarget.Name = "zskroll"
		zskTarget.ZSKAlgorithm = dns.RSASHA256
		ktWithLivePolicies(t, map[string]DnssecPolicy{"zskroll": zskTarget})
		refused(t, zd, kdb, "zskroll", "roll one role at a time")
	})

	t.Run("no-engine", func(t *testing.T) {
		zd, kdb, _ := ktBoundFixture(t)
		noEngine := *zd.DnssecPolicy
		noEngine.Name = "noengine"
		noEngine.KSKAlgorithm = dns.RSASHA256
		noEngine.Rollover.Method = RolloverMethodNone
		ktWithLivePolicies(t, map[string]DnssecPolicy{"noengine": noEngine})
		refused(t, zd, kdb, "noengine", "no auto-rollover engine")
	})
}

// KT-9: a zone reload (re-parse + re-sign) mid-roll neither retires the
// old-algorithm active KSK nor clears the roll state.
func TestKT9ReloadMidRollKeepsOldHead(t *testing.T) {
	zd, kdb, a := ktBoundFixture(t)
	if _, err := changeZonePolicy(context.Background(), zd, kdb, "newalg"); err != nil {
		t.Fatalf("change-policy: %v", err)
	}
	ktTick(t, zd, kdb, time.Now())
	before, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	for i := 0; i < 3; i++ {
		if _, err := zd.SignZone(kdb, true); err != nil {
			t.Fatalf("re-sign %d mid-roll: %v", i, err)
		}
		dak, _ := kdb.GetDnssecKeys(ktAlgZone, DnskeyStateActive)
		if changed, err := zd.reconcileActiveKeyAlgorithms(kdb, dak); err != nil || changed {
			t.Fatalf("reconcile %d mid-roll: changed=%v err=%v", i, changed, err)
		}
	}
	if st := ktKeyState(t, kdb, ktAlgZone, a); st != DnskeyStateActive {
		t.Fatalf("A is %s after reloads, want active", st)
	}
	after, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	if after == nil || *before != *after {
		t.Fatalf("roll state changed across reloads: %+v → %+v", before, after)
	}
}

// KT-16: after the spawn's re-sign, the apex DNSKEY RRset carries exactly
// two RRSIGs, one per algorithm, and no other RRset gained a second.
func TestKT16SignerDoubleSignsDNSKEYOnly(t *testing.T) {
	zd, kdb, a := ktBoundFixture(t)
	if _, err := changeZonePolicy(context.Background(), zd, kdb, "newalg"); err != nil {
		t.Fatalf("change-policy: %v", err)
	}
	ktTick(t, zd, kdb, time.Now())
	st, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	if st == nil {
		t.Fatal("no roll")
	}
	// The spawn's triggerResign is a no-op here (no resigner); do its job.
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone after spawn: %v", err)
	}
	tags := zd.mustRRSIGKeytags(t, ktAlgZone, dns.TypeDNSKEY)
	if len(tags) != 2 || !ktHasKeytag(tags, a) || !ktHasKeytag(tags, st.NewHeadKeyID) {
		t.Fatalf("apex DNSKEY RRSIG keytags = %v, want exactly {%d, %d}", tags, a, st.NewHeadKeyID)
	}
	for _, name := range []string{ktAlgZone, "www." + ktAlgZone} {
		for _, rrt := range []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeA} {
			owner, _ := zd.GetOwner(name)
			if owner == nil {
				continue
			}
			rrset, ok := owner.RRtypes.Get(rrt)
			if !ok || len(rrset.RRs) == 0 {
				continue
			}
			if n := len(rrset.RRSIGs); n != 1 {
				t.Fatalf("%s %s has %d RRSIGs, want 1 (only the DNSKEY RRset double-signs)", name, dns.TypeToString[rrt], n)
			}
		}
	}
}
