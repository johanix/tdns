package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// withLivePolicies publishes a runtime-config snapshot whose DnssecPolicies map
// is exactly `policies`, so ConfLive() (which the apply core reads, lock-free)
// returns them. Restores the previous snapshot on cleanup. This is distinct
// from withPolicies (zsk_alg_rollover_test.go), which sets the parse-scratch
// Conf.Internal.DnssecPolicies but does NOT publish.
func withLivePolicies(t *testing.T, policies map[string]DnssecPolicy) {
	t.Helper()
	prev := liveConfig.Load()
	liveConfig.Store(&RuntimeConfig{DnssecPolicies: policies})
	t.Cleanup(func() { liveConfig.Store(prev) })
}

func kskzsk(ksk, zsk uint8) DnssecPolicy {
	return DnssecPolicy{Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: ksk, ZSKAlgorithm: zsk}
}

// TestClassifyPolicyChange covers the four change classes. The design lock ①
// case is the CompatibleName row: a DIFFERENT applied name with the SAME
// algorithms must classify as a change, which is only detectable because the
// classifier compares applied-name vs intent-name, not a binding.
func TestClassifyPolicyChange(t *testing.T) {
	polA := kskzsk(dns.ED25519, dns.ED25519)
	polB := kskzsk(dns.ED25519, dns.ED25519) // same algs, different name
	polBenign := kskzsk(dns.ED25519, dns.ED25519)
	polBenign.SigValidity.Default = 1234 // same name+algs, internals differ
	polAlg := kskzsk(dns.RSASHA256, dns.ED25519)

	cases := []struct {
		name        string
		appliedPol  DnssecPolicy
		appliedName string
		intentPol   DnssecPolicy
		intentName  string
		want        PolicyChangeClass
	}{
		{"identical", polA, "a", polA, "a", PolicyChangeNone},
		{"benign-internals", polA, "a", polBenign, "a", PolicyChangeBenignInternals},
		{"compatible-rename", polA, "a", polB, "b", PolicyChangeCompatibleName},
		{"incompatible-ksk-alg", polA, "a", polAlg, "b", PolicyChangeIncompatibleAlg},
		// An alg change even under the SAME name is still incompatible.
		{"incompatible-same-name", polA, "a", polAlg, "a", PolicyChangeIncompatibleAlg},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ap, ip := c.appliedPol, c.intentPol
			got := classifyPolicyChange(&ap, c.appliedName, &ip, c.intentName)
			if got != c.want {
				t.Fatalf("classify: got %s, want %s", got, c.want)
			}
		})
	}
}

// TestResolvePolicyPairRestartDetectsChange is the ① regression: on restart the
// zone's in-memory binding is freshly loaded from config and EQUALS intent, so
// classifying the binding against intent would return None and silently miss the
// YAML edit. resolvePolicyPair + classifyPolicyChange compare the DB last-applied
// against intent instead, and correctly detect the compatible rename.
func TestResolvePolicyPairRestartDetectsChange(t *testing.T) {
	kdb := newTestKeyDB(t)
	// Two same-algorithm policies with different names.
	withLivePolicies(t, map[string]DnssecPolicy{
		"polA": kskzsk(dns.ED25519, dns.ED25519),
		"polB": kskzsk(dns.ED25519, dns.ED25519),
	})
	// DB records the zone was last signed under polA; the YAML now says polB
	// (intent), with no CLI override.
	if err := SetZoneAppliedPolicy(kdb, algZone, "polA", "config"); err != nil {
		t.Fatalf("SetZoneAppliedPolicy: %v", err)
	}

	intentName, intentPol, appliedName, appliedPol, appliedOK, err := resolvePolicyPair(kdb, algZone, "polB")
	if err != nil {
		t.Fatalf("resolvePolicyPair: %v", err)
	}
	if intentName != "polB" || appliedName != "polA" || !appliedOK {
		t.Fatalf("resolve: got intent=%q applied=%q ok=%v, want intent=polB applied=polA ok=true", intentName, appliedName, appliedOK)
	}
	if intentPol == nil || appliedPol == nil {
		t.Fatalf("resolve: both structs must be non-nil (intent=%v applied=%v)", intentPol, appliedPol)
	}

	// Correct: applied (polA) vs intent (polB) → a change is detected.
	if got := classifyPolicyChange(appliedPol, appliedName, intentPol, intentName); got != PolicyChangeCompatibleName {
		t.Fatalf("applied-vs-intent classify: got %s, want compatible-name", got)
	}

	// The trap ① avoids: on restart the binding == intent (polB). Classifying the
	// binding against intent would hide the change.
	binding := intentPol // fresh restart binding equals intent
	if got := classifyPolicyChange(binding, intentName, intentPol, intentName); got != PolicyChangeNone {
		t.Fatalf("sanity: binding-vs-intent should read None (the ① trap), got %s", got)
	}
}

// TestBackfillAppliedIfEligible covers blocking ②: a config-only signed zone
// with no applied record but active keys already matching intent is backfilled
// WITHOUT a re-sign; a zone whose active-key algorithms differ from intent is
// NOT eligible (the caller then drives a real apply).
func TestBackfillAppliedIfEligible(t *testing.T) {
	t.Run("eligible: keys match intent -> backfill, no sign", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := algTestZone(dns.ED25519, dns.ED25519)
		// Active KSK + ZSK of ED25519 — already signed under the intent alg.
		if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
			t.Fatalf("KSK: %v", err)
		}
		genZSK(t, kdb, DnskeyStateActive, dns.ED25519)

		intent := kskzsk(dns.ED25519, dns.ED25519)
		backfilled, err := backfillAppliedIfEligible(kdb, zd, "intentpol", &intent)
		if err != nil {
			t.Fatalf("backfill: %v", err)
		}
		if !backfilled {
			t.Fatal("zone already signed under intent must be eligible for backfill")
		}
		// Applied is recorded as config-source; nothing signed (a data-less zone
		// would have errored in SignZone — proving backfill did not re-sign).
		name, source, ok, err := GetZoneAppliedPolicy(kdb, algZone)
		if err != nil || !ok || name != "intentpol" || source != "config" {
			t.Fatalf("applied after backfill: got (%q,%q,%v,err=%v), want (intentpol,config,true,nil)", name, source, ok, err)
		}
	})

	t.Run("ineligible: keys differ from intent -> no backfill", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := algTestZone(dns.ED25519, dns.ED25519)
		// Active keys are ED25519, but intent wants an RSASHA256 KSK.
		if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
			t.Fatalf("KSK: %v", err)
		}
		genZSK(t, kdb, DnskeyStateActive, dns.ED25519)

		intent := kskzsk(dns.RSASHA256, dns.ED25519)
		backfilled, err := backfillAppliedIfEligible(kdb, zd, "intentpol", &intent)
		if err != nil {
			t.Fatalf("backfill: %v", err)
		}
		if backfilled {
			t.Fatal("keys whose algorithm differs from intent must NOT be backfilled")
		}
		if _, _, ok, _ := GetZoneAppliedPolicy(kdb, algZone); ok {
			t.Fatal("ineligible zone must not get an applied record")
		}
	})

	t.Run("unsigned zone -> no backfill", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := algTestZone(dns.ED25519, dns.ED25519)
		zd.Options = map[ZoneOption]bool{} // not signed
		intent := kskzsk(dns.ED25519, dns.ED25519)
		if backfilled, err := backfillAppliedIfEligible(kdb, zd, "intentpol", &intent); err != nil || backfilled {
			t.Fatalf("unsigned zone must not backfill (backfilled=%v err=%v)", backfilled, err)
		}
	})
}

// TestApplyZonePolicyTransactionalRevertOnSignFailure asserts the transactional
// contract: when SignZone fails (here via an incompatible KSK algorithm change,
// which reconcileActiveKeyAlgorithms refuses), the in-memory binding is reverted
// to the prior policy and NOTHING is persisted (no applied record, no override).
func TestApplyZonePolicyTransactionalRevertOnSignFailure(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.DnssecPolicyName = "polA"
	// Active KSK is ED25519 — a switch to a policy wanting an RSASHA256 KSK will
	// be refused inside SignZone (KSK alg rollover not implemented).
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)

	polB := kskzsk(dns.RSASHA256, dns.ED25519) // KSK alg change → SignZone refuses
	withLivePolicies(t, map[string]DnssecPolicy{"polB": polB})

	if _, err := applyZonePolicyTransactional(zd, kdb, &polB, "polB", PolicyApplySourceCommand); err == nil {
		t.Fatal("expected SignZone failure on incompatible KSK algorithm change")
	}

	// Binding reverted to polA.
	zd.mu.Lock()
	gotName := zd.DnssecPolicyName
	gotKSK := zd.DnssecPolicy.KSKAlgorithm
	zd.mu.Unlock()
	if gotName != "polA" || gotKSK != dns.ED25519 {
		t.Fatalf("binding not reverted: got (%q, ksk=%s), want (polA, ED25519)", gotName, dns.AlgorithmToString[gotKSK])
	}
	// Nothing persisted.
	if _, _, ok, _ := GetZoneAppliedPolicy(kdb, algZone); ok {
		t.Fatal("failed apply must not write an applied record")
	}
	if _, ok, _ := GetZonePolicyOverride(kdb, algZone); ok {
		t.Fatal("failed apply must not write a CLI override")
	}
}
