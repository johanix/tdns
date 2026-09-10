package tdns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// KT-5 (status), KT-when (when + asap refusal), KT-abort (D-12), and the
// E13 / stall warnings: the operator surface of the KSK algorithm rollover.

// ktRollToConfirm drives a fresh zone through spawn, push and confirm and
// returns the fixture plus the clock at the confirm. Mirrors KT-6's steps.
func ktRollToConfirm(t *testing.T) (zd *ZoneData, kdb *KeyDB, parent *ktFakeParent, a, b uint16, tick func(string, time.Time), tConfirm time.Time) {
	t.Helper()
	parent = ktInstallFakeParent(t)
	kdb = newTestKeyDB(t)
	pol := ktSequencePolicy(RolloverMethodMultiDS)
	zd = ktEngineZone(t, kdb, ktAlgZone, ktAlgZoneText, pol)
	a = ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tick = func(step string, now time.Time) {
		t.Helper()
		deps := ktDeps(zd, kdb, now)
		deps.Imr = &Imr{}
		if err := RolloverAutomatedTick(ctx, deps); err != nil {
			t.Fatalf("%s: tick: %v", step, err)
		}
	}
	pol.KSKAlgorithm = dns.RSASHA256
	t0 := time.Now()
	tick("spawn", t0.Add(time.Second))
	st, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	if st == nil {
		t.Fatal("no spawn")
	}
	b = st.NewHeadKeyID
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("re-sign after spawn: %v", err)
	}
	tArm := t0.Add(time.Minute + time.Duration(pol.TTLS.DNSKEY)*time.Second + 30*time.Second)
	tick("arm", tArm)
	tPush := tArm.Add(time.Second)
	tick("push", tPush)
	pushes := parent.pushes()
	if len(pushes) != 1 {
		t.Fatalf("%d pushes, want 1", len(pushes))
	}
	parent.serve(ktDSSubset(pushes[0], 3600, a, b))
	tConfirm = tPush.Add(pol.Rollover.ConfirmInitialWait + time.Second)
	tick("confirm", tConfirm)
	if p, _ := ktPhase(t, kdb, ktAlgZone); p != rolloverPhasePendingChildWithdraw {
		t.Fatalf("after confirm: phase %q", p)
	}
	return
}

func ktStatus(t *testing.T, kdb *KeyDB, zd *ZoneData, now time.Time) *RolloverStatus {
	t.Helper()
	s, err := ComputeRolloverStatus(kdb, ktAlgZone, zd.DnssecPolicy, 0, time.Minute, now)
	if err != nil {
		t.Fatalf("ComputeRolloverStatus: %v", err)
	}
	return s
}

func ktFindKSK(s *RolloverStatus, kid uint16) *RolloverKeyEntry {
	for i := range s.KSKs {
		if s.KSKs[i].KeyID == kid {
			return &s.KSKs[i]
		}
	}
	return nil
}

// KT-5: status shows the KSK transition and both keys with their
// algorithms throughout the roll, with phase-appropriate hints.
func TestKT5StatusShowsKskAlgRoll(t *testing.T) {
	zd, kdb, _, a, b, _, tConfirm := ktRollToConfirm(t)

	s := ktStatus(t, kdb, zd, tConfirm.Add(time.Minute))
	if len(s.AlgTransitions) != 1 || s.AlgTransitions[0].Role != "KSK" ||
		s.AlgTransitions[0].FromAlg != "ED25519" || s.AlgTransitions[0].ToAlg != "RSASHA256" {
		t.Fatalf("AlgTransitions = %+v", s.AlgTransitions)
	}
	if s.AlgTransition != nil {
		t.Fatalf("the deprecated singular is the ZSK transition only; got %+v", s.AlgTransition)
	}
	if s.AlgRollFromAlg != "ED25519" || s.AlgRollToAlg != "RSASHA256" || s.AlgRollHeadKeyID != b || s.AlgRollOldHeadKeyID != a ||
		s.AlgRollStartedAt == "" || s.AlgRollOldHeadRetireAt == "" || s.AlgRollProjectedRemoveAt == "" {
		t.Fatalf("AlgRoll* fields incomplete: from=%q to=%q head=%d old=%d started=%q retire=%q projected=%q",
			s.AlgRollFromAlg, s.AlgRollToAlg, s.AlgRollHeadKeyID, s.AlgRollOldHeadKeyID, s.AlgRollStartedAt, s.AlgRollOldHeadRetireAt, s.AlgRollProjectedRemoveAt)
	}
	if s.Headline != "ACTIVE" || !strings.Contains(s.Hint, "holding the old-algorithm KSK") {
		t.Fatalf("headline=%q hint=%q", s.Headline, s.Hint)
	}
	ea, eb := ktFindKSK(s, a), ktFindKSK(s, b)
	if ea == nil || eb == nil {
		t.Fatalf("both KSKs must be listed: %+v", s.KSKs)
	}
	if ea.State != DnskeyStateActive || ea.Algorithm != "ED25519" || eb.State != DnskeyStateActive || eb.Algorithm != "RSASHA256" {
		t.Fatalf("key rows: A=%+v B=%+v", ea, eb)
	}
	if ea.NextTransition != "active → removed" || ea.NextTransitionAt == "" {
		t.Fatalf("old head's next transition = %q at %q (note %q)", ea.NextTransition, ea.NextTransitionAt, ea.NextTransitionNote)
	}
	if ea.NextTransitionAt != s.AlgRollProjectedRemoveAt {
		t.Fatalf("old head row (%s) and header projection (%s) disagree", ea.NextTransitionAt, s.AlgRollProjectedRemoveAt)
	}
	if eb.NextTransition != "active → retired" {
		t.Fatalf("new head's next transition = %q", eb.NextTransition)
	}
	for _, w := range s.Warnings {
		if strings.HasPrefix(w, "E13") {
			t.Fatalf("E13 must not fire while the parent DS TTL is known: %q", w)
		}
	}
}

// E13: with the parent DS TTL forgotten (a restart), status warns and the
// old head's removal reads as deferred; the drain itself holds.
func TestE13WarnsWhenParentDSTTLUnknown(t *testing.T) {
	zd, kdb, _, a, _, tick, tConfirm := ktRollToConfirm(t)
	zd.ParentDSTTLObserved = 0 // what a restart does (in-memory field)

	s := ktStatus(t, kdb, zd, tConfirm.Add(time.Minute))
	found := false
	for _, w := range s.Warnings {
		if strings.HasPrefix(w, "E13") && strings.Contains(w, "not observed since startup") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an E13 warning, got %v", s.Warnings)
	}
	if s.AlgRollProjectedRemoveAt != "" {
		t.Fatalf("no projection without a DS TTL, got %q", s.AlgRollProjectedRemoveAt)
	}
	if ea := ktFindKSK(s, a); ea == nil || ea.NextTransitionAt != "" || !strings.Contains(ea.NextTransitionNote, "DS TTL") {
		t.Fatalf("old head row must read as deferred: %+v", ea)
	}
	// The engine defers too, far past the margin.
	tick("drain-held", tConfirm.Add(10*24*time.Hour))
	if st := ktKeyState(t, kdb, ktAlgZone, a); st != DnskeyStateActive {
		t.Fatalf("A was removed without a known parent DS TTL: %s", st)
	}
}

// Q3: a roll that has waited on the parent for more than twice
// confirm-timeout is called out.
func TestStallWarningAfterTwiceConfirmTimeout(t *testing.T) {
	ktInstallFakeParent(t)
	kdb := newTestKeyDB(t)
	pol := ktSequencePolicy(RolloverMethodMultiDS)
	zd := ktEngineZone(t, kdb, ktAlgZone, ktAlgZoneText, pol)
	ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	pol.KSKAlgorithm = dns.RSASHA256
	t0 := time.Now()
	ktTick(t, zd, kdb, t0.Add(time.Second))
	// Park the zone in observe with an old start.
	tx, _ := kdb.Begin("test")
	_, _ = tx.Exec(`UPDATE RolloverZoneState SET alg_roll_started_at = ? WHERE zone = ?`,
		t0.Add(-3*pol.Rollover.ConfirmTimeout).UTC().Format(time.RFC3339), ktAlgZone)
	_ = setRolloverPhaseTx(tx, ktAlgZone, rolloverPhasePendingParentObserve)
	_ = tx.Commit()

	s := ktStatus(t, kdb, zd, t0)
	found := false
	for _, w := range s.Warnings {
		if strings.Contains(w, "more than 2 x confirm-timeout") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the stall warning, got %v", s.Warnings)
	}
}

// KT-when: the KSK schedule during an algorithm roll is the projected
// completion, not a misleading next lifetime roll.
func TestKTWhenReportsAlgRolloverInProgress(t *testing.T) {
	zd, kdb, _, a, b, _, tConfirm := ktRollToConfirm(t)
	w, err := ComputeRolloverWhen(kdb, ktAlgZone, zd.DnssecPolicy, tConfirm.Add(time.Minute))
	if err != nil {
		t.Fatalf("ComputeRolloverWhen: %v", err)
	}
	if w.Status != "alg-rollover-in-progress" || !w.InProgress || w.FromKeyID != a || w.ToKeyID != b {
		t.Fatalf("when = %+v", w)
	}
	if w.NextScheduled == "" || !strings.Contains(w.Note, "projected completion") {
		t.Fatalf("when: next=%q note=%q", w.NextScheduled, w.Note)
	}
	s := ktStatus(t, kdb, zd, tConfirm.Add(time.Minute))
	if w.NextScheduled != s.AlgRollProjectedRemoveAt {
		t.Fatalf("when (%s) and status (%s) project different completions", w.NextScheduled, s.AlgRollProjectedRemoveAt)
	}
}

// KT-abort (D-12): before confirmation the roll can be aborted -- B goes,
// its signature goes, the zone is idle; after confirmation it is refused.
func TestKTAbortKskAlgRoll(t *testing.T) {
	t.Run("before-confirm", func(t *testing.T) {
		parent := ktInstallFakeParent(t)
		kdb := newTestKeyDB(t)
		pol := ktSequencePolicy(RolloverMethodMultiDS)
		zd := ktEngineZone(t, kdb, ktAlgZone, ktAlgZoneText, pol)
		a := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
		ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
		if _, err := zd.SignZone(kdb, true); err != nil {
			t.Fatalf("SignZone: %v", err)
		}
		pol.KSKAlgorithm = dns.RSASHA256
		t0 := time.Now()
		ktTick(t, zd, kdb, t0.Add(time.Second))
		st, _ := LoadKskAlgRollState(kdb, ktAlgZone)
		b := st.NewHeadKeyID
		if _, err := zd.SignZone(kdb, true); err != nil {
			t.Fatalf("re-sign: %v", err)
		}
		if tags := zd.mustRRSIGKeytags(t, ktAlgZone, dns.TypeDNSKEY); !ktHasKeytag(tags, b) {
			t.Fatalf("fixture: B has not signed: %v", tags)
		}

		detail, err := AbortKskAlgRollover(&Conf, kdb, ktAlgZone)
		if err != nil {
			t.Fatalf("abort before confirm: %v", err)
		}
		if !strings.Contains(detail, "aborted") {
			t.Fatalf("detail = %q", detail)
		}
		if s := ktKeyState(t, kdb, ktAlgZone, b); s != DnskeyStateRemoved {
			t.Fatalf("B is %s, want removed", s)
		}
		if s := ktKeyState(t, kdb, ktAlgZone, a); s != DnskeyStateActive {
			t.Fatalf("A is %s, want active", s)
		}
		if tags := zd.mustRRSIGKeytags(t, ktAlgZone, dns.TypeDNSKEY); ktHasKeytag(tags, b) || !ktHasKeytag(tags, a) {
			t.Fatalf("after abort the DNSKEY RRSIG keytags are %v, want only %d", tags, a)
		}
		if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st != nil {
			t.Fatalf("roll state not cleared: %+v", st)
		}
		if p, ip := ktPhase(t, kdb, ktAlgZone); p != rolloverPhaseIdle || ip {
			t.Fatalf("after abort: phase=%q in_progress=%v", p, ip)
		}
		// Bound policy still names RSASHA256: the engine would start again.
		// Bind back, and the next tick leaves the zone alone (no pushes either).
		pol.KSKAlgorithm = dns.ED25519
		ktTick(t, zd, kdb, t0.Add(2*time.Second))
		if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st != nil {
			t.Fatalf("re-spawned after policy was bound back: %+v", st)
		}
		if n := len(parent.pushes()); n != 0 {
			t.Fatalf("%d pushes after an abort with nothing submitted", n)
		}
	})

	t.Run("after-confirm-refused", func(t *testing.T) {
		zd, kdb, _, a, b, _, _ := ktRollToConfirm(t)
		_, err := AbortKskAlgRollover(&Conf, kdb, ktAlgZone)
		if err == nil || !strings.Contains(err.Error(), "reverse algorithm rollover") {
			t.Fatalf("abort after confirm must be refused with the finish-then-reverse guidance, got %v", err)
		}
		for _, kid := range []uint16{a, b} {
			if s := ktKeyState(t, kdb, ktAlgZone, kid); s != DnskeyStateActive {
				t.Fatalf("refusal must not touch key %d: %s", kid, s)
			}
		}
		if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st == nil {
			t.Fatal("refusal must not clear the roll")
		}
		_ = zd
	})

	t.Run("nothing-to-abort", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		if _, err := AbortKskAlgRollover(&Conf, kdb, ktAlgZone); err == nil || !strings.Contains(err.Error(), "no KSK algorithm rollover") {
			t.Fatalf("got %v", err)
		}
	})
}
