package tdns

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// docs/2026-10-06-first-ds-publication-does-not-block.md: the engine's first
// DS publication to a parent that holds no DS does not block a KSK algorithm
// change, the roll that takes over from it does not wait for the parent, and
// a roll against a parent that does hold DS is unchanged.

// ndRig: a zone signed under "base" -- one ED25519 KSK, the multi-DS engine,
// lifetime forever -- with "newalg" (an RSASHA256 KSK, same engine) published
// beside it, ticked with an injected clock against a fake parent that starts
// out serving no DS.
type ndRig struct {
	t      *testing.T
	zd     *ZoneData
	kdb    *KeyDB
	a      uint16
	parent *ktFakeParent
	ctx    context.Context
}

func newNoDSRig(t *testing.T, numDS int) *ndRig {
	t.Helper()
	withCompleteness(t, CompletenessRelaxed)
	parent := ktInstallFakeParent(t)
	kdb := newTestKeyDB(t)
	base := ktSequencePolicy(RolloverMethodMultiDS)
	base.Name = "base"
	base.Rollover.NumDS = numDS
	base.KSK.Lifetime = foreverLifetimeSecs
	// A clamping margin well below the TTLs, so the drain of an insecure
	// roll is visibly the propagation-plus-TTL one.
	base.Clamping.Margin = time.Minute
	target := *base
	target.Name = "newalg"
	target.KSKAlgorithm = dns.RSASHA256
	ktWithLivePolicies(t, map[string]DnssecPolicy{"base": *base, "newalg": target})

	zd := ktEngineZone(t, kdb, ktAlgZone, ktAlgZoneText, base)
	a := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &ndRig{t: t, zd: zd, kdb: kdb, a: a, parent: parent, ctx: ctx}
}

func (r *ndRig) tick(step string, now time.Time) {
	r.t.Helper()
	deps := ktDeps(r.zd, r.kdb, now)
	deps.Imr = &Imr{} // non-nil so the push branch runs; the push itself is faked
	if err := RolloverAutomatedTick(r.ctx, deps); err != nil {
		r.t.Fatalf("%s: tick: %v", step, err)
	}
}

func (r *ndRig) row(step string) *RolloverZoneRow {
	r.t.Helper()
	row, err := LoadRolloverZoneRow(r.kdb, ktAlgZone)
	if err != nil || row == nil {
		r.t.Fatalf("%s: LoadRolloverZoneRow: row=%v err=%v", step, row, err)
	}
	return row
}

func (r *ndRig) roll(step string) *KskAlgRollState {
	r.t.Helper()
	st, err := LoadKskAlgRollState(r.kdb, ktAlgZone)
	if err != nil {
		r.t.Fatalf("%s: LoadKskAlgRollState: %v", step, err)
	}
	return st
}

func (r *ndRig) expectPhase(step, phase string, inProgress bool) {
	r.t.Helper()
	row := r.row(step)
	if row.RolloverPhase != phase || row.RolloverInProgress != inProgress {
		r.t.Fatalf("%s: phase=%q in_progress=%v, want %q/%v", step, row.RolloverPhase, row.RolloverInProgress, phase, inProgress)
	}
}

func (r *ndRig) expectKeyState(step string, keyid uint16, want string) {
	r.t.Helper()
	if got := ktKeyState(r.t, r.kdb, ktAlgZone, keyid); got != want {
		r.t.Fatalf("%s: key %d is %s, want %s", step, keyid, got, want)
	}
}

func (r *ndRig) changePolicy(name string) (string, error) {
	return changeZonePolicy(context.Background(), r.zd, r.kdb, name)
}

// dsOfActiveKSK is the DS of the zone's active KSK as the parent would serve
// it, with ttl.
func (r *ndRig) dsOfActiveKSK(ttl uint32) []dns.RR {
	r.t.Helper()
	set, _, _, _, err := ComputeTargetDSSetForZone(r.kdb, ktAlgZone, uint8(dns.SHA256), r.zd.DnssecPolicy)
	if err != nil {
		r.t.Fatalf("target DS set: %v", err)
	}
	ds := ktDSSubset(set, ttl, r.a)
	if len(ds) != 1 {
		r.t.Fatalf("no DS for the active KSK %d in the target set %v", r.a, ktDSKeytags(set))
	}
	return ds
}

// firstDSPoll drives the engine from idle through its first DS publication
// up to and including one observe poll, answered with whatever the parent
// serves. The clock starts in the past so the poll lands just before now:
// rollover_phase_at is stamped from the wall clock, and the roll that
// follows is measured from it.
func (r *ndRig) firstDSPoll() time.Time {
	r.t.Helper()
	wait := r.zd.DnssecPolicy.Rollover.ConfirmInitialWait
	t0 := time.Now().Add(-(wait + time.Minute))
	r.tick("arm", t0)
	r.expectPhase("arm", rolloverPhasePendingParentPush, false)
	r.tick("push", t0.Add(time.Second))
	r.expectPhase("push", rolloverPhasePendingParentObserve, false)
	tPoll := t0.Add(wait + 2*time.Second)
	r.tick("poll", tPoll)
	return tPoll
}

// spawnAndPush binds newalg, spawns the roll, waits out the child-side
// publish wait and pushes. Returns the roll, the push time and the DS set
// pushed.
func (r *ndRig) spawnAndPush() (*KskAlgRollState, time.Time, []dns.RR) {
	r.t.Helper()
	if _, err := r.changePolicy("newalg"); err != nil {
		r.t.Fatalf("change-policy: %v", err)
	}
	r.tick("spawn", time.Now())
	r.expectPhase("spawn", rolloverPhasePendingChildPublish, true)
	st := r.roll("spawn")
	if st == nil || st.OldHeadKeyID != r.a {
		r.t.Fatalf("spawn: roll state %+v", st)
	}
	phaseAt, ok := parseOptionalTime(r.row("spawn").RolloverPhaseAt)
	if !ok {
		r.t.Fatal("spawn: no rollover_phase_at")
	}
	pol := r.zd.DnssecPolicy
	wait := time.Minute + time.Duration(pol.TTLS.DNSKEY)*time.Second // ktDeps' propagation delay + DNSKEY TTL
	r.tick("wait-early", phaseAt.Add(wait-30*time.Second))
	r.expectPhase("wait-early", rolloverPhasePendingChildPublish, true)
	before := len(r.parent.pushes())
	tArm := phaseAt.Add(wait + 30*time.Second)
	r.tick("arm", tArm)
	r.expectPhase("arm", rolloverPhasePendingParentPush, true)
	tPush := tArm.Add(time.Second)
	r.tick("push", tPush)
	r.expectPhase("push", rolloverPhasePendingParentObserve, true)
	pushes := r.parent.pushes()
	if len(pushes) != before+1 {
		r.t.Fatalf("push: %d pushes, want %d", len(pushes), before+1)
	}
	pushed := pushes[len(pushes)-1]
	if tags := ktDSKeytags(pushed); len(tags) != 1 || tags[0] != st.NewHeadKeyID {
		r.t.Fatalf("push: DS set keytags %v, want exactly {%d}", tags, st.NewHeadKeyID)
	}
	return st, tPush, pushed
}

// The predicate and the insecure decision, row by row.
func TestFirstDSPublicationPredicate(t *testing.T) {
	observed := func(keyids string) RolloverZoneRow {
		return RolloverZoneRow{
			LastDsObservedKeyids: sql.NullString{String: keyids, Valid: true},
			LastDsObservedAt:     sql.NullString{String: "2026-10-06T10:00:00Z", Valid: true},
		}
	}
	confirmed := sql.NullInt64{Int64: 3, Valid: true}
	cases := []struct {
		name     string
		row      RolloverZoneRow
		phase    string
		mod      func(*RolloverZoneRow)
		firstDS  bool
		insecure bool
		blocks   bool
	}{
		{"observe, no DS", observed(""), rolloverPhasePendingParentObserve, nil, true, true, false},
		{"push, no DS", observed(""), rolloverPhasePendingParentPush, nil, true, true, false},
		{"softfail, no DS", observed(""), rolloverPhasePushSoftfail, nil, true, true, false},
		// A parent that once held DS: validators may still have it cached.
		{"softfail, no DS, a DS once confirmed", observed(""), rolloverPhasePushSoftfail,
			func(r *RolloverZoneRow) { r.LastConfirmedLow, r.LastConfirmedHigh = confirmed, confirmed }, false, false, true},
		{"observe, no DS, a DS once confirmed", observed(""), rolloverPhasePendingParentObserve,
			func(r *RolloverZoneRow) { r.LastConfirmedLow, r.LastConfirmedHigh = confirmed, confirmed }, false, false, true},
		{"observe, parent has DS", observed("12345"), rolloverPhasePendingParentObserve, nil, false, false, true},
		{"push, never polled", RolloverZoneRow{}, rolloverPhasePendingParentPush, nil, false, false, true},
		{"observe, no DS, own rollover", observed(""), rolloverPhasePendingParentObserve,
			func(r *RolloverZoneRow) { r.RolloverInProgress = true }, false, false, true},
		{"observe, no DS, algorithm roll", observed(""), rolloverPhasePendingParentObserve,
			func(r *RolloverZoneRow) { r.AlgRollFromAlg = sql.NullInt64{Int64: 15, Valid: true} }, false, false, true},
		{"child-publish, no DS", observed(""), rolloverPhasePendingChildPublish, nil, false, false, true},
		{"withdraw, no DS", observed(""), rolloverPhasePendingChildWithdraw, nil, false, false, true},
		{"idle, no DS, never confirmed", observed(""), rolloverPhaseIdle, nil, false, true, false},
		{"idle, no DS, a DS once confirmed", observed(""), rolloverPhaseIdle,
			func(r *RolloverZoneRow) { r.LastConfirmedLow, r.LastConfirmedHigh = confirmed, confirmed }, false, false, false},
		{"idle, parent has DS", observed("12345"), rolloverPhaseIdle, nil, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			row := c.row
			row.RolloverPhase = c.phase
			if c.mod != nil {
				c.mod(&row)
			}
			if got := firstDSPublicationWithoutParentDS(&row); got != c.firstDS {
				t.Errorf("firstDSPublicationWithoutParentDS = %v, want %v", got, c.firstDS)
			}
			if got := kskAlgRollStartsInsecure(&row); got != c.insecure {
				t.Errorf("kskAlgRollStartsInsecure = %v, want %v", got, c.insecure)
			}
			if got := kskRolloverPolicyChangeBlock("child.example.", &row) != ""; got != c.blocks {
				t.Errorf("blocks a policy change = %v, want %v", got, c.blocks)
			}
		})
	}
}

// The insecure flag round-trips, reads NULL as secure, is cleared one way,
// and goes with the rest of the roll record.
func TestKskAlgRollParentInsecureRoundTrip(t *testing.T) {
	kdb := newTestKeyDB(t)
	st := KskAlgRollState{FromAlg: dns.ED25519, ToAlg: dns.RSASHA256, StartedAt: time.Now(), NewHeadKeyID: 1001, OldHeadKeyID: 1000, ParentInsecure: true}
	ktSetAlgRoll(t, kdb, st)
	if got, err := LoadKskAlgRollState(kdb, ktStateZone); err != nil || got == nil || !got.ParentInsecure {
		t.Fatalf("after set: %+v, %v; want ParentInsecure", got, err)
	}
	if err := clearKskAlgRollParentInsecure(kdb, ktStateZone); err != nil {
		t.Fatalf("clearKskAlgRollParentInsecure: %v", err)
	}
	if got, err := LoadKskAlgRollState(kdb, ktStateZone); err != nil || got == nil || got.ParentInsecure {
		t.Fatalf("after clear: %+v, %v; want a secure roll", got, err)
	}
	// A roll recorded before the column existed.
	if _, err := kdb.DB.Exec(`UPDATE RolloverZoneState SET alg_roll_parent_insecure = NULL WHERE zone = ?`, ktStateZone); err != nil {
		t.Fatalf("NULL the flag: %v", err)
	}
	if got, err := LoadKskAlgRollState(kdb, ktStateZone); err != nil || got == nil || got.ParentInsecure {
		t.Fatalf("NULL flag: %+v, %v; want a secure roll", got, err)
	}
	ktSetAlgRoll(t, kdb, st)
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := clearKskAlgRollTx(tx, ktStateZone); err != nil {
		tx.Rollback()
		t.Fatalf("clearKskAlgRollTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if row, err := LoadRolloverZoneRow(kdb, ktStateZone); err != nil || row == nil || row.AlgRollParentInsecure.Valid {
		t.Fatalf("clearKskAlgRollTx left the flag set: %+v, %v", row, err)
	}
}

// change-policy: the first DS publication to a parent with no DS does not
// block a KSK algorithm change. A rollover of the zone's own, and a DS push
// to a parent that holds DS, still do, and the refusal says what the engine
// is waiting for.
func TestFirstDSPublicationDoesNotBlockChangePolicy(t *testing.T) {
	t.Run("parent has no DS: accepted", func(t *testing.T) {
		r := newNoDSRig(t, 1)
		r.firstDSPoll()
		if row := r.row("first DS"); row.RolloverPhase != rolloverPhasePendingParentObserve || !firstDSPublicationWithoutParentDS(row) {
			t.Fatalf("not in the first DS publication against a parent with no DS: %+v", row)
		}
		msg, err := r.changePolicy("newalg")
		if err != nil {
			t.Fatalf("change-policy refused during the first DS publication: %v", err)
		}
		if !strings.Contains(msg, "held no DS") {
			t.Fatalf("bind message does not say the roll will not wait for the parent: %q", msg)
		}
		if r.zd.DnssecPolicyName != "newalg" || r.zd.DnssecPolicy.KSKAlgorithm != dns.RSASHA256 {
			t.Fatalf("not bound: %q / %s", r.zd.DnssecPolicyName, dns.AlgorithmToString[r.zd.DnssecPolicy.KSKAlgorithm])
		}
	})

	t.Run("own rollover in progress: refused", func(t *testing.T) {
		r := newNoDSRig(t, 1)
		r.firstDSPoll()
		// The same phase and the same empty answer, but a rollover of the
		// zone's own is what is pushing.
		ktSetInProgress(t, r.kdb, ktAlgZone, true)
		_, err := r.changePolicy("newalg")
		if err == nil || !strings.Contains(err.Error(), "already in progress") ||
			!strings.Contains(err.Error(), "waiting for the parent to publish the DS set") {
			t.Fatalf("err = %v, want a refusal naming the rollover and what it waits for", err)
		}
		if r.zd.DnssecPolicyName != "base" {
			t.Fatalf("a refusal rebound the zone to %q", r.zd.DnssecPolicyName)
		}
	})

	t.Run("parent holds DS: refused", func(t *testing.T) {
		// Two DS: the parent has the active KSK's, and the engine pushes it
		// together with the next key's -- multi-DS pipeline maintenance.
		r := newNoDSRig(t, 2)
		r.parent.serve(r.dsOfActiveKSK(3600))
		r.firstDSPoll()
		if row := r.row("pipeline push"); row.RolloverPhase != rolloverPhasePendingParentObserve || firstDSPublicationWithoutParentDS(row) {
			t.Fatalf("want a blocking DS push in pending-parent-observe: %+v", row)
		}
		_, err := r.changePolicy("newalg")
		if err == nil || !strings.Contains(err.Error(), "DS push is in flight") ||
			!strings.Contains(err.Error(), "served DS for key tag(s)") {
			t.Fatalf("err = %v, want a refusal naming the DS the parent serves", err)
		}
	})

	t.Run("parent once held DS, holds none now: refused", func(t *testing.T) {
		// The parent confirms DS(A), then withdraws it; a DS-set change (a
		// second DS) sends the engine back to the parent, which now answers
		// with no DS. Validators may still hold DS(A) cached.
		r := newNoDSRig(t, 1)
		r.parent.serve(r.dsOfActiveKSK(3600))
		tPoll := r.firstDSPoll()
		r.expectPhase("confirmed", rolloverPhaseIdle, false)
		if !dsRangeEverConfirmed(r.row("confirmed")) {
			t.Fatal("test premise: no confirmed DS range")
		}
		r.parent.serve(nil)
		r.zd.DnssecPolicy.Rollover.NumDS = 2
		r.tick("arm", tPoll.Add(time.Second))
		r.expectPhase("arm", rolloverPhasePendingParentPush, false)
		tPush := tPoll.Add(2 * time.Second)
		r.tick("push", tPush)
		r.tick("poll", tPush.Add(r.zd.DnssecPolicy.Rollover.ConfirmInitialWait+time.Second))
		row := r.row("poll")
		if row.RolloverPhase != rolloverPhasePendingParentObserve || !parentShowedNoDS(row) {
			t.Fatalf("test premise: want pending-parent-observe after an empty answer: %+v", row)
		}
		if firstDSPublicationWithoutParentDS(row) || kskAlgRollStartsInsecure(row) {
			t.Fatalf("a once-secure zone reads as the first DS publication: %+v", row)
		}
		_, err := r.changePolicy("newalg")
		if err == nil || !strings.Contains(err.Error(), "held DS for the zone before") {
			t.Fatalf("err = %v, want a refusal saying the parent held DS before", err)
		}
		if r.zd.DnssecPolicyName != "base" {
			t.Fatalf("a refusal rebound the zone to %q", r.zd.DnssecPolicyName)
		}
		// Nor does the engine take over.
		if _, err := SpawnKskAlgRollover(&Conf, r.kdb, ktAlgZone, dns.ED25519, dns.RSASHA256); err == nil {
			t.Fatal("the spawn took over from a DS push to a parent that once held DS")
		}
		if st := r.roll("after refused spawn"); st != nil {
			t.Fatalf("a roll was recorded: %+v", st)
		}
	})

	t.Run("parent not polled yet: refused", func(t *testing.T) {
		r := newNoDSRig(t, 1)
		t0 := time.Now()
		r.tick("arm", t0)
		r.tick("push", t0.Add(time.Second))
		_, err := r.changePolicy("newalg")
		if err == nil || !strings.Contains(err.Error(), "has not polled the parent yet") {
			t.Fatalf("err = %v, want a refusal saying the parent has not been polled", err)
		}
	})
}

// The tick spawns the algorithm roll from the first DS publication, ends that
// publication's attempt group in the same transaction, and records the roll
// as insecure -- from pending-parent-observe and from parent-push-softfail.
func TestSpawnFromFirstDSPublicationRecordsAnInsecureRoll(t *testing.T) {
	for _, phase := range []string{rolloverPhasePendingParentObserve, rolloverPhasePushSoftfail} {
		t.Run(phase, func(t *testing.T) {
			r := newNoDSRig(t, 1)
			if phase == rolloverPhasePushSoftfail {
				// One failed attempt is enough for softfail, and the first
				// poll comes after the attempt has timed out.
				r.zd.DnssecPolicy.Rollover.MaxAttemptsBeforeBackoff = 1
				r.zd.DnssecPolicy.Rollover.ConfirmTimeout = 30 * time.Minute
				tPoll := r.firstDSPoll()
				r.expectPhase("timed out", rolloverPhasePushSoftfail, false)
				r.tick("softfail poll", tPoll.Add(time.Second))
			} else {
				r.firstDSPoll()
			}
			row := r.row("before")
			if row.RolloverPhase != phase || !firstDSPublicationWithoutParentDS(row) {
				t.Fatalf("before the bind: want the first DS publication in %s, got %+v", phase, row)
			}
			if phase == rolloverPhasePushSoftfail && (row.HardfailCount == 0 || !row.NextPushAt.Valid || !row.LastSoftfailAt.Valid) {
				t.Fatalf("test premise: softfail without its attempt-group state: %+v", row)
			}
			if !row.ObserveNextPollAt.Valid {
				t.Fatalf("test premise: no observe schedule: %+v", row)
			}

			if _, err := r.changePolicy("newalg"); err != nil {
				t.Fatalf("change-policy: %v", err)
			}
			r.tick("spawn", time.Now())
			r.expectPhase("spawn", rolloverPhasePendingChildPublish, true)
			st := r.roll("spawn")
			if st == nil || st.OldHeadKeyID != r.a || st.ToAlg != dns.RSASHA256 {
				t.Fatalf("spawn: roll state %+v", st)
			}
			if !st.ParentInsecure {
				t.Fatal("spawn: the roll was not recorded as insecure")
			}
			row = r.row("spawn")
			if row.HardfailCount != 0 || row.NextPushAt.Valid || row.LastSoftfailAt.Valid ||
				row.LastSoftfailCategory.Valid || row.LastSoftfailDetail.Valid ||
				row.ObserveStartedAt.Valid || row.ObserveNextPollAt.Valid || row.ObserveBackoffSecs.Valid {
				t.Fatalf("spawn: the first DS publication's attempt group was not ended: %+v", row)
			}
			if seps := ktActiveSEPs(t, r.kdb, ktAlgZone); len(seps) != 2 {
				t.Fatalf("spawn: %d active SEP keys, want 2", len(seps))
			}
		})
	}
}

// An insecure roll end to end: the child-side waits are the usual ones, the
// parent step confirms on an answer without DS, the old KSK is removed after
// propagation-delay plus the DNSKEY/RRSIG TTL drain and not before, and the
// first DS publication then re-arms for the new KSK without blocking a later
// change.
func TestInsecureAlgRollCompletesWithoutParentDS(t *testing.T) {
	r := newNoDSRig(t, 1)
	r.firstDSPoll()
	st, tPush, _ := r.spawnAndPush()
	b := st.NewHeadKeyID
	if !st.ParentInsecure {
		t.Fatal("the roll was not recorded as insecure")
	}
	pol := r.zd.DnssecPolicy
	// The spawn's triggerResign is a no-op here; do its job.
	ktAssertDNSKEYSigs(t, r.zd, r.kdb, "spawn", r.a, b)

	// The parent still serves no DS, and no parent DS TTL is known: the
	// secure drain could never be measured.
	if _, known := resolveDSTTL(r.zd, pol); known {
		t.Fatal("test premise: a parent DS TTL is known")
	}
	tConfirm := tPush.Add(pol.Rollover.ConfirmInitialWait + time.Second)
	r.tick("confirm", tConfirm)
	r.expectPhase("confirm", rolloverPhasePendingChildWithdraw, true)
	st = r.roll("confirm")
	if st == nil || st.OldHeadRetireAt == nil || !st.OldHeadRetireAt.Equal(tConfirm.UTC().Truncate(time.Second)) || !st.ParentInsecure {
		t.Fatalf("confirm: drain clock not started at the confirm: %+v", st)
	}
	if row := r.row("confirm"); row.LastConfirmedLow.Valid || row.LastConfirmedHigh.Valid {
		t.Fatalf("confirm: a DS range was recorded as confirmed by a parent with no DS: %+v", row)
	}
	r.expectKeyState("confirm", r.a, DnskeyStateActive)
	ktAssertDNSKEYSigs(t, r.zd, r.kdb, "drain", r.a, b)

	maxTTL, err := LoadZoneSigningMaxTTL(r.kdb, ktAlgZone)
	if err != nil {
		t.Fatalf("LoadZoneSigningMaxTTL: %v", err)
	}
	ttl := time.Duration(pol.TTLS.DNSKEY) * time.Second
	if m := time.Duration(maxTTL) * time.Second; m > ttl {
		ttl = m
	}
	margin := time.Minute + ttl // ktDeps' propagation delay + max(DNSKEY TTL, max signed TTL)
	r.tick("drain-early", tConfirm.Add(margin-30*time.Second))
	r.expectPhase("drain-early", rolloverPhasePendingChildWithdraw, true)
	r.expectKeyState("drain-early", r.a, DnskeyStateActive)
	// The drain itself asks the parent nothing.
	if got := r.row("drain-early").LastPollAt.String; got != tConfirm.UTC().Format(time.RFC3339) {
		t.Fatalf("drain-early: the parent was polled during the drain (last poll %s, confirm %s)", got, tConfirm.UTC().Format(time.RFC3339))
	}

	// The removal is due: the parent is asked once more, still shows no DS,
	// and the old KSK goes.
	tDone := tConfirm.Add(margin + 30*time.Second)
	r.tick("drain-done", tDone)
	if got := r.row("drain-done").LastPollAt.String; got != tDone.UTC().Format(time.RFC3339) {
		t.Fatalf("drain-done: no parent poll before the removal (last poll %s)", got)
	}
	r.expectKeyState("drain-done", r.a, DnskeyStateRemoved)
	if tags := r.zd.mustRRSIGKeytags(t, ktAlgZone, dns.TypeDNSKEY); ktHasKeytag(tags, r.a) {
		t.Fatalf("drain-done: RRSIG by removed KSK %d still on the DNSKEY RRset: %v", r.a, tags)
	}
	r.expectPhase("drain-done", rolloverPhaseIdle, false)
	if st := r.roll("drain-done"); st != nil {
		t.Fatalf("drain-done: roll state not cleared: %+v", st)
	}
	if seps := ktActiveSEPs(t, r.kdb, ktAlgZone); len(seps) != 1 || seps[0].KeyTag != b {
		t.Fatalf("drain-done: active SEP keys %+v, want only %d", seps, b)
	}
	// Idle until the next tick re-arms: a roll bound in this window starts
	// insecure too.
	if row := r.row("drain-done"); !kskAlgRollStartsInsecure(row) {
		t.Fatalf("drain-done: a roll spawned now would wait for a parent with no DS: %+v", row)
	}

	// The first DS publication re-arms, now for the new KSK.
	r.tick("re-arm", tDone.Add(time.Minute))
	r.expectPhase("re-arm", rolloverPhasePendingParentPush, false)
	tRePush := tDone.Add(2 * time.Minute)
	r.tick("re-push", tRePush)
	pushes := r.parent.pushes()
	if tags := ktDSKeytags(pushes[len(pushes)-1]); len(tags) != 1 || tags[0] != b {
		t.Fatalf("re-push: DS set keytags %v, want exactly {%d}", tags, b)
	}
	r.tick("re-poll", tRePush.Add(pol.Rollover.ConfirmInitialWait+time.Second))
	if row := r.row("re-poll"); !firstDSPublicationWithoutParentDS(row) {
		t.Fatalf("re-poll: not back in the first DS publication: %+v", row)
	}
	// ... and it does not block the next change either.
	if _, err := r.changePolicy("base"); err != nil {
		t.Fatalf("a change after the insecure roll was refused: %v", err)
	}
}

// A DS at the parent mid-roll -- here the old KSK's, taken late -- makes an
// insecure roll an ordinary one for good: an answer without DS no longer
// confirms, the roll waits for the parent to serve only the new KSK's DS,
// and the drain is the parent-DS-TTL one.
func TestInsecureAlgRollTurnsOrdinaryWhenTheParentShowsDS(t *testing.T) {
	r := newNoDSRig(t, 1)
	const parentDSTTL = 4 * 3600 // long enough to tell the two drains apart
	dsA := r.dsOfActiveKSK(parentDSTTL)
	r.firstDSPoll()
	st, tPush, pushed := r.spawnAndPush()
	b := st.NewHeadKeyID
	if !st.ParentInsecure {
		t.Fatal("the roll was not recorded as insecure")
	}
	pol := r.zd.DnssecPolicy
	pollMax := pol.Rollover.ConfirmPollMax

	r.parent.serve(dsA)
	tObs1 := tPush.Add(pol.Rollover.ConfirmInitialWait + time.Second)
	r.tick("parent shows DS(A)", tObs1)
	r.expectPhase("parent shows DS(A)", rolloverPhasePendingParentObserve, true)
	if st := r.roll("parent shows DS(A)"); st == nil || st.ParentInsecure || st.OldHeadRetireAt != nil {
		t.Fatalf("parent shows DS(A): want an ordinary roll still waiting for the parent: %+v", st)
	}

	r.parent.serve(nil)
	tObs2 := tObs1.Add(pollMax + time.Second)
	r.tick("parent shows nothing", tObs2)
	r.expectPhase("parent shows nothing", rolloverPhasePendingParentObserve, true)
	if st := r.roll("parent shows nothing"); st == nil || st.ParentInsecure || st.OldHeadRetireAt != nil {
		t.Fatalf("an answer without DS confirmed a roll that had seen the parent hold DS: %+v", st)
	}

	r.parent.serve(ktDSSubset(pushed, parentDSTTL, b))
	tConfirm := tObs2.Add(pollMax + time.Second)
	r.tick("parent shows DS(B)", tConfirm)
	r.expectPhase("parent shows DS(B)", rolloverPhasePendingChildWithdraw, true)
	if row := r.row("parent shows DS(B)"); !row.LastConfirmedLow.Valid {
		t.Fatalf("the ordinary confirm did not record the confirmed range: %+v", row)
	}

	maxTTL, err := LoadZoneSigningMaxTTL(r.kdb, ktAlgZone)
	if err != nil {
		t.Fatalf("LoadZoneSigningMaxTTL: %v", err)
	}
	ttl := time.Duration(pol.TTLS.DNSKEY) * time.Second
	if m := time.Duration(maxTTL) * time.Second; m > ttl {
		ttl = m
	}
	insecureMargin := time.Minute + ttl
	secureMargin := parentDSTTL*time.Second + pol.Rollover.DsPublishDelay
	if secureMargin <= insecureMargin+time.Minute {
		t.Fatalf("test premise: the drains are not apart (%s vs %s)", secureMargin, insecureMargin)
	}
	r.tick("past the insecure drain", tConfirm.Add(insecureMargin+30*time.Second))
	r.expectKeyState("past the insecure drain", r.a, DnskeyStateActive)
	r.tick("past the ordinary drain", tConfirm.Add(secureMargin+30*time.Second))
	r.expectKeyState("past the ordinary drain", r.a, DnskeyStateRemoved)
	r.expectPhase("past the ordinary drain", rolloverPhaseIdle, false)
}

// A roll started against a parent that holds DS is unchanged: an answer
// without DS mid-roll does not confirm it.
func TestSecureAlgRollIgnoresAnEmptyParentAnswer(t *testing.T) {
	r := newNoDSRig(t, 1)
	r.parent.serve(r.dsOfActiveKSK(3600))
	r.firstDSPoll() // confirms DS(A): idle, a confirmed range
	r.expectPhase("confirmed", rolloverPhaseIdle, false)
	st, tPush, pushed := r.spawnAndPush()
	b := st.NewHeadKeyID
	if st.ParentInsecure {
		t.Fatal("a roll against a parent holding DS was recorded as insecure")
	}
	pol := r.zd.DnssecPolicy

	r.parent.serve(nil) // a lagging parent nameserver, say
	tObs := tPush.Add(pol.Rollover.ConfirmInitialWait + time.Second)
	r.tick("empty answer", tObs)
	r.expectPhase("empty answer", rolloverPhasePendingParentObserve, true)
	if st := r.roll("empty answer"); st == nil || st.OldHeadRetireAt != nil || st.ParentInsecure {
		t.Fatalf("an empty answer confirmed a secure roll: %+v", st)
	}

	r.parent.serve(ktDSSubset(pushed, 3600, b))
	r.tick("DS(B)", tObs.Add(pol.Rollover.ConfirmPollMax+time.Second))
	r.expectPhase("DS(B)", rolloverPhasePendingChildWithdraw, true)
}

// A config reload binds a KSK algorithm change during the first DS
// publication to a parent with no DS; during a DS push to a parent that
// holds DS it still waits.
func TestConfigReloadAppliesDuringFirstDSPublication(t *testing.T) {
	syncFromConfig := func(t *testing.T, r *ndRig) string {
		t.Helper()
		if err := syncZoneDnssecPolicyFromConfig(context.Background(), r.zd, r.kdb, &Config{}, "newalg"); err != nil {
			t.Fatalf("sync: %v", err)
		}
		name, _, ok, err := GetZoneAppliedPolicy(r.kdb, ktAlgZone)
		if err != nil || !ok {
			t.Fatalf("applied policy: ok=%v err=%v", ok, err)
		}
		return name
	}

	t.Run("parent has no DS: applied", func(t *testing.T) {
		r := newNoDSRig(t, 1)
		if err := SetZoneAppliedPolicy(r.kdb, ktAlgZone, "base", string(PolicyApplySourceConfig)); err != nil {
			t.Fatalf("SetZoneAppliedPolicy: %v", err)
		}
		r.firstDSPoll()
		if applied := syncFromConfig(t, r); applied != "newalg" || r.zd.DnssecPolicyName != "newalg" {
			t.Fatalf("the reload was held back: applied %q, bound %q", applied, r.zd.DnssecPolicyName)
		}
		r.tick("spawn", time.Now())
		if st := r.roll("spawn"); st == nil || !st.ParentInsecure {
			t.Fatalf("the engine did not take over with an insecure roll: %+v", st)
		}
	})

	t.Run("parent holds DS: waits", func(t *testing.T) {
		r := newNoDSRig(t, 2)
		if err := SetZoneAppliedPolicy(r.kdb, ktAlgZone, "base", string(PolicyApplySourceConfig)); err != nil {
			t.Fatalf("SetZoneAppliedPolicy: %v", err)
		}
		r.parent.serve(r.dsOfActiveKSK(3600))
		r.firstDSPoll()
		if applied := syncFromConfig(t, r); applied != "base" || r.zd.DnssecPolicyName != "base" {
			t.Fatalf("applied during a DS push to a parent holding DS: applied %q, bound %q", applied, r.zd.DnssecPolicyName)
		}
	})
}

// The spawn releases the CDS the first DS publication left at the apex
// before it takes the old KSK out of the target set. After the spawn the
// release can no longer tell that CDS is the engine's, and leaves it.
func TestSpawnReleasesTheFirstDSPublicationCDSFirst(t *testing.T) {
	r := newNoDSRig(t, 1)
	r.kdb.UpdateQ = make(chan UpdateRequest, 8)
	r.kdb.DSEngineQ = make(chan DSEngineRequest, 8)
	serveQueue(t, r.kdb.UpdateQ, func(_ context.Context, ur UpdateRequest) {
		applyApexActions(r.zd, ur.Actions)
		ur.respond(true, nil)
	})
	startDSEngine(t, r.kdb)
	r.firstDSPoll()

	// What a NOTIFY push of the first DS publication leaves behind: the CDS
	// for the active KSK, and the engine's claim on it.
	claim := func(step string) {
		t.Helper()
		cds, low, high, ok, err := ComputeTargetCDSSetForZone(r.kdb, ktAlgZone)
		if err != nil || !ok || len(cds) == 0 {
			t.Fatalf("%s: target CDS: %v (%d records, range known %v)", step, err, len(cds), ok)
		}
		stageCDS(t, r.zd, cds)
		if err := setPublishedCdsRange(r.kdb, ktAlgZone, low, high); err != nil {
			t.Fatalf("%s: setPublishedCdsRange: %v", step, err)
		}
	}
	claim("first DS publication")
	if got := servedCDS(t, r.zd); len(got) != 1 {
		t.Fatalf("test premise: served CDS keyids %v", tupleKeyids(got))
	}

	if _, err := r.changePolicy("newalg"); err != nil {
		t.Fatalf("change-policy: %v", err)
	}
	r.tick("spawn", time.Now())
	if st := r.roll("spawn"); st == nil {
		t.Fatal("no roll spawned")
	}
	if got := servedCDS(t, r.zd); len(got) != 0 {
		t.Fatalf("the old KSK's CDS is still served after the spawn: keyids %v", tupleKeyids(got))
	}
	if row := r.row("spawn"); row.LastPublishedCdsIndexLow.Valid || row.LastPublishedCdsIndexHigh.Valid {
		t.Fatalf("the CDS claim was not released: %+v", row)
	}

	// Why before: the same CDS and claim, released after the spawn.
	cds := cdsFromDS(ktAlgZone, r.dsOfOldHead(t))
	stageCDS(t, r.zd, cds)
	idx, ok, err := RolloverIndexForKey(r.kdb, ktAlgZone, r.a)
	if err != nil || !ok {
		t.Fatalf("rollover_index of %d: %v %v", r.a, ok, err)
	}
	if err := setPublishedCdsRange(r.kdb, ktAlgZone, idx, idx); err != nil {
		t.Fatalf("setPublishedCdsRange: %v", err)
	}
	cleanupCdsAfterConfirm(context.Background(), r.zd, r.kdb)
	if got := servedCDS(t, r.zd); len(got) != 1 {
		t.Fatalf("released after the spawn, the CDS was withdrawn after all (keyids %v); the ordering comment is stale", tupleKeyids(got))
	}
}

// confirmInsecure drives an insecure roll from the first DS publication up to
// its confirm on an empty parent answer. Returns the roll, the confirm time
// and the insecure drain margin.
func (r *ndRig) confirmInsecure() (*KskAlgRollState, time.Time, time.Duration) {
	r.t.Helper()
	r.firstDSPoll()
	st, tPush, _ := r.spawnAndPush()
	if !st.ParentInsecure {
		r.t.Fatal("the roll was not recorded as insecure")
	}
	pol := r.zd.DnssecPolicy
	tConfirm := tPush.Add(pol.Rollover.ConfirmInitialWait + time.Second)
	r.tick("confirm", tConfirm)
	r.expectPhase("confirm", rolloverPhasePendingChildWithdraw, true)
	maxTTL, err := LoadZoneSigningMaxTTL(r.kdb, ktAlgZone)
	if err != nil {
		r.t.Fatalf("LoadZoneSigningMaxTTL: %v", err)
	}
	ttl := time.Duration(pol.TTLS.DNSKEY) * time.Second
	if m := time.Duration(maxTTL) * time.Second; m > ttl {
		ttl = m
	}
	return r.roll("confirm"), tConfirm, time.Minute + ttl
}

// A DS the parent took late -- the old KSK's, from the first DS publication's
// request -- found when the insecure drain is over: the old KSK is kept, and
// the roll goes back through the ordinary parent path (push {DS(new)}, wait
// for DS(old) to be gone, drain for the parent DS TTL).
func TestInsecureDrainFindsDSAndGoesBackToTheParent(t *testing.T) {
	r := newNoDSRig(t, 1)
	const parentDSTTL = 4 * 3600 // long enough to tell the two drains apart
	dsA := r.dsOfActiveKSK(parentDSTTL)
	st, tConfirm, insecureMargin := r.confirmInsecure()
	b := st.NewHeadKeyID
	pol := r.zd.DnssecPolicy
	ktAssertDNSKEYSigs(t, r.zd, r.kdb, "drain", r.a, b)

	r.parent.serve(dsA)
	tDue := tConfirm.Add(insecureMargin + 30*time.Second)
	r.tick("removal due, parent shows DS(A)", tDue)
	r.expectKeyState("removal due, parent shows DS(A)", r.a, DnskeyStateActive)
	if tags := r.zd.mustRRSIGKeytags(t, ktAlgZone, dns.TypeDNSKEY); !ktHasKeytag(tags, r.a) {
		t.Fatalf("the old KSK's RRSIGs were stripped although it was kept: %v", tags)
	}
	r.expectPhase("removal due, parent shows DS(A)", rolloverPhasePendingParentPush, true)
	if st := r.roll("removal due, parent shows DS(A)"); st == nil || st.ParentInsecure || st.OldHeadRetireAt != nil {
		t.Fatalf("want an ordinary roll back before its confirm: %+v", st)
	}

	// The ordinary parent path: push {DS(B)} ...
	tPush := tDue.Add(time.Second)
	r.tick("re-push", tPush)
	r.expectPhase("re-push", rolloverPhasePendingParentObserve, true)
	pushes := r.parent.pushes()
	pushed := pushes[len(pushes)-1]
	if tags := ktDSKeytags(pushed); len(tags) != 1 || tags[0] != b {
		t.Fatalf("re-push: DS set keytags %v, want exactly {%d}", tags, b)
	}
	// ... no confirm while DS(A) is still served ...
	tObs := tPush.Add(pol.Rollover.ConfirmInitialWait + time.Second)
	r.tick("parent still shows DS(A)", tObs)
	r.expectPhase("parent still shows DS(A)", rolloverPhasePendingParentObserve, true)
	// ... the ordinary confirm once only DS(B) is ...
	r.parent.serve(ktDSSubset(pushed, parentDSTTL, b))
	tConfirm2 := tObs.Add(pol.Rollover.ConfirmPollMax + time.Second)
	r.tick("parent shows DS(B)", tConfirm2)
	r.expectPhase("parent shows DS(B)", rolloverPhasePendingChildWithdraw, true)
	if st := r.roll("parent shows DS(B)"); st == nil || st.OldHeadRetireAt == nil || !st.OldHeadRetireAt.Equal(tConfirm2.UTC().Truncate(time.Second)) {
		t.Fatalf("parent shows DS(B): drain clock not restarted at the ordinary confirm: %+v", st)
	}
	// ... and the parent-DS-TTL drain, not the insecure one.
	secureMargin := parentDSTTL*time.Second + pol.Rollover.DsPublishDelay
	r.tick("past the insecure drain", tConfirm2.Add(insecureMargin+30*time.Second))
	r.expectKeyState("past the insecure drain", r.a, DnskeyStateActive)
	r.tick("past the ordinary drain", tConfirm2.Add(secureMargin+30*time.Second))
	r.expectKeyState("past the ordinary drain", r.a, DnskeyStateRemoved)
	r.expectPhase("past the ordinary drain", rolloverPhaseIdle, false)
}

// When the parent cannot be asked before the removal -- the poll fails, or
// no parent-agent is configured -- the insecure roll holds and asks again
// next tick; once the parent answers with no DS the old KSK goes.
func TestInsecureDrainHoldsWhenTheParentCannotBeAsked(t *testing.T) {
	r := newNoDSRig(t, 1)
	st, tConfirm, margin := r.confirmInsecure()
	retireAt := *st.OldHeadRetireAt
	held := func(step string) {
		t.Helper()
		r.expectKeyState(step, r.a, DnskeyStateActive)
		r.expectPhase(step, rolloverPhasePendingChildWithdraw, true)
		if st := r.roll(step); st == nil || !st.ParentInsecure || st.OldHeadRetireAt == nil || !st.OldHeadRetireAt.Equal(retireAt) {
			t.Fatalf("%s: the roll changed while holding: %+v", step, st)
		}
	}
	tDue := tConfirm.Add(margin + 30*time.Second)

	saved := queryParentAgentDS
	queryParentAgentDS = func(ctx context.Context, zone, agent string) ([]dns.RR, error) {
		return nil, errors.New("i/o timeout")
	}
	r.tick("poll fails", tDue)
	queryParentAgentDS = saved
	held("poll fails")

	agent := r.zd.DnssecPolicy.Rollover.ParentAgent
	r.zd.DnssecPolicy.Rollover.ParentAgent = ""
	r.tick("no parent-agent", tDue.Add(time.Minute))
	r.zd.DnssecPolicy.Rollover.ParentAgent = agent
	held("no parent-agent")

	r.tick("parent answers, no DS", tDue.Add(2*time.Minute))
	r.expectKeyState("parent answers, no DS", r.a, DnskeyStateRemoved)
	r.expectPhase("parent answers, no DS", rolloverPhaseIdle, false)
}

// A first DS publication whose CDS cannot be withdrawn does not give way to
// the roll yet: the roll would not wait for the parent, and the old KSK's CDS
// could outlive the old KSK. The tick holds and retries; once the release
// succeeds the roll starts.
func TestSpawnHoldsWhileTheFirstDSPublicationCDSCannotBeReleased(t *testing.T) {
	r := newNoDSRig(t, 1)
	r.kdb.UpdateQ = make(chan UpdateRequest, 8)
	r.kdb.DSEngineQ = make(chan DSEngineRequest, 8)
	var refuse atomic.Bool
	serveQueue(t, r.kdb.UpdateQ, func(_ context.Context, ur UpdateRequest) {
		if refuse.Load() {
			ur.respond(false, errTestApplyRefused)
			return
		}
		applyApexActions(r.zd, ur.Actions)
		ur.respond(true, nil)
	})
	startDSEngine(t, r.kdb)
	r.firstDSPoll()
	cds, low, high, ok, err := ComputeTargetCDSSetForZone(r.kdb, ktAlgZone)
	if err != nil || !ok || len(cds) == 0 {
		t.Fatalf("target CDS: %v (%d records, range known %v)", err, len(cds), ok)
	}
	stageCDS(t, r.zd, cds)
	if err := setPublishedCdsRange(r.kdb, ktAlgZone, low, high); err != nil {
		t.Fatalf("setPublishedCdsRange: %v", err)
	}
	if _, err := r.changePolicy("newalg"); err != nil {
		t.Fatalf("change-policy: %v", err)
	}

	refuse.Store(true)
	r.tick("release fails", time.Now())
	if st := r.roll("release fails"); st != nil {
		t.Fatalf("the roll started although the old CDS could not be withdrawn: %+v", st)
	}
	row := r.row("release fails")
	if !firstDSPublicationWithoutParentDS(row) || !row.LastPublishedCdsIndexLow.Valid {
		t.Fatalf("release fails: want the first DS publication and its claim untouched: %+v", row)
	}
	if got := servedCDS(t, r.zd); len(got) != 1 {
		t.Fatalf("release fails: served CDS keyids %v, want the old KSK's", tupleKeyids(got))
	}
	if seps := ktActiveSEPs(t, r.kdb, ktAlgZone); len(seps) != 1 {
		t.Fatalf("release fails: %d active SEP keys, want 1", len(seps))
	}

	refuse.Store(false)
	r.tick("release succeeds", time.Now())
	if st := r.roll("release succeeds"); st == nil || !st.ParentInsecure {
		t.Fatalf("release succeeds: no insecure roll: %+v", st)
	}
	if got := servedCDS(t, r.zd); len(got) != 0 {
		t.Fatalf("release succeeds: the old KSK's CDS is still served: keyids %v", tupleKeyids(got))
	}
}

// dsOfOldHead is the old head's DS, computed from its DNSKEY directly: once
// the roll is spawned the target set no longer carries it.
func (r *ndRig) dsOfOldHead(t *testing.T) []dns.RR {
	t.Helper()
	var keyrr string
	if err := r.kdb.DB.QueryRow(`SELECT keyrr FROM DnssecKeyStore WHERE zonename = ? AND keyid = ?`, ktAlgZone, int(r.a)).Scan(&keyrr); err != nil {
		t.Fatalf("keyrr of %d: %v", r.a, err)
	}
	rr, err := dns.NewRR(keyrr)
	if err != nil {
		t.Fatalf("parse DNSKEY: %v", err)
	}
	dk, ok := rr.(*dns.DNSKEY)
	if !ok {
		t.Fatalf("key %d is not a DNSKEY", r.a)
	}
	return []dns.RR{dk.ToDS(dns.SHA256)}
}
