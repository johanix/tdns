package tdns

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// KT-6 / KT-7 / KT-8 / KT-14 / KT-15: the KSK algorithm rollover driven end
// to end through RolloverAutomatedTick against a fake parent, with the
// tick's clock injected.

// ktFakeParent stands in for the parent-agent on both wire seams: it
// records every DS set the engine pushes and serves whatever the test
// tells it to.
type ktFakeParent struct {
	mu      sync.Mutex
	serving []dns.RR
	pushed  [][]dns.RR
}

func (p *ktFakeParent) serve(rrs []dns.RR) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.serving = rrs
}

func (p *ktFakeParent) pushes() [][]dns.RR {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([][]dns.RR, len(p.pushed))
	copy(out, p.pushed)
	return out
}

func ktInstallFakeParent(t *testing.T) *ktFakeParent {
	t.Helper()
	p := &ktFakeParent{}
	prevQ, prevP := queryParentAgentDS, pushDSRRsetForRollover
	queryParentAgentDS = func(ctx context.Context, zone, agent string) ([]dns.RR, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		return append([]dns.RR(nil), p.serving...), nil
	}
	pushDSRRsetForRollover = func(ctx context.Context, deps RolloverEngineDeps) (KSKDSPushResult, error) {
		ds, _, _, _, err := ComputeTargetDSSetForZone(deps.KDB, deps.Zone.ZoneName, uint8(dns.SHA256), deps.Policy)
		if err != nil {
			return KSKDSPushResult{Category: SoftfailChildConfigLocalError}, err
		}
		p.mu.Lock()
		p.pushed = append(p.pushed, ds)
		p.mu.Unlock()
		return KSKDSPushResult{Rcode: dns.RcodeSuccess, Scheme: "UPDATE"}, nil
	}
	t.Cleanup(func() {
		queryParentAgentDS, pushDSRRsetForRollover = prevQ, prevP
	})
	return p
}

// ktDSSubset returns copies of the DS records in set whose keytag is in
// keep, with a fixed TTL so the engine's parent-DS-TTL observation is
// deterministic.
func ktDSSubset(set []dns.RR, ttl uint32, keep ...uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range set {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		for _, k := range keep {
			if ds.KeyTag == k {
				c := *ds
				c.Hdr.Ttl = ttl
				out = append(out, &c)
			}
		}
	}
	return out
}

func ktDSKeytags(set []dns.RR) []uint16 {
	var out []uint16
	for _, rr := range set {
		if ds, ok := rr.(*dns.DS); ok {
			out = append(out, ds.KeyTag)
		}
	}
	return out
}

// ktSequencePolicy passes the E5/E10 invariants so the engine never
// gates itself on a policy error mid-sequence, and spaces its timers so
// the injected clock can step over each one deterministically.
func ktSequencePolicy(method RolloverMethod) *DnssecPolicy {
	pol := ktMultiDSPolicy(dns.ED25519, dns.ED25519)
	pol.Rollover.Method = method
	pol.Rollover.ParentAgent = "127.0.0.1:1" // never dialled: the seam is faked
	pol.Rollover.ConfirmInitialWait = time.Hour
	pol.Rollover.ConfirmPollMax = time.Hour
	pol.Rollover.ConfirmTimeout = 24 * time.Hour
	pol.TTLS.DNSKEY = 3600
	pol.Clamping.Margin = 2 * time.Hour
	return pol
}

func ktAssertOneActivePerAlg(t *testing.T, kdb *KeyDB, zone, step string) {
	t.Helper()
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	byAlg, err := activeSEPsByAlgTx(tx, zone)
	if err != nil {
		t.Fatalf("%s: activeSEPsByAlgTx: %v", step, err)
	}
	for alg, kids := range byAlg {
		if len(kids) > 1 {
			t.Fatalf("%s: %d active SEP keys of %s, want at most 1", step, len(kids), dns.AlgorithmToString[alg])
		}
	}
}

func ktPhase(t *testing.T, kdb *KeyDB, zone string) (string, bool) {
	t.Helper()
	row, err := LoadRolloverZoneRow(kdb, zone)
	if err != nil || row == nil {
		t.Fatalf("LoadRolloverZoneRow: row=%v err=%v", row, err)
	}
	return row.RolloverPhase, row.RolloverInProgress
}

// ktAssertChain: for the DS RRset a resolver could hold (parentDS), at least
// one DS names a DNSKEY that is in the served RRset AND has an RRSIG over
// the DNSKEY RRset by that key -- one complete DS→DNSKEY→RRSIG chain.
func ktAssertChain(t *testing.T, zd *ZoneData, step string, parentDS []dns.RR) {
	t.Helper()
	owner, _ := zd.GetOwner(zd.ZoneName)
	if owner == nil {
		t.Fatalf("%s: no apex", step)
	}
	dnskeys, _ := owner.RRtypes.Get(dns.TypeDNSKEY)
	published := map[uint16]bool{}
	for _, rr := range dnskeys.RRs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			published[k.KeyTag()] = true
		}
	}
	signed := map[uint16]bool{}
	for _, sig := range dnskeys.RRSIGs {
		signed[sig.(*dns.RRSIG).KeyTag] = true
	}
	for _, rr := range parentDS {
		if ds, ok := rr.(*dns.DS); ok && published[ds.KeyTag] && signed[ds.KeyTag] {
			return
		}
	}
	t.Fatalf("%s: no complete chain: parent DS %v, published %v, signed %v", step, ktDSKeytags(parentDS), published, signed)
}

// ktAssertDNSKEYSigs runs every zone-level re-sign path -- SignZone forced,
// SignZone unforced, ResignZone (strip-and-replace) -- and after each
// asserts the apex DNSKEY RRset carries exactly the RRSIGs by want. This
// is KT-17, the join between the engine and the signer: whichever path a
// key-state change or the periodic pass takes, the drain window keeps
// both signatures and removal leaves neither behind.
func ktAssertDNSKEYSigs(t *testing.T, zd *ZoneData, kdb *KeyDB, step string, want ...uint16) {
	t.Helper()
	paths := []struct {
		name string
		run  func() error
	}{
		{"SignZone(force)", func() error { _, err := zd.SignZone(kdb, true); return err }},
		{"SignZone(renew)", func() error { _, err := zd.SignZone(kdb, false); return err }},
		{"ResignZone", func() error { _, err := zd.ResignZone(kdb); return err }},
	}
	for _, p := range paths {
		if err := p.run(); err != nil {
			t.Fatalf("%s: %s: %v", step, p.name, err)
		}
		tags := zd.mustRRSIGKeytags(t, zd.ZoneName, dns.TypeDNSKEY)
		if len(tags) != len(want) {
			t.Fatalf("%s: after %s the DNSKEY RRSIG keytags are %v, want %v", step, p.name, tags, want)
		}
		for _, w := range want {
			if !ktHasKeytag(tags, w) {
				t.Fatalf("%s: after %s the DNSKEY RRSIG keytags are %v, want %v", step, p.name, tags, want)
			}
		}
	}
}

// KT-6, with KT-8 (mixed confirm), KT-14 (D-7 wait), KT-15 (delegation
// sync hands-off) and KT-17 (both re-sign paths keep the double signature
// through the drain) asserted along the way.
func TestKT6FullKskAlgRolloverSequence(t *testing.T) {
	parent := ktInstallFakeParent(t)
	kdb := newTestKeyDB(t)
	pol := ktSequencePolicy(RolloverMethodMultiDS)
	zd := ktEngineZone(t, kdb, ktAlgZone, ktAlgZoneText, pol)
	a := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tick := func(step string, now time.Time) {
		t.Helper()
		deps := ktDeps(zd, kdb, now)
		deps.Imr = &Imr{} // non-nil so the push branch runs; the push itself is faked
		if err := RolloverAutomatedTick(ctx, deps); err != nil {
			t.Fatalf("%s: tick: %v", step, err)
		}
		ktAssertOneActivePerAlg(t, kdb, ktAlgZone, step)
	}
	expectPhase := func(step, phase string, inProgress bool) {
		t.Helper()
		p, ip := ktPhase(t, kdb, ktAlgZone)
		if p != phase || ip != inProgress {
			t.Fatalf("%s: phase=%q in_progress=%v, want %q/%v", step, p, ip, phase, inProgress)
		}
	}
	expectOwnsDS := func(step string, want bool) {
		t.Helper()
		if got := zd.rolloverOwnsDS(); got != want {
			t.Fatalf("%s: rolloverOwnsDS=%v, want %v (KT-15)", step, got, want)
		}
	}

	pol.KSKAlgorithm = dns.RSASHA256 // the bind
	t0 := time.Now()
	dnskeyTTL := time.Duration(pol.TTLS.DNSKEY) * time.Second
	propagation := time.Minute // ktDeps' PropagationDelay

	// 1. spawn
	tick("spawn", t0.Add(time.Second))
	expectPhase("spawn", rolloverPhasePendingChildPublish, true)
	expectOwnsDS("spawn", true)
	st, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	if st == nil || st.OldHeadKeyID != a {
		t.Fatalf("spawn: roll state %+v", st)
	}
	b := st.NewHeadKeyID
	// The spawn's triggerResign is a no-op here (no resigner): do its job,
	// and check every re-sign path double-signs. A pre-push resolver holds
	// {DS(A)}; its chain runs through A.
	ktAssertDNSKEYSigs(t, zd, kdb, "spawn", a, b)
	preTarget, _, _, _, _ := ComputeTargetDSSetForZone(kdb, ktAlgZone, uint8(dns.SHA256), pol)
	ktAssertChain(t, zd, "spawn", ktDSSubset(preTarget, 3600, a))

	// 2. KT-14: no push before propagation-delay + DNSKEY_TTL from the spawn.
	tick("wait-early", t0.Add(propagation+dnskeyTTL-30*time.Second))
	expectPhase("wait-early", rolloverPhasePendingChildPublish, true)
	if n := len(parent.pushes()); n != 0 {
		t.Fatalf("wait-early: %d pushes before the D-7 wait elapsed", n)
	}
	tArm := t0.Add(propagation + dnskeyTTL + 30*time.Second)
	tick("wait-done", tArm)
	expectPhase("wait-done", rolloverPhasePendingParentPush, true)
	expectOwnsDS("wait-done", true)

	// 3. push {DS(A), DS(B)}
	tPush := tArm.Add(time.Second)
	tick("push", tPush)
	expectPhase("push", rolloverPhasePendingParentObserve, true)
	pushes := parent.pushes()
	if len(pushes) != 1 {
		t.Fatalf("push: %d pushes, want 1", len(pushes))
	}
	tags := ktDSKeytags(pushes[0])
	if len(tags) != 2 || !ktHasKeytag(tags, a) || !ktHasKeytag(tags, b) {
		t.Fatalf("push: DS set keytags = %v, want exactly {%d, %d}", tags, a, b)
	}
	target := pushes[0]

	// 4. KT-8 live: DS(A) alone at the parent does not confirm.
	parent.serve(ktDSSubset(target, 3600, a))
	tObs1 := tPush.Add(pol.Rollover.ConfirmInitialWait + time.Second)
	tick("observe-partial", tObs1)
	expectPhase("observe-partial", rolloverPhasePendingParentObserve, true)
	if s := ktKeyState(t, kdb, ktAlgZone, a); s != DnskeyStateActive {
		t.Fatalf("observe-partial: A is %s", s)
	}

	// 5. confirm: both DS present. A stays ACTIVE (A2); its clock starts.
	parent.serve(ktDSSubset(target, 3600, a, b))
	tConfirm := tObs1.Add(pol.Rollover.ConfirmPollMax + time.Second)
	tick("confirm", tConfirm)
	expectPhase("confirm", rolloverPhasePendingChildWithdraw, true)
	expectOwnsDS("confirm", true)
	if s := ktKeyState(t, kdb, ktAlgZone, a); s != DnskeyStateActive {
		t.Fatalf("confirm: A must stay active through the drain, is %s", s)
	}
	st, _ = LoadKskAlgRollState(kdb, ktAlgZone)
	if st == nil || st.OldHeadRetireAt == nil || !st.OldHeadRetireAt.Equal(tConfirm.UTC().Truncate(time.Second)) {
		t.Fatalf("confirm: old head retire_at not stamped at the confirm: %+v", st)
	}
	if zd.ParentDSTTLObserved != 3600 {
		t.Fatalf("confirm: parent DS TTL observed = %d, want 3600", zd.ParentDSTTLObserved)
	}
	// KT-17: through the drain every re-sign path keeps BOTH signatures --
	// including ResignZone, which strips and re-signs with the active keys
	// only, and which a key-state change triggers after PR #514.
	ktAssertDNSKEYSigs(t, zd, kdb, "drain", a, b)
	ktAssertChain(t, zd, "drain (pre-push resolver)", ktDSSubset(target, 3600, a))
	ktAssertChain(t, zd, "drain (post-push resolver)", ktDSSubset(target, 3600, a, b))

	// 6. F1 margin: max(2h margin, 3600s max TTL, 3600s DS TTL + 5m) = 2h.
	tick("drain-early", tConfirm.Add(2*time.Hour-30*time.Second))
	expectPhase("drain-early", rolloverPhasePendingChildWithdraw, true)
	if s := ktKeyState(t, kdb, ktAlgZone, a); s != DnskeyStateActive {
		t.Fatalf("drain-early: A removed before the margin elapsed, is %s", s)
	}
	expectOwnsDS("drain-early", true)

	tDone := tConfirm.Add(2*time.Hour + 30*time.Second)
	tick("drain-done", tDone)
	if s := ktKeyState(t, kdb, ktAlgZone, a); s != DnskeyStateRemoved {
		t.Fatalf("drain-done: A is %s, want removed", s)
	}
	if tags := zd.mustRRSIGKeytags(t, ktAlgZone, dns.TypeDNSKEY); ktHasKeytag(tags, a) {
		t.Fatalf("drain-done: RRSIG by removed KSK %d still on the DNSKEY RRset: %v", a, tags)
	}
	// KT-17: after removal no re-sign path brings RRSIG(A) back, and a
	// resolver holding the still-mixed parent RRset validates through B.
	ktAssertDNSKEYSigs(t, zd, kdb, "removed", b)
	ktAssertChain(t, zd, "removed", ktDSSubset(target, 3600, a, b))
	if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st != nil {
		t.Fatalf("drain-done: roll state not cleared: %+v", st)
	}
	expectPhase("drain-done", rolloverPhasePendingParentPush, false)
	expectOwnsDS("drain-done", true) // phase busy: the shrink push is still ours

	// 7. the DS set shrinks to the new algorithm (plus the refilled pipeline).
	tShrink := tDone.Add(time.Second)
	tick("shrink-push", tShrink)
	expectPhase("shrink-push", rolloverPhasePendingParentObserve, false)
	pushes = parent.pushes()
	if len(pushes) != 2 {
		t.Fatalf("shrink-push: %d pushes, want 2", len(pushes))
	}
	final := pushes[1]
	if tags := ktDSKeytags(final); ktHasKeytag(tags, a) || !ktHasKeytag(tags, b) {
		t.Fatalf("shrink-push: DS set keytags = %v; must drop %d and keep %d", tags, a, b)
	}
	for _, rr := range final {
		if ds := rr.(*dns.DS); ds.Algorithm != dns.RSASHA256 {
			t.Fatalf("shrink-push: DS for keytag %d is algorithm %d, want RSASHA256", ds.KeyTag, ds.Algorithm)
		}
	}
	parent.serve(ktDSSubset(final, 3600, ktDSKeytags(final)...))
	tick("shrink-confirm", tShrink.Add(pol.Rollover.ConfirmInitialWait+time.Second))
	expectPhase("shrink-confirm", rolloverPhaseIdle, false)
	expectOwnsDS("shrink-confirm", false)

	seps := ktActiveSEPs(t, kdb, ktAlgZone)
	if len(seps) != 1 || seps[0].KeyTag != b || seps[0].Algorithm != dns.RSASHA256 {
		t.Fatalf("end: active SEP keys = %+v, want only B (RSASHA256)", seps)
	}
}

// KT-14 (deferral half): with no observable DNSKEY TTL the phase holds
// rather than arming a push with a shorter wait.
func TestKT14DeferWithoutDnskeyTTL(t *testing.T) {
	ktInstallFakeParent(t)
	kdb := newTestKeyDB(t)
	pol := ktSequencePolicy(RolloverMethodMultiDS)
	pol.TTLS.DNSKEY, pol.TTLS.MaxServed = 0, 0
	zd := ktEngineZone(t, kdb, ktAlgZone, ktAlgZoneText, pol)
	ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	pol.KSKAlgorithm = dns.RSASHA256
	t0 := time.Now()
	ktTick(t, zd, kdb, t0.Add(time.Second))
	if p, _ := ktPhase(t, kdb, ktAlgZone); p != rolloverPhasePendingChildPublish {
		t.Fatalf("after spawn: phase %q", p)
	}
	// Forget the signing pass's max-TTL observation: nothing left to
	// derive the served DNSKEY TTL from.
	if _, err := kdb.DB.Exec(`DELETE FROM ZoneSigningState WHERE zone = ?`, ktAlgZone); err != nil {
		t.Fatalf("forget max TTL: %v", err)
	}
	ktTick(t, zd, kdb, t0.Add(10*24*time.Hour))
	if p, _ := ktPhase(t, kdb, ktAlgZone); p != rolloverPhasePendingChildPublish {
		t.Fatalf("without a DNSKEY TTL the push must defer, phase %q", p)
	}
}

// KT-8: the DS confirm matcher on a mixed-algorithm expected set.
func TestKT8MixedAlgDSConfirm(t *testing.T) {
	kdb := newTestKeyDB(t)
	pol := ktSequencePolicy(RolloverMethodMultiDS)
	a := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	b := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.RSASHA256)
	expected, _, _, _, err := ComputeTargetDSSetForZone(kdb, ktAlgZone, uint8(dns.SHA256), pol)
	if err != nil || len(expected) != 2 {
		t.Fatalf("target DS set: %v (%d records)", err, len(expected))
	}
	if ObservedDSSetMatchesExpected(ktDSSubset(expected, 3600, a), expected) {
		t.Fatal("DS(A) alone must not confirm a mixed set")
	}
	if ObservedDSSetMatchesExpected(ktDSSubset(expected, 3600, b), expected) {
		t.Fatal("DS(B) alone must not confirm a mixed set")
	}
	if !ObservedDSSetMatchesExpected(ktDSSubset(expected, 3600, a, b), expected) {
		t.Fatal("both DS present must confirm")
	}
}

// KT-7: the withdraw margin, widened only for an algorithm roll.
func TestKT7EffectiveMarginForRoll(t *testing.T) {
	kdb := newTestKeyDB(t)
	if err := UpsertZoneSigningMaxTTL(kdb, ktAlgZone, 3600); err != nil {
		t.Fatalf("UpsertZoneSigningMaxTTL: %v", err)
	}
	roll := &KskAlgRollState{FromAlg: dns.ED25519, ToAlg: dns.RSASHA256}
	mk := func(margin time.Duration, dsDelay time.Duration, observed uint32, override uint32) (*ZoneData, *DnssecPolicy) {
		pol := &DnssecPolicy{Clamping: ClampingPolicy{Margin: margin}}
		pol.Rollover.DsPublishDelay = dsDelay
		pol.TTLS.ParentDS = override
		return &ZoneData{ZoneName: ktAlgZone, ParentDSTTLObserved: observed}, pol
	}
	cases := []struct {
		name     string
		margin   time.Duration
		dsDelay  time.Duration
		observed uint32
		override uint32
		roll     *KskAlgRollState
		want     time.Duration
		wantOK   bool
	}{
		{"same-alg: max(margin, maxTTL)", 15 * time.Minute, 5 * time.Minute, 86400, 0, nil, time.Hour, true},
		{"same-alg ignores DS TTL", 15 * time.Minute, 5 * time.Minute, 86400, 0, nil, time.Hour, true},
		{"alg-roll: DS TTL unknown defers", 15 * time.Minute, 5 * time.Minute, 0, 0, roll, time.Hour, false},
		{"alg-roll: DS TTL + delay widens", 15 * time.Minute, 5 * time.Minute, 86400, 0, roll, 24*time.Hour + 5*time.Minute, true},
		{"alg-roll: margin already wider", 48 * time.Hour, 5 * time.Minute, 3600, 0, roll, 48 * time.Hour, true},
		{"alg-roll: ttls.parent-ds override wins", 15 * time.Minute, 5 * time.Minute, 3600, 7200, roll, 2*time.Hour + 5*time.Minute, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			zd, pol := mk(c.margin, c.dsDelay, c.observed, c.override)
			got, ok, err := effectiveMarginForRoll(zd, kdb, ktAlgZone, pol, c.roll)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v", ok, c.wantOK)
			}
			if ok && got != c.want {
				t.Fatalf("margin=%v, want %v", got, c.want)
			}
			if c.roll == nil {
				base, _ := effectiveMarginForZone(kdb, ktAlgZone, pol)
				if got != base {
					t.Fatalf("same-algorithm path must equal effectiveMarginForZone: %v vs %v", got, base)
				}
			}
		})
	}
}
