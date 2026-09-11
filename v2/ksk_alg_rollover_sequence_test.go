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

	// The DS the parent serves before the roll: the pre-swap resolver's
	// view for the chain assertions below.
	dsBefore, _, _, _, err := ComputeTargetDSSetForZone(kdb, ktAlgZone, uint8(dns.SHA256), pol)
	if err != nil || len(dsBefore) != 1 {
		t.Fatalf("pre-roll target DS set: %v (%d records)", err, len(dsBefore))
	}
	dsA := ktDSSubset(dsBefore, 3600, a)

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
	ktAssertChain(t, zd, "spawn", dsA)
	// KT-18 in situ: from the spawn on the target DS set is {DS(B)} -- the
	// active, signing old head is deliberately not in it (A4).
	postTarget, _, _, _, _ := ComputeTargetDSSetForZone(kdb, ktAlgZone, uint8(dns.SHA256), pol)
	if tags := ktDSKeytags(postTarget); len(tags) != 1 || !ktHasKeytag(tags, b) {
		t.Fatalf("spawn: target DS set keytags = %v, want exactly {%d}", tags, b)
	}

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

	// 3. push: the parent's DS is swapped, DS(B) replacing DS(A) in one
	// step (RFC 6781 §4.1.4, A4). A is still active and signing.
	tPush := tArm.Add(time.Second)
	tick("push", tPush)
	expectPhase("push", rolloverPhasePendingParentObserve, true)
	pushes := parent.pushes()
	if len(pushes) != 1 {
		t.Fatalf("push: %d pushes, want 1", len(pushes))
	}
	tags := ktDSKeytags(pushes[0])
	if len(tags) != 1 || !ktHasKeytag(tags, b) {
		t.Fatalf("push: DS set keytags = %v, want exactly {%d}: the old-algorithm DS leaves the parent before the old KSK leaves the child", tags, b)
	}
	if s := ktKeyState(t, kdb, ktAlgZone, a); s != DnskeyStateActive {
		t.Fatalf("push: A is %s, want active", s)
	}
	dsB := ktDSSubset(pushes[0], 3600, b)
	dsAB := append(append([]dns.RR{}, dsA...), dsB...)

	// 4. KT-8 live: a parent still serving DS(A) -- alone, or next to
	// DS(B) as a lagging nameserver would -- does not confirm. The drain
	// clock must not start while a resolver can still pick up DS(A).
	parent.serve(dsA)
	tObs1 := tPush.Add(pol.Rollover.ConfirmInitialWait + time.Second)
	tick("observe-old", tObs1)
	expectPhase("observe-old", rolloverPhasePendingParentObserve, true)
	parent.serve(dsAB)
	tObs2 := tObs1.Add(pol.Rollover.ConfirmPollMax + time.Second)
	tick("observe-lagging", tObs2)
	expectPhase("observe-lagging", rolloverPhasePendingParentObserve, true)
	if s := ktKeyState(t, kdb, ktAlgZone, a); s != DnskeyStateActive {
		t.Fatalf("observe-lagging: A is %s", s)
	}
	if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st == nil || st.OldHeadRetireAt != nil {
		t.Fatalf("observe-lagging: drain clock started while the parent still served DS(A): %+v", st)
	}

	// 5. confirm: the parent serves DS(B) only. A stays ACTIVE (A2); its
	// clock starts.
	parent.serve(dsB)
	tConfirm := tObs2.Add(pol.Rollover.ConfirmPollMax + time.Second)
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
	// only, and which a key-state change triggers after PR #514. A resolver
	// that still holds the pre-swap DS(A) validates through A; one that
	// has the new DS(B) validates through B.
	ktAssertDNSKEYSigs(t, zd, kdb, "drain", a, b)
	ktAssertChain(t, zd, "drain (resolver holding the pre-swap DS)", dsA)
	ktAssertChain(t, zd, "drain (resolver holding the new DS)", dsB)

	// 6. F1 margin: max(2h margin, 3600s max TTL, 3600s DS TTL + 5m) = 2h --
	// the time for every cached copy of the pre-swap DS(A) to expire.
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
	// KT-17: after removal no re-sign path brings RRSIG(A) back, and the
	// chain runs through the DS the parent has served since the confirm.
	ktAssertDNSKEYSigs(t, zd, kdb, "removed", b)
	ktAssertChain(t, zd, "removed", dsB)
	if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st != nil {
		t.Fatalf("drain-done: roll state not cleared: %+v", st)
	}
	// Nothing left to push: the parent has held the final set since the
	// confirm, so the roll ends in idle, not in another push.
	expectPhase("drain-done", rolloverPhaseIdle, false)
	expectOwnsDS("drain-done", false)

	// 7. Whatever the idle branch pushes from here on (the refilled
	// multi-DS pipeline) is new-algorithm only: DS(A) never comes back.
	tick("after", tDone.Add(time.Minute))
	for i, push := range parent.pushes()[1:] {
		if tags := ktDSKeytags(push); ktHasKeytag(tags, a) {
			t.Fatalf("after: push %d carries DS(%d) again: %v", i+2, a, tags)
		}
		for _, rr := range push {
			if ds := rr.(*dns.DS); ds.Algorithm != dns.RSASHA256 {
				t.Fatalf("after: DS for keytag %d is algorithm %d, want RSASHA256", ds.KeyTag, ds.Algorithm)
			}
		}
	}

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

// KT-8: the DS confirm on a swapped set. The generic matcher ignores DS
// records for keys it does not manage, so {DS(A), DS(B)} would satisfy an
// expected {DS(B)}; the algorithm-roll tightening refuses it until DS(A)
// is gone from the parent (A4).
func TestKT8SwappedDSConfirm(t *testing.T) {
	kdb := newTestKeyDB(t)
	pol := ktSequencePolicy(RolloverMethodMultiDS)
	a := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	b := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.RSASHA256)
	all, _, _, _, err := ComputeTargetDSSetForZone(kdb, ktAlgZone, uint8(dns.SHA256), pol)
	if err != nil || len(all) != 2 {
		t.Fatalf("target DS set: %v (%d records)", err, len(all))
	}
	expected := ktDSSubset(all, 3600, b)
	roll := &KskAlgRollState{FromAlg: dns.ED25519, ToAlg: dns.RSASHA256, OldHeadKeyID: a, NewHeadKeyID: b}
	confirms := func(obs []dns.RR) bool {
		return ObservedDSSetMatchesExpected(obs, expected) && !observedDSStillHasOldHead(obs, roll)
	}
	if confirms(ktDSSubset(all, 3600, a)) {
		t.Fatal("DS(A) alone must not confirm")
	}
	if confirms(ktDSSubset(all, 3600, a, b)) {
		t.Fatal("DS(A) next to DS(B) must not confirm: the old-algorithm DS has to leave the parent first")
	}
	if !confirms(ktDSSubset(all, 3600, b)) {
		t.Fatal("DS(B) alone must confirm")
	}
	if observedDSStillHasOldHead(ktDSSubset(all, 3600, a, b), nil) {
		t.Fatal("no roll in flight: the tightening must not apply")
	}
}

// KT-18 (A4): the target DS set drops the roll's old head at the spawn,
// while that key is still active and signing, and an abort brings it
// back so a swap that already went out can be undone at the parent.
func TestKT18TargetDSSetExcludesOldHeadDuringRoll(t *testing.T) {
	ktInstallFakeParent(t)
	kdb := newTestKeyDB(t)
	pol := ktSequencePolicy(RolloverMethodMultiDS)
	zd := ktEngineZone(t, kdb, ktAlgZone, ktAlgZoneText, pol)
	a := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	target := func(step string) []uint16 {
		t.Helper()
		set, _, _, _, err := ComputeTargetDSSetForZone(kdb, ktAlgZone, uint8(dns.SHA256), pol)
		if err != nil {
			t.Fatalf("%s: target DS set: %v", step, err)
		}
		return ktDSKeytags(set)
	}
	if tags := target("before"); len(tags) != 1 || !ktHasKeytag(tags, a) {
		t.Fatalf("before the roll: target DS set = %v, want {%d}", tags, a)
	}
	pol.KSKAlgorithm = dns.RSASHA256
	ktTick(t, zd, kdb, time.Now().Add(time.Second))
	st, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	if st == nil {
		t.Fatal("no roll spawned")
	}
	b := st.NewHeadKeyID
	if s := ktKeyState(t, kdb, ktAlgZone, a); s != DnskeyStateActive {
		t.Fatalf("A is %s, want active", s)
	}
	if tags := target("during"); len(tags) != 1 || !ktHasKeytag(tags, b) {
		t.Fatalf("during the roll: target DS set = %v, want {%d}: the active old head %d must not be in it", tags, b, a)
	}
	if _, err := AbortKskAlgRollover(&Conf, kdb, ktAlgZone); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if tags := target("after-abort"); len(tags) != 1 || !ktHasKeytag(tags, a) {
		t.Fatalf("after the abort: target DS set = %v, want {%d} back", tags, a)
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
