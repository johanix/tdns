package tdns

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// T1b.5 and T1b.6: what the parent sees over a rollover in each DS model, with
// the invariants I1-I9 holding after every step, on the engine's injected
// clock and the fake parent of the rollover sequence tests.
//
// The parent's view is the DS set the child asks it to hold: under none it is
// the DS intent the delegation syncher sends; under multi-DS it is the set
// the rollover engine pushes.

func dsIntentKeytags(t *testing.T, kdb *KeyDB, zone string) (known bool, tags []uint16) {
	t.Helper()
	intent, err := DSIntentForZone(kdb, zone, dns.SHA256)
	if err != nil {
		t.Fatalf("DSIntentForZone: %v", err)
	}
	for _, rr := range intent.Set {
		tags = append(tags, rr.(*dns.DS).KeyTag)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })
	return intent.Known, tags
}

func dsOneSepKeytags(t *testing.T, kdb *KeyDB, zone string) []uint16 {
	t.Helper()
	var tags []uint16
	for _, r := range dsRows(t, kdb, zone) {
		if r.sep && r.ds != nil && *r.ds != 0 {
			tags = append(tags, r.keyid)
		}
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })
	return tags
}

func sameTags(a, b []uint16) bool { return fmt.Sprint(a) == fmt.Sprint(b) }

// checkStep re-signs the zone from its signing keys and runs the checker: I5
// and I6 hold once the served zone has caught up with a key change, and the
// test asks about the key state machine, not about the re-sign trigger.
func checkStep(t *testing.T, kdb *KeyDB, zd *ZoneData, step string) {
	t.Helper()
	if _, err := zd.ResignZone(context.Background(), kdb); err != nil {
		t.Fatalf("%s: ResignZone: %v", step, err)
	}
	if vs := CheckKeyInvariants(kdb, zd); len(vs) != 0 {
		t.Errorf("%s: %s", step, violationList(vs))
	}
}

// None: a KSK gets its DS once it is standby, not while it is published; the
// DS goes when the key is retired, which is the operator's explicit rollover.
func TestDsTimelineNoneModel(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "none-timeline.example."
	zd := dsTestZone(t, kdb, zone, RolloverMethodNone)
	a := ktGenKSK(t, kdb, zone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, zone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatal(err)
	}
	checkStep(t, kdb, zd, "start")
	if known, tags := dsIntentKeytags(t, kdb, zone); !known || !sameTags(tags, []uint16{a}) {
		t.Fatalf("start: intent known=%v %v, want {%d}", known, tags, a)
	}

	b, err := GenerateAndStageKey(kdb, zone, "test", dns.ED25519, "KSK")
	if err != nil {
		t.Fatal(err)
	}
	checkStep(t, kdb, zd, "published")
	if got := dsOf(t, kdb, zone, b); got != "0" {
		t.Errorf("published KSK: ds=%s, want 0 (no DS for a published key outside multi-DS)", got)
	}
	if _, tags := dsIntentKeytags(t, kdb, zone); !sameTags(tags, []uint16{a}) {
		t.Errorf("published: the parent is asked for %v, want only {%d}", tags, a)
	}

	// The key state worker's timer: propagated, standby.
	transitionPublishedToStandby(&Conf, kdb, time.Now().Add(2*time.Hour), time.Hour)
	if st := ktKeyState(t, kdb, zone, b); st != DnskeyStateStandby {
		t.Fatalf("after the propagation delay: B is %s, want standby", st)
	}
	checkStep(t, kdb, zd, "standby")
	if got := dsOf(t, kdb, zone, b); got != "1" {
		t.Errorf("standby KSK: ds=%s, want 1", got)
	}
	want := []uint16{a, b}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if _, tags := dsIntentKeytags(t, kdb, zone); !sameTags(tags, want) {
		t.Errorf("standby: the parent is asked for %v, want %v", tags, want)
	}

	// The operator rolls: the explicit withdrawal of A's DS.
	oldKid, newKid, err := kdb.RolloverKey(zone, "KSK", nil)
	if err != nil || oldKid != a || newKid != b {
		t.Fatalf("RolloverKey: old=%d new=%d err=%v", oldKid, newKid, err)
	}
	checkStep(t, kdb, zd, "rolled")
	if got := dsOf(t, kdb, zone, a); got != "0" {
		t.Errorf("retired KSK under none: ds=%s, want 0", got)
	}
	if _, tags := dsIntentKeytags(t, kdb, zone); !sameTags(tags, []uint16{b}) {
		t.Errorf("rolled: the parent is asked for %v, want {%d}", tags, b)
	}

	transitionRetiredToRemoved(context.Background(), &Conf, kdb, time.Now().Add(48*time.Hour), time.Hour)
	if st := ktKeyState(t, kdb, zone, a); st != DnskeyStateRemoved {
		t.Fatalf("after the margin: A is %s, want removed", st)
	}
	checkStep(t, kdb, zd, "removed")
	if _, tags := dsIntentKeytags(t, kdb, zone); !sameTags(tags, []uint16{b}) {
		t.Errorf("removed: the parent is asked for %v, want {%d}", tags, b)
	}
}

// Multi-DS: the DS is placed before the DNSKEY; a created pipeline key
// carries its DS intent from creation, the push carries it, the parent's
// confirmation moves it to ds-published, and the retired key keeps its DS
// until the withdraw phase removes the key. Every push equals the ds=1 rows
// at that moment.
func TestDsTimelineMultiDS(t *testing.T) {
	parent := ktInstallFakeParent(t)
	kdb := newTestKeyDB(t)
	const zone = "multids-timeline.example."
	pol := ktSequencePolicy(RolloverMethodMultiDS)
	zd := ktEngineZone(t, kdb, zone, fmt.Sprintf("%s 3600 IN SOA ns.%s hostmaster.%s 1 7200 1800 604800 7200\n%s 3600 IN NS ns.%s\nns.%s 3600 IN A 192.0.2.1\n", zone, zone, zone, zone, zone, zone), pol)
	a := ktGenKSK(t, kdb, zone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, zone, DnskeyStateActive, dns.ED25519)
	if err := RegisterBootstrapActiveKSK(kdb, zone, a, RolloverMethodMultiDS, dns.ED25519); err != nil {
		t.Fatal(err)
	}
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatal(err)
	}
	checkStep(t, kdb, zd, "start")

	t0 := time.Now()
	tick := func(step string, now time.Time) {
		t.Helper()
		before := len(parent.pushes())
		deps := ktDeps(zd, kdb, now)
		deps.Imr = &Imr{}
		if err := RolloverAutomatedTick(context.Background(), deps); err != nil {
			t.Fatalf("%s: tick: %v", step, err)
		}
		checkStep(t, kdb, zd, step)
		// A push made on this tick carries exactly the ds=1 rows.
		if pushes := parent.pushes(); len(pushes) > before {
			got := ktDSKeytags(pushes[len(pushes)-1])
			sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
			if want := dsOneSepKeytags(t, kdb, zone); !sameTags(got, want) {
				t.Errorf("%s: the push %v is not the ds=1 rows %v", step, got, want)
			}
		}
	}

	b, _, err := GenerateKskRolloverCreated(kdb, zone, "test", dns.ED25519, RolloverMethodMultiDS)
	if err != nil {
		t.Fatal(err)
	}
	if got := dsOf(t, kdb, zone, b); got != "1" {
		t.Errorf("created pipeline KSK: ds=%s, want 1 (its DS goes up before its DNSKEY)", got)
	}
	tick("arm", t0)
	tick("push", t0.Add(time.Second))
	pushes := parent.pushes()
	if len(pushes) != 1 {
		t.Fatalf("after the push tick: %d pushes, want 1", len(pushes))
	}
	if st := ktKeyState(t, kdb, zone, b); st != DnskeyStateCreated {
		t.Fatalf("B is %s before the parent confirmed, want created", st)
	}
	parent.serve(ktDSSubset(pushes[0], 3600, a, b))
	tick("confirm", t0.Add(pol.Rollover.ConfirmInitialWait+2*time.Second))
	if st := ktKeyState(t, kdb, zone, b); st != DnskeyStateDsPublished {
		t.Fatalf("B is %s after the parent served its DS, want ds-published", st)
	}
	if got := dsOf(t, kdb, zone, b); got != "1" {
		t.Errorf("ds-published: ds=%s, want 1", got)
	}

	// The rest of the pipeline through the state machine's own writes.
	for _, st := range []string{DnskeyStatePublished, DnskeyStateStandby} {
		if err := UpdateDnssecKeyState(kdb, zone, b, st); err != nil {
			t.Fatal(err)
		}
		checkStep(t, kdb, zd, st)
		if got := dsOf(t, kdb, zone, b); got != "1" {
			t.Errorf("%s: ds=%s, want 1", st, got)
		}
	}
	// The roll: A retired keeps its DS; the withdraw phase removes it, and
	// only then does a push leave A out.
	if _, _, err := AtomicRollover(&Conf, kdb, zone); err != nil {
		t.Fatalf("AtomicRollover: %v", err)
	}
	checkStep(t, kdb, zd, "rolled")
	if got := dsOf(t, kdb, zone, a); got != "1" {
		t.Errorf("retired KSK under multi-DS: ds=%s, want 1 until the withdrawal", got)
	}
	// The engine takes the rolled zone through the publish wait, a push that
	// still carries A (retired keeps its DS under multi-DS), the parent's
	// confirmation and the withdraw phase. Only A's removal drops its DS,
	// and the push after that leaves A out.
	tRoll := t0.Add(pol.Rollover.ConfirmInitialWait + 3*time.Second)
	tick("publish-wait", tRoll)
	tick("push-2", tRoll.Add(time.Second))
	pushes = parent.pushes()
	if len(pushes) != 2 {
		t.Fatalf("after the second push tick: %d pushes, want 2", len(pushes))
	}
	parent.serve(ktDSSubset(pushes[1], 3600, a, b))
	tConfirm := tRoll.Add(pol.Rollover.ConfirmInitialWait + 3*time.Second)
	tick("confirm-2", tConfirm)
	if st := ktKeyState(t, kdb, zone, a); st != DnskeyStateRetired {
		t.Fatalf("confirm-2: A is %s, want retired", st)
	}
	for _, p := range parent.pushes() {
		if !ktHasKeytag(ktDSKeytags(p), a) {
			t.Fatalf("a push without A's DS before A was withdrawn: %v", ktDSKeytags(p))
		}
	}
	tick("withdraw", tConfirm.Add(pol.Clamping.Margin+time.Second))
	if st := ktKeyState(t, kdb, zone, a); st != DnskeyStateRemoved {
		t.Fatalf("withdraw: A is %s, want removed", st)
	}
	if got := dsOf(t, kdb, zone, a); got != "0" {
		t.Errorf("removed KSK: ds=%s, want 0", got)
	}
	tAfter := tConfirm.Add(pol.Clamping.Margin + 2*time.Second)
	tick("after", tAfter)
	tick("after-push", tAfter.Add(time.Second))
	last := parent.pushes()[len(parent.pushes())-1]
	if tags := ktDSKeytags(last); ktHasKeytag(tags, a) || !ktHasKeytag(tags, b) {
		t.Errorf("after the withdrawal the last push is %v, want {%d} only", tags, b)
	}
}

// Algorithm rollover under multi-DS: the old head is active and signs but
// never gains a DS from the spawn on; every push is the ds=1 rows; the
// invariants hold at every tick.
func TestDsTimelineAlgRollover(t *testing.T) {
	parent := ktInstallFakeParent(t)
	kdb := newTestKeyDB(t)
	pol := ktSequencePolicy(RolloverMethodMultiDS)
	zd := ktEngineZone(t, kdb, ktAlgZone, ktAlgZoneText, pol)
	a := ktGenKSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, ktAlgZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatal(err)
	}
	checkStep(t, kdb, zd, "start")
	tick := func(step string, now time.Time) {
		t.Helper()
		before := len(parent.pushes())
		deps := ktDeps(zd, kdb, now)
		deps.Imr = &Imr{}
		if err := RolloverAutomatedTick(context.Background(), deps); err != nil {
			t.Fatalf("%s: tick: %v", step, err)
		}
		checkStep(t, kdb, zd, step)
		if got := dsOf(t, kdb, ktAlgZone, a); got != "0" {
			if st, _ := LoadKskAlgRollState(kdb, ktAlgZone); st != nil {
				t.Errorf("%s: the old head has ds=%s while the roll is in flight, want 0", step, got)
			}
		}
		for _, p := range parent.pushes() {
			if ktHasKeytag(ktDSKeytags(p), a) {
				t.Fatalf("%s: a push carried the old head's DS: %v", step, ktDSKeytags(p))
			}
		}
		// A push made on this tick carries exactly the ds=1 rows.
		if pushes := parent.pushes(); len(pushes) > before {
			got := ktDSKeytags(pushes[len(pushes)-1])
			sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
			if want := dsOneSepKeytags(t, kdb, ktAlgZone); !sameTags(got, want) {
				t.Errorf("%s: the push %v is not the ds=1 rows %v", step, got, want)
			}
		}
	}
	pol.KSKAlgorithm = dns.RSASHA256
	t0 := time.Now()
	dnskeyTTL := time.Duration(pol.TTLS.DNSKEY) * time.Second
	propagation := time.Minute
	tick("spawn", t0.Add(time.Second))
	st, _ := LoadKskAlgRollState(kdb, ktAlgZone)
	if st == nil || st.OldHeadKeyID != a {
		t.Fatalf("spawn: roll state %+v", st)
	}
	b := st.NewHeadKeyID
	if got := dsOf(t, kdb, ktAlgZone, b); got != "1" {
		t.Errorf("spawn: new head ds=%s, want 1", got)
	}
	tArm := t0.Add(propagation + dnskeyTTL + 30*time.Second)
	tick("wait-done", tArm)
	tPush := tArm.Add(time.Second)
	tick("push", tPush)
	pushes := parent.pushes()
	if len(pushes) != 1 || !sameTags(ktDSKeytags(pushes[0]), []uint16{b}) {
		t.Fatalf("push: %d pushes, first %v, want one push of {%d}", len(pushes), ktDSKeytags(pushes[0]), b)
	}
	parent.serve(ktDSSubset(pushes[0], 3600, b))
	tConfirm := tPush.Add(pol.Rollover.ConfirmInitialWait + time.Second)
	tick("confirm", tConfirm)
	if s := ktKeyState(t, kdb, ktAlgZone, a); s != DnskeyStateActive {
		t.Fatalf("confirm: A is %s, want active through the drain", s)
	}
	if got := dsOf(t, kdb, ktAlgZone, a); got != "0" {
		t.Errorf("drain: old head ds=%s, want 0", got)
	}
	tDone := tConfirm.Add(2*time.Hour + 30*time.Second)
	tick("drain-done", tDone)
	if s := ktKeyState(t, kdb, ktAlgZone, a); s != DnskeyStateRemoved {
		t.Fatalf("drain-done: A is %s, want removed", s)
	}
	if got := dsOf(t, kdb, ktAlgZone, a); got != "0" {
		t.Errorf("removed old head: ds=%s, want 0", got)
	}
	if got := dsOf(t, kdb, ktAlgZone, b); got != "1" {
		t.Errorf("new head after the roll: ds=%s, want 1", got)
	}
}
