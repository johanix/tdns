package tdns

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// S1b: the ds column. The expectations follow design §3.4 as amended on
// 2026-09-14: per-model, retired as each model treats it today, and a
// created KSK under multi-DS carries its DS intent from creation.

// wantDs is the table for a KSK: model -> state -> ds.
var wantDs = map[DSModel]map[string]bool{
	DSModelMultiDS: {
		DnskeyStateCreated: true, DnskeyStateDsPublished: true, DnskeyStatePublished: true,
		DnskeyStateStandby: true, DnskeyStateActive: true, DnskeyStateRetired: true, DnskeyStateRemoved: false,
	},
	DSModelNone: {
		DnskeyStateCreated: false, DnskeyStateDsPublished: true, DnskeyStatePublished: false,
		DnskeyStateStandby: true, DnskeyStateActive: true, DnskeyStateRetired: false, DnskeyStateRemoved: false,
	},
	DSModelDoubleSignature: {
		DnskeyStateCreated: false, DnskeyStateDsPublished: true, DnskeyStatePublished: false,
		DnskeyStateStandby: true, DnskeyStateActive: true, DnskeyStateRetired: false, DnskeyStateRemoved: false,
	},
}

var tdnsKeyStates = []string{DnskeyStateCreated, DnskeyStateDsPublished, DnskeyStatePublished, DnskeyStateStandby, DnskeyStateActive, DnskeyStateRetired, DnskeyStateRemoved}

// T1b.1: every state x model gives the design's ds; a ZSK never has one; a
// multi-provider zone and the owner's states get no answer from tdns.
func TestDsTableFollowsTheDesign(t *testing.T) {
	for model, states := range wantDs {
		for state, want := range states {
			got := dsFlagFor(model, state, true)
			if !got.Valid || got.Bool != want {
				t.Errorf("%s KSK %s: ds=%v (valid=%v), want %v", model, state, got.Bool, got.Valid, want)
			}
			if z := dsFlagFor(model, state, false); !z.Valid || z.Bool {
				t.Errorf("%s ZSK %s: ds=%v (valid=%v), want 0", model, state, z.Bool, z.Valid)
			}
		}
		for _, mp := range []string{DnskeyStateMpdist, DnskeyStateForeign, DnskeyStateMpremove} {
			if v := dsFlagFor(model, mp, true); v.Valid {
				t.Errorf("%s %s: tdns wrote ds=%v; the owner's states must stay unknown", model, mp, v.Bool)
			}
		}
	}
	for _, state := range tdnsKeyStates {
		if v := dsFlagFor(DSModelMultiProvider, state, true); v.Valid {
			t.Errorf("multi-provider zone, %s: tdns wrote ds=%v; the owner decides", state, v.Bool)
		}
	}
}

// dsTestZone registers a signing zone with a policy of the given rollover
// method, so the writers can look up its DS model.
func dsTestZone(t *testing.T, kdb *KeyDB, name string, method RolloverMethod) *ZoneData {
	t.Helper()
	pol := ktMultiDSPolicy(dns.ED25519, dns.ED25519)
	pol.Rollover.Method = method
	pol.Rollover.ParentAgent = "127.0.0.1:1"
	zd := testZone(t, name, fmt.Sprintf("%s 3600 IN SOA ns.%s hostmaster.%s 1 7200 1800 604800 7200\n%s 3600 IN NS ns.%s\nns.%s 3600 IN A 192.0.2.1\n", name, name, name, name, name, name))
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true}
	zd.DnssecPolicy = pol
	zd.DnssecPolicyName = pol.Name
	zd.InstallInitialSnapshot()
	return zd
}

func dsOf(t *testing.T, kdb *KeyDB, zone string, keyid uint16) string {
	t.Helper()
	_, _, ds := readKeyRowFlags(t, kdb, zone, keyid)
	return flagString(ds)
}

// The same table through the writers: a state write on a loaded zone sets ds
// by the zone's model, including retired as the model treats it.
func TestStateWritesSetDsByTheZonesModel(t *testing.T) {
	kdb := newTestKeyDB(t)
	for model, method := range map[DSModel]RolloverMethod{DSModelNone: RolloverMethodNone, DSModelMultiDS: RolloverMethodMultiDS} {
		zone := fmt.Sprintf("%s.ds.example.", model)
		dsTestZone(t, kdb, zone, method)
		// Real keys: a transition on a loaded zone republishes its signing set.
		ksk := ktGenKSK(t, kdb, zone, DnskeyStateCreated, dns.ED25519)
		zsk := ktGenZSK(t, kdb, zone, DnskeyStateCreated, dns.ED25519)
		if got, want := dsOf(t, kdb, zone, ksk), boolFlag(wantDs[model][DnskeyStateCreated]); got != want {
			t.Errorf("%s: created KSK ds=%s, want %s", model, got, want)
		}
		for _, state := range []string{DnskeyStatePublished, DnskeyStateStandby, DnskeyStateActive, DnskeyStateRetired, DnskeyStateRemoved} {
			if err := UpdateDnssecKeyState(kdb, zone, ksk, state); err != nil {
				t.Fatalf("%s: KSK to %s: %v", model, state, err)
			}
			if got, want := dsOf(t, kdb, zone, ksk), boolFlag(wantDs[model][state]); got != want {
				t.Errorf("%s: KSK %s: ds=%s, want %s", model, state, got, want)
			}
			if err := UpdateDnssecKeyState(kdb, zone, zsk, state); err != nil {
				t.Fatalf("%s: ZSK to %s: %v", model, state, err)
			}
			if got := dsOf(t, kdb, zone, zsk); got != "0" {
				t.Errorf("%s: ZSK %s: ds=%s, want 0", model, state, got)
			}
		}
	}
	// A zone that is not loaded: the writer cannot know the model, ds stays unknown.
	rng := newTestRand(45)
	k := insertTestKeyRow(t, kdb, "unloaded.ds.example.", DnskeyStateActive, "KSK", rng)
	if got := dsOf(t, kdb, "unloaded.ds.example.", k); got != "NULL" {
		t.Errorf("unloaded zone: ds=%s, want NULL", got)
	}
}

// The old head of an in-flight algorithm rollover is active and signs, but
// has no DS: from the spawn on, and back once the roll is cleared.
func TestAlgRolloverOldHeadHasNoDs(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "algroll.ds.example."
	zd := dsTestZone(t, kdb, zone, RolloverMethodMultiDS)
	old := ktGenKSK(t, kdb, zone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, zone, DnskeyStateActive, dns.ED25519)
	if got := dsOf(t, kdb, zone, old); got != "1" {
		t.Fatalf("active KSK before the roll: ds=%s, want 1", got)
	}
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatal(err)
	}
	zd.DnssecPolicy.KSKAlgorithm = dns.RSASHA256
	deps := ktDeps(zd, kdb, time.Now())
	deps.Imr = &Imr{}
	ktInstallFakeParent(t)
	if err := RolloverAutomatedTick(context.Background(), deps); err != nil {
		t.Fatalf("spawn tick: %v", err)
	}
	st, err := LoadKskAlgRollState(kdb, zone)
	if err != nil || st == nil || st.OldHeadKeyID != old {
		t.Fatalf("no algorithm roll after the spawn tick: %+v %v", st, err)
	}
	if got := dsOf(t, kdb, zone, old); got != "0" {
		t.Errorf("old head after the spawn: ds=%s, want 0", got)
	}
	if got := dsOf(t, kdb, zone, st.NewHeadKeyID); got != "1" {
		t.Errorf("new head after the spawn: ds=%s, want 1", got)
	}
	if vs := violationsByInvariant(CheckKeyInvariants(kdb, zd)); len(vs["I9"]) != 0 || len(vs["I3"]) != 0 || len(vs["I1"]) != 0 {
		t.Errorf("after the spawn: %s", violationList(CheckKeyInvariants(kdb, zd)))
	}
	// Abort: the old head is a plain active key again, with its DS.
	if _, err := AbortKskAlgRollover(context.Background(), &Conf, kdb, zone); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if got := dsOf(t, kdb, zone, old); got != "1" {
		t.Errorf("old head after the abort: ds=%s, want 1", got)
	}
}

// T1b.2: today's readers, kept here as the reference, against the ds-based
// answer, over every small keystore x model and seeded random ones. The
// reference for none and double-signature is dsBelongsAtParent's
// classification (DSIntentForZone); for multi-DS it is the rollover target.
// Allowed differences: a published KSK outside multi-DS (#635) and the
// algorithm rollover's old head. Any other difference fails.
func refDsIntentByState(state string) bool {
	switch state {
	case DnskeyStateDsPublished, DnskeyStatePublished, DnskeyStateStandby, DnskeyStateActive:
		return true
	}
	return false
}

func refRolloverTargetByState(state string) bool {
	switch state {
	case DnskeyStateCreated, DnskeyStateDsPublished, DnskeyStateStandby, DnskeyStatePublished, DnskeyStateActive, DnskeyStateRetired:
		return true
	}
	return false
}

type dsRow struct {
	keyid uint16
	state string
	sep   bool
	ds    *int64
}

func dsRows(t *testing.T, kdb *KeyDB, zone string) []dsRow {
	t.Helper()
	rows, err := kdb.DB.Query(`SELECT keyid, state, flags, ds FROM DnssecKeyStore WHERE zonename=? ORDER BY keyid`, zone)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []dsRow
	for rows.Next() {
		var r dsRow
		var flags int
		if err := rows.Scan(&r.keyid, &r.state, &flags, &r.ds); err != nil {
			t.Fatal(err)
		}
		r.sep = flags&int(dns.SEP) != 0
		out = append(out, r)
	}
	return out
}

// assertDsAgrees compares the reference for the model with the ds column and
// reports every difference not on the allowed list.
func assertDsAgrees(t *testing.T, kdb *KeyDB, zone string, model DSModel, oldHead uint16) {
	t.Helper()
	for _, r := range dsRows(t, kdb, zone) {
		if !r.sep {
			if r.ds == nil || *r.ds != 0 {
				t.Errorf("%s %s: ZSK %d has ds=%s, want 0", zone, model, r.keyid, flagString(r.ds))
			}
			continue
		}
		var ref bool
		if model == DSModelMultiDS {
			ref = refRolloverTargetByState(r.state) && r.keyid != oldHead
		} else {
			ref = refDsIntentByState(r.state)
		}
		if r.ds == nil {
			t.Errorf("%s %s: KSK %d (%s) has ds unset", zone, model, r.keyid, r.state)
			continue
		}
		got := *r.ds != 0
		if got == ref {
			continue
		}
		switch {
		case model != DSModelMultiDS && r.state == DnskeyStatePublished && ref && !got:
			// tdns #635: allowed.
		case r.keyid == oldHead && ref && !got:
			// the algorithm rollover's old head: allowed.
		default:
			t.Errorf("%s %s: KSK %d (%s): from state %v, from ds %v: not an allowed difference", zone, model, r.keyid, r.state, ref, got)
		}
	}
}

func TestOldAndNewDsAgreeOnEverySmallKeystore(t *testing.T) {
	kdb := newTestKeyDB(t)
	rng := newTestRand(50)
	for model, method := range map[DSModel]RolloverMethod{DSModelNone: RolloverMethodNone, DSModelMultiDS: RolloverMethodMultiDS, DSModelDoubleSignature: RolloverMethodDoubleSignature} {
		for _, state := range tdnsKeyStates {
			for _, role := range []string{"KSK", "ZSK"} {
				for n := 0; n <= 2; n++ {
					zone := fmt.Sprintf("%s-%s-%s-%d.ds.example.", model, state, role, n)
					dsTestZone(t, kdb, zone, method)
					insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "KSK", rng)
					insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "ZSK", rng)
					for i := 0; i < n; i++ {
						insertTestKeyRow(t, kdb, zone, state, role, rng)
					}
					assertDsAgrees(t, kdb, zone, model, 0)
				}
			}
		}
	}
}

func TestOldAndNewDsAgreeOnRandomKeystores(t *testing.T) {
	kdb := newTestKeyDB(t)
	models := []struct {
		m DSModel
		r RolloverMethod
	}{{DSModelNone, RolloverMethodNone}, {DSModelMultiDS, RolloverMethodMultiDS}, {DSModelDoubleSignature, RolloverMethodDoubleSignature}}
	for seed := uint64(0); seed < 100; seed++ {
		rng := newTestRand(seed + 1000)
		mm := models[int(seed)%len(models)]
		zone := fmt.Sprintf("seed%d.ds.example.", seed)
		dsTestZone(t, kdb, zone, mm.r)
		for _, state := range tdnsKeyStates {
			for _, role := range []string{"KSK", "ZSK"} {
				for i, n := 0, rng.IntN(3); i < n; i++ {
					insertTestKeyRow(t, kdb, zone, state, role, rng)
				}
			}
		}
		assertDsAgrees(t, kdb, zone, mm.m, 0)
	}
}

// T1b.3: the S1a fixtures, which carry ds unset, get ds from the one-time
// pass per the table, and the pass reports exactly the allowed differences.
func TestFixturesGetDsFromTheOneTimePass(t *testing.T) {
	cases := map[string]struct {
		method   RolloverMethod
		mp       bool
		wantDiff []string
	}{
		"none-standby-ksk":   {method: RolloverMethodNone},
		"multi-ds-pipeline":  {method: RolloverMethodMultiDS},
		"alg-roll-in-flight": {method: RolloverMethodMultiDS, wantDiff: []string{DsDiffAlgRollOldHead}},
		"zsk-pipeline":       {method: RolloverMethodNone},
		"multi-provider":     {mp: true},
		"removed-key":        {method: RolloverMethodNone},
	}
	for _, fx := range keyFixtures {
		c, ok := cases[fx.name]
		if !ok {
			t.Fatalf("fixture %s has no case here", fx.name)
		}
		t.Run(fx.name, func(t *testing.T) {
			kdb := loadKeyFixture(t, fx.name)
			var zd *ZoneData
			if c.mp {
				zd = testZone(t, fx.zone, fmt.Sprintf("%s 3600 IN SOA ns.%s hostmaster.%s 1 7200 1800 604800 7200\n%s 3600 IN NS ns.%s\n", fx.zone, fx.zone, fx.zone, fx.zone, fx.zone))
				registerZones(t, zd)
				zd.KeyDB = kdb
				zd.Options = map[ZoneOption]bool{OptInlineSigning: true, OptMultiProvider: true}
			} else {
				zd = dsTestZone(t, kdb, fx.zone, c.method)
			}
			rep, err := kdb.FillDsForZone(zd)
			if err != nil {
				t.Fatalf("pass: %v", err)
			}
			var kinds []string
			for _, d := range rep.Differences {
				kinds = append(kinds, d.Kind)
			}
			if fmt.Sprint(kinds) != fmt.Sprint(c.wantDiff) {
				t.Errorf("differences %v, want %v", kinds, c.wantDiff)
			}
			rows := dsRows(t, kdb, fx.zone)
			if c.mp {
				for _, r := range rows {
					if r.ds != nil {
						t.Errorf("multi-provider zone: key %d (%s) got ds=%d from tdns's pass", r.keyid, r.state, *r.ds)
					}
				}
				return
			}
			model := dsModelForZone(zd)
			var oldHead uint16
			if st, _ := LoadKskAlgRollState(kdb, fx.zone); st != nil {
				oldHead = st.OldHeadKeyID
			}
			for _, r := range rows {
				want := false
				if r.sep && r.keyid != oldHead {
					want = wantDs[model][r.state]
				}
				if r.ds == nil || (*r.ds != 0) != want {
					t.Errorf("key %d (%s, sep=%v): ds=%s, want %s", r.keyid, r.state, r.sep, flagString(r.ds), boolFlag(want))
				}
			}
			assertDsAgrees(t, kdb, fx.zone, model, oldHead)
			if vs := CheckKeyRowInvariants(kdb, fx.zone); len(vs) != 0 {
				t.Errorf("after the pass: %s", violationList(vs))
			}
			// A second pass touches nothing.
			rep2, err := kdb.FillDsForZone(zd)
			if err != nil || rep2.Filled != 0 {
				t.Errorf("second pass filled %d rows (err=%v), want 0", rep2.Filled, err)
			}
		})
	}
}

// T1b.4: with any SEP row's ds unset, the DS intent is unknown, the DS engine
// leaves the served CDS as it is, and nothing is sent to the parent.
func TestUnsetDsMeansUnknown(t *testing.T) {
	r := buildDSEngineRig(t, 0, false)
	zd, kdb := r.zd, r.kdb
	zd.Options[OptInlineSigning] = true
	zd.DnssecPolicy = ktMultiDSPolicy(dns.ED25519, dns.ED25519)
	zd.DnssecPolicy.Rollover.Method = RolloverMethodNone
	rng := newTestRand(60)
	ksk := insertTestKeyRow(t, kdb, zd.ZoneName, DnskeyStateActive, "KSK", rng)
	standby := insertTestKeyRow(t, kdb, zd.ZoneName, DnskeyStateStandby, "KSK", rng)
	insertTestKeyRow(t, kdb, zd.ZoneName, DnskeyStateActive, "ZSK", rng)
	intent, err := DSIntentForZone(kdb, zd.ZoneName, dns.SHA256)
	if err != nil || !intent.Known || len(intent.Set) != 2 {
		t.Fatalf("with ds set on both KSKs: known=%v set=%d err=%v, want known with 2", intent.Known, len(intent.Set), err)
	}
	// One SEP row loses its ds: the answer is unknown, whatever the other says.
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET ds=NULL WHERE zonename=? AND keyid=?`, zd.ZoneName, standby); err != nil {
		t.Fatal(err)
	}
	intent, err = DSIntentForZone(kdb, zd.ZoneName, dns.SHA256)
	if err != nil || intent.Known {
		t.Errorf("with one ds unset: known=%v err=%v, want unknown", intent.Known, err)
	}
	// The DS engine leaves a served CDS alone.
	cds := cdsFor(zd.ZoneName, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	stageCDS(t, zd, cds)
	before := servedCDS(t, zd)
	kdb.followKeysWithCDS(context.Background(), zd)
	if after := servedCDS(t, zd); !cdsTupleSetsEqual(before, after) {
		t.Errorf("the DS engine changed a CDS while a ds was unset: %v -> %v", tupleKeyids(before), tupleKeyids(after))
	}
	// And a ds of 0 on every SEP row is a known, empty answer: withdraw.
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET ds=0 WHERE zonename=? AND keyid IN (?, ?)`, zd.ZoneName, ksk, standby); err != nil {
		t.Fatal(err)
	}
	intent, err = DSIntentForZone(kdb, zd.ZoneName, dns.SHA256)
	if err != nil || !intent.Known || len(intent.Set) != 0 {
		t.Errorf("with every ds 0: known=%v set=%d err=%v, want known and empty", intent.Known, len(intent.Set), err)
	}
}

var _ = sql.NullBool{}
