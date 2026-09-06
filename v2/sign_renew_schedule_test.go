package tdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// setExpiration rewrites, in the published snapshot, when one RRset's signatures
// expire -- without making them due. Used to plant a known minimum.
func setExpiration(t *testing.T, zd *ZoneData, name string, rrtype uint16, at time.Time) {
	t.Helper()
	od := getOwnerFrom(zd.publishedSnapshot(), name)
	if od == nil {
		t.Fatalf("%s: no such owner", name)
	}
	sigs := od.RRtypes.GetOnlyRRSet(rrtype).RRSIGs
	if len(sigs) == 0 {
		t.Fatalf("%s %s carries no signature", name, dns.TypeToString[rrtype])
	}
	for _, sig := range sigs {
		sig.(*dns.RRSIG).Expiration = uint32(at.Unix())
	}
}

// The schedule must be derived from the same threshold the check applies, or a
// wake lands after the renewal it was aiming at.
func TestRenewalScheduleMatchesTheSignatureThreshold(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	// A known minimum: one RRset expiring well before the rest, but not yet due.
	expiry := time.Now().Add(48 * time.Hour)
	setExpiration(t, zd, "alpha.renew.example.", dns.TypeA, expiry)

	renewed, err := zd.RenewZoneSignatures(kdb)
	if err != nil {
		t.Fatal(err)
	}
	if renewed != 0 {
		t.Fatalf("renewed %d RRsets; a signature 48h from expiry is not due", renewed)
	}

	due, ok := zd.resignDue()
	if !ok {
		t.Fatal("the pass walked the whole zone and still reported no schedule")
	}

	// expiry, less the served TTL, the propagation delay and one scan interval.
	want := expiry.Add(-(3600*time.Second + Conf.KaspPropagationDelay() + resignScanInterval()))
	if delta := due.Sub(want); delta > time.Second || delta < -time.Second {
		t.Errorf("scheduled for %s, want %s (%s off): the schedule and NeedsResigning must"+
			" use the same threshold, or the wake lands after the check",
			due.UTC(), want.UTC(), delta)
	}
	if !due.After(time.Now()) {
		t.Errorf("scheduled in the past (%s) for a signature that is not due", due.UTC())
	}
}

// An estimate computed from a version that is no longer published says nothing
// about the one that is: another path may have rewritten signatures with a
// different validity.
func TestRenewalScheduleIsDiscardedAfterAnUnrelatedPublish(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	if _, err := zd.RenewZoneSignatures(kdb); err != nil {
		t.Fatal(err)
	}
	if _, ok := zd.resignDue(); !ok {
		t.Fatal("no schedule after a full walk")
	}

	rr, err := dns.NewRR("delta.renew.example. 3600 IN A 10.0.0.4")
	if err != nil {
		t.Fatal(err)
	}
	applyRR(t, zd, kdb, VerbAddRR, rr.String())

	if due, ok := zd.resignDue(); ok {
		t.Errorf("the schedule (%s) survived a publish that may have rewritten signatures;"+
			" sleeping on it could miss a renewal", due.UTC())
	}
}

// A pass that renews recomputes wholesale from what it published. Lowering the
// old estimate incrementally would leave a wake scheduled for a signature that
// no longer exists.
func TestRenewalScheduleIsRecomputedAfterRenewing(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	ageSignatures(t, zd, "alpha.renew.example.", dns.TypeA)

	renewed, err := zd.RenewZoneSignatures(kdb)
	if err != nil {
		t.Fatal(err)
	}
	if renewed == 0 {
		t.Fatal("nothing was renewed, so there is no recomputation to test")
	}

	due, ok := zd.resignDue()
	if !ok {
		t.Fatal("the pass published and then left no schedule; the resigner would fall" +
			" back to its coarse tick on every zone it renews")
	}
	if !due.After(time.Now()) {
		t.Errorf("still scheduled in the past (%s) after renewing the signature that was due",
			due.UTC())
	}
	if snap := zd.publishedSnapshot(); zd.nextResign.Load().serial != snap.Serial {
		t.Errorf("the schedule was recorded against serial %d but %d is published",
			zd.nextResign.Load().serial, snap.Serial)
	}
}

// The estimate is a minimum, and the RRset holding it can be deleted. An
// estimate that only ever decreased would keep waking for a signature that is
// gone.
func TestRenewalScheduleRisesWhenTheMinimumHolderIsRemoved(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	setExpiration(t, zd, "alpha.renew.example.", dns.TypeA, time.Now().Add(48*time.Hour))
	if _, err := zd.RenewZoneSignatures(kdb); err != nil {
		t.Fatal(err)
	}
	low, ok := zd.resignDue()
	if !ok {
		t.Fatal("no schedule")
	}

	applyRR(t, zd, kdb, VerbDelRR, "alpha.renew.example. 3600 IN A 10.0.0.1")

	if _, err := zd.RenewZoneSignatures(kdb); err != nil {
		t.Fatal(err)
	}
	high, ok := zd.resignDue()
	if !ok {
		t.Fatal("no schedule after the deletion")
	}
	if !high.After(low) {
		t.Errorf("the schedule stayed at %s after the RRset holding that minimum was"+
			" deleted (now %s); it must be recomputed, not lowered", low.UTC(), high.UTC())
	}
}

// The wake is bounded at both ends, and an unknown is never slept through.
func TestNextResignWakeBounds(t *testing.T) {
	const floor = 60 * time.Second

	zone := func(due time.Time, known bool) *ZoneData {
		zd := &ZoneData{
			ZoneName: "b.example.",
			Options:  map[ZoneOption]bool{OptInlineSigning: true},
		}
		snap := &zoneSnapshot{Serial: 7}
		zd.snapshot.Store(snap)
		if known {
			zd.setResignSchedule(due, snap.Serial)
		}
		return zd
	}

	for _, tc := range []struct {
		name  string
		zones map[string]*ZoneData
		want  time.Duration
		why   string
	}{
		{
			name:  "nothing watched",
			zones: map[string]*ZoneData{},
			want:  resignSafetyTick,
			why:   "with no zones there is nothing to be early for",
		},
		{
			name:  "a zone with no estimate",
			zones: map[string]*ZoneData{"a": zone(time.Time{}, false)},
			want:  floor,
			why:   "sleeping through an unknown is the one thing this must not do",
		},
		{
			name:  "due sooner than the floor",
			zones: map[string]*ZoneData{"a": zone(time.Now().Add(-time.Hour), true)},
			want:  floor,
			why:   "a zone stuck reporting the past must not spin the engine",
		},
		{
			name:  "due beyond the safety tick",
			zones: map[string]*ZoneData{"a": zone(time.Now().Add(14*24*time.Hour), true)},
			want:  resignSafetyTick,
			why:   "the ceiling is what turns a wrong estimate into a late renewal, not a missed one",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextResignWake(tc.zones, floor); got != tc.want {
				t.Errorf("slept %s, want %s: %s", got, tc.want, tc.why)
			}
		})
	}

	t.Run("due between the bounds", func(t *testing.T) {
		zones := map[string]*ZoneData{"a": zone(time.Now().Add(10*time.Minute), true)}
		got := nextResignWake(zones, floor)
		if got < 9*time.Minute || got > 10*time.Minute {
			t.Errorf("slept %s, want about ten minutes: between the bounds the estimate is"+
				" used as it stands", got)
		}
	})

	t.Run("the earliest zone wins", func(t *testing.T) {
		zones := map[string]*ZoneData{
			"far":  zone(time.Now().Add(50*time.Minute), true),
			"near": zone(time.Now().Add(5*time.Minute), true),
		}
		if got := nextResignWake(zones, floor); got > 5*time.Minute {
			t.Errorf("slept %s, past the zone that is due in five minutes", got)
		}
	})
}

// The apex SOA is not collected for signing, but it is still a signature with an
// expiry, and a publish is the only thing that renews it. If the walk left it out
// of the schedule too, a zone whose SOA is the earliest to cross would be
// scheduled past it -- and the engine would sleep, bounded only by the safety
// tick, while the signature that every denial depends on expired.
func TestRenewalScheduleAccountsForTheApexSoa(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	// The SOA the earliest to cross, by a wide margin, but not yet due.
	expiry := time.Now().Add(48 * time.Hour)
	od := getOwnerFrom(zd.publishedSnapshot(), zd.ZoneName)
	for _, sig := range od.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs {
		sig.(*dns.RRSIG).Expiration = uint32(expiry.Unix())
	}

	renewed, err := zd.RenewZoneSignatures(kdb)
	if err != nil {
		t.Fatal(err)
	}
	if renewed != 0 {
		t.Fatalf("renewed %d; a signature 48h out is not due yet", renewed)
	}

	due, ok := zd.resignDue()
	if !ok {
		t.Fatal("no schedule")
	}
	want := expiry.Add(-(3600*time.Second + Conf.KaspPropagationDelay() + resignScanInterval()))
	if delta := due.Sub(want); delta > time.Second || delta < -time.Second {
		t.Errorf("scheduled for %s, want %s: the apex SOA's crossing has to reach nextDue,"+
			" or the engine sleeps past the one signature it cannot collect",
			due.UTC(), want.UTC())
	}
}
