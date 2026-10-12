/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// S7 (key lifecycle ownership design §6, Q1): the standby counts as fields
// of the zone's DNSSEC policy. A policy may set standby-zsks and
// standby-ksks; unset leaves the global kasp count to apply, so a config
// without them keeps its behaviour.

func intp(n int) *int { return &n }

// standbyPolicyConf is a minimal same-algorithm policy conf.
func standbyPolicyConf() *DnssecPolicyConf {
	conf := &DnssecPolicyConf{Algorithm: "ED25519"}
	conf.KSK.Lifetime = "forever"
	conf.ZSK.Lifetime = "forever"
	conf.SigValidity.Default = "2w"
	return conf
}

// The parse keeps 0 and positive counts, leaves an unset count unset, and
// refuses a negative one.
func TestStandbyCountsParse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		zsks, ksks *int
		wantErr    string
	}{
		{name: "unset: the global count applies"},
		{name: "set", zsks: intp(2), ksks: intp(1)},
		{name: "zero is a count", zsks: intp(0), ksks: intp(0)},
		{name: "a negative ZSK count is refused", zsks: intp(-1), wantErr: "standby-zsks must be non-negative"},
		{name: "a negative KSK count is refused", ksks: intp(-2), wantErr: "standby-ksks must be non-negative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := standbyPolicyConf()
			conf.StandbyZSKs, conf.StandbyKSKs = tc.zsks, tc.ksks
			pol, err := ParseDnssecPolicyConfQuiet("p", conf)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v, want one naming %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			for _, role := range []struct {
				sep  bool
				want *int
			}{{false, tc.zsks}, {true, tc.ksks}} {
				n, ok := pol.StandbyCount(role.sep)
				if ok != (role.want != nil) || (ok && n != *role.want) {
					t.Errorf("StandbyCount(sep=%v) = %d,%v, want %v", role.sep, n, ok, role.want)
				}
			}
		})
	}
	var none *DnssecPolicy
	if n, ok := none.StandbyCount(false); n != 0 || ok {
		t.Errorf("a nil policy's StandbyCount = %d,%v, want 0,false", n, ok)
	}
}

// A template fills a count the policy leaves unset, and a policy's explicit
// 0 survives the template's count.
func TestStandbyCountsTemplateMerge(t *testing.T) {
	tmpl := &DnssecPolicyConf{Algorithm: "ED25519", StandbyZSKs: intp(2), StandbyKSKs: intp(1)}
	p := DnssecPolicyConf{Name: "p", StandbyZSKs: intp(0)}
	got := ExpandPolicyTemplate(p, tmpl)
	if got.StandbyZSKs == nil || *got.StandbyZSKs != 0 {
		t.Errorf("StandbyZSKs = %v, want the policy's explicit 0", got.StandbyZSKs)
	}
	if got.StandbyKSKs == nil || *got.StandbyKSKs != 1 {
		t.Errorf("StandbyKSKs = %v, want 1 from the template", got.StandbyKSKs)
	}
}

// The count with the fallback: the policy's own when set, else kasp's, else
// the default of one ZSK and no KSK.
func TestStandbyKeyCountFallsBackToKasp(t *testing.T) {
	conf := &Config{}
	plain := &DnssecPolicy{Name: "plain"}
	if z, k := conf.StandbyKeyCount(plain, false), conf.StandbyKeyCount(plain, true); z != 1 || k != 0 {
		t.Errorf("defaults: zsks %d ksks %d, want 1 and 0", z, k)
	}
	if z, k := conf.StandbyKeyCount(nil, false), conf.StandbyKeyCount(nil, true); z != 1 || k != 0 {
		t.Errorf("no policy: zsks %d ksks %d, want the defaults 1 and 0", z, k)
	}
	conf.Dnssec.Kasp.StandbyZskCount, conf.Dnssec.Kasp.StandbyKskCount = 3, 2
	if z, k := conf.StandbyKeyCount(plain, false), conf.StandbyKeyCount(plain, true); z != 3 || k != 2 {
		t.Errorf("kasp: zsks %d ksks %d, want 3 and 2", z, k)
	}
	own := &DnssecPolicy{Name: "own", StandbyZSKs: intp(0), StandbyKSKs: intp(1)}
	if z, k := conf.StandbyKeyCount(own, false), conf.StandbyKeyCount(own, true); z != 0 || k != 1 {
		t.Errorf("the policy's own: zsks %d ksks %d, want 0 and 1", z, k)
	}
}

// standbyZone is a signing zone bound to pol with an active KSK and ZSK and
// nothing in standby, registered so the worker's walk finds it.
func standbyZone(t *testing.T, kdb *KeyDB, name string, pol *DnssecPolicy) *ZoneData {
	t.Helper()
	text := fmt.Sprintf("%s 3600 IN SOA ns.%s hostmaster.%s 1 7200 1800 604800 7200\n%s 3600 IN NS ns.%s\nns.%s 3600 IN A 192.0.2.1\n", name, name, name, name, name, name)
	zd := ktEngineZone(t, kdb, name, text, pol)
	ktGenKSK(t, kdb, name, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, name, DnskeyStateActive, dns.ED25519)
	return zd
}

// publishedOfRole counts the zone's published keys of a role: what one tick
// of the standby maintenance mints.
func publishedOfRole(t *testing.T, kdb *KeyDB, zone string, sep bool) int {
	t.Helper()
	keys, err := GetDnssecKeysByState(kdb, zone, DnskeyStatePublished)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, k := range keys {
		if (k.Flags&dns.SEP != 0) == sep {
			n++
		}
	}
	return n
}

// The worker's standby maintenance reads the zone's policy first and falls
// back to the global counts: one tick over three zones under the globals
// (1, 0), one zone with no counts of its own, one with more of each role,
// one with none.
func TestStandbyMaintenanceReadsTheZonesPolicy(t *testing.T) {
	kdb := newTestKeyDB(t)
	plain := func(name string) *DnssecPolicy {
		return &DnssecPolicy{Name: name, Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519,
			SigValidity: PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400}}
	}
	fallback := plain("fallback")
	more := plain("more")
	more.StandbyZSKs, more.StandbyKSKs = intp(2), intp(1)
	none := plain("none")
	none.StandbyZSKs = intp(0)
	standbyZone(t, kdb, "sbfallback.example.", fallback)
	standbyZone(t, kdb, "sbmore.example.", more)
	standbyZone(t, kdb, "sbnone.example.", none)

	maintainStandbyKeys(context.Background(), noResignQ(), kdb, time.Minute, 1, 0)

	for _, tc := range []struct {
		zone       string
		zsks, ksks int
	}{
		{"sbfallback.example.", 1, 0},
		{"sbmore.example.", 2, 1},
		{"sbnone.example.", 0, 0},
	} {
		if z, k := publishedOfRole(t, kdb, tc.zone, false), publishedOfRole(t, kdb, tc.zone, true); z != tc.zsks || k != tc.ksks {
			t.Errorf("%s: minted %d ZSKs and %d KSKs, want %d and %d", tc.zone, z, k, tc.zsks, tc.ksks)
		}
	}
}

// Q1: the standby counts are the owner's fields on an owned zone. tdns's
// policy-set refuses a policy that changes one; the owner's binding applies
// it.
func TestStandbyCountsAreTheOwners(t *testing.T) {
	ctx := context.Background()
	kdb := newTestKeyDB(t)
	zd := ownerZone(t, kdb, "sbowned.example.")
	cur := *zd.DnssecPolicy
	zsks := cur
	zsks.Name = "mds-zsks"
	zsks.StandbyZSKs = intp(2)
	ksks := cur
	ksks.Name = "mds-ksks"
	ksks.StandbyKSKs = intp(1)
	publishPolicies(t, &cur, &zsks, &ksks)
	installOwner(t, &testOwner{owns: map[string]bool{zd.ZoneName: true}})

	for _, name := range []string{"mds-zsks", "mds-ksks"} {
		if _, err := setZonePolicy(ctx, zd, kdb, name); !errors.Is(err, ErrZoneOwned) {
			t.Errorf("tdns's policy-set of %q on an owned zone: err=%v, want ErrZoneOwned", name, err)
		}
	}
	if _, err := SetZonePolicyForOwner(ctx, zd, kdb, "mds-zsks"); err != nil {
		t.Fatalf("the owner's binding of mds-zsks: %v", err)
	}
	if n, ok := zd.DnssecPolicy.StandbyCount(false); !ok || n != 2 {
		t.Errorf("after the owner's binding the zone's ZSK standby count is %d,%v, want 2", n, ok)
	}
	if _, err := SetZonePolicyForOwner(ctx, zd, kdb, "mds-ksks"); err != nil {
		t.Fatalf("the owner's binding of mds-ksks: %v", err)
	}
	if n, ok := zd.DnssecPolicy.StandbyCount(true); !ok || n != 1 {
		t.Errorf("after the owner's binding the zone's KSK standby count is %d,%v, want 1", n, ok)
	}
}

// The owner-field comparison: a count set against one left to kasp differs,
// the same number set twice does not, and a mechanism change beside equal
// counts is not an owner-field change.
func TestOwnerPolicyFieldsIncludeStandbyCounts(t *testing.T) {
	a := ktMultiDSPolicy(dns.ED25519, dns.ED25519)
	b := *a
	b.StandbyZSKs = intp(1)
	if !ownerPolicyFieldsDiffer(a, &b) {
		t.Error("a ZSK standby count set against one left to kasp is not an owner-field change")
	}
	c := *a
	c.StandbyKSKs = intp(0)
	if !ownerPolicyFieldsDiffer(a, &c) {
		t.Error("a KSK standby count of 0 against one left to kasp is not an owner-field change")
	}
	a.StandbyZSKs, a.StandbyKSKs = intp(2), intp(1)
	d := *a
	d.StandbyZSKs, d.StandbyKSKs = intp(2), intp(1)
	d.SigValidity.Default++
	if ownerPolicyFieldsDiffer(a, &d) {
		t.Error("equal standby counts beside a mechanism change count as an owner-field change")
	}
}

// The policy listing carries the counts, absent when the global one applies.
func TestPolicyInfoShowsStandbyCounts(t *testing.T) {
	info := DnssecPolicyToInfo(DnssecPolicy{Name: "p", StandbyZSKs: intp(2)})
	if info.StandbyZSKs == nil || *info.StandbyZSKs != 2 || info.StandbyKSKs != nil {
		t.Errorf("info standby counts %v %v, want 2 and absent", info.StandbyZSKs, info.StandbyKSKs)
	}
}

// A policy that keeps no standby ZSK: the replacement is minted once the
// roll comes within the propagation window (propagation-delay plus the
// served DNSKEY TTL, what published takes to reach standby), not before and
// not at the lifetime, so it is standby when the roll fires; the roll
// promotes it, and the zone keeps none again. A manual request is minted
// at the request, with no lead. Lifetime 1 h, window 5 min + 10 min.
func TestZeroStandbyZsksMintTheReplacementAheadOfTheRoll(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf := noResignQ()
	const propagation = 5 * time.Minute
	pol := &DnssecPolicy{Name: "nostandby", Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519,
		SigValidity: PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400}}
	pol.StandbyZSKs = intp(0)
	pol.ZSK.Lifetime = 3600
	pol.TTLS.DNSKEY = 600
	soon := standbyZone(t, kdb, "sbsoon.example.", pol)
	standbyZone(t, kdb, "sbearly.example.", pol)
	standbyZone(t, kdb, "sbmanual.example.", pol)
	stamp := func(zone, column, state string, flags int, age time.Duration) {
		t.Helper()
		at := time.Now().UTC().Add(-age).Format(time.RFC3339)
		if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET `+column+`=? WHERE zonename=? AND flags=? AND state=?`, at, zone, flags, state); err != nil {
			t.Fatalf("%s: set %s: %v", zone, column, err)
		}
	}
	zsks := func(zone, state string) int {
		t.Helper()
		keys, err := GetDnssecKeysByState(kdb, zone, state)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, k := range keys {
			if k.Flags == 256 {
				n++
			}
		}
		return n
	}
	activeZSK := func(zone string) uint16 {
		t.Helper()
		keys, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if k.Flags == 256 {
				return k.KeyTag
			}
		}
		t.Fatalf("%s: no active ZSK", zone)
		return 0
	}
	// soon's roll is due in 10 min, inside the 15 min window; early's in 20 min, outside it
	stamp("sbsoon.example.", "active_at", DnskeyStateActive, 256, 50*time.Minute)
	stamp("sbearly.example.", "active_at", DnskeyStateActive, 256, 40*time.Minute)

	maintainStandbyKeys(context.Background(), conf, kdb, propagation, 1, 0)
	if z := zsks("sbsoon.example.", DnskeyStatePublished); z != 1 {
		t.Errorf("the zone whose roll is inside the window: minted %d ZSKs, want 1", z)
	}
	for _, zone := range []string{"sbearly.example.", "sbmanual.example."} {
		if z := zsks(zone, DnskeyStatePublished); z != 0 {
			t.Errorf("%s: minted %d ZSKs, want 0 (no standby kept, no roll in the window)", zone, z)
		}
	}

	// a manual request: minted at the request
	if err := SetZskManualRolloverRequest(kdb, "sbmanual.example.", time.Now(), time.Now()); err != nil {
		t.Fatalf("manual request: %v", err)
	}
	maintainStandbyKeys(context.Background(), conf, kdb, propagation, 1, 0)
	if z := zsks("sbmanual.example.", DnskeyStatePublished); z != 1 {
		t.Errorf("the manual request: minted %d ZSKs, want 1", z)
	}

	// the window passes: the key is standby before the lifetime ends, and
	// nothing more is minted while the roll waits for it
	stamp("sbsoon.example.", "published_at", DnskeyStatePublished, 256, propagation+10*time.Minute+time.Second)
	transitionPublishedToStandby(conf, kdb, time.Now(), propagation)
	if s, p := zsks("sbsoon.example.", DnskeyStateStandby), zsks("sbsoon.example.", DnskeyStatePublished); s != 1 || p != 0 {
		t.Fatalf("after the window: %d standby and %d published ZSKs, want 1 and 0", s, p)
	}
	maintainStandbyKeys(context.Background(), conf, kdb, propagation, 1, 0)
	if p := zsks("sbsoon.example.", DnskeyStatePublished); p != 0 {
		t.Errorf("with the replacement standing by: minted %d more, want 0", p)
	}

	// the lifetime ends: the roll promotes the standby, and the zone keeps none again
	old := activeZSK("sbsoon.example.")
	stamp("sbsoon.example.", "active_at", DnskeyStateActive, 256, 61*time.Minute)
	if err := rolloverZskForZone(context.Background(), conf, kdb, soon, propagation, time.Now()); err != nil {
		t.Fatalf("the roll: %v", err)
	}
	if now := activeZSK("sbsoon.example."); now == old {
		t.Errorf("the roll did not promote the standby: active ZSK still %d", old)
	}
	if s := zsks("sbsoon.example.", DnskeyStateStandby); s != 0 {
		t.Errorf("after the roll: %d standby ZSKs, want 0", s)
	}
	if zskReplacementDue(kdb, "sbsoon.example.", pol, time.Now(), propagation) {
		t.Error("after the roll the replacement is reported due")
	}
	maintainStandbyKeys(context.Background(), conf, kdb, propagation, 1, 0)
	if p := zsks("sbsoon.example.", DnskeyStatePublished); p != 0 {
		t.Errorf("after the roll: minted %d ZSKs, want 0", p)
	}
}
