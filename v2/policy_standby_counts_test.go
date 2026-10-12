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

	maintainStandbyKeys(context.Background(), noResignQ(), kdb, 1, 0)

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

// A policy with standby-zsks 0 keeps no standby, but the roll still gets its
// replacement: once the active ZSK's lifetime has elapsed the worker mints
// one on demand; before that, nothing.
func TestZeroStandbyZsksPreparesAReplacementWhenTheRollIsDue(t *testing.T) {
	kdb := newTestKeyDB(t)
	pol := &DnssecPolicy{Name: "nostandby", Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519,
		SigValidity: PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400}}
	pol.StandbyZSKs = intp(0)
	pol.ZSK.Lifetime = 3600
	standbyZone(t, kdb, "sbdue.example.", pol)
	standbyZone(t, kdb, "sbfresh.example.", pol)
	// the due zone's active ZSK went active two lifetimes ago
	old := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET active_at=? WHERE zonename=? AND flags=256 AND state=?`, old, "sbdue.example.", DnskeyStateActive); err != nil {
		t.Fatalf("age the active ZSK: %v", err)
	}

	maintainStandbyKeys(context.Background(), noResignQ(), kdb, 1, 0)

	if z := publishedOfRole(t, kdb, "sbdue.example.", false); z != 1 {
		t.Errorf("the due zone: minted %d ZSKs, want 1 (the replacement prepared on demand)", z)
	}
	if z := publishedOfRole(t, kdb, "sbfresh.example.", false); z != 0 {
		t.Errorf("the fresh zone: minted %d ZSKs, want 0 (no standby kept, roll not due)", z)
	}
	if !zskReplacementDue(kdb, "sbdue.example.", pol, time.Now()) || zskReplacementDue(kdb, "sbfresh.example.", pol, time.Now()) {
		t.Error("zskReplacementDue disagrees with the setup")
	}
}
