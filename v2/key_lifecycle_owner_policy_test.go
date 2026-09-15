package tdns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// publishPolicies adds the policies to the live runtime config for the
// test and restores the snapshot afterwards.
func publishPolicies(t *testing.T, pols ...*DnssecPolicy) {
	t.Helper()
	old := liveConfig.Load()
	rc := *old
	rc.DnssecPolicies = map[string]DnssecPolicy{}
	for k, v := range old.DnssecPolicies {
		rc.DnssecPolicies[k] = v
	}
	for _, p := range pols {
		rc.DnssecPolicies[p.Name] = *p
	}
	liveConfig.Store(&rc)
	t.Cleanup(func() { liveConfig.Store(old) })
}

// The owner's policy binding (S3, design Q1): on an owned zone tdns's
// policy-set refuses a policy that changes the owner's fields; the owner's
// own binding applies it, and the zone is resigned under it with no key
// row written. A change of mode, algorithm or DS model is not a binding
// and is refused. A zone nobody owns keeps policy-set.
func TestSetZonePolicyForOwner(t *testing.T) {
	ctx := context.Background()
	kdb := newTestKeyDB(t)
	zd := ownerZone(t, kdb, "polowned.example.")
	cur := *zd.DnssecPolicy
	longer := cur
	longer.Name = "mds-long"
	longer.ZSK = KeyLifetime{Lifetime: 60 * 86400}
	longer.Clamping.Margin = 2 * time.Minute
	rsa := cur
	rsa.Name = "mds-rsa"
	rsa.KSKAlgorithm = dns.RSASHA256
	model := cur
	model.Name = "mds-3"
	model.Rollover.NumDS = 3
	publishPolicies(t, &cur, &longer, &rsa, &model)
	owner := &testOwner{owns: map[string]bool{zd.ZoneName: true}}
	installOwner(t, owner)

	if _, err := setZonePolicy(ctx, zd, kdb, "mds-long"); !errors.Is(err, ErrZoneOwned) {
		t.Fatalf("tdns's policy-set with a longer ZSK lifetime on an owned zone: err=%v, want ErrZoneOwned", err)
	}
	resetKeystoreWrites(t, kdb)
	msg, err := SetZonePolicyForOwner(ctx, zd, kdb, "mds-long")
	if err != nil {
		t.Fatalf("the owner's binding: %v", err)
	}
	if !strings.Contains(msg, "mds-long") {
		t.Errorf("the owner's binding message does not name the policy: %q", msg)
	}
	if zd.DnssecPolicyName != "mds-long" || zd.DnssecPolicy == nil || zd.DnssecPolicy.ZSK.Lifetime != 60*86400 || zd.DnssecPolicy.Clamping.Margin != 2*time.Minute {
		t.Errorf("after the owner's binding: name %q policy %+v", zd.DnssecPolicyName, zd.DnssecPolicy)
	}
	if w := keystoreWrites(t, kdb); len(w) != 0 {
		t.Errorf("the owner's binding wrote key rows: %v", w)
	}
	if name, ok, err := GetZonePolicyOverride(kdb, zd.ZoneName); err != nil || !ok || name != "mds-long" {
		t.Errorf("the binding was not persisted as the CLI override: %q %v", name, err)
	}

	for _, tc := range []struct{ policy, refusal string }{
		{"mds-rsa", "algorithm"},
		{"mds-3", "DS model"},
		{"nonesuch", "does not exist"},
	} {
		if _, err := SetZonePolicyForOwner(ctx, zd, kdb, tc.policy); err == nil || !strings.Contains(err.Error(), tc.refusal) {
			t.Errorf("the owner's binding of %q: err=%v, want a refusal naming %q", tc.policy, err, tc.refusal)
		}
		if zd.DnssecPolicyName != "mds-long" {
			t.Errorf("after the refused binding of %q the zone is bound to %q", tc.policy, zd.DnssecPolicyName)
		}
	}

	plain := ownerZone(t, kdb, "polplain.example.")
	if _, err := SetZonePolicyForOwner(ctx, plain, kdb, "mds-long"); err == nil || !strings.Contains(err.Error(), "policy-set") {
		t.Errorf("the owner's binding on a zone nobody owns: err=%v, want a refusal pointing at policy-set", err)
	}
}

// The owner's fields (design Q1) include the pause before a rollover.
func TestOwnerPolicyFieldsIncludeStandbyTime(t *testing.T) {
	a := ktMultiDSPolicy(dns.ED25519, dns.ED25519)
	b := *a
	if ownerPolicyFieldsDiffer(a, &b) {
		t.Fatal("a copy differs")
	}
	b.Rollover.StandbyTime = a.Rollover.StandbyTime + time.Hour
	if !ownerPolicyFieldsDiffer(a, &b) {
		t.Error("Rollover.StandbyTime is not one of the owner's fields")
	}
	c := *a
	c.SigValidity.Default = a.SigValidity.Default + 3600
	if ownerPolicyFieldsDiffer(a, &c) {
		t.Error("a signature validity is mechanism, not the owner's")
	}
}

// Q4: on an owned zone the store's generate names the columns; with them
// the key is minted in the shape named, through the one write function.
func TestOwnedZoneGenerateNamesTheColumns(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := ownerZone(t, kdb, "genowned.example.")
	installOwner(t, &testOwner{owns: map[string]bool{zd.ZoneName: true}})
	yes, no := true, false
	resp, err := kdb.DnssecKeyMgmt(context.Background(), nil, KeystorePost{Command: "dnssec-mgmt", SubCommand: "generate", Zone: zd.ZoneName, KeyType: "KSK", Algorithm: dns.ED25519, State: DnskeyStatePublished, Pub: &yes, Sign: &no, DS: &no})
	if err != nil || resp == nil || resp.Error {
		t.Fatalf("generate with the columns named: err=%v resp=%+v", err, resp)
	}
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND state=? AND pub=1 AND sign=0 AND ds=0 AND (flags & 1)=1`, zd.ZoneName, DnskeyStatePublished).Scan(&n); err != nil || n != 1 {
		t.Errorf("the generated KSK with the columns named: %d rows, err %v", n, err)
	}
}
