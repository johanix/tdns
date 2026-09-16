package tdns

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	csk := cur
	csk.Name = "mds-csk"
	csk.Algorithm = dns.RSASHA256 // the top-level algorithm, what CSK mode generates with
	model := cur
	model.Name = "mds-3"
	model.Rollover.NumDS = 3
	publishPolicies(t, &cur, &longer, &rsa, &csk, &model)
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
		{"mds-csk", "algorithm"},
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
	resetKeystoreWrites(t, kdb)
	yes, no := true, false
	resp, err := kdb.DnssecKeyMgmt(context.Background(), nil, KeystorePost{Command: "dnssec-mgmt", SubCommand: "generate", Zone: zd.ZoneName, KeyType: "KSK", Algorithm: dns.ED25519, State: DnskeyStatePublished, Pub: &yes, Sign: &no, DS: &no})
	if err != nil || resp == nil || resp.Error {
		t.Fatalf("generate with the columns named: err=%v resp=%+v", err, resp)
	}
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND state=? AND pub=1 AND sign=0 AND ds=0 AND (flags & 1)=1`, zd.ZoneName, DnskeyStatePublished).Scan(&n); err != nil || n != 1 {
		t.Errorf("the generated KSK with the columns named: %d rows, err %v", n, err)
	}
	// one write: the INSERT carries the columns; no UPDATE follows
	if w := keystoreWrites(t, kdb); len(w) != 1 || !strings.HasPrefix(w[0], "insert") {
		t.Errorf("generate with the columns named wrote %v, want one INSERT", w)
	}
	// ... and the stamp the state owns: a key minted into published carries
	// its published_at, so the propagation wait (T8) can run from it
	var published string
	if err := kdb.DB.QueryRow(`SELECT COALESCE(published_at,'') FROM DnssecKeyStore WHERE zonename=? AND state=? AND (flags & 1)=1`, zd.ZoneName, DnskeyStatePublished).Scan(&published); err != nil || published == "" {
		t.Errorf("the key minted into published has published_at %q (err %v), want the time it entered the state", published, err)
	}
	// no state named: GenerateKeypair's default, active, on the row too
	resp, err = kdb.DnssecKeyMgmt(context.Background(), nil, KeystorePost{Command: "dnssec-mgmt", SubCommand: "generate", Zone: zd.ZoneName, KeyType: "ZSK", Algorithm: dns.ED25519, Pub: &yes, Sign: &yes, DS: &no})
	if err != nil || resp == nil || resp.Error {
		t.Fatalf("generate without a state: err=%v resp=%+v", err, resp)
	}
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND state='' `, zd.ZoneName).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d rows with an empty state after generate without a state (err %v), want 0", n, err)
	}
}

// An owner's write that leaves ds open keeps the row's ds, NULL included;
// the zone's DS model does not fill it in behind the owner's back. The
// zone here is one with a DS model the store would otherwise apply (a
// multi-DS policy; a multi-provider zone's model writes NULL anyway).
func TestOwnerWriteLeavingDsOpenKeepsTheRowsDs(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := ownerZone(t, kdb, "dsopen.example.")
	zd.Options[OptMultiProvider] = false
	ksk := activeKeytags(t, kdb, zd.ZoneName, true)[0]
	dsOf := func() string {
		var ds sql.NullBool
		if err := kdb.DB.QueryRow(`SELECT ds FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zd.ZoneName, ksk).Scan(&ds); err != nil {
			t.Fatal(err)
		}
		if !ds.Valid {
			return "NULL"
		}
		return fmt.Sprint(ds.Bool)
	}
	if err := UpdateKeyRow(kdb, zd.ZoneName, ksk, DnskeyStateActive, KeyRowFlags{Pub: true, Sign: true, DS: sql.NullBool{Bool: true, Valid: true}}); err != nil {
		t.Fatal(err)
	}
	if err := UpdateKeyRow(kdb, zd.ZoneName, ksk, DnskeyStateStandby, KeyRowFlags{Pub: true}); err != nil {
		t.Fatal(err)
	}
	if got := dsOf(); got != "true" {
		t.Errorf("ds left open on a standby write: %s, want the row's true kept", got)
	}
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET ds=NULL WHERE zonename=? AND keyid=?`, zd.ZoneName, ksk); err != nil {
		t.Fatal(err)
	}
	if err := UpdateKeyRow(kdb, zd.ZoneName, ksk, DnskeyStateActive, KeyRowFlags{Pub: true, Sign: true}); err != nil {
		t.Fatal(err)
	}
	if got := dsOf(); got != "NULL" {
		t.Errorf("ds left open on a row with ds NULL: %s, want NULL kept (the multi-DS model would say true)", got)
	}
	if err := UpdateKeyRow(kdb, zd.ZoneName, ksk, DnskeyStateActive, KeyRowFlags{Pub: true, Sign: true, DS: sql.NullBool{Bool: false, Valid: true}}); err != nil {
		t.Fatal(err)
	}
	if got := dsOf(); got != "false" {
		t.Errorf("an explicit false: %s, want false", got)
	}
}
