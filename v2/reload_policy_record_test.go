/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// A config reload has to record the DNSSEC policy its configuration names for a
// zone that is already loaded and does not sign (neither online- nor inline-
// signing), whatever the zone had before: none, another policy, or a binding a
// derived app made with BindPolicyWithoutSigning. The record is what a signing
// role learned later resolves its policy from, so a reload that drops it leaves
// the zone unable to start signing until the daemon restarts (#1000).
//
// Every zone here is loaded and reloaded through a running RefreshEngine, by
// the refresher ParseZones builds (relayedZone.configRefresher).

// otherPolicy is a second policy, of other algorithms than "base".
func otherPolicy() DnssecPolicy {
	return kskzsk(dns.ECDSAP256SHA256, dns.ECDSAP256SHA256)
}

func reloadPolicySetup(t *testing.T) *KeyDB {
	t.Helper()
	kdb, _ := roleSetup(t)
	withLivePolicies(t, map[string]DnssecPolicy{
		"base":  kskzsk(dns.ED25519, dns.ED25519),
		"other": otherPolicy(),
	})
	return kdb
}

// loadedWithPolicy is a loaded zone that does not sign, whose first load's
// configuration named policy (or none).
func loadedWithPolicy(t *testing.T, kdb *KeyDB, policy string) *relayedZone {
	t.Helper()
	up := startRelayUpstream(t, 40)
	z := startRelayedZoneWith(t, kdb, up, &relayedZone{policy: policy}, nil)
	if z.zd.signsItsOwnContent() {
		t.Fatal("the zone signs from its first load; the test has lost its point")
	}
	if z.zd.DnssecPolicyName != policy {
		t.Fatalf("the first load recorded policy %q, want %q", z.zd.DnssecPolicyName, policy)
	}
	return z
}

// reloadedWithPolicy is a config reload whose configuration names policy.
func reloadedWithPolicy(t *testing.T, z *relayedZone, policy string) {
	t.Helper()
	z.policy = policy
	z.reloaded(t)
}

// wantPolicyRecord: the name the zone records, and the policy bound to it.
// bound is the name of the policy struct that is bound; "" says none is.
func wantPolicyRecord(t *testing.T, zd *ZoneData, name, bound, when string) {
	t.Helper()
	zd.mu.Lock()
	gotName, pol := zd.DnssecPolicyName, zd.DnssecPolicy
	zd.mu.Unlock()
	if gotName != name {
		t.Errorf("%s: the zone records policy %q, want %q", when, gotName, name)
	}
	switch {
	case bound == "" && pol != nil:
		t.Errorf("%s: a policy is bound (KSK algorithm %d), want none", when, pol.KSKAlgorithm)
	case bound != "" && pol == nil:
		t.Errorf("%s: no policy is bound, want %q", when, bound)
	case bound != "":
		want := ConfLive().DnssecPolicies[bound]
		if pol.KSKAlgorithm != want.KSKAlgorithm {
			t.Errorf("%s: the bound policy has KSK algorithm %d, want that of %q (%d)", when, pol.KSKAlgorithm, bound, want.KSKAlgorithm)
		}
	}
}

// The issue's case: a policy added to a loaded zone that has none. The zone then
// starts signing at once, with no restart.
func TestAReloadThatAddsAPolicyLetsTheZoneStartSigning(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "")
	own := genActiveKeys(t, kdb)

	reloadedWithPolicy(t, z, "base")

	wantPolicyRecord(t, z.zd, "base", "", "after the reload")
	if z.zd.signsItsOwnContent() {
		t.Fatal("the reload switched signing on")
	}
	if err := z.zd.StartSigning(context.Background(), 0); err != nil {
		t.Fatalf("StartSigning after a reload that named a policy: %v", err)
	}
	wantReady(t, z.zd, "after the start")
	wantPolicyRecord(t, z.zd, "base", "base", "after the start")
	wantOnlyOwnSignatures(t, z.zd, own, "after the start")
	if name, _, ok, err := GetZoneAppliedPolicy(kdb, ovZone); err != nil || !ok || name != "base" {
		t.Errorf("last-applied record: %q %v %v, want base", name, ok, err)
	}
}

// A zone that does not sign has no binding for a reload to move: the name is the
// whole record, changed or removed.
func TestAReloadChangesOrRemovesThePolicyOfAZoneThatIsNotBound(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "base")
	wantPolicyRecord(t, z.zd, "base", "", "before the reload")

	reloadedWithPolicy(t, z, "other")
	wantPolicyRecord(t, z.zd, "other", "", "after the policy was changed")

	reloadedWithPolicy(t, z, "")
	wantPolicyRecord(t, z.zd, "", "", "after the policy was removed")
	err := z.zd.StartSigning(context.Background(), 0)
	if err == nil || !strings.Contains(err.Error(), "names no DNSSEC policy") {
		t.Fatalf("StartSigning on a zone whose configuration names none: %v", err)
	}

	reloadedWithPolicy(t, z, "base")
	wantPolicyRecord(t, z.zd, "base", "", "after the policy was added again")
}

// A zone a derived app bound a policy to without signing keeps the name and the
// policy together: the policy a later start signs under is the one the
// configuration names.
func TestAReloadMovesTheBindingOfAZoneBoundWithoutSigning(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "base")
	if err := z.zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	wantPolicyRecord(t, z.zd, "base", "base", "after the bind")

	reloadedWithPolicy(t, z, "base")
	wantPolicyRecord(t, z.zd, "base", "base", "after a reload that changed nothing")

	reloadedWithPolicy(t, z, "other")
	wantPolicyRecord(t, z.zd, "other", "other", "after the policy was changed")
	if z.zd.signsItsOwnContent() {
		t.Fatal("the reload switched signing on")
	}

	reloadedWithPolicy(t, z, "")
	wantPolicyRecord(t, z.zd, "", "", "after the policy was removed")
	if z.zd.signsItsOwnContent() {
		t.Fatal("the reload switched signing on")
	}

	// And a policy named again binds nothing by itself: the owner binds.
	reloadedWithPolicy(t, z, "base")
	wantPolicyRecord(t, z.zd, "base", "", "after the policy was added again")
}

// A bound zone that a reload points at a policy that does not exist keeps its
// binding, as a signing zone does, and says so.
func TestAReloadToAPolicyThatDoesNotExistKeepsTheBinding(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "base")
	if err := z.zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}

	reloadedWithPolicy(t, z, "gone")

	wantPolicyRecord(t, z.zd, "base", "base", "after a reload to a policy that does not exist")
	z.zd.mu.Lock()
	_, warned := z.zd.Errors[DnssecPolicyWarning]
	z.zd.mu.Unlock()
	if !warned {
		t.Error("no DNSSEC policy warning on the zone")
	}

	// Pointed back at a policy that exists, the warning goes and the zone follows.
	reloadedWithPolicy(t, z, "other")
	wantPolicyRecord(t, z.zd, "other", "other", "after a reload to a policy that exists")
	z.zd.mu.Lock()
	_, warned = z.zd.Errors[DnssecPolicyWarning]
	z.zd.mu.Unlock()
	if warned {
		t.Error("the DNSSEC policy warning outlived the reload that fixed it")
	}
}

// A zone that signs is not touched by any of this: its policy goes through the
// policy sync, whose result a reload that changes nothing leaves as it was.
func TestAReloadLeavesTheRecordOfASigningZoneToThePolicySync(t *testing.T) {
	kdb := reloadPolicySetup(t)
	up := startRelayUpstream(t, 40)
	z := startRelayedZoneWith(t, kdb, up, &relayedZone{
		opts:   map[ZoneOption]bool{OptInlineSigning: true},
		policy: "base",
	}, nil)
	wantPolicyRecord(t, z.zd, "base", "base", "after the first load")
	if !z.zd.signsItsOwnContent() {
		t.Fatal("the zone does not sign; the test has lost its point")
	}

	z.reloaded(t)

	wantPolicyRecord(t, z.zd, "base", "base", "after a reload")
	if !z.zd.signsItsOwnContent() {
		t.Fatal("a reload took signing away")
	}
}
