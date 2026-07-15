package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestApplyReloadedPolicyLocked exercises the config-reload guard that refuses
// an incompatible DNSSEC-algorithm policy change (which would need an
// unimplemented key rollover) while still applying benign, same-algorithm
// edits. This is the reload-path (FirstZoneLoad == false) analogue of the
// SignZone algorithm check in reconcileActiveKeyAlgorithms (sign.go).
func TestApplyReloadedPolicyLocked(t *testing.T) {
	// A KSK+ZSK policy currently bound to the zone (the OLD, effective policy).
	oldPol := &DnssecPolicy{
		Name:         "pq-sqisign",
		Mode:         DnssecPolicyModeKSKZSK,
		Algorithm:    dns.ED25519,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ECDSAP256SHA256,
	}

	tests := []struct {
		name       string
		newPol     *DnssecPolicy
		newName    string
		wantApply  bool   // did the rebind happen?
		wantPolPtr string // expected DnssecPolicyName after the call
	}{
		{
			// Effective KSK algorithm changes (ED25519 -> RSASHA256): needs a
			// KSK rollover, not implemented -> REFUSE, keep the old policy.
			name: "ksk-algorithm-change-refused",
			newPol: &DnssecPolicy{
				Name:         "pq-mldsa",
				Mode:         DnssecPolicyModeKSKZSK,
				Algorithm:    dns.RSASHA256,
				KSKAlgorithm: dns.RSASHA256,
				ZSKAlgorithm: dns.ECDSAP256SHA256,
			},
			newName:    "pq-mldsa",
			wantApply:  false,
			wantPolPtr: "pq-sqisign",
		},
		{
			// Effective ZSK algorithm changes (ECDSAP256 -> ED25519): also an
			// algorithm change -> REFUSE, keep the old policy.
			name: "zsk-algorithm-change-refused",
			newPol: &DnssecPolicy{
				Name:         "pq-mldsa",
				Mode:         DnssecPolicyModeKSKZSK,
				Algorithm:    dns.ED25519,
				KSKAlgorithm: dns.ED25519,
				ZSKAlgorithm: dns.ED25519,
			},
			newName:    "pq-mldsa",
			wantApply:  false,
			wantPolPtr: "pq-sqisign",
		},
		{
			// Same effective KSK and ZSK algorithms, only non-algorithm fields
			// changed (mode/rollover/name) -> benign, APPLY.
			name: "benign-same-algorithm-edit-applied",
			newPol: &DnssecPolicy{
				Name:         "pq-sqisign-v2",
				Mode:         DnssecPolicyModeKSKZSK,
				Algorithm:    dns.ED25519,
				KSKAlgorithm: dns.ED25519,
				ZSKAlgorithm: dns.ECDSAP256SHA256,
				Rollover:     RolloverPolicy{Method: RolloverMethodMultiDS},
			},
			newName:    "pq-sqisign-v2",
			wantApply:  true,
			wantPolPtr: "pq-sqisign-v2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zd := &ZoneData{
				ZoneName:         "example.",
				DnssecPolicy:     oldPol,
				DnssecPolicyName: oldPol.Name,
			}
			zd.mu.Lock()
			applied := zd.applyReloadedPolicyLocked(tc.newPol, tc.newName)
			zd.mu.Unlock()

			if applied != tc.wantApply {
				t.Fatalf("applyReloadedPolicyLocked returned %v, want %v", applied, tc.wantApply)
			}
			if zd.DnssecPolicyName != tc.wantPolPtr {
				t.Fatalf("DnssecPolicyName = %q, want %q", zd.DnssecPolicyName, tc.wantPolPtr)
			}
			if tc.wantApply {
				// Benign edit: the new policy struct is now bound.
				if zd.DnssecPolicy != tc.newPol {
					t.Fatalf("expected new policy pointer to be bound after a benign edit")
				}
			} else {
				// Refusal: the OLD policy struct must still be bound, so the
				// zone keeps signing with its existing keys.
				if zd.DnssecPolicy != oldPol {
					t.Fatalf("expected the old policy pointer to remain bound after a refused algorithm change")
				}
			}
		})
	}
}

// TestApplyReloadedPolicyLocked_FirstBind verifies that a zone with no policy
// yet bound (the nil-current case) always applies the new policy — the guard
// only fires when there is an OLD effective policy to compare against.
func TestApplyReloadedPolicyLocked_FirstBind(t *testing.T) {
	zd := &ZoneData{ZoneName: "example."}
	newPol := &DnssecPolicy{
		Name:         "pq-mldsa",
		Mode:         DnssecPolicyModeKSKZSK,
		Algorithm:    dns.RSASHA256,
		KSKAlgorithm: dns.RSASHA256,
		ZSKAlgorithm: dns.RSASHA256,
	}
	zd.mu.Lock()
	applied := zd.applyReloadedPolicyLocked(newPol, "pq-mldsa")
	zd.mu.Unlock()

	if !applied {
		t.Fatalf("expected a first bind (nil current policy) to apply")
	}
	if zd.DnssecPolicyName != "pq-mldsa" || zd.DnssecPolicy != newPol {
		t.Fatalf("first bind did not bind the new policy: name=%q", zd.DnssecPolicyName)
	}
}
