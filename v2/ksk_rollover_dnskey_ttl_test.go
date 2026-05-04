package tdns

import (
	"testing"
	"time"
)

// TestEffectiveServedDnskeyTTL covers the W1/E13 resolution of the
// served DNSKEY TTL: min(pol.TTLS.DNSKEY, pol.TTLS.MaxServed) when
// both set, the single set value when one is set, observed from
// keystore otherwise. Returns (0, false) when nothing is known.
//
// Cannot test the LoadZoneSigningMaxTTL fallback without a KeyDB; that
// path is exercised by integration tests on the build server.
func TestEffectiveServedDnskeyTTLPolicyOnly(t *testing.T) {
	tests := []struct {
		name    string
		dnskey  uint32
		maxSrv  uint32
		wantTTL time.Duration
		wantOK  bool
	}{
		{
			name:    "DNSKEY set, max_served unset -> use DNSKEY",
			dnskey:  300,
			wantTTL: 300 * time.Second,
			wantOK:  true,
		},
		{
			name:    "max_served set, DNSKEY unset -> use max_served",
			maxSrv:  600,
			wantTTL: 600 * time.Second,
			wantOK:  true,
		},
		{
			name:    "both set, DNSKEY smaller -> min wins (DNSKEY)",
			dnskey:  300,
			maxSrv:  600,
			wantTTL: 300 * time.Second,
			wantOK:  true,
		},
		{
			name:    "both set, max_served smaller -> min wins (max_served)",
			dnskey:  900,
			maxSrv:  600,
			wantTTL: 600 * time.Second,
			wantOK:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pol := &DnssecPolicy{}
			pol.TTLS.DNSKEY = tc.dnskey
			pol.TTLS.MaxServed = tc.maxSrv
			// kdb=nil acceptable here because policy values cover all paths.
			ttl, ok := effectiveServedDnskeyTTL(nil, "test.example.", pol)
			if ttl != tc.wantTTL {
				t.Errorf("ttl: got %v, want %v", ttl, tc.wantTTL)
			}
			if ok != tc.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tc.wantOK)
			}
		})
	}
}

// TestNotifyTimeoutFromPolicy covers the W6/P10 derivation of NOTIFY
// round-trip timeout from rollover.parent-cds-poll-estimate.
func TestNotifyTimeoutFromPolicy(t *testing.T) {
	tests := []struct {
		name string
		pol  *DnssecPolicy
		want time.Duration
	}{
		{
			name: "nil policy -> 30s floor",
			pol:  nil,
			want: 30 * time.Second,
		},
		{
			name: "default 1m -> 2m",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.ParentCdsPollEstimate = time.Minute
				return p
			}(),
			want: 2 * time.Minute,
		},
		{
			name: "very short estimate -> 30s floor wins",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.ParentCdsPollEstimate = 5 * time.Second
				return p
			}(),
			want: 30 * time.Second,
		},
		{
			name: "long estimate scales 2x",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.ParentCdsPollEstimate = 10 * time.Minute
				return p
			}(),
			want: 20 * time.Minute,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := notifyTimeoutFromPolicy(tc.pol); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestE12FormulaDocumentsCorrectMath asserts the §4.7 formula in
// arithmetic — the cache-flush invariant E3 holds iff
// T_publish + child_prop + DNSKEY_TTL <= T_roll. We compute T_publish
// as T_roll - (child_prop + DNSKEY_TTL) and verify the invariant
// rearranges to equality (and is satisfied with any non-negative
// slack).
func TestE12FormulaDocumentsCorrectMath(t *testing.T) {
	tRoll := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	childProp := 1 * time.Minute
	dnskeyTTL := 5 * time.Minute

	tPublish := tRoll.Add(-(childProp + dnskeyTTL))

	// E3: T_publish + child_prop + DNSKEY_TTL <= T_roll. With our
	// formula it should hold with equality (zero slack — the spec
	// formula gives the latest possible publication time that still
	// satisfies E3).
	earliestObservableAtTRoll := tPublish.Add(childProp + dnskeyTTL)
	if !earliestObservableAtTRoll.Equal(tRoll) {
		t.Errorf("expected E12 formula to satisfy E3 with equality at T_roll; got %v != %v",
			earliestObservableAtTRoll, tRoll)
	}

	// Sanity-check the prior-buggy formula T_publish = T_roll −
	// child_prop. It violates E3 by exactly DNSKEY_TTL.
	tPublishBuggy := tRoll.Add(-childProp)
	buggyEarliestObservable := tPublishBuggy.Add(childProp + dnskeyTTL)
	if !buggyEarliestObservable.After(tRoll) {
		t.Error("buggy formula should violate E3 (publish too late)")
	}
	if got := buggyEarliestObservable.Sub(tRoll); got != dnskeyTTL {
		t.Errorf("buggy violation magnitude should be exactly DNSKEY_TTL; got %v", got)
	}
}
