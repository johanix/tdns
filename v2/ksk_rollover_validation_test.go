package tdns

import (
	"testing"
	"time"
)

// TestCheckE5 exercises the §4.5.1 retirement_period bound check.
// E5: retirement_period ≥ min(DNSKEY_TTL, KSK.SigValidity).
func TestCheckE5(t *testing.T) {
	tests := []struct {
		name      string
		pol       *DnssecPolicy
		wantEmpty bool
	}{
		{
			name: "clamping disabled -> skipped",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Clamping.Enabled = false
				p.TTLS.DNSKEY = 300
				p.KSK.SigValidity = 60
				return p
			}(),
			wantEmpty: true,
		},
		{
			name: "clamping enabled, margin satisfies floor -> ok",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Clamping.Enabled = true
				p.Clamping.Margin = 5 * time.Minute
				p.TTLS.DNSKEY = 300         // 5m
				p.KSK.SigValidity = 60 * 60 // 1h
				return p
			}(),
			wantEmpty: true,
		},
		{
			// Rapid-rollover pattern: long configured TTL clamped low.
			// E5 must use the SERVED TTL = min(2h, 5m) = 5m, not 2h.
			name: "long ttls.dnskey clamped by max_served -> uses served TTL -> pass",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Clamping.Enabled = true
				p.Clamping.Margin = 5 * time.Minute
				p.TTLS.DNSKEY = 7200        // 2h configured
				p.TTLS.MaxServed = 300      // 5m clamp
				p.KSK.SigValidity = 20 * 60 // 20m
				return p
			}(),
			wantEmpty: true,
		},
		{
			// Same shape but with a low margin: should fail because
			// served TTL = 5m and margin = 1m < 5m.
			name: "rapid-rollover pattern, margin below served TTL -> violation",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Clamping.Enabled = true
				p.Clamping.Margin = 1 * time.Minute
				p.TTLS.DNSKEY = 7200
				p.TTLS.MaxServed = 300
				p.KSK.SigValidity = 20 * 60
				return p
			}(),
			wantEmpty: false,
		},
		{
			name: "clamping enabled, margin below floor -> violation",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Clamping.Enabled = true
				p.Clamping.Margin = 1 * time.Minute
				p.TTLS.DNSKEY = 300         // 5m -> floor
				p.KSK.SigValidity = 60 * 60 // 1h
				return p
			}(),
			wantEmpty: false,
		},
		{
			name: "clamping enabled, no TTL hints -> skipped",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Clamping.Enabled = true
				p.Clamping.Margin = 1 * time.Minute
				return p
			}(),
			wantEmpty: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkE5(tc.pol)
			if tc.wantEmpty && got.Failed() {
				t.Errorf("expected pass, got %q", got.Message)
			}
			if !tc.wantEmpty && !got.Failed() {
				t.Errorf("expected violation, got pass")
			}
		})
	}
}

// TestCheckE10 exercises the cadence-vs-cache-flush invariant.
// E10: (N − 1) × KSK.Lifetime ≥ retirement_period + parent_prop + DS_TTL + standby_time.
func TestCheckE10(t *testing.T) {
	tests := []struct {
		name      string
		pol       *DnssecPolicy
		dsTTL     time.Duration
		wantEmpty bool
	}{
		{
			name: "N<2 -> skipped",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.NumDS = 1
				p.KSK.Lifetime = 10 * 60
				return p
			}(),
			dsTTL:     5 * time.Minute,
			wantEmpty: true,
		},
		{
			name: "comfortable headroom -> ok",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.NumDS = 3
				p.KSK.Lifetime = 60 * 60 // 1h, so (N-1)*L = 2h
				p.Clamping.Margin = 5 * time.Minute
				p.Rollover.DsPublishDelay = 5 * time.Minute
				return p
			}(),
			dsTTL:     5 * time.Minute,
			wantEmpty: true,
		},
		{
			name: "tight cadence -> violation",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.NumDS = 2
				p.KSK.Lifetime = 60 // 1m, so (N-1)*L = 1m
				p.Clamping.Margin = 5 * time.Minute
				p.Rollover.DsPublishDelay = 5 * time.Minute
				return p
			}(),
			dsTTL:     5 * time.Minute,
			wantEmpty: false,
		},
		{
			name: "force-notify adds parent-cds-poll-estimate",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.NumDS = 3
				p.KSK.Lifetime = 10 * 60 // 10m, (N-1)*L = 20m
				p.Clamping.Margin = 5 * time.Minute
				p.Rollover.DsPublishDelay = 5 * time.Minute
				p.Rollover.DsyncSchemePreference = DsyncSchemePreferenceForceNotify
				p.Rollover.ParentCdsPollEstimate = 12 * time.Minute
				return p
			}(),
			dsTTL: 5 * time.Minute,
			// 5 + (5+12) + 5 + 0 = 27m > 20m -> violation
			wantEmpty: false,
		},
		{
			// standby_time eats into the available cadence budget.
			// Without standby_time: 5+1+5 = 11m vs 20m -> ok.
			// With standby_time=10m: required = 21m > 20m -> violation.
			name: "standby_time pushes required over the cadence budget",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.NumDS = 3
				p.KSK.Lifetime = 10 * 60 // (N-1)*L = 20m
				p.Clamping.Margin = 5 * time.Minute
				p.Rollover.DsPublishDelay = 1 * time.Minute
				p.Rollover.StandbyTime = 10 * time.Minute
				return p
			}(),
			dsTTL:     5 * time.Minute,
			wantEmpty: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkE10(tc.pol, tc.dsTTL)
			if tc.wantEmpty && got.Failed() {
				t.Errorf("expected pass, got %q", got.Message)
			}
			if !tc.wantEmpty && !got.Failed() {
				t.Errorf("expected violation, got pass")
			}
		})
	}
}

// TestResolveDSTTL confirms the resolution priority: override > observation > none.
func TestResolveDSTTL(t *testing.T) {
	policy := func(override uint32) *DnssecPolicy {
		p := &DnssecPolicy{}
		p.TTLS.DS = override
		return p
	}
	zone := func(observed uint32) *ZoneData {
		return &ZoneData{ParentDSTTLObserved: observed}
	}

	tests := []struct {
		name    string
		zd      *ZoneData
		pol     *DnssecPolicy
		wantTTL time.Duration
		wantOK  bool
	}{
		{
			name:    "override only",
			zd:      zone(0),
			pol:     policy(900),
			wantTTL: 900 * time.Second,
			wantOK:  true,
		},
		{
			name:    "observation only",
			zd:      zone(300),
			pol:     policy(0),
			wantTTL: 300 * time.Second,
			wantOK:  true,
		},
		{
			name:    "override wins over observation",
			zd:      zone(300),
			pol:     policy(900),
			wantTTL: 900 * time.Second,
			wantOK:  true,
		},
		{
			name:    "neither set -> not ok",
			zd:      zone(0),
			pol:     policy(0),
			wantTTL: 0,
			wantOK:  false,
		},
		{
			name:    "nil zone, override only",
			zd:      nil,
			pol:     policy(600),
			wantTTL: 600 * time.Second,
			wantOK:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ttl, ok := resolveDSTTL(tc.zd, tc.pol)
			if ttl != tc.wantTTL {
				t.Errorf("ttl: got %v, want %v", ttl, tc.wantTTL)
			}
			if ok != tc.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tc.wantOK)
			}
		})
	}
}

// TestCheckE11 confirms the rule-of-thumb headroom warning fires only
// at <25% headroom and that comfortable margins pass silently.
func TestCheckE11(t *testing.T) {
	tightHeadroom := func() *DnssecPolicy {
		p := &DnssecPolicy{}
		p.Rollover.NumDS = 2
		p.KSK.Lifetime = 21 * 60 // 21m, (N-1)*L = 21m
		p.Clamping.Margin = 5 * time.Minute
		p.Rollover.DsPublishDelay = 5 * time.Minute
		return p
	}()
	// required = 5 + 5 + 10 = 20m. available = 21m. ratio = 21/20 = 1.05 < 1.25 -> warn.
	if got := checkE11(tightHeadroom, 10*time.Minute); !got.Failed() {
		t.Error("expected E11 warning at <25% headroom, got pass")
	}

	comfortable := func() *DnssecPolicy {
		p := &DnssecPolicy{}
		p.Rollover.NumDS = 3
		p.KSK.Lifetime = 60 * 60 // 1h, (N-1)*L = 2h
		p.Clamping.Margin = 5 * time.Minute
		p.Rollover.DsPublishDelay = 5 * time.Minute
		return p
	}()
	if got := checkE11(comfortable, 5*time.Minute); got.Failed() {
		t.Errorf("expected silence at comfortable margin, got %q", got.Message)
	}

	// standby_time inflates required just like the other terms.
	// Without standby_time: required = 5 + 5 + 5 = 15m, available = 2h
	// -> ratio 8 > 1.25 (silent). With standby_time = 1h: required = 75m,
	// available = 2h -> ratio 1.6 > 1.25 (still silent). Bump to 1h30m
	// -> required = 105m, available = 120m, ratio = 1.143 < 1.25 (warn).
	standbyTight := func() *DnssecPolicy {
		p := &DnssecPolicy{}
		p.Rollover.NumDS = 3
		p.KSK.Lifetime = 60 * 60
		p.Clamping.Margin = 5 * time.Minute
		p.Rollover.DsPublishDelay = 5 * time.Minute
		p.Rollover.StandbyTime = 90 * time.Minute
		return p
	}()
	if got := checkE11(standbyTight, 5*time.Minute); !got.Failed() {
		t.Error("expected E11 warning when standby_time consumes headroom, got pass")
	}
}
