package tdns

import (
	"testing"
	"time"
)

// TestStandbyTimeGateMath captures the arithmetic of the
// standby→active gate added in C19. The actual gate runs against a
// keystore inside rolloverDue; here we exercise the pure-math piece:
// "now ≥ standby_at + standby_time."
func TestStandbyTimeGateMath(t *testing.T) {
	standbyAt := time.Date(2026, 5, 4, 11, 35, 0, 0, time.UTC)
	tests := []struct {
		name        string
		now         time.Time
		standbyTime time.Duration
		wantPass    bool
	}{
		{
			name:        "now exactly at gate -> pass",
			now:         standbyAt.Add(time.Minute),
			standbyTime: time.Minute,
			wantPass:    true,
		},
		{
			name:        "now 1s before gate -> fail",
			now:         standbyAt.Add(time.Minute - time.Second),
			standbyTime: time.Minute,
			wantPass:    false,
		},
		{
			name:        "zero standby_time -> always pass",
			now:         standbyAt,
			standbyTime: 0,
			wantPass:    true,
		},
		{
			name:        "production-like 15m pause -> 14m elapsed not enough",
			now:         standbyAt.Add(14 * time.Minute),
			standbyTime: 15 * time.Minute,
			wantPass:    false,
		},
		{
			name:        "production-like 15m pause -> 15m exactly is enough",
			now:         standbyAt.Add(15 * time.Minute),
			standbyTime: 15 * time.Minute,
			wantPass:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// rolloverDue's gate: pause > 0 && now.Before(standbyAt.Add(pause))
			// pass = NOT (pause > 0 AND now < standbyAt+pause)
			gateOpen := !(tc.standbyTime > 0 && tc.now.Before(standbyAt.Add(tc.standbyTime)))
			if gateOpen != tc.wantPass {
				t.Errorf("got %v, want %v", gateOpen, tc.wantPass)
			}
		})
	}
}

// TestPublishedToStandbyGateMath captures the arithmetic for the
// published→standby transition (C18): the engine fires when both
// child-side and parent-side propagation gates have elapsed.
func TestPublishedToStandbyGateMath(t *testing.T) {
	// Helper for the gate: returns the moment both have elapsed.
	gateAt := func(tPublished time.Time, childProp, dnskeyTTL time.Duration,
		tDsObs *time.Time, parentProp, dsTTL time.Duration) time.Time {
		dnskeyReady := tPublished.Add(childProp + dnskeyTTL)
		latest := dnskeyReady
		if tDsObs != nil {
			dsReady := tDsObs.Add(parentProp + dsTTL)
			if dsReady.After(latest) {
				latest = dsReady
			}
		}
		return latest
	}

	// Testbed: child-side dominates (1m + 5m = 6m vs DS ~earlier).
	tPublished := time.Date(2026, 5, 4, 11, 30, 0, 0, time.UTC)
	tDsObs := tPublished.Add(-2 * time.Minute) // DS observed before publish
	got := gateAt(tPublished, time.Minute, 5*time.Minute, &tDsObs, 30*time.Second, 2*time.Minute)
	want := tPublished.Add(6 * time.Minute) // child-side wins
	if !got.Equal(want) {
		t.Errorf("child-side dominates case: got %v, want %v", got, want)
	}

	// DS-side dominates: very recent observation with long DS TTL.
	tDsObsRecent := tPublished.Add(time.Minute) // ds_observed_at AFTER published_at
	got = gateAt(tPublished, time.Minute, 5*time.Minute, &tDsObsRecent, 30*time.Second, 30*time.Minute)
	// child-side: tPublished + 6m = 11:36
	// DS-side: tDsObsRecent + 30s + 30m = tPublished + 1m + 30s + 30m = 11:31:30 + 30m = 12:01:30
	want = tDsObsRecent.Add(30*time.Second + 30*time.Minute)
	if !got.Equal(want) {
		t.Errorf("DS-side dominates case: got %v, want %v", got, want)
	}

	// No DS observation: child-side alone.
	got = gateAt(tPublished, time.Minute, 5*time.Minute, nil, 30*time.Second, 2*time.Minute)
	want = tPublished.Add(6 * time.Minute)
	if !got.Equal(want) {
		t.Errorf("no DS obs case: got %v, want %v", got, want)
	}
}

// TestStandbyTimePolicyParse verifies that rollover.standby-time
// parses with the documented default and explicit overrides.
func TestStandbyTimePolicyParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want time.Duration
	}{
		{name: "empty -> default 1m", in: "", want: time.Minute},
		{name: "explicit 15m", in: "15m", want: 15 * time.Minute},
		{name: "explicit 0s allowed (operator opts out of pause)", in: "0s", want: 0},
		{name: "explicit 1h", in: "1h", want: time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := &DnssecPolicyConf{
				Algorithm: "ECDSAP256SHA256",
			}
			conf.KSK.Lifetime = "10m"
			conf.KSK.SigValidity = "20m"
			conf.ZSK.Lifetime = "10m"
			conf.ZSK.SigValidity = "20m"
			conf.CSK.Lifetime = "10m"
			conf.CSK.SigValidity = "20m"
			conf.Rollover.Method = "multi-ds"
			conf.Rollover.NumDS = 3
			conf.Rollover.ParentAgent = "127.0.0.1:53"
			conf.Rollover.DsPublishDelay = "30s"
			conf.Rollover.StandbyTime = tc.in
			pol, err := ParseDnssecPolicyConfQuiet("test", conf)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if pol.Rollover.StandbyTime != tc.want {
				t.Errorf("got %v, want %v", pol.Rollover.StandbyTime, tc.want)
			}
		})
	}
}
