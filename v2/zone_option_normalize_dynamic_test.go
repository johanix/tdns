package tdns

import (
	"context"
	"testing"
)

// Regression tests for findings from the PR #331 reviews.
//
// These drive the REAL ModifyDynamicZone/ProvisionDynamicZone paths rather than
// the normalizer helper: an earlier version of this file exercised only the
// helper, so it would still have passed if the dynamic-zone paths stopped
// calling it — which was precisely the bug under test.

// TestModifyNormalizesSubmittedOptions: options SUBMITTED with a modify must be
// normalized, not just the ones carried forward when none are supplied.
//
// Without this, `zone modify --options allow-updates` on a secondary installed
// them live and persisted them with no ConfigWarning — re-enabling exactly what
// the normalizer exists to strip, through the ingress the design doc singled
// out as most likely to be missed.
func TestModifyNormalizesSubmittedOptions(t *testing.T) {
	withAppType(t, AppTypeAuth)
	resetZonesForTest()
	conf, ch := newTestConfigForCores(t)

	in := DynamicZoneInput{Name: "modopt.example", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}}}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	<-ch

	// Submit an origination option against the (secondary) zone.
	mod := DynamicZoneInput{Name: "modopt.example", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.9:53", Key: NOKEY}},
		Options:   map[ZoneOption]bool{OptAllowUpdates: true},
	}
	if _, err := conf.ModifyDynamicZone(context.Background(), mod); err != nil {
		t.Fatalf("modify failed: %v", err)
	}
	<-ch

	zd, _ := Zones.Get("modopt.example.")
	if zd.Options[OptAllowUpdates] {
		t.Error("submitted allow-updates went live on a secondary: normalization was skipped")
	}
	if !zd.SuppressedOptions[OptAllowUpdates] {
		t.Error("suppressed record does not mention the submitted option")
	}
	if !zd.HasError(ConfigWarning) {
		t.Error("no ConfigWarning raised for the submitted origination option")
	}
	// The operator's intent must still round-trip into the persisted config.
	if !zd.asConfiguredOptions()[OptAllowUpdates] {
		t.Error("as-configured view lost the submitted option")
	}
}

// TestModifyWithoutOptionsPreservesSuppressed is the regression for the bug the
// FIRST round of review fixes introduced: with in.Options == nil, the carried
// options are already the EFFECTIVE (stripped) set, so re-normalizing them
// finds nothing to strip and returns an empty suppressed set — which then
// overwrote the carried-forward record. The operator's origination options
// would be permanently deleted from their own persisted config by the next
// rewrite, silently, with the warning clearing at the same time.
func TestModifyWithoutOptionsPreservesSuppressed(t *testing.T) {
	withAppType(t, AppTypeAuth)
	resetZonesForTest()
	conf, ch := newTestConfigForCores(t)

	// Add a secondary that asks for an origination option; it is stripped at
	// provisioning and recorded as suppressed.
	in := DynamicZoneInput{Name: "modnil.example", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		Options:   map[ZoneOption]bool{OptAllowUpdates: true},
	}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	<-ch

	before, _ := Zones.Get("modnil.example.")
	if !before.SuppressedOptions[OptAllowUpdates] {
		t.Fatal("setup: provisioning did not record the suppressed option")
	}

	// A TSIG/primaries-only modify, carrying NO options.
	mod := DynamicZoneInput{Name: "modnil.example", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.9:53", Key: NOKEY}}}
	if _, err := conf.ModifyDynamicZone(context.Background(), mod); err != nil {
		t.Fatalf("modify failed: %v", err)
	}
	<-ch

	after, _ := Zones.Get("modnil.example.")
	if after.Options[OptAllowUpdates] {
		t.Error("allow-updates became effective across a modify")
	}
	if !after.SuppressedOptions[OptAllowUpdates] {
		t.Error("modify DESTROYED the suppressed record: the operator's config would be silently rewritten")
	}
	if !after.asConfiguredOptions()[OptAllowUpdates] {
		t.Error("as-configured view lost the option across a modify")
	}
}

// TestGlobalSuppressionCandidate covers the predicate the suppression warning
// is driven by. It takes loose values, not a *ZoneData, because zd.ZoneType is
// assigned asynchronously by the RefreshEngine: reading it at parse time
// classified PRIMARIES as secondaries and mis-reported them on every cold start.
func TestGlobalSuppressionCandidate(t *testing.T) {
	withAppType(t, AppTypeAuth)

	// What a registry entry actually looks like at warning time on cold start.
	unpopulated := &ZoneData{ZoneName: "primary.example.", Options: map[ZoneOption]bool{}}
	if zoneMayOriginateContent(unpopulated) {
		t.Fatal("setup: an unpopulated ZoneData reads as non-originating — the trap being avoided")
	}

	for _, tc := range []struct {
		name      string
		appType   AppType
		ztype     ZoneType
		opts      map[ZoneOption]bool
		perZone   string
		candidate bool
	}{
		{"primary is never a candidate", AppTypeAuth, Primary, nil, "", false},
		{"plain secondary inheriting the global", AppTypeAuth, Secondary, nil, "", true},
		{"inline-signing secondary may originate", AppTypeAuth, Secondary,
			map[ZoneOption]bool{OptInlineSigning: true}, "", false},
		{"secondary with its own explicit mode already warned", AppTypeAuth, Secondary,
			nil, OutboundSoaSerialPersist, false},
		{"non-auth app is never a candidate", AppTypeAgent, Secondary, nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			if opts == nil {
				opts = map[ZoneOption]bool{}
			}
			if got := serialSuppressionCandidate(tc.appType, tc.ztype, opts, tc.perZone); got != tc.candidate {
				t.Errorf("serialSuppressionCandidate = %v, want %v", got, tc.candidate)
			}
		})
	}
}
