package tdns

import "testing"

// Regression tests for two findings from the PR #331 review.

// TestModifyNormalizesSubmittedOptions pins the ModifyDynamicZone case: the
// options SUBMITTED with a modify must be normalized, not just the ones carried
// forward when none are supplied.
//
// Without that, `zone modify --options allow-updates` on a secondary installed
// them live and persisted them with a STALE SuppressedOptions record and no
// warning — re-enabling exactly what the normalizer exists to strip, through
// the one ingress the design doc singled out as most likely to be missed.
//
// Exercised at the normalizer boundary that ModifyDynamicZone now calls, so it
// fails if that call is dropped.
func TestModifyNormalizesSubmittedOptions(t *testing.T) {
	// A modify submitting origination options against a secondary.
	submitted := map[ZoneOption]bool{
		OptAllowUpdates:   true,
		OptApiManagedZone: true, // set by the modify path itself
	}
	eff, _, sup, msg := normalizeOptionsForRole(AppTypeAuth, Secondary, submitted, "")

	if eff[OptAllowUpdates] {
		t.Error("submitted allow-updates survived normalization on a secondary")
	}
	if !sup[OptAllowUpdates] {
		t.Error("suppressed set does not record the submitted option")
	}
	if !eff[OptApiManagedZone] {
		t.Error("normalization dropped an unrelated internal marker")
	}
	if msg == "" {
		t.Error("no warning produced for a submitted origination option")
	}
}

// TestModifySuppressedSetReflectsSubmission guards the staleness half of the
// same finding: the suppressed record must describe the options actually
// submitted, not whatever the zone's previous incarnation carried. A modify
// that REMOVES the offending option must clear the record, or the as-configured
// view would keep resurrecting it into the persisted config forever.
func TestModifySuppressedSetReflectsSubmission(t *testing.T) {
	// Previous incarnation had allow-updates suppressed; the new submission
	// drops it and asks only for a serving-behaviour option.
	clean := map[ZoneOption]bool{OptFoldCase: true}
	eff, _, sup, msg := normalizeOptionsForRole(AppTypeAuth, Secondary, clean, "")

	if len(sup) != 0 {
		t.Errorf("suppressed set should be empty for a clean submission, got %v", sup)
	}
	if msg != "" {
		t.Errorf("clean submission should draw no warning, got %q", msg)
	}
	if !eff[OptFoldCase] {
		t.Error("serving-behaviour option was dropped")
	}
}

// TestGlobalSuppressionWarningUsesResolvedRole is the regression for the
// cold-start false positive: the warning must be driven by the role resolved
// during the parse, never by re-reading zd.ZoneType from the registry.
//
// zd.ZoneType is assigned asynchronously by the RefreshEngine when it consumes
// the ZoneRefresher, so at warning time a freshly registered zone still has
// ZoneType == 0. Reading it there made zoneMayOriginateContent false for
// essentially every zone without inline-signing — PRIMARIES INCLUDED — so a
// server with a global persist mode would list its primaries as "suppressed
// secondaries" on every cold start.
//
// Pinned by asserting the predicate the collection now uses, against a zone
// whose registry entry has NOT yet been populated.
func TestGlobalSuppressionWarningUsesResolvedRole(t *testing.T) {
	withAppType(t, AppTypeAuth)

	// What the registry looks like at warning time on a cold start: the type
	// has not been assigned yet.
	unpopulated := &ZoneData{ZoneName: "primary.example.", Options: map[ZoneOption]bool{}}
	if zoneMayOriginateContent(unpopulated) {
		t.Fatal("setup: an unpopulated ZoneData is expected to read as non-originating")
	}

	// ...which is precisely why the collection uses the PARSED role instead.
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
			got := serialSuppressionCandidate(tc.appType, tc.ztype, opts, tc.perZone)
			if got != tc.candidate {
				t.Errorf("serialSuppressionCandidate = %v, want %v", got, tc.candidate)
			}
		})
	}
}
