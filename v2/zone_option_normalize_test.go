package tdns

import (
	"strings"
	"testing"
)

// Fix B: the option normalizer. It strips origination settings a tdns-auth
// secondary may not act on, records what it stripped so the AS-CONFIGURED view
// survives, and warns the operator without taking the zone out of service.

func optSet(opts ...ZoneOption) map[ZoneOption]bool {
	m := map[ZoneOption]bool{}
	for _, o := range opts {
		m[o] = true
	}
	return m
}

// TestNormalizeStripsEveryOriginationOption walks the full turn-off list. Each
// of the five is stripped on a plain tdns-auth secondary, and each appears in
// the operator-facing message.
func TestNormalizeStripsEveryOriginationOption(t *testing.T) {
	for _, opt := range originationOptions {
		t.Run(ZoneOptionToString[opt], func(t *testing.T) {
			eff, _, sup, msg := normalizeOptionsForRole(
				AppTypeAuth, Secondary, optSet(opt), "")

			if eff[opt] {
				t.Errorf("%s still effective on a secondary", ZoneOptionToString[opt])
			}
			if !sup[opt] {
				t.Errorf("%s not recorded as suppressed", ZoneOptionToString[opt])
			}
			if !strings.Contains(msg, ZoneOptionToString[opt]) {
				t.Errorf("message does not name the option: %q", msg)
			}
		})
	}
}

// TestNormalizeKeepsSanctionedAndServingOptions guards the carve-outs: the
// catalog options (consumption provisions OTHER zones — the whole point of
// RFC 9432), delegation-sync-child, and serving-behaviour options must survive
// untouched on a secondary.
func TestNormalizeKeepsSanctionedAndServingOptions(t *testing.T) {
	keep := optSet(
		OptCatalogZone, OptCatalogMemberAutoCreate, OptCatalogMemberAutoDelete,
		OptDelSyncChild, OptFoldCase, OptBlackLies,
	)
	eff, _, sup, msg := normalizeOptionsForRole(AppTypeAuth, Secondary, keep, "")

	for opt := range keep {
		if !eff[opt] {
			t.Errorf("%s was stripped but must be kept on a secondary", ZoneOptionToString[opt])
		}
	}
	if len(sup) != 0 {
		t.Errorf("nothing should have been suppressed, got %v", sup)
	}
	if msg != "" {
		t.Errorf("no warning expected, got %q", msg)
	}
}

// TestNormalizeNoopForOriginators covers the three cases that may originate:
// a primary, an inline-signing secondary (the sanctioned exception), and any
// zone off tdns-auth (the §1.1 guarantee for tdns-mp / tdns-agent).
func TestNormalizeNoopForOriginators(t *testing.T) {
	all := optSet(originationOptions...)

	cases := []struct {
		name    string
		appType AppType
		ztype   ZoneType
		opts    map[ZoneOption]bool
	}{
		{"primary", AppTypeAuth, Primary, all},
		{"inline-signing secondary", AppTypeAuth, Secondary, optSet(append(originationOptions, OptInlineSigning)...)},
		{"non-auth app secondary", AppTypeAgent, Secondary, all},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eff, serial, sup, msg := normalizeOptionsForRole(
				tc.appType, tc.ztype, tc.opts, OutboundSoaSerialPersist)

			for _, opt := range originationOptions {
				if !eff[opt] {
					t.Errorf("%s was stripped but this zone may originate", ZoneOptionToString[opt])
				}
			}
			if serial != OutboundSoaSerialPersist {
				t.Errorf("serial mode = %q, want it left alone", serial)
			}
			if len(sup) != 0 || msg != "" {
				t.Errorf("expected a complete no-op, got suppressed=%v msg=%q", sup, msg)
			}
		})
	}
}

// TestNormalizeStripsExplicitSerialMode pins that an explicit per-zone
// persist/unixtime is cleared on a secondary (it would rewrite a serial that
// belongs to upstream), while an EMPTY value — "inherit the global" — is left
// alone and draws no warning. Warning about a server-wide default on every
// secondary would be noise; the global is suppressed at the point of use.
func TestNormalizeStripsExplicitSerialMode(t *testing.T) {
	for _, mode := range []string{OutboundSoaSerialPersist, OutboundSoaSerialUnixtime} {
		_, serial, _, msg := normalizeOptionsForRole(
			AppTypeAuth, Secondary, map[ZoneOption]bool{}, mode)
		if serial != "" {
			t.Errorf("%s: serial mode = %q, want cleared", mode, serial)
		}
		if !strings.Contains(msg, "outbound_soa_serial") {
			t.Errorf("%s: message does not mention the serial mode: %q", mode, msg)
		}
	}

	// Empty (inherit) and explicit keep are both harmless.
	for _, mode := range []string{"", OutboundSoaSerialKeep} {
		_, serial, _, msg := normalizeOptionsForRole(
			AppTypeAuth, Secondary, map[ZoneOption]bool{}, mode)
		if serial != mode {
			t.Errorf("mode %q was altered to %q", mode, serial)
		}
		if msg != "" {
			t.Errorf("mode %q drew a warning: %q", mode, msg)
		}
	}
}

// TestNormalizeSuggestsInlineSigning checks the actionable half of the message:
// the likeliest intent behind online-signing on a secondary is the sanctioned
// signing-secondary setup, which is a different option.
func TestNormalizeSuggestsInlineSigning(t *testing.T) {
	_, _, _, msg := normalizeOptionsForRole(
		AppTypeAuth, Secondary, optSet(OptOnlineSigning), "")
	if !strings.Contains(msg, "inline-signing") {
		t.Errorf("message should point at inline-signing, got %q", msg)
	}
}

// TestNormalizeDoesNotMutateCallerMap guards the copy-on-write: the caller's
// map may be shared with a live ZoneData or a config struct, so stripping must
// not reach back into it.
func TestNormalizeDoesNotMutateCallerMap(t *testing.T) {
	in := optSet(OptAllowUpdates, OptFoldCase)
	eff, _, _, _ := normalizeOptionsForRole(AppTypeAuth, Secondary, in, "")

	if !in[OptAllowUpdates] {
		t.Error("caller's map was mutated")
	}
	if eff[OptAllowUpdates] {
		t.Error("effective map still carries the stripped option")
	}
}

// TestAsConfiguredOptionsRoundTrip is the anti-silent-deletion guard. The
// dynamic config file is regenerated from live state, so the as-configured view
// (effective ∪ suppressed) is what must be written back — otherwise the
// operator's allow-updates is deleted from their own config, the warning then
// clears, and the misconfiguration becomes invisible.
func TestAsConfiguredOptionsRoundTrip(t *testing.T) {
	withAppType(t, AppTypeAuth)

	zd := &ZoneData{ZoneName: "sec.example.", ZoneType: Secondary}
	opts, serial := zd.applyOptionNormalization(
		Secondary, optSet(OptAllowUpdates, OptFoldCase), OutboundSoaSerialPersist)
	zd.Options = opts
	zd.OutboundSoaSerial = serial

	if zd.Options[OptAllowUpdates] {
		t.Error("effective options still carry allow-updates")
	}
	asConf := zd.asConfiguredOptions()
	if !asConf[OptAllowUpdates] {
		t.Error("as-configured view lost allow-updates: the operator's config would be silently rewritten")
	}
	if !asConf[OptFoldCase] {
		t.Error("as-configured view lost an untouched option")
	}

	// And it must survive into the serialized ZoneConf.
	zconf := zoneDataToZoneConf(zd, "/tmp/zones")
	var found bool
	for _, s := range zconf.OptionsStrs {
		if s == ZoneOptionToString[OptAllowUpdates] {
			found = true
		}
	}
	if !found {
		t.Errorf("serialized options lost allow-updates: %v", zconf.OptionsStrs)
	}
}

// TestApplyOptionNormalizationUsesConfigWarning pins the severity choice.
// ConfigError is in serviceImpactingErrors ("a NOTIFY/UPDATE/query handler
// should refuse with SERVFAIL"), so using it here would eventually take a
// merely-misconfigured secondary out of service. The zone is serving correctly;
// only some of its config is ignored.
func TestApplyOptionNormalizationUsesConfigWarning(t *testing.T) {
	withAppType(t, AppTypeAuth)

	zd := &ZoneData{ZoneName: "sec.example.", ZoneType: Secondary}
	zd.applyOptionNormalization(Secondary, optSet(OptAllowUpdates), "")

	if !zd.HasError(ConfigWarning) {
		t.Fatal("expected a ConfigWarning")
	}
	if zd.HasError(ConfigError) {
		t.Error("must not raise ConfigError: that category is service-impacting")
	}
	if ErrorTypeIsServiceImpacting(ConfigWarning) {
		t.Error("ConfigWarning must not be service-impacting")
	}

	// Recomputed each parse: a clean config clears the warning on reload.
	zd.applyOptionNormalization(Secondary, optSet(OptFoldCase), "")
	if zd.HasError(ConfigWarning) {
		t.Error("warning should clear once the config is clean")
	}
	if len(zd.SuppressedOptions) != 0 {
		t.Error("suppressed set should be empty once the config is clean")
	}
}
