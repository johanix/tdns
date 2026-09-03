package tdns

import (
	"strings"
	"testing"
)

// The use-hsyncparam zone option round-trips through the string<->enum maps.
// Adding the name to only one of them compiles and then fails at runtime, in
// the switch's default arm, with "unknown config option" -- which takes the
// zone off the air.
func TestUseHsyncparamOptionMapping(t *testing.T) {
	const name = "use-hsyncparam"

	opt, ok := StringToZoneOption[name]
	if !ok {
		t.Fatalf("StringToZoneOption has no entry for %q", name)
	}
	if opt != OptUseHsyncparam {
		t.Fatalf("StringToZoneOption[%q] = %d, want OptUseHsyncparam (%d)", name, opt, OptUseHsyncparam)
	}
	if got := ZoneOptionToString[OptUseHsyncparam]; got != name {
		t.Fatalf("ZoneOptionToString[OptUseHsyncparam] = %q, want %q", got, name)
	}
}

// On a secondary -- the only role the republisher runs in -- the option is
// enabled and the zone stays clean.
func TestParseZoneOptionsAcceptsUseHsyncparamOnSecondary(t *testing.T) {
	zd := &ZoneData{ZoneName: "customer.example."}
	zconf := &ZoneConf{
		Name:        "customer.example.",
		Type:        "secondary",
		OptionsStrs: []string{"use-hsyncparam"},
	}

	options := parseZoneOptions(&Config{}, "customer.example.", zconf, zd)

	if !options[OptUseHsyncparam] {
		t.Fatalf("parseZoneOptions did not enable OptUseHsyncparam; got %v", options)
	}
	for _, e := range zd.ErrorList() {
		t.Fatalf("unexpected %v after parsing a valid option: %q", e.Type, e.Msg)
	}
	// The as-configured list is what a config re-serialization writes back.
	var found bool
	for _, o := range zconf.Options {
		if o == OptUseHsyncparam {
			found = true
		}
	}
	if !found {
		t.Fatalf("OptUseHsyncparam missing from zconf.Options: %v", zconf.Options)
	}
}

// On a primary the option is inert: the republisher is driven by an inbound
// transfer of a zone somebody else owns, and a primary receives none. Drop it
// and TELL the operator -- an option that silently does nothing leaves them
// believing it works.
//
// A ConfigWarning, not a ConfigError: ConfigError is in serviceImpactingErrors,
// so raising one here would stop a perfectly healthy zone answering queries
// over a setting whose only fault is having no effect.
func TestParseZoneOptionsWarnsOnUseHsyncparamOnPrimary(t *testing.T) {
	zd := &ZoneData{ZoneName: "example."}
	zconf := &ZoneConf{
		Name:        "example.",
		Type:        "primary",
		OptionsStrs: []string{"use-hsyncparam"},
	}

	options := parseZoneOptions(&Config{}, "example.", zconf, zd)

	if options[OptUseHsyncparam] {
		t.Fatal("parseZoneOptions enabled use-hsyncparam on a primary")
	}
	for _, o := range zconf.Options {
		if o == OptUseHsyncparam {
			t.Fatal("a dropped option must not survive into zconf.Options")
		}
	}

	var warned bool
	for _, e := range zd.ErrorList() {
		switch e.Type {
		case ConfigError:
			t.Fatalf("use-hsyncparam on a primary must not take the zone off the air: %q", e.Msg)
		case ConfigWarning:
			if strings.Contains(e.Msg, "use-hsyncparam") && strings.Contains(e.Msg, "secondary") {
				warned = true
			}
		}
	}
	if !warned {
		t.Fatalf("no ConfigWarning naming the option and the reason; errors: %v", zd.ErrorList())
	}
}

// A dynamic (template-provisioned) primary must REFUSE the option rather than
// warn: that path exists so a blessed template cannot silently lose an option,
// and a secondary-only option in a primary template is a template bug.
func TestDynamicPrimaryDisallowsUseHsyncparam(t *testing.T) {
	if !dynamicPrimaryDisallowedOptions[OptUseHsyncparam] {
		t.Fatal("use-hsyncparam must be in dynamicPrimaryDisallowedOptions")
	}
}
