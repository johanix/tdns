package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
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
//
// Driven through prepareDynamicPrimary rather than by asserting map membership.
// The map is only the arm; the refusal is what an operator meets, and only the
// real producer proves the option is consulted before the zone is minted.
func TestDynamicPrimaryRefusesUseHsyncparam(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	tmpl := dynPrimaryTestTemplate(t.TempDir())
	tmpl.OptionsStrs = []string{"use-hsyncparam"}
	withTestTemplates(t, map[string]ZoneConf{"hp": tmpl})

	_, err := conf.prepareDynamicPrimary(ZoneConf{Name: "a.example", Template: "hp"}, nil, true)
	if err == nil {
		t.Fatal("a template carrying use-hsyncparam produced a dynamic primary")
	}
	if !strings.Contains(err.Error(), "use-hsyncparam") || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("refusal does not name the option and the reason: %v", err)
	}

	// The same template without the option must still work, so the failure
	// above is the option and not a broken fixture.
	ok := dynPrimaryTestTemplate(t.TempDir())
	withTestTemplates(t, map[string]ZoneConf{"plain": ok})
	if _, err := conf.prepareDynamicPrimary(ZoneConf{Name: "b.example", Template: "plain"}, nil, true); err != nil {
		t.Fatalf("template without the option was refused too: %v", err)
	}
}

// The republish hook is registered once, but on a zone that BECOMES a secondary
// — the reload gap CodeRabbit found (#489 review, finding on parseconfig.go).
// ParseZones reuses the ZoneData, so a hook keyed on FirstZoneLoad is never
// registered on a zone reconfigured from primary to secondary (FirstZoneLoad is
// already false by then), and a hook re-appended every reload accumulates
// duplicates. registerSignalRepublishHookOnce must do neither.
func TestRegisterSignalRepublishHookOnce(t *testing.T) {
	// A zone that starts as a primary registers nothing on that pass (ParseZones
	// only calls the helper for secondaries), then is reconfigured to secondary.
	zdp := &ZoneData{ZoneName: "customer.example."}

	// Primary pass: ParseZones would not call the helper at all. Nothing set.
	if got := len(zdp.OnZonePostRefresh); got != 0 {
		t.Fatalf("pre-registration hook count = %d, want 0", got)
	}

	// Becomes secondary — first registration.
	zdp.registerSignalRepublishHookOnce()
	if got := len(zdp.OnZonePostRefresh); got != 1 {
		t.Fatalf("after first registration: hook count = %d, want 1 "+
			"(a primary→secondary reload must register the hook)", got)
	}
	if !zdp.signalRepublishHookRegistered {
		t.Fatal("guard not set after registration")
	}

	// Every subsequent reload calls the helper again; it must not duplicate.
	for i := 0; i < 5; i++ {
		zdp.registerSignalRepublishHookOnce()
	}
	if got := len(zdp.OnZonePostRefresh); got != 1 {
		t.Fatalf("after repeated reloads: hook count = %d, want 1 (no duplicates)", got)
	}
}

// The proxy hooks share the same reload-aware registration. A zone that gains
// delegation-sync-proxy on a later reload must get both hooks; repeated reloads
// must not stack them.
func TestRegisterProxyDelegationHooksOnce(t *testing.T) {
	zdp := &ZoneData{ZoneName: "child.example."}
	q := make(chan DelegationSyncRequest, 1)

	zdp.registerProxyDelegationHooksOnce(q)
	if pre, post := len(zdp.OnZonePreRefresh), len(zdp.OnZonePostRefresh); pre != 1 || post != 1 {
		t.Fatalf("after first registration: pre=%d post=%d, want 1 and 1", pre, post)
	}

	for i := 0; i < 5; i++ {
		zdp.registerProxyDelegationHooksOnce(q)
	}
	if pre, post := len(zdp.OnZonePreRefresh), len(zdp.OnZonePostRefresh); pre != 1 || post != 1 {
		t.Fatalf("after repeated reloads: pre=%d post=%d, want 1 and 1 (no duplicates)", pre, post)
	}
}

// The option read in RepublishAtSignalNames is synchronized against a concurrent
// reload replacing zd.Options (CodeRabbit #489 review, data-race finding). Run
// under `go test -race`: an unsynchronized map read here races SetOption's write
// and fails the race detector. The hook is a no-op on this bare zone (no apex),
// so this exercises only the guarded read.
func TestRepublishAtSignalNamesOptionReadIsSynchronized(t *testing.T) {
	zd := newMapZone("z.example.", Secondary, map[string][]dns.RR{
		"z.example.": {mustRR(t, "z.example. 3600 IN NS ns.z.example.")},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			zd.RepublishAtSignalNames()
		}
	}()
	for i := 0; i < 2000; i++ {
		// Mirrors ParseZones replacing zd.Options wholesale on reload, via the
		// same lock (SetOption).
		zd.SetOption(OptUseHsyncparam, i%2 == 0)
	}
	<-done
}
