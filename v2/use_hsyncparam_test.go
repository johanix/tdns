package tdns

import (
	"strings"
	"testing"
	"time"

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

// Both refresh hooks are registered once, at first load, for EVERY zone, and
// self-gate at run time (#489 review: the reload registration gap, and the
// data race it would take to fix it any other way). This is what lets a zone
// reconfigured from primary to secondary on reload still act -- the hook is
// already there from first load -- without ever mutating the OnZone*Refresh
// slices after the zone is live.
func TestRefreshHooksRegisterAtFirstLoad(t *testing.T) {
	zdp := &ZoneData{ZoneName: "z.example."}

	zdp.registerSignalRepublishHook()
	zdp.registerProxyDelegationHooks(make(chan DelegationSyncRequest, 1))

	// One signal post-refresh hook + one proxy pre/post pair.
	if pre := len(zdp.OnZonePreRefresh); pre != 1 {
		t.Fatalf("OnZonePreRefresh = %d, want 1 (proxy)", pre)
	}
	if post := len(zdp.OnZonePostRefresh); post != 2 {
		t.Fatalf("OnZonePostRefresh = %d, want 2 (signal + proxy)", post)
	}
}

// The proxy's registered pre-refresh closure gates on OptDelSyncProxy. The
// closure is the live wiring registered on every zone; ProxyDelegationPreRefresh
// itself is the pure diff (exercised directly by the delsync_proxy_p2 tests).
// Without the option the closure must not run the diff, so registering it
// everywhere costs a non-proxy zone nothing; with the option, the CSYNC change
// is detected. Driven through the registered slice, which is the real gate.
func TestProxyRefreshClosureGatesOnOption(t *testing.T) {
	makeZones := func() (*ZoneData, *ZoneData) {
		old := newMapZone("child.example.", Secondary, map[string][]dns.RR{
			"child.example.": {mustRR(t, "child.example. 3600 IN CSYNC 1 3 A NS AAAA")},
		})
		next := newMapZone("child.example.", Secondary, map[string][]dns.RR{
			"child.example.": {mustRR(t, "child.example. 3600 IN CSYNC 2 3 A NS AAAA")},
		})
		return old, next
	}

	// Register the hooks as ParseZones would, then invoke the pre-refresh
	// closure directly.
	zdp := &ZoneData{ZoneName: "reg.example."}
	zdp.registerProxyDelegationHooks(make(chan DelegationSyncRequest, 1))
	if len(zdp.OnZonePreRefresh) != 1 {
		t.Fatalf("expected 1 pre-refresh closure, got %d", len(zdp.OnZonePreRefresh))
	}
	preClosure := zdp.OnZonePreRefresh[0]

	// Option off: the closure must not run the diff.
	off, offNew := makeZones()
	preClosure(off, offNew)
	if off.ProxyRefreshAnalysis != nil {
		t.Fatal("proxy closure ran the diff without delegation-sync-proxy set")
	}

	// Option on: the CSYNC change is detected.
	on, onNew := makeZones()
	on.SetOption(OptDelSyncProxy, true)
	preClosure(on, onNew)
	if on.ProxyRefreshAnalysis == nil || !on.ProxyRefreshAnalysis.CsyncChanged {
		t.Fatalf("proxy closure missed the CSYNC change with the option set: %+v", on.ProxyRefreshAnalysis)
	}
}

// The option read in RepublishAtSignalNames is synchronized against a concurrent
// reload replacing zd.Options (#489 review, data-race finding). Run under
// `go test -race`: an unsynchronized map read here races SetOption's write and
// fails the race detector. The hook is a no-op on this bare zone (no apex), so
// this exercises only the guarded read. Both loops are bounded and the wait is
// capped, so the test cannot hang if the goroutine wedges.
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
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("republish goroutine did not finish; possible deadlock in the option read")
	}
}
