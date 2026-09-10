/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"log"
	"os"
	"testing"
)

func TestChildsyncProxyOptionRoundTrips(t *testing.T) {
	if StringToZoneOption["childsync-proxy"] != OptChildSyncProxy || ZoneOptionToString[OptChildSyncProxy] != "childsync-proxy" {
		t.Fatal("childsync-proxy is not in both option name maps")
	}
}

// childsync-proxy implies childsync in the effective set (design D-1), and
// the as-configured list keeps saying what the operator wrote. Writing both
// is legal and redundant.
func TestChildsyncProxyImpliesChildsync(t *testing.T) {
	zd := &ZoneData{ZoneName: "example."}
	zconf := &ZoneConf{Name: "example.", Type: "secondary", OptionsStrs: []string{"childsync-proxy"}}
	options := parseZoneOptions(nil, "example.", zconf, zd)

	if !options[OptChildSyncProxy] || !options[OptChildSync] {
		t.Fatalf("effective options = %v; want childsync-proxy AND childsync", options)
	}
	for _, e := range zd.ErrorList() {
		if e.Type == ConfigError {
			t.Fatalf("unexpected ConfigError: %q", e.Msg)
		}
	}
	if len(zconf.Options) != 1 || zconf.Options[0] != OptChildSyncProxy {
		t.Fatalf("as-configured options = %v; want exactly what was written", zconf.Options)
	}

	both := &ZoneConf{Name: "example.", Type: "secondary", OptionsStrs: []string{"childsync-proxy", "childsync"}}
	zd2 := &ZoneData{ZoneName: "example."}
	if opts := parseZoneOptions(nil, "example.", both, zd2); !opts[OptChildSyncProxy] || !opts[OptChildSync] {
		t.Fatalf("both spelled: %v", opts)
	}
	for _, e := range zd2.ErrorList() {
		if e.Type == ConfigError {
			t.Fatalf("writing both is legal, got ConfigError: %q", e.Msg)
		}
	}
}

// The gate: childsync-proxy is an agent secondary's option and nothing else's.
func TestChildsyncProxyGate(t *testing.T) {
	prevApp := Globals.App.Type
	t.Cleanup(func() { Globals.App.Type = prevApp })

	proxyZone := func(ztype ZoneType) *ZoneData {
		return &ZoneData{
			ZoneName: "example.",
			ZoneType: ztype,
			Options:  map[ZoneOption]bool{OptChildSyncProxy: true, OptChildSync: true},
			Logger:   log.New(os.Stderr, "", 0),
		}
	}

	Globals.App.Type = AppTypeAuth
	if err := proxyZone(Secondary).SetupZoneSync(nil); err == nil {
		t.Fatal("childsync-proxy on tdns-auth must be rejected")
	}
	Globals.App.Type = AppTypeAgent
	if err := proxyZone(Primary).SetupZoneSync(nil); err == nil {
		t.Fatal("childsync-proxy on a primary must be rejected")
	}
	zd := proxyZone(Secondary)
	if err := zd.SetupZoneSync(nil); err != nil {
		t.Fatalf("childsync-proxy on an agent secondary must pass the gate: %v", err)
	}
	if zd.HasError(ConfigError) {
		t.Fatalf("the accepted case left a ConfigError: %+v", zd.Errors)
	}
}

// A childsync-proxy zone never publishes the advertisement into its own copy
// of the zone: that update would be applied and lost at the next transfer.
// The same zone, with the same configuration, has a non-empty advertisement
// to publish -- so it is the option, not an empty build, that keeps the
// update off the queue.
func TestChildsyncProxyNeverPublishesLocally(t *testing.T) {
	prevApp := Globals.App.Type
	t.Cleanup(func() { Globals.App.Type = prevApp })
	Globals.App.Type = AppTypeAgent
	allSchemesChildSync(t)

	q := make(chan UpdateRequest, 4)
	zd := testZone(t, "example.", partiallyAdvertisedParent)
	zd.ZoneType = Secondary
	zd.KeyDB = newTestKeyDB(t)
	zd.KeyDB.UpdateQ = q
	zd.Options = map[ZoneOption]bool{OptChildSyncProxy: true, OptChildSync: true}
	p := DefaultDelegationPolicy()
	zd.DelegationPolicy = &p

	pub, err := zd.BuildDsyncPublication()
	if err != nil || pub.Empty() {
		t.Fatalf("the control is wrong: pub=%+v err=%v; this zone must have something to advertise", pub, err)
	}
	if err := zd.SetupZoneSync(nil); err != nil {
		t.Fatalf("SetupZoneSync: %v", err)
	}
	if len(q) != 0 {
		t.Fatalf("a childsync-proxy zone posted %d update(s) for its own copy of the zone", len(q))
	}
}

// Off tdns-auth the normaliser is a no-op, and on tdns-auth the option must
// survive to reach SetupZoneSync's gate, which is what turns it into a
// ConfigError that names the mistake.
func TestNormalizeKeepsChildsyncProxy(t *testing.T) {
	eff, _, _, _ := normalizeOptionsForRole(AppTypeAuth, Secondary, optSet(OptChildSyncProxy), "")
	if !eff[OptChildSyncProxy] {
		t.Fatal("childsync-proxy was stripped by the normaliser; the gate would never see it")
	}
}
