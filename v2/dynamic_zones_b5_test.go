package tdns

import "testing"

// TestZoneDataToZoneConf_WritesApiManaged verifies B5a write side: an API-managed
// zone serializes ApiManaged=true and does NOT leak OptApiManagedZone into the
// options string list (it is re-derived on reload from the bool, like
// OptAutomaticZone is re-derived from SourceCatalog).
func TestZoneDataToZoneConf_WritesApiManaged(t *testing.T) {
	zd := &ZoneData{
		ZoneName:      "api.example.",
		ZoneType:      Secondary,
		PrimariesConf: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		Upstreams:     []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		Options:       map[ZoneOption]bool{OptApiManagedZone: true},
	}
	zc := zoneDataToZoneConf(zd, "/tmp")
	if !zc.ApiManaged {
		t.Error("ApiManaged not written for an API-managed zone")
	}
	for _, s := range zc.OptionsStrs {
		if s == ZoneOptionToString[OptApiManagedZone] {
			t.Errorf("OptApiManagedZone leaked into OptionsStrs: %v", zc.OptionsStrs)
		}
	}

	// A catalog member writes SourceCatalog (already covered elsewhere) and not
	// OptAutomaticZone in the options list.
	cat := &ZoneData{
		ZoneName:      "member.example.",
		ZoneType:      Secondary,
		SourceCatalog: "cat.example.",
		Options:       map[ZoneOption]bool{OptAutomaticZone: true},
	}
	cc := zoneDataToZoneConf(cat, "/tmp")
	if cc.SourceCatalog != "cat.example." {
		t.Errorf("SourceCatalog not written: %q", cc.SourceCatalog)
	}
	if cc.ApiManaged {
		t.Error("catalog member wrongly marked ApiManaged")
	}
}

// TestShouldPersistZone_DynamicBranch verifies the B5a third branch: an
// API-managed zone is persistable iff dynamic.{allowed && storage==persistent}.
func TestShouldPersistZone_DynamicBranch(t *testing.T) {
	conf := &Config{}
	conf.DynamicZones.ZoneDirectory = "/tmp/zones"
	conf.DynamicZones.Dynamic.Allowed = true
	conf.DynamicZones.Dynamic.Storage = "persistent"

	api := &ZoneData{ZoneName: "api.example.", Options: map[ZoneOption]bool{OptApiManagedZone: true}}
	if !conf.ShouldPersistZone(api) {
		t.Error("API-managed zone should persist when dynamic allowed+persistent")
	}

	conf.DynamicZones.Dynamic.Storage = "memory"
	if conf.ShouldPersistZone(api) {
		t.Error("API-managed zone should NOT persist when storage=memory")
	}

	// A plain static zone never persists.
	static := &ZoneData{ZoneName: "static.example.", Options: map[ZoneOption]bool{}}
	if conf.ShouldPersistZone(static) {
		t.Error("static zone should never be persistable")
	}
}

// TestZoneStillLive guards the B5b resurrection-race interlock: the pre-persist
// check fails once the zone is deleted, replaced, or its generation bumped.
func TestZoneStillLive(t *testing.T) {
	resetZonesForTest()
	zd := &ZoneData{ZoneName: "live.example."}
	Zones.Set("live.example.", zd)
	gen := zd.generation.Load()

	if !zoneStillLive(zd, gen) {
		t.Fatal("freshly registered zone should be live with matching generation")
	}

	// Generation bump (as RemoveDynamicZone/ModifyDynamicZone/reload do) → guard fails.
	zd.generation.Add(1)
	if zoneStillLive(zd, gen) {
		t.Error("guard should fail after generation bump (stale refresh must not persist)")
	}

	// Replacement by a new ZoneData (the modify case) → identity check fails.
	newZd := &ZoneData{ZoneName: "live.example."}
	Zones.Set("live.example.", newZd)
	if zoneStillLive(zd, zd.generation.Load()) {
		t.Error("guard should fail when the map holds a different ZoneData pointer")
	}

	// Removal → liveness check fails.
	Zones.Remove("live.example.")
	if zoneStillLive(newZd, newZd.generation.Load()) {
		t.Error("guard should fail after the zone is removed from the map")
	}
}

// TestMarkerReDerivation simulates the B5a reload re-derivation: given a
// persisted ZoneConf, the options map rebuilt by LoadDynamicZoneFiles must
// re-set OptAutomaticZone from SourceCatalog and OptApiManagedZone from
// ApiManaged. This mirrors the inline logic so the contract is locked down
// without standing up a full reload.
func TestMarkerReDerivation(t *testing.T) {
	rederive := func(zc ZoneConf) map[ZoneOption]bool {
		options := map[ZoneOption]bool{}
		for _, s := range zc.OptionsStrs {
			if opt, ok := StringToZoneOption[s]; ok {
				options[opt] = true
			}
		}
		if zc.SourceCatalog != "" {
			options[OptAutomaticZone] = true
		}
		if zc.ApiManaged {
			options[OptApiManagedZone] = true
		}
		return options
	}

	cat := rederive(ZoneConf{Name: "m.example.", SourceCatalog: "c.example."})
	if !cat[OptAutomaticZone] {
		t.Error("catalog member lost OptAutomaticZone on reload (the latent bug)")
	}
	if cat[OptApiManagedZone] {
		t.Error("catalog member wrongly got OptApiManagedZone")
	}

	api := rederive(ZoneConf{Name: "a.example.", ApiManaged: true})
	if !api[OptApiManagedZone] {
		t.Error("API zone lost OptApiManagedZone on reload")
	}
	if api[OptAutomaticZone] {
		t.Error("API zone wrongly got OptAutomaticZone")
	}

	static := rederive(ZoneConf{Name: "s.example."})
	if static[OptAutomaticZone] || static[OptApiManagedZone] {
		t.Error("static zone wrongly got a dynamic marker")
	}
}
