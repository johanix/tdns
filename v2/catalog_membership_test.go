package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The catalog fixes: the member list is rebuilt from the catalog's records
// at load, a catalog the config file defines writes its changes to its own
// zone file (and stays out of the dynamic config), and a catalog the server
// produces needs no catalog.config-groups.

// newTestCatalog creates an API catalog zone (published, empty) and cleans
// it up afterwards.
func newTestCatalog(t *testing.T, zone string) *ZoneData {
	t.Helper()
	t.Cleanup(func() {
		if zd, ok := Zones.Get(zone); ok {
			zd.stopPublisher()
			zd.joinPublisher()
		}
		Zones.Remove(zone)
		forgetCatalogMembership(zone)
	})
	if err := handleCatalogCreate(zone, &CatalogResponse{}); err != nil {
		t.Fatalf("handleCatalogCreate: %v", err)
	}
	zd, ok := Zones.Get(zone)
	if !ok {
		t.Fatal("the catalog zone is not registered")
	}
	return zd
}

// catalogPTRs returns the member zone names the catalog's published content
// lists, keyed by owner name.
func catalogPTRs(zd *ZoneData) map[string]string {
	out := map[string]string{}
	snap := zd.publishedSnapshot()
	if snap == nil {
		return out
	}
	for owner, od := range snap.Data {
		for _, rr := range od.RRtypes.GetOnlyRRSet(dns.TypePTR).RRs {
			if ptr, ok := rr.(*dns.PTR); ok {
				out[owner] = ptr.Ptr
			}
		}
	}
	return out
}

func waitForMembers(t *testing.T, zd *ZoneData, n int) map[string]string {
	t.Helper()
	var ptrs map[string]string
	waitFor(t, 3*time.Second, "the catalog's publish", func() bool {
		ptrs = catalogPTRs(zd)
		return len(ptrs) == n
	})
	return ptrs
}

func TestRebuildCatalogMembershipSurvivesARestart(t *testing.T) {
	const zone = "catalog.rebuild.example."
	zd := newTestCatalog(t, zone)

	if err := handleCatalogGroupAdd(zone, "blue", &CatalogResponse{}); err != nil {
		t.Fatalf("group add: %v", err)
	}
	for _, m := range []string{"m1.example.", "m2.example."} {
		if err := handleCatalogZoneAdd(zone, m, nil, &CatalogResponse{}); err != nil {
			t.Fatalf("zone add %s: %v", m, err)
		}
	}
	if err := handleCatalogZoneGroupAdd(zone, "m2.example.", "blue", &CatalogResponse{}); err != nil {
		t.Fatalf("zone group add: %v", err)
	}
	before := waitForMembers(t, zd, 2)

	// The restart: the in-memory member list is gone, the zone content stays.
	forgetCatalogMembership(zone)
	n, err := rebuildCatalogMembership(zd)
	if err != nil || n != 2 {
		t.Fatalf("rebuild: %d members, %v", n, err)
	}
	cm := catalogMembershipOf(zone)
	m2, ok := cm.MemberZones["m2.example."]
	if !ok || len(m2.Groups) != 1 || m2.Groups[0] != "blue" {
		t.Errorf("m2's groups not rebuilt: %+v", m2)
	}
	if m2.Hash != generateZoneHash("m2.example.") {
		t.Errorf("member id not taken from the owner name: %q", m2.Hash)
	}
	if len(cm.AvailableGroups) != 1 || cm.AvailableGroups[0] != "blue" {
		t.Errorf("groups in use not made available: %v", cm.AvailableGroups)
	}

	// The next add keeps every earlier member, at its old owner name.
	if err := handleCatalogZoneAdd(zone, "m3.example.", nil, &CatalogResponse{}); err != nil {
		t.Fatalf("zone add m3: %v", err)
	}
	after := waitForMembers(t, zd, 3)
	for owner, name := range before {
		if after[owner] != name {
			t.Errorf("member %s lost or moved by the add after a restart (owner %s)", name, owner)
		}
	}
}

func TestRebuildCatalogMembershipLeavesASecondaryAlone(t *testing.T) {
	withAppType(t, AppTypeAuth) // the app type whose secondaries may not originate
	const zone = "catalog.mirror.example."
	zd := newTestCatalog(t, zone)
	if err := handleCatalogZoneAdd(zone, "m1.example.", nil, &CatalogResponse{}); err != nil {
		t.Fatalf("zone add: %v", err)
	}
	waitForMembers(t, zd, 1)
	zd.mu.Lock()
	zd.ZoneType = Secondary
	zd.mu.Unlock()
	forgetCatalogMembership(zone)
	if n, err := rebuildCatalogMembership(zd); n != 0 || err != nil {
		t.Errorf("a secondary's catalog must not be given a member list: %d, %v", n, err)
	}
	if cm := catalogMembershipOf(zone); cm != nil {
		t.Errorf("a secondary's catalog got a member list: %+v", cm.MemberZones)
	}
}

func TestConfiguredCatalogWritesItsOwnZoneFile(t *testing.T) {
	const zone = "catalog.configured.example."
	dir := t.TempDir()
	prev := Conf.DynamicZones
	t.Cleanup(func() { Conf.DynamicZones = prev })
	Conf.DynamicZones.ZoneDirectory = filepath.Join(dir, "zones")
	Conf.DynamicZones.ConfigFile = filepath.Join(dir, "dynamic-zones.yaml")
	Conf.DynamicZones.CatalogZones.Storage = "persistent"
	Conf.DynamicZones.CatalogZones.Allowed = true

	zd := newTestCatalog(t, zone)
	own := filepath.Join(dir, "catalog.configured.example.zone")
	zd.mu.Lock()
	zd.fromStaticConfig = true // as ParseZones leaves a zone the config defines
	zd.Zonefile = own
	zd.mu.Unlock()
	if Conf.ShouldPersistZone(zd) {
		t.Error("a zone the config file defines must not be written into the dynamic config")
	}
	// Whatever the API create wrote before the zone was marked as configured.
	os.RemoveAll(Conf.DynamicZones.ZoneDirectory)
	os.Remove(Conf.DynamicZones.ConfigFile)

	if err := handleCatalogZoneAdd(zone, "m1.example.", nil, &CatalogResponse{}); err != nil {
		t.Fatalf("zone add: %v", err)
	}
	waitForMembers(t, zd, 1)
	var data []byte
	waitFor(t, 3*time.Second, "the write-back", func() bool {
		b, err := os.ReadFile(own)
		data = b
		return err == nil && strings.Contains(string(b), "m1.example.")
	})
	if !strings.Contains(string(data), "PTR") {
		t.Errorf("the catalog's own file lacks the member:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(Conf.DynamicZones.ZoneDirectory, "catalog.configured.example.zone")); err == nil {
		t.Error("a configured catalog must not be written to a zonedirectory copy")
	}
	if b, err := os.ReadFile(Conf.DynamicZones.ConfigFile); err == nil && strings.Contains(string(b), zone) {
		t.Errorf("a configured catalog was written into the dynamic config:\n%s", b)
	}
}

func TestProducerCatalogNeedsNoConfigGroups(t *testing.T) {
	saved := Conf.Catalog
	t.Cleanup(func() { Conf.Catalog = saved })

	for _, c := range []struct {
		name    string
		catalog *CatalogConf
		options []string
		wantErr bool
	}{
		{"producer, no catalog block", nil, []string{"catalog-zone"}, false},
		{"producer, no config groups", &CatalogConf{}, []string{"catalog-zone"}, false},
		{"consumer that auto-creates, no catalog block", nil, []string{"catalog-zone", "catalog-member-auto-create"}, true},
		{"consumer that auto-creates, option order reversed", &CatalogConf{}, []string{"catalog-member-auto-create", "catalog-zone"}, true},
	} {
		conf := &Config{Catalog: c.catalog}
		zd := &ZoneData{ZoneName: "cat.example."}
		zc := &ZoneConf{Name: "cat.example.", Type: "primary", OptionsStrs: c.options}
		opts := parseZoneOptions(conf, "cat.example.", zc, zd)
		hasErr := zd.HasError(ConfigError)
		if hasErr != c.wantErr {
			t.Errorf("%s: config error %v (%q), want %v", c.name, hasErr, zd.ErrorMsg, c.wantErr)
		}
		if !c.wantErr && !opts[OptCatalogZone] {
			t.Errorf("%s: catalog-zone option lost", c.name)
		}
	}
}
