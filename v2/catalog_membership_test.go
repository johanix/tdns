package tdns

import (
	"context"
	"fmt"
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
	zd.fromStaticConfig.Store(true) // as ParseZones leaves a zone the config defines
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

func TestRebuildKeepsAMemberNotYetPublished(t *testing.T) {
	const zone = "catalog.busy.example."
	zd := newTestCatalog(t, zone)
	if err := handleCatalogZoneAdd(zone, "m1.example.", nil, &CatalogResponse{}); err != nil {
		t.Fatalf("zone add m1: %v", err)
	}
	waitForMembers(t, zd, 1)

	// A busy zone: the next change waits for the publish cadence.
	zd.mu.Lock()
	zd.publishCadence = 700 * time.Millisecond
	zd.lastPublish = time.Now()
	zd.mu.Unlock()
	if err := handleCatalogZoneAdd(zone, "m2.example.", nil, &CatalogResponse{}); err != nil {
		t.Fatalf("zone add m2: %v", err)
	}
	if got := len(catalogPTRs(zd)); got != 1 {
		t.Fatalf("m2 was published before the cadence: %d members", got)
	}
	// A rebuild now (an edited zone file reloaded, say) reads a zone without
	// m2. The list is ahead of the zone, so it must be kept.
	if _, err := rebuildCatalogMembership(zd); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if _, ok := catalogMembershipOf(zone).MemberZones["m2.example."]; !ok {
		t.Fatal("a rebuild dropped a member whose publish had not landed yet")
	}
	// Once the publish has landed the list and the zone agree, and a rebuild
	// runs again.
	waitForMembers(t, zd, 2)
	waitFor(t, 3*time.Second, "the publish bookkeeping", func() bool {
		cm := catalogMembershipOf(zone)
		cm.mu.RLock()
		defer cm.mu.RUnlock()
		return cm.edits == cm.publishedEdits
	})
	forgetCatalogMembership(zone)
	if n, err := rebuildCatalogMembership(zd); n != 2 || err != nil {
		t.Errorf("rebuild after the publish: %d members, %v", n, err)
	}
}

func TestAutoConfigureLeavesAProducedCatalogAlone(t *testing.T) {
	const zone = "catalog.produced.example."
	zd := newTestCatalog(t, zone)
	conf := &Config{Catalog: &CatalogConf{GroupPrefixes: GroupPrefixesConf{Config: "config", Signing: "sign"}}}
	update := &CatalogZoneUpdate{
		CatalogZone: zone,
		MemberZones: map[string]*MemberZone{
			"m1.example.": {ZoneName: "m1.example.", MetaGroup: "config-blue"},
		},
	}
	if err := AutoConfigureZonesFromCatalog(context.Background(), update, conf); err != nil {
		t.Errorf("a produced catalog that does not auto-create needs no local config groups: %v", err)
	}
	if zd.HasError(ConfigError) {
		t.Errorf("a produced catalog was put in error state over its members' groups: %q", zd.ErrorMsg)
	}
}

func TestParseCatalogZoneEmptyPrefixesMeanNone(t *testing.T) {
	const zone = "catalog.prefixes.example."
	zd := newTestCatalog(t, zone)
	saved := Conf.Catalog
	t.Cleanup(func() { Conf.Catalog = saved })
	Conf.Catalog = &CatalogConf{} // a catalog: block without group-prefixes

	if err := handleCatalogGroupAdd(zone, "blue", &CatalogResponse{}); err != nil {
		t.Fatalf("group add: %v", err)
	}
	if err := handleCatalogZoneAdd(zone, "m1.example.", []string{"blue"}, &CatalogResponse{}); err != nil {
		t.Fatalf("zone add: %v", err)
	}
	waitForMembers(t, zd, 1)
	update, err := ParseCatalogZone(zd)
	if err != nil {
		t.Fatalf("ParseCatalogZone: %v", err)
	}
	m := update.MemberZones["m1.example."]
	if m == nil || m.SigningGroup != "" || m.MetaGroup != "" || len(m.ServiceGroups) != 1 {
		t.Errorf("with no prefixes every group is ordinary: %+v", m)
	}
}

func TestAutoConfigureLeavesAReadOnlyCatalogAlone(t *testing.T) {
	// A secondary catalog that only reads: group prefixes configured, no
	// config groups, no auto-create. A member's config-type group that is
	// not defined locally is not this server's business.
	const zone = "catalog.readonly.example."
	zd := newTestCatalog(t, zone)
	zd.mu.Lock()
	zd.ZoneType = Secondary
	zd.mu.Unlock()
	// A ConfigError from an earlier pass (auto-create on before a reload)
	// is cleared now that nothing is wrong.
	zd.SetError(ConfigError, "Member zone m1.example. in catalog %s references group 'config-blue' which does not exist in local config", zone)
	conf := &Config{Catalog: &CatalogConf{GroupPrefixes: GroupPrefixesConf{Config: "config", Signing: "sign"}}}
	update := &CatalogZoneUpdate{
		CatalogZone: zone,
		MemberZones: map[string]*MemberZone{
			"m1.example.": {ZoneName: "m1.example.", MetaGroup: "config-blue"},
		},
	}
	if err := AutoConfigureZonesFromCatalog(context.Background(), update, conf); err != nil {
		t.Errorf("a read-only catalog needs no local config groups: %v", err)
	}
	if zd.HasError(ConfigError) {
		t.Errorf("a read-only catalog is in error state over a member's group: %q", zd.ErrorMsg)
	}

	// With auto-create the check still applies.
	zd.mu.Lock()
	zd.Options[OptCatalogMemberAutoCreate] = true
	zd.mu.Unlock()
	_ = AutoConfigureZonesFromCatalog(context.Background(), update, conf)
	if !zd.HasError(ConfigError) {
		t.Error("a catalog that auto-creates must still be refused a member group it has no config for")
	}
}

func TestCatalogGroupDeleteRefusedWhileInUse(t *testing.T) {
	const zone = "catalog.groups.example."
	zd := newTestCatalog(t, zone)
	if err := handleCatalogGroupAdd(zone, "blue", &CatalogResponse{}); err != nil {
		t.Fatalf("group add: %v", err)
	}
	if err := handleCatalogZoneAdd(zone, "m1.example.", []string{"blue"}, &CatalogResponse{}); err != nil {
		t.Fatalf("zone add: %v", err)
	}
	waitForMembers(t, zd, 1)
	if err := handleCatalogGroupDelete(zone, "blue", &CatalogResponse{}); err == nil ||
		!strings.Contains(err.Error(), "still used") {
		t.Errorf("deleting a group a member still carries must be refused: %v", err)
	}
	if err := handleCatalogZoneGroupDelete(zone, "m1.example.", "blue", &CatalogResponse{}); err != nil {
		t.Fatalf("zone group delete: %v", err)
	}
	if err := handleCatalogGroupDelete(zone, "blue", &CatalogResponse{}); err != nil {
		t.Errorf("deleting a group no member carries: %v", err)
	}
}

func TestConfiguredCatalogWriteBacksEndAtTheNewestSerial(t *testing.T) {
	const zone = "catalog.writeback.example."
	dir := t.TempDir()
	zd := newTestCatalog(t, zone)
	own := filepath.Join(dir, "catalog.writeback.example.zone")
	zd.mu.Lock()
	zd.fromStaticConfig.Store(true)
	zd.Zonefile = own
	zd.mu.Unlock()
	for _, m := range []string{"m1.example.", "m2.example.", "m3.example."} {
		if err := handleCatalogZoneAdd(zone, m, nil, &CatalogResponse{}); err != nil {
			t.Fatalf("zone add %s: %v", m, err)
		}
	}
	waitForMembers(t, zd, 3)
	// Several write-backs at once, as quick successive edits start them.
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() { writeBackCatalogZone(zd); done <- struct{}{} }()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	want := zd.publishedSnapshot().Serial
	waitFor(t, 3*time.Second, "the file at the newest serial", func() bool {
		b, err := os.ReadFile(own)
		return err == nil && strings.Contains(string(b), fmt.Sprintf(" %d ", want))
	})
}

// A catalog member is registered with its options and then handed to the
// refresh engine, which fetches the zone. The request must not carry the
// options as they were when it was built: the engine replaces the zone's whole
// options map with the request's, so a freeze stored on the zone in between
// (`zone freeze` over the API) would be undone. The options are normalized for
// the zone's role when the zone is registered instead, and the request carries
// none (johanix/tdns#981 review).
func TestCatalogMemberRefreshRequestDoesNotReplaceTheZonesOptions(t *testing.T) {
	const zone = "catalog.members.example."
	const member = "m1.example."
	authApp(t) // tdns-auth, with a keystore
	kdb := Conf.Internal.KeyDB
	catalogZd := newTestCatalog(t, zone)
	catalogZd.mu.Lock()
	catalogZd.ZoneType = Secondary
	catalogZd.mu.Unlock()
	catalogZd.SetOption(OptCatalogMemberAutoCreate, true)
	t.Cleanup(func() { Zones.Remove(member) })

	conf := &Config{Catalog: &CatalogConf{
		GroupPrefixes: GroupPrefixesConf{Config: "config", Signing: "sign"},
		ConfigGroups: map[string]*ConfigGroupConfig{
			// allow-updates is origination, which a tdns-auth secondary that
			// does not sign may not do: normalization strips it.
			"config-blue": {Upstream: "127.0.0.1:1", Options: []string{"allow-updates", "fold-case"}},
		},
	}}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	update := &CatalogZoneUpdate{
		CatalogZone: zone,
		MemberZones: map[string]*MemberZone{member: {ZoneName: member, MetaGroup: "config-blue"}},
	}
	if err := AutoConfigureZonesFromCatalog(context.Background(), update, conf); err != nil {
		t.Fatalf("AutoConfigureZonesFromCatalog: %v", err)
	}
	zd, ok := Zones.Get(member)
	if !ok {
		t.Fatal("the member was not registered")
	}

	// Normalized at registration: before any request is taken.
	if !zd.Option(OptFoldCase) || !zd.Option(OptAutomaticZone) {
		t.Errorf("the registered zone's options are %v, want the group's fold-case and the automatic-zone mark", zd.OptionsSnapshot())
	}
	if zd.Option(OptAllowUpdates) {
		t.Error("the registered zone has allow-updates on: a tdns-auth secondary may not originate, so it is stripped at registration")
	}
	zd.mu.Lock()
	suppressed := zd.SuppressedOptions[OptAllowUpdates]
	zd.mu.Unlock()
	if !suppressed {
		t.Error("the suppressed allow-updates is not recorded on the zone")
	}

	var zr ZoneRefresher
	select {
	case zr = <-conf.Internal.RefreshZoneCh:
	default:
		t.Fatal("no refresh request was enqueued for the member")
	}
	if zr.Options != nil {
		t.Errorf("the refresh request carries the options %v: the engine would replace the zone's with them", zr.Options)
	}

	// The window: a freeze stored after the request was built and before the
	// engine takes it. Run the engine on the request, as the daemon does.
	zd.SetOption(OptFrozen, true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RefreshEngine(ctx, conf) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("RefreshEngine did not shut down")
		}
		zd.stopPublisher()
	})
	zr.Wait = true
	zr.Response = make(chan RefresherResponse, 1)
	conf.Internal.RefreshZoneCh <- zr
	select {
	case <-zr.Response: // the fetch itself fails, nothing listens upstream; the options were settled before it
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh was not answered")
	}
	if !zd.Option(OptFrozen) {
		t.Error("the freeze stored before the engine took the request was undone by it")
	}
	if !zd.Option(OptFoldCase) || zd.Option(OptAllowUpdates) {
		t.Errorf("after the engine took the request the options are %v", zd.OptionsSnapshot())
	}
}
