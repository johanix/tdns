package tdns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTestTemplates installs templates into the global Templates map for the
// duration of the test.
func withTestTemplates(t *testing.T, tmpls map[string]ZoneConf) {
	t.Helper()
	saved := Templates
	Templates = tmpls
	t.Cleanup(func() { Templates = saved })
}

// dynPrimaryTestTemplate returns a minimal blessed primary template whose
// zonefile pattern lands in dir.
func dynPrimaryTestTemplate(dir string) ZoneConf {
	tmpl := ZoneConf{
		Name:         "dyn-test",
		Type:         "primary",
		Store:        "map",
		DynamicZones: true,
		Zonefile:     filepath.Join(dir, "%szone"),
		OptionsStrs:  []string{"allow-updates"},
		Downstreams:  []AclEntry{{Prefix: "127.0.0.1/32", Key: NOKEY}},
	}
	tmpl.UpdatePolicy.Zone.Type = "selfsub"
	tmpl.UpdatePolicy.Zone.RRtypes = []string{"TXT"}
	return tmpl
}

func TestBootstrapApexRecords(t *testing.T) {
	lines := bootstrapApexRecords("boot.example.", []string{
		"127.0.0.1:5354",   // v4 with port
		"127.0.0.1:5355",   // same address, different port -> deduplicated
		"[2001:db8::1]:53", // v6 with port
		"0.0.0.0:53",       // wildcard -> skipped with WARN
		"::",               // wildcard, no port -> skipped
		"not-an-address",   // unparsable -> skipped
	})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "SOA\tns.boot.example. hostmaster.boot.example. 1 3600 600 604800 300") {
		t.Errorf("SOA missing or malformed:\n%s", joined)
	}
	if !strings.Contains(joined, "NS\tns.boot.example.") {
		t.Errorf("apex NS missing:\n%s", joined)
	}
	if c := strings.Count(joined, "\tA\t127.0.0.1"); c != 1 {
		t.Errorf("want exactly 1 deduplicated A record, got %d:\n%s", c, joined)
	}
	if !strings.Contains(joined, "\tAAAA\t2001:db8::1") {
		t.Errorf("AAAA glue missing:\n%s", joined)
	}
	if strings.Contains(joined, "0.0.0.0") || strings.Contains(joined, "\tAAAA\t::") {
		t.Errorf("wildcard listener leaked into apex:\n%s", joined)
	}

	// Zero usable addresses: zone still gets SOA + NS, no glue.
	lines = bootstrapApexRecords("empty.example.", []string{"0.0.0.0:53"})
	if len(lines) != 2 {
		t.Errorf("zero-address bootstrap should yield SOA+NS only, got %d lines", len(lines))
	}
}

func TestPrepareDynamicPrimary_Gates(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	dir := t.TempDir()
	tmpl := dynPrimaryTestTemplate(dir)
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": tmpl})

	// Missing template.
	if _, err := conf.prepareDynamicPrimary(ZoneConf{Name: "a.example", Template: "nope"}, nil, true); err == nil ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing template: %v", err)
	}

	// Unblessed template refused on the API path, tolerated on the boot path.
	unblessed := tmpl
	unblessed.DynamicZones = false
	Templates["unblessed"] = unblessed
	if _, err := conf.prepareDynamicPrimary(ZoneConf{Name: "a.example", Template: "unblessed"}, nil, true); err == nil ||
		!strings.Contains(err.Error(), "not blessed") {
		t.Errorf("unblessed template on API path: %v", err)
	}
	if _, err := conf.prepareDynamicPrimary(ZoneConf{Name: "a.example", Template: "unblessed"}, nil, false); err != nil {
		t.Errorf("unblessed template must load on the boot path (blessing gates new adds): %v", err)
	}

	// Wrong template type.
	sec := tmpl
	sec.Type = "secondary"
	Templates["sec"] = sec
	if _, err := conf.prepareDynamicPrimary(ZoneConf{Name: "a.example", Template: "sec"}, nil, true); err == nil ||
		!strings.Contains(err.Error(), "not primary") {
		t.Errorf("secondary template: %v", err)
	}

	// No zonefile pattern.
	nofile := tmpl
	nofile.Zonefile = ""
	Templates["nofile"] = nofile
	if _, err := conf.prepareDynamicPrimary(ZoneConf{Name: "a.example", Template: "nofile"}, nil, true); err == nil ||
		!strings.Contains(err.Error(), "zonefile") {
		t.Errorf("missing zonefile: %v", err)
	}

	// Non-map store.
	xfr := tmpl
	xfr.Store = "xfr"
	Templates["xfr"] = xfr
	if _, err := conf.prepareDynamicPrimary(ZoneConf{Name: "a.example", Template: "xfr"}, nil, true); err == nil ||
		!strings.Contains(err.Error(), "map-only") {
		t.Errorf("xfr store: %v", err)
	}

	// Disallowed option.
	cat := tmpl
	cat.OptionsStrs = []string{"catalog-zone"}
	Templates["cat"] = cat
	if _, err := conf.prepareDynamicPrimary(ZoneConf{Name: "a.example", Template: "cat"}, nil, true); err == nil ||
		!strings.Contains(err.Error(), "not supported") {
		t.Errorf("catalog-zone option: %v", err)
	}

	// Signing option without a policy.
	signing := tmpl
	signing.OptionsStrs = []string{"online-signing"}
	Templates["signing"] = signing
	if _, err := conf.prepareDynamicPrimary(ZoneConf{Name: "a.example", Template: "signing"}, nil, true); err == nil ||
		!strings.Contains(err.Error(), "dnssecpolicy") {
		t.Errorf("signing without policy: %v", err)
	}

	// allow-child-updates refused (v1).
	child := tmpl
	child.OptionsStrs = []string{"allow-child-updates"}
	child.DelegationBackend = "direct"
	child.UpdatePolicy.Child.Type = "selfsub"
	Templates["child"] = child
	if _, err := conf.prepareDynamicPrimary(ZoneConf{Name: "a.example", Template: "child"}, nil, true); err == nil ||
		!strings.Contains(err.Error(), "allow-child-updates") {
		t.Errorf("allow-child-updates: %v", err)
	}
}

func TestPrepareDynamicPrimary_HappyPathAndTsigRewire(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	dir := t.TempDir()
	tmpl := dynPrimaryTestTemplate(dir)
	tmpl.Downstreams = []AclEntry{
		{Prefix: "127.0.0.1/32", Key: NOKEY},     // rewired
		{Prefix: "192.0.2.0/24", Key: "BLOCKED"}, // never rewired
	}
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": tmpl})

	spec, err := conf.prepareDynamicPrimary(ZoneConf{Name: "happy.example", Template: "dyn-test"}, nil, true)
	if err != nil {
		t.Fatalf("prepareDynamicPrimary: %v", err)
	}
	if spec.Zconf.Zonefile != filepath.Join(dir, "happy.example.zone") {
		t.Errorf("zonefile not %%s-expanded: %q", spec.Zconf.Zonefile)
	}
	if !spec.Options[OptAllowUpdates] {
		t.Error("allow-updates option lost")
	}
	if spec.Policy.Zone.Type != "selfsub" {
		t.Errorf("update policy not activated: %+v", spec.Policy)
	}

	// Inline TSIG rewiring: keyless entries get the staged key, BLOCKED stays.
	staged := &TsigDetails{Name: "test-key.", Algorithm: "hmac-sha256", Secret: "c2VjcmV0"}
	spec, err = conf.prepareDynamicPrimary(ZoneConf{Name: "tsig.example", Template: "dyn-test"}, staged, true)
	if err != nil {
		t.Fatalf("prepareDynamicPrimary with staged key: %v", err)
	}
	if spec.Zconf.Downstreams[0].Key != "test-key." {
		t.Errorf("keyless downstream not rewired: %+v", spec.Zconf.Downstreams[0])
	}
	if spec.Zconf.Downstreams[1].Key != "BLOCKED" {
		t.Errorf("BLOCKED downstream must never be rewired: %+v", spec.Zconf.Downstreams[1])
	}
	// Rewiring must not leak the staged key back into the template: the next
	// zone stamped from it would inherit this zone's key. (ExpandTemplate's
	// gap-fill clones slices; this pins that invariant.)
	if got := Templates["dyn-test"].Downstreams[0].Key; got != NOKEY {
		t.Errorf("template mutated by rewiring: downstream key %q", got)
	}
}

func TestProvisionDynamicZone_RejectsPathSeparatorNames(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	dir := t.TempDir()
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": dynPrimaryTestTemplate(dir)})

	// dns.IsDomainName accepts "/" — the add path must not, for either type,
	// since the name feeds file paths (template %s-pattern, zonedirectory).
	for _, name := range []string{"evil/zone.example", `evil\zone.example`} {
		if _, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
			Name: name, Type: Primary, Template: "dyn-test",
		}, true); err == nil || !strings.Contains(err.Error(), "path separators") {
			t.Errorf("primary add with name %q must be rejected: %v", name, err)
		}
		if _, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
			Name: name, Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		}, true); err == nil || !strings.Contains(err.Error(), "path separators") {
			t.Errorf("secondary add with name %q must be rejected: %v", name, err)
		}
	}
}

func TestProvisionDynamicPrimary_EnqueueFailureMarksError(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	dir := t.TempDir()
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": dynPrimaryTestTemplate(dir)})

	// A cancelled context makes enqueueRefresh fail immediately: the zone
	// must be left registered with a visible error, not stuck "provisioning".
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Fill the channel so the select cannot take the send arm first.
	ch := conf.Internal.RefreshZoneCh
	for len(ch) < cap(ch) {
		ch <- ZoneRefresher{}
	}
	if _, err := conf.ProvisionDynamicZone(ctx, DynamicZoneInput{
		Name: "stuck.example", Type: Primary, Template: "dyn-test",
	}, true); err == nil {
		t.Fatal("expected enqueue failure with a cancelled context and full channel")
	}
	zd, ok := Zones.Get("stuck.example.")
	if !ok {
		t.Fatal("zone should remain registered after enqueue failure")
	}
	if !zd.HasError(RefreshError) {
		t.Error("zone must carry a visible RefreshError after enqueue failure")
	}
}

func TestProvisionDynamicPrimary_EndToEnd(t *testing.T) {
	resetZonesForTest()
	conf, ch := newTestConfigForCores(t)
	conf.Listeners.Addresses = []string{"127.0.0.1:5354", "[2001:db8::1]:5354"}
	dir := t.TempDir()
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": dynPrimaryTestTemplate(dir)})

	// Caller-supplied options/primaries are refused for primaries.
	if _, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
		Name: "p1.example", Type: Primary, Template: "dyn-test",
		Options: map[ZoneOption]bool{OptFoldCase: true},
	}, true); err == nil || !strings.Contains(err.Error(), "options") {
		t.Errorf("caller options must be refused: %v", err)
	}
	if _, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
		Name: "p1.example", Type: Primary, Template: "dyn-test",
		Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
	}, true); err == nil || !strings.Contains(err.Error(), "primaries") {
		t.Errorf("caller primaries must be refused: %v", err)
	}

	// Happy path.
	msg, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
		Name: "p1.example", Type: Primary, Template: "dyn-test",
	}, true)
	if err != nil {
		t.Fatalf("primary add failed: %v", err)
	}
	if !strings.Contains(msg, "dyn-test") {
		t.Errorf("response should name the template: %q", msg)
	}
	zd, ok := Zones.Get("p1.example.")
	if !ok {
		t.Fatal("zone not registered")
	}
	if zd.ZoneType != Primary || zd.ZoneStore != MapZone || !zd.FirstZoneLoad {
		t.Errorf("zone shape wrong: type=%v store=%v firstLoad=%v", zd.ZoneType, zd.ZoneStore, zd.FirstZoneLoad)
	}
	if zd.Template != "dyn-test" {
		t.Errorf("template not recorded on ZoneData: %q", zd.Template)
	}
	if !zd.Options[OptApiManagedZone] || !zd.Options[OptAllowUpdates] {
		t.Errorf("options wrong: %v", zd.Options)
	}
	if zd.UpdatePolicy.Zone.Type != "selfsub" {
		t.Errorf("update policy not activated on ZoneData: %+v", zd.UpdatePolicy)
	}

	// Bootstrap file synthesized with SOA/NS/glue.
	content, err := os.ReadFile(filepath.Join(dir, "p1.example.zone"))
	if err != nil {
		t.Fatalf("bootstrap zone file not written: %v", err)
	}
	for _, want := range []string{"SOA", "NS\tns.p1.example.", "A\t127.0.0.1", "AAAA\t2001:db8::1"} {
		if !strings.Contains(string(content), want) {
			t.Errorf("bootstrap file missing %q:\n%s", want, content)
		}
	}

	// A file-load refresher was enqueued with the activated policy.
	select {
	case zr := <-ch:
		if zr.ZoneType != Primary || !zr.Force || zr.Zonefile == "" {
			t.Errorf("refresher shape wrong: %+v", zr)
		}
		if zr.UpdatePolicy.Zone.Type != "selfsub" {
			t.Errorf("refresher lacks the activated policy: %+v", zr.UpdatePolicy)
		}
		if zr.Template != "dyn-test" {
			t.Errorf("refresher lacks the template name: %q", zr.Template)
		}
	default:
		t.Error("expected a ZoneRefresher to be enqueued")
	}

	// Duplicate add refused.
	if _, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
		Name: "p1.example", Type: Primary, Template: "dyn-test",
	}, true); err == nil {
		t.Error("duplicate primary add must be refused")
	}

	// An existing zone file is used as-is (not overwritten).
	pre := filepath.Join(dir, "p2.example.zone")
	if err := os.WriteFile(pre, []byte("p2.example.\t3600\tIN\tSOA\tns.p2.example. h.p2.example. 42 3600 600 604800 300\np2.example.\t3600\tIN\tNS\tns.p2.example.\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
		Name: "p2.example", Type: Primary, Template: "dyn-test",
	}, true); err != nil {
		t.Fatalf("add with pre-existing file failed: %v", err)
	}
	content, _ = os.ReadFile(pre)
	if !strings.Contains(string(content), " 42 ") {
		t.Errorf("pre-existing zone file was overwritten:\n%s", content)
	}
}

func TestModifyDynamicZone_RefusesPrimary(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)

	zd := &ZoneData{ZoneName: "prim.example.", ZoneType: Primary, Options: map[ZoneOption]bool{OptApiManagedZone: true}}
	Zones.Set("prim.example.", zd)
	if _, err := conf.ModifyDynamicZone(context.Background(), DynamicZoneInput{Name: "prim.example"}); err == nil ||
		!strings.Contains(err.Error(), "not supported for primary") {
		t.Errorf("modify on a primary must be refused: %v", err)
	}
}

func TestRemoveDynamicZone_RemovesTemplatePathZonefile(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	dir := t.TempDir()

	zonefile := filepath.Join(dir, "del.example.zone")
	if err := os.WriteFile(zonefile, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	zd := &ZoneData{ZoneName: "del.example.", ZoneType: Primary, Zonefile: zonefile,
		Options: map[ZoneOption]bool{OptApiManagedZone: true}}
	Zones.Set("del.example.", zd)

	if _, err := conf.RemoveDynamicZone("del.example"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, err := os.Stat(zonefile); !os.IsNotExist(err) {
		t.Error("template-path zone file not removed on delete")
	}
}

// TestLoadDynamicZoneFiles_PrimaryReExpansion drives the boot path: a
// persisted template primary re-expands and enqueues with a re-derived update
// policy; a missing template registers a visible error-state zone.
func TestLoadDynamicZoneFiles_PrimaryReExpansion(t *testing.T) {
	resetZonesForTest()
	conf, ch := newTestConfigForCores(t)
	dir := t.TempDir()
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": dynPrimaryTestTemplate(dir)})

	zonefile := filepath.Join(dir, "boot.example.zone")
	if err := os.WriteFile(zonefile, []byte("boot.example.\t3600\tIN\tSOA\tns.boot.example. h.boot.example. 1 3600 600 604800 300\nboot.example.\t3600\tIN\tNS\tns.boot.example.\n"), 0644); err != nil {
		t.Fatal(err)
	}
	dynCfg := filepath.Join(dir, "dynamic-zones.yaml")
	cfgYaml := `zones:
  - name: boot.example.
    type: primary
    store: map
    template: dyn-test
    zonefile: ` + zonefile + `
    apimanaged: true
  - name: lost.example.
    type: primary
    store: map
    template: gone-template
    zonefile: /nonexistent/lost.example.zone
    apimanaged: true
`
	if err := os.WriteFile(dynCfg, []byte(cfgYaml), 0644); err != nil {
		t.Fatal(err)
	}
	conf.DynamicZones.ConfigFile = dynCfg
	conf.DynamicZones.ZoneDirectory = dir

	if err := conf.LoadDynamicZoneFiles(context.Background()); err != nil {
		t.Fatalf("LoadDynamicZoneFiles: %v", err)
	}

	// boot.example: enqueued with the template's re-derived policy.
	select {
	case zr := <-ch:
		if zr.Name != "boot.example." || zr.ZoneType != Primary {
			t.Errorf("unexpected refresher: %+v", zr)
		}
		if zr.UpdatePolicy.Zone.Type != "selfsub" {
			t.Errorf("boot re-expansion lost the update policy: %+v", zr.UpdatePolicy)
		}
		if !zr.Options[OptApiManagedZone] {
			t.Error("ApiManaged marker not re-derived on boot")
		}
		if zr.Zonefile != zonefile {
			t.Errorf("persisted zonefile must win over the template pattern: %q", zr.Zonefile)
		}
	default:
		t.Error("expected boot.example. to be enqueued")
	}

	// lost.example: registered in ERROR state, not silently skipped, not enqueued.
	zd, ok := Zones.Get("lost.example.")
	if !ok {
		t.Fatal("zone with missing template must be registered (visible), not skipped")
	}
	if !zd.Error || !strings.Contains(zd.ErrorMsg, "does not exist") {
		t.Errorf("zone with missing template must be in ERROR state: err=%v msg=%q", zd.Error, zd.ErrorMsg)
	}
	select {
	case zr := <-ch:
		t.Errorf("zone with missing template must not be enqueued: %+v", zr)
	default:
	}
}
