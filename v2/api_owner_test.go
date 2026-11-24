/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	certCaller   = ApiIdentity{Name: "provisioner", Role: RoleReadWrite, Via: ApiViaCertificate}
	socketCaller = ApiIdentity{Name: "local", Role: RoleAdmin, Via: ApiViaSocket}
	keyCaller    = ApiIdentity{Name: "apikey", Role: RoleReadWrite, Via: ApiViaKey}
)

func TestApiIdentityApiOwner(t *testing.T) {
	for _, tc := range []struct {
		id   ApiIdentity
		want string
	}{
		{certCaller, "cert:provisioner"},
		{socketCaller, ApiOwnerApi},
		{keyCaller, ApiOwnerApi},
		{ApiIdentity{Via: ApiViaCertificate}, ApiOwnerApi}, // no name, nothing to record
	} {
		if got := tc.id.ApiOwner(); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.id, got, tc.want)
		}
		ctx := context.WithValue(context.Background(), apiIdentityKey{}, tc.id)
		if got := CallerApiOwner(ctx); got != tc.want {
			t.Errorf("CallerApiOwner(%+v): %q, want %q", tc.id, got, tc.want)
		}
	}
	if got := CallerApiOwner(context.Background()); got != ApiOwnerApi {
		t.Errorf("a path inside the daemon records %q, want api", got)
	}
}

func TestApiOwnerValues(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"", ApiOwnerConfig, true},
		{"config", ApiOwnerConfig, true},
		{"cert:provisioner", "cert:provisioner", true},
		{"api", "", false},
		{"cert:", "", false},
		{"cert:two words", "", false},
		{"provisioner", "", false},
	} {
		got, err := StaticApiOwner(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("StaticApiOwner(%q) = %q, %v; want %q, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"api", true}, {"cert:provisioner", true},
		{"config", false}, {"", false}, {"cert:", false}, {"cert:a\tb", false}, {"cert", false},
	} {
		if err := CheckSettableApiOwner(tc.in); (err == nil) != tc.ok {
			t.Errorf("CheckSettableApiOwner(%q) = %v, want ok=%v", tc.in, err, tc.ok)
		}
	}
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"", ApiOwnerApi, true},
		{"api", ApiOwnerApi, true},
		{"cert:provisioner", "cert:provisioner", true},
		{"config", ApiOwnerApi, false}, // reported, and grants nothing
		{"cert:", ApiOwnerApi, false},
	} {
		got, err := dynamicApiOwner(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("dynamicApiOwner(%q) = %q, %v; want %q, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

// A config-file zone is the config's unless its own config hands it to a
// certificate client. A value the daemon does not accept quarantines the zone
// like any other invalid zone setting, and grants nothing. A reload that
// removes or breaks a grant takes it away.
func TestStaticZoneApiOwner(t *testing.T) {
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	zone := func(name, owner string) ZoneConf {
		return ZoneConf{Name: name, Type: "primary", Store: "map", Zonefile: "/nonexistent", ApiOwner: owner}
	}
	conf := &Config{Zones: []ZoneConf{
		zone("plain.example.", ""),
		zone("explicit.example.", "config"),
		zone("granted.example.", "cert:provisioner"),
		zone("api.example.", "api"),
		zone("noname.example.", "cert:"),
		zone("junk.example.", "provisioner"),
	}}
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 32)

	_, broken, err := conf.ParseZones(context.Background(), false)
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	isBroken := map[string]bool{}
	for _, z := range broken {
		isBroken[z] = true
	}
	for name, want := range map[string]string{
		"plain.example.":    ApiOwnerConfig,
		"explicit.example.": ApiOwnerConfig,
		"granted.example.":  "cert:provisioner",
		"api.example.":      ApiOwnerConfig,
		"noname.example.":   ApiOwnerConfig,
		"junk.example.":     ApiOwnerConfig,
	} {
		zd, ok := Zones.Get(name)
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		if got := zd.EffectiveApiOwner(); got != want {
			t.Errorf("%s: API owner %q, want %q", name, got, want)
		}
		wantBroken := name == "api.example." || name == "noname.example." || name == "junk.example."
		if isBroken[name] != wantBroken {
			t.Errorf("%s: broken=%v, want %v", name, isBroken[name], wantBroken)
		}
		if wantBroken && (!zd.HasError(ConfigError) || !strings.Contains(zd.ErrorMsg, "api-owner")) {
			t.Errorf("%s: want a ConfigError naming api-owner, got %q", name, zd.ErrorMsg)
		}
	}

	conf.Zones = []ZoneConf{zone("granted.example.", "cert:")}
	if _, _, err := conf.ParseZones(context.Background(), true); err != nil {
		t.Fatalf("reload: %v", err)
	}
	zd, _ := Zones.Get("granted.example.")
	if got := zd.EffectiveApiOwner(); got != ApiOwnerConfig {
		t.Errorf("a grant the reload broke still in force: %q", got)
	}
	conf.Zones = []ZoneConf{zone("granted.example.", "cert:provisioner")}
	if _, _, err := conf.ParseZones(context.Background(), true); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := zd.EffectiveApiOwner(); got != "cert:provisioner" || zd.HasError(ConfigError) {
		t.Errorf("a repaired grant: owner %q, error %q", got, zd.ErrorMsg)
	}
	conf.Zones = []ZoneConf{zone("granted.example.", "")}
	if _, _, err := conf.ParseZones(context.Background(), true); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := zd.EffectiveApiOwner(); got != ApiOwnerConfig {
		t.Errorf("a grant the reload removed still in force: %q", got)
	}
}

// A grant on a template would hand over every zone stamped from it, the
// dynamic ones included.
func TestTemplateDoesNotHandOutApiOwner(t *testing.T) {
	tmpl := ZoneConf{Name: "t", Type: "secondary", ApiOwner: "cert:provisioner"}
	got, err := ExpandTemplate(ZoneConf{Name: "z.example.", Template: "t"}, &tmpl, AppTypeAuth)
	if err != nil {
		t.Fatal(err)
	}
	if got.ApiOwner != "" {
		t.Errorf("the zone took the template's api-owner: %q", got.ApiOwner)
	}
	if got.Type != "secondary" {
		t.Errorf("the rest of the template did not apply: %+v", got)
	}
}

// ownerTestConf points the global Conf, which the API handlers use, at a
// persistent dynamic config in a temporary directory and a keystore, and
// puts it back afterwards.
func ownerTestConf(t *testing.T) string {
	t.Helper()
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	saved := Conf.DynamicZones
	prevCh, prevKdb, prevTsig, prevAccess := Conf.Internal.RefreshZoneCh, Conf.Internal.KeyDB, Conf.Internal.TsigKeyStore, Conf.Internal.ApiAccess
	t.Cleanup(func() {
		Conf.DynamicZones = saved
		Conf.Internal.RefreshZoneCh, Conf.Internal.KeyDB, Conf.Internal.TsigKeyStore, Conf.Internal.ApiAccess = prevCh, prevKdb, prevTsig, prevAccess
	})
	dir := t.TempDir()
	Conf.DynamicZones.ConfigFile = filepath.Join(dir, "dynamic-zones.yaml")
	Conf.DynamicZones.ZoneDirectory = dir
	Conf.DynamicZones.Dynamic.Allowed = ZoneTypeList{"secondary"}
	Conf.DynamicZones.Dynamic.Storage = "persistent"
	Conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 64)
	Conf.Internal.KeyDB = newTestKeyDB(t)
	Conf.Internal.TsigKeyStore = NewTsigKeyStore()
	Conf.Internal.ApiAccess = nil
	return dir
}

// postZone sends zp to the /zone handler as id (nil: no identity, as from a
// path inside the daemon).
func postZone(t *testing.T, zp ZonePost, id *ApiIdentity) ZoneResponse {
	t.Helper()
	body, err := json.Marshal(zp)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zone", bytes.NewReader(body))
	if id != nil {
		req = req.WithContext(context.WithValue(req.Context(), apiIdentityKey{}, *id))
	}
	rec := httptest.NewRecorder()
	APIzone(&AppDetails{Name: "tdns-auth"}, Conf.Internal.RefreshZoneCh, Conf.Internal.KeyDB)(rec, req)
	var resp ZoneResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v\n%s", err, rec.Body.String())
	}
	return resp
}

// persistedOwners is the api-owner of each entry of the dynamic config.
func persistedOwners(t *testing.T) map[string]string {
	t.Helper()
	cf, err := Conf.loadDynamicConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, z := range cf.Zones {
		out[z.Name] = z.ApiOwner
	}
	return out
}

func secondaryAdd(zone string) ZonePost {
	return ZonePost{Command: "add", Zone: zone, Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}}}
}

// zone add records the caller's API owner: a certificate client's name, and
// "api" for the socket, the API key and a request without an identity. The
// owner is in the dynamic config and in both listings, and a modify keeps it.
func TestZoneAddRecordsTheCallersApiOwner(t *testing.T) {
	ownerTestConf(t)
	for zone, id := range map[string]*ApiIdentity{
		"cert.example.":   &certCaller,
		"socket.example.": &socketCaller,
		"key.example.":    &keyCaller,
		"none.example.":   nil,
	} {
		if resp := postZone(t, secondaryAdd(zone), id); resp.Error {
			t.Fatalf("add %s: %s", zone, resp.ErrorMsg)
		}
	}
	want := map[string]string{
		"cert.example.":   "cert:provisioner",
		"socket.example.": ApiOwnerApi,
		"key.example.":    ApiOwnerApi,
		"none.example.":   ApiOwnerApi,
	}
	persisted := persistedOwners(t)
	for zone, owner := range want {
		zd, ok := Zones.Get(zone)
		if !ok {
			t.Fatalf("%s not registered", zone)
		}
		if got := zd.EffectiveApiOwner(); got != owner {
			t.Errorf("%s: API owner %q, want %q", zone, got, owner)
		}
		if persisted[zone] != owner {
			t.Errorf("%s: dynamic config has api-owner %q, want %q", zone, persisted[zone], owner)
		}
	}

	dyn := postZone(t, ZonePost{Command: "list-dynamic"}, &socketCaller)
	all := postZone(t, ZonePost{Command: "list-zones"}, &socketCaller)
	for zone, owner := range want {
		if got := dyn.Zones[zone].ApiOwner; got != owner {
			t.Errorf("list-dynamic %s: %q, want %q", zone, got, owner)
		}
		if got := all.Zones[zone].ApiOwner; got != owner {
			t.Errorf("list-zones %s: %q, want %q", zone, got, owner)
		}
	}

	mod := ZonePost{Command: "modify", Zone: "cert.example.", Primaries: []PeerConf{{Addr: "192.0.2.9:53", Key: NOKEY}}}
	if resp := postZone(t, mod, &socketCaller); resp.Error {
		t.Fatalf("modify: %s", resp.ErrorMsg)
	}
	zd, _ := Zones.Get("cert.example.")
	if got := zd.EffectiveApiOwner(); got != "cert:provisioner" {
		t.Errorf("a modify by the socket changed the API owner to %q", got)
	}
	if got := persistedOwners(t)["cert.example."]; got != "cert:provisioner" {
		t.Errorf("after the modify the dynamic config has %q", got)
	}
}

// An inline TSIG key that zone add puts into the keystore is the caller's.
// The same key named again by another caller is a no-op and keeps its owner.
func TestInlineTsigKeyTakesTheCallersApiOwner(t *testing.T) {
	ownerTestConf(t)
	add := func(zone string, id *ApiIdentity) {
		t.Helper()
		zp := secondaryAdd(zone)
		zp.TsigName, zp.TsigSecret = "inline-owner.", b64Secret16
		if resp := postZone(t, zp, id); resp.Error {
			t.Fatalf("add %s: %s", zone, resp.ErrorMsg)
		}
	}
	add("tsig1.example.", &certCaller)
	row, err := getTsigKeystoreByName(Conf.Internal.KeyDB, "inline-owner.")
	if err != nil {
		t.Fatal(err)
	}
	if row.Owner != "cert:provisioner" || row.Creator != "inline-zone" {
		t.Errorf("inline key: owner %q creator %q, want cert:provisioner and inline-zone", row.Owner, row.Creator)
	}
	add("tsig2.example.", &socketCaller)
	if row, _ := getTsigKeystoreByName(Conf.Internal.KeyDB, "inline-owner."); row.Owner != "cert:provisioner" {
		t.Errorf("an identical key named again took owner %q", row.Owner)
	}
}

// zone setowner: an API-created zone takes the new owner, in memory and in
// the dynamic config, and keeps it across a load of that config. A
// config-file zone, a catalog member and a bad value are refused; an owner
// the access file has no client for is set, with a warning.
func TestZoneSetOwner(t *testing.T) {
	if got := RequiredApiRole("/api/v1/zone", "setowner"); got != RoleAdmin {
		t.Errorf("zone setowner needs %v, want admin", got)
	}
	ownerTestConf(t)
	if resp := postZone(t, secondaryAdd("dyn.example."), &socketCaller); resp.Error {
		t.Fatalf("add: %s", resp.ErrorMsg)
	}
	setowner := func(zone, owner string) ZoneResponse {
		t.Helper()
		return postZone(t, ZonePost{Command: "setowner", Zone: zone, ApiOwner: owner}, &socketCaller)
	}

	resp := setowner("dyn.example.", "cert:provisioner")
	if resp.Error {
		t.Fatalf("setowner: %s", resp.ErrorMsg)
	}
	if resp.Msg != "zone dyn.example.: API owner cert:provisioner (was api)" || len(resp.Warnings) != 0 {
		t.Errorf("setowner said %q, warnings %q", resp.Msg, resp.Warnings)
	}
	zd, _ := Zones.Get("dyn.example.")
	if got := zd.EffectiveApiOwner(); got != "cert:provisioner" {
		t.Errorf("in memory: %q", got)
	}
	if got := persistedOwners(t)["dyn.example."]; got != "cert:provisioner" {
		t.Errorf("in the dynamic config: %q", got)
	}
	if resp := setowner("dyn.example.", "cert:provisioner"); resp.Error || !strings.Contains(resp.Msg, "already") {
		t.Errorf("the same owner again: %q %q", resp.Msg, resp.ErrorMsg)
	}

	// Loaded again, as at a restart.
	resetZonesForTest()
	ch := make(chan ZoneRefresher, 8)
	Conf.Internal.RefreshZoneCh = ch
	if err := Conf.LoadDynamicZoneFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if zr := <-ch; zr.Name != "dyn.example." || zr.ApiOwner != "cert:provisioner" {
		t.Errorf("loaded back: %s with API owner %q", zr.Name, zr.ApiOwner)
	}

	// Back to the operators, and an owner no client of the access file has.
	dyn := &ZoneData{ZoneName: "dyn2.example.", ZoneType: Secondary, Options: map[ZoneOption]bool{OptApiManagedZone: true}}
	Zones.Set("dyn2.example.", dyn)
	Conf.Internal.ApiAccess = &apiAccessHolder{}
	Conf.Internal.ApiAccess.p.Store(newAccessState("/access.yaml", &AccessFile{Clients: []AccessClient{
		{Name: "provisioner", Pin: "pin1", Role: "read-write"}}}, nil))
	if resp := setowner("dyn2.example.", "cert:provisioner"); resp.Error || len(resp.Warnings) != 0 {
		t.Errorf("an enrolled client: %q %q %q", resp.Msg, resp.ErrorMsg, resp.Warnings)
	}
	resp = setowner("dyn2.example.", "cert:nobody")
	if resp.Error || len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], `no client "nobody"`) {
		t.Errorf("an unknown client: %q %q %q", resp.Msg, resp.ErrorMsg, resp.Warnings)
	}
	if got := dyn.EffectiveApiOwner(); got != "cert:nobody" {
		t.Errorf("an unknown client is set anyway; owner %q", got)
	}
	if resp := setowner("dyn2.example.", "api"); resp.Error || dyn.EffectiveApiOwner() != ApiOwnerApi {
		t.Errorf("back to api: %q %q", resp.Msg, resp.ErrorMsg)
	}

	static := &ZoneData{ZoneName: "static.example.", ZoneType: Primary, Options: map[ZoneOption]bool{}}
	static.fromStaticConfig.Store(true)
	Zones.Set("static.example.", static)
	member := &ZoneData{ZoneName: "member.example.", ZoneType: Secondary, SourceCatalog: "cat.example.",
		Options: map[ZoneOption]bool{OptAutomaticZone: true}}
	Zones.Set("member.example.", member)
	for _, tc := range []struct{ zone, owner, want string }{
		{"static.example.", "cert:provisioner", "set api-owner: in its config"},
		{"member.example.", "cert:provisioner", "catalog zone cat.example."},
		{"dyn2.example.", "config", "use api or cert:<name>"},
		{"dyn2.example.", "cert:", "client name is empty"},
		{"nowhere.example.", "api", "not found"},
	} {
		resp := setowner(tc.zone, tc.owner)
		if !resp.Error || !strings.Contains(resp.ErrorMsg, tc.want) {
			t.Errorf("setowner %s %s: error=%v %q, want one containing %q", tc.zone, tc.owner, resp.Error, resp.ErrorMsg, tc.want)
		}
	}
	if got := static.EffectiveApiOwner(); got != ApiOwnerConfig {
		t.Errorf("a refused setowner changed the static zone's owner to %q", got)
	}
}

// A catalog member has its catalog zone's API owner, looked up when asked:
// a new owner of the catalog zone is the member's at once. It records none
// of its own in the dynamic config.
func TestCatalogMemberFollowsItsCatalogZone(t *testing.T) {
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	cat := &ZoneData{ZoneName: "cat.example.", Options: map[ZoneOption]bool{OptCatalogZone: true}}
	cat.setApiOwner("cert:provisioner")
	Zones.Set("cat.example.", cat)
	member := &ZoneData{ZoneName: "m.example.", ZoneType: Secondary, SourceCatalog: "cat.example.",
		Options: map[ZoneOption]bool{OptAutomaticZone: true}}
	Zones.Set("m.example.", member)

	if got := member.EffectiveApiOwner(); got != "cert:provisioner" {
		t.Errorf("member: %q, want its catalog zone's", got)
	}
	cat.setApiOwner(ApiOwnerApi)
	if got := member.EffectiveApiOwner(); got != ApiOwnerApi {
		t.Errorf("after the catalog zone's change: %q", got)
	}
	if zc := zoneDataToZoneConf(member, "/tmp"); zc.ApiOwner != "" || zc.SourceCatalog != "cat.example." {
		t.Errorf("persisted member: api-owner %q, catalog %q", zc.ApiOwner, zc.SourceCatalog)
	}
	if owner, ok := ZoneApiOwner("m.example"); !ok || owner != ApiOwnerApi {
		t.Errorf("ZoneApiOwner: %q %v", owner, ok)
	}

	// A static catalog zone hands its members to the client it is granted to.
	cat.fromStaticConfig.Store(true)
	cat.setApiOwner("cert:other")
	if got := member.EffectiveApiOwner(); got != "cert:other" {
		t.Errorf("member of a granted static catalog: %q", got)
	}

	Zones.Remove("cat.example.")
	if got := member.EffectiveApiOwner(); got != ApiOwnerApi {
		t.Errorf("member of a catalog zone not served here: %q, want api", got)
	}
	// The config file took the member over: the config's.
	member.fromStaticConfig.Store(true)
	member.setApiOwner(ApiOwnerConfig)
	if got := member.EffectiveApiOwner(); got != ApiOwnerConfig {
		t.Errorf("a member the config took over: %q", got)
	}
	if _, ok := ZoneApiOwner("gone.example."); ok {
		t.Error("ZoneApiOwner found a zone that is not served")
	}
}

// The boot path: each entry's API owner and catalog reach the refresher
// (and so the zone the refresh engine builds). No api-owner is "api", a
// catalog member records none, and a value the daemon would not write is
// read as "api".
func TestLoadDynamicZoneFilesCarriesApiOwners(t *testing.T) {
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	conf, ch := newTestConfigForCores(t)
	dir := t.TempDir()
	conf.DynamicZones.ConfigFile = filepath.Join(dir, "dynamic-zones.yaml")
	conf.DynamicZones.ZoneDirectory = dir
	entry := func(name, extra string) string {
		return "  - name: " + name + "\n    type: secondary\n    store: map\n" + extra +
			"    primaries:\n      - addr: 198.51.100.1:53\n        key: NOKEY\n"
	}
	yaml := "zones:\n" +
		entry("granted.example.", "    apimanaged: true\n    api-owner: cert:provisioner\n") +
		entry("old.example.", "    apimanaged: true\n") +
		entry("member.example.", "    sourcecatalog: cat.example.\n    api-owner: cert:provisioner\n") +
		entry("damaged.example.", "    apimanaged: true\n    api-owner: config\n")
	if err := os.WriteFile(conf.DynamicZones.ConfigFile, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := conf.LoadDynamicZoneFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := map[string]ZoneRefresher{}
	for len(ch) > 0 {
		zr := <-ch
		got[zr.Name] = zr
	}
	for name, want := range map[string][2]string{
		"granted.example.": {"cert:provisioner", ""},
		"old.example.":     {ApiOwnerApi, ""},
		"member.example.":  {"", "cat.example."},
		"damaged.example.": {ApiOwnerApi, ""},
	} {
		zr, ok := got[name]
		if !ok {
			t.Fatalf("%s not enqueued", name)
		}
		if zr.ApiOwner != want[0] || zr.SourceCatalog != want[1] {
			t.Errorf("%s: API owner %q catalog %q, want %q %q", name, zr.ApiOwner, zr.SourceCatalog, want[0], want[1])
		}
	}
}

// The zone the refresh engine builds from such a refresher has them.
func TestARestoredDynamicZoneKeepsItsApiOwnerAndCatalog(t *testing.T) {
	authApp(t)
	conf := &Config{}
	conf.Internal.KeyDB = Conf.Internal.KeyDB
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 2)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	runRefreshEngine(t, conf)

	const owned, member = "owned.refresh.example.", "member.refresh.example."
	t.Cleanup(func() { Zones.Remove(owned); Zones.Remove(member) })
	conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: owned, ZoneType: Primary, ZoneStore: MapZone,
		Zonefile: t.TempDir() + "/absent.zone", ConfigUpdate: true, ApiOwner: "cert:provisioner"}
	conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: member, ZoneType: Primary, ZoneStore: MapZone,
		Zonefile: t.TempDir() + "/absent.zone", ConfigUpdate: true, SourceCatalog: "cat.refresh.example.",
		Options: map[ZoneOption]bool{OptAutomaticZone: true}}

	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		zo, ok1 := Zones.Get(owned)
		zm, ok2 := Zones.Get(member)
		if ok1 && ok2 {
			if got := zo.recordedApiOwner(); got != "cert:provisioner" {
				t.Errorf("restored zone records API owner %q", got)
			}
			if zm.SourceCatalog != "cat.refresh.example." || zm.recordedApiOwner() != "" {
				t.Errorf("restored member: catalog %q, owner %q", zm.SourceCatalog, zm.recordedApiOwner())
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the config-bearing refreshes created no zones")
		}
	}
}

// keystore tsig-mgmt add, generate and import give a new key the caller's
// API owner unless the request names one.
func TestKeystoreTsigOwnerDefaultsToTheCaller(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	handler := kdb.APIkeystore(conf)
	post := func(kp KeystorePost, id ApiIdentity) {
		t.Helper()
		body, _ := json.Marshal(kp)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keystore", bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), apiIdentityKey{}, id))
		rec := httptest.NewRecorder()
		handler(rec, req)
		var resp KeystoreResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Error {
			t.Fatalf("%s: %v %s", kp.SubCommand, err, resp.ErrorMsg)
		}
	}
	tsig := func(sub, name, owner string) KeystorePost {
		return KeystorePost{Command: "tsig-mgmt", SubCommand: sub, TsigKeyname: name,
			TsigAlgorithm: "hmac-sha256", TsigSecret: b64Secret16, Owner: owner}
	}
	post(tsig("add", "added.", ""), certCaller)
	post(tsig("generate", "generated.", ""), socketCaller)
	post(tsig("add", "explicit.", "ops"), certCaller)
	post(KeystorePost{Command: "tsig-mgmt", SubCommand: "import", TsigImportFormat: "bind",
		TsigImportData: `key "imported." { algorithm hmac-sha256; secret "` + b64Secret16 + `"; };`}, certCaller)
	for name, want := range map[string]string{
		"added.":     "cert:provisioner",
		"generated.": ApiOwnerApi,
		"explicit.":  "ops",
		"imported.":  "cert:provisioner",
	} {
		row, err := getTsigKeystoreByName(kdb, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if row.Owner != want {
			t.Errorf("%s: owner %q, want %q", name, row.Owner, want)
		}
	}
}

// SIG(0) and DNSSEC key rows carry their zone's API owner, or "-" when the
// zone is not served here.
func TestKeystoreListsCarryTheZonesApiOwner(t *testing.T) {
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	served := &ZoneData{ZoneName: "served.example.", Options: map[ZoneOption]bool{OptApiManagedZone: true}}
	served.setApiOwner("cert:provisioner")
	Zones.Set("served.example.", served)

	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []string{"served.example.", "gone.example."} {
		if _, err := tx.Exec(`INSERT INTO Sig0KeyStore (zonename, state, keyid, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			zone, "active", 1, "ED25519", "test", "x", zone+" KEY 256 3 15 AAAA"); err != nil {
			t.Fatal(err)
		}
		if err := insertKeyRowTx(tx, KeyRow{Zone: zone, State: DnskeyStatePublished, Keyid: 2, Flags: 257,
			Algorithm: "ED25519", Creator: "test", PrivateKey: "x", KeyRR: zone + " DNSKEY 257 3 15 AAAA"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"served.example.": "cert:provisioner", "gone.example.": ApiOwnerNoZone}

	tx, _ = kdb.Begin("test")
	sig0, err := kdb.Sig0KeyMgmt(tx, KeystorePost{SubCommand: "list"})
	if err != nil {
		t.Fatal(err)
	}
	dnssec, err := kdb.DnssecKeyMgmt(context.Background(), tx, KeystorePost{SubCommand: "list"})
	if err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	if len(sig0.Sig0keys) != 2 || len(dnssec.Dnskeys) != 2 {
		t.Fatalf("listed %d SIG(0) and %d DNSSEC keys, want 2 of each", len(sig0.Sig0keys), len(dnssec.Dnskeys))
	}
	for _, k := range sig0.Sig0keys {
		if k.ApiOwner != want[k.Name] {
			t.Errorf("SIG(0) key of %s: API owner %q, want %q", k.Name, k.ApiOwner, want[k.Name])
		}
	}
	for _, k := range dnssec.Dnskeys {
		if k.ApiOwner != want[k.Name] {
			t.Errorf("DNSSEC key of %s: API owner %q, want %q", k.Name, k.ApiOwner, want[k.Name])
		}
	}
}
