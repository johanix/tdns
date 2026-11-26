/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var (
	// The application client "provisioner", and a second one. certCaller
	// (api_owner_test.go) has the same name but is no application client:
	// an operator, as every certificate client is without app-clients.
	appCaller   = ApiIdentity{Name: "provisioner", Role: RoleReadWrite, Via: ApiViaCertificate, App: true}
	otherApp    = ApiIdentity{Name: "other", Role: RoleReadWrite, Via: ApiViaCertificate, App: true}
	appRefusals = []string{"not a zone of API owner", "API owner is api", "API owner is config"}
)

func refusedForApp(msg string) bool {
	for _, r := range appRefusals {
		if strings.Contains(msg, r) {
			return true
		}
	}
	return false
}

// scopeZones sets up, on top of ownerTestConf, one zone of each kind an
// application client meets: its own (added by it), another application's,
// an operator's (api), a config-file zone (config), and a config-file zone
// granted to it. It returns their names by kind; "missing" is served by no
// one.
func scopeZones(t *testing.T) map[string]string {
	t.Helper()
	ownerTestConf(t)
	z := map[string]string{
		"own":     "own.example.",
		"other":   "other.example.",
		"api":     "ops.example.",
		"config":  "static.example.",
		"granted": "granted.example.",
		"missing": "missing.example.",
	}
	for kind, id := range map[string]*ApiIdentity{"own": &appCaller, "other": &otherApp, "api": &socketCaller} {
		if resp := postZone(t, secondaryAdd(z[kind]), id); resp.Error {
			t.Fatalf("add %s: %s", z[kind], resp.ErrorMsg)
		}
	}
	static := &ZoneData{ZoneName: z["config"], ZoneType: Primary, Options: map[ZoneOption]bool{}}
	static.fromStaticConfig.Store(true)
	Zones.Set(z["config"], static)
	granted := &ZoneData{ZoneName: z["granted"], ZoneType: Primary, Options: map[ZoneOption]bool{}}
	granted.fromStaticConfig.Store(true)
	granted.setApiOwner("cert:provisioner")
	Zones.Set(z["granted"], granted)
	return z
}

// sameModuloName says whether two refusals are the same text once each
// one's zone name is taken out.
func sameModuloName(a, an, b, bn string) bool {
	return strings.ReplaceAll(a, an, "ZONE") == strings.ReplaceAll(b, bn, "ZONE")
}

// The application table has an entry, explicit refusals included, for every
// route and command of the role table and for every command the handlers
// switch on, and none for anything else. So a new route or command is
// refused to application clients until someone decides otherwise, as it
// needs admin until someone decides its role (design R2).
func TestApiAppTableMatchesTheRoleTable(t *testing.T) {
	keys := func(m map[string]AppScope) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	for route, roles := range apiRouteRoles {
		app, ok := apiAppScopes[route]
		if !ok {
			t.Errorf("route %s has no entry in apiAppScopes: decide how application clients are scoped", route)
			continue
		}
		for cmd := range roles {
			if _, ok := app[cmd]; !ok {
				t.Errorf("route %s: command %q is in apiRouteRoles but not in apiAppScopes", route, cmd)
			}
		}
		for _, cmd := range keys(app) {
			if _, ok := roles[cmd]; !ok {
				t.Errorf("route %s: apiAppScopes lists %q, which apiRouteRoles does not have", route, cmd)
			}
		}
	}
	for route := range apiAppScopes {
		if _, ok := apiRouteRoles[route]; !ok {
			t.Errorf("apiAppScopes has %s, which apiRouteRoles does not", route)
		}
	}

	routes, funcs := parseApiRoutes(t)
	for route, handler := range routes {
		app := apiAppScopes[route]
		fd := funcs[handler]
		if app == nil || fd == nil {
			continue // reported above, or by the role table's test
		}
		cmds := commandsOf(fd)
		star, hasStar := app["*"]
		// "*" by subcommand is apiAppSubScopes', which
		// TestApiAppKeystoreTableMatchesTheHandlers holds to the handler.
		if hasStar && star != AppRefused && star != AppBySubCommand && len(cmds) > 0 {
			t.Errorf("route %s: \"*\" opens a handler with commands %v; list them instead", route, cmds)
		}
		for _, c := range cmds {
			if _, ok := app[c]; !ok && !(hasStar && (star == AppRefused || star == AppBySubCommand)) {
				t.Errorf("route %s: command %q (in %s) has no entry in apiAppScopes", route, c, handler)
			}
		}
	}

	// What design 4.5 refuses by name, and the one open command.
	for _, tc := range []struct{ route, cmd string }{
		{"/api/v1/config", "reload"}, {"/api/v1/config", "reload-zones"}, {"/api/v1/config", "transport-signal-release"},
		{"/api/v1/scanner/poll", "on"}, {"/api/v1/scanner/poll", "off"}, {"/api/v1/scanner/poll", "follow-config"},
		{"/api/v1/scanner", "scan"}, {"/api/v1/scanner/delete", ""},
		{"/api/v1/imr", "imr-flush"}, {"/api/v1/imr", "imr-reset"},
		{"/api/v1/keystore", "tsig-mgmt"}, {"/api/v1/truststore", "list"},
		{"/api/v1/dsync-api/credential", "issue"}, {"/api/v1/dsync-api/cert-credential", ""},
		{"/api/v1/zone", "setowner"}, {"/api/v1/zone", "no-such-command"}, {"/api/v1/no-such-route", ""},
		{"/api/v1/zone", unknownCommand},
	} {
		if got := ApiAppScopeOf(tc.route, tc.cmd, ""); got != AppRefused {
			t.Errorf("%s %q: %s, want refused", tc.route, tc.cmd, got)
		}
	}
	if got := ApiAppScopeOf("/api/v1/ping", "", ""); got != AppOpen {
		t.Errorf("ping: %s, want open", got)
	}
	if got := ApiAppScopeOf("/api/v1/zone", " UPDATE ", ""); got != AppOwnZone {
		t.Errorf("zone UPDATE: %s, want own zone (case and space do not matter)", got)
	}

	// Commands a handler answers before its switch are in both tables
	// (commandsOf sees the comparison): delegation sync-log, which no
	// zone scopes, is admin and refused to application clients.
	cmds := commandsOf(funcs["APIdelegation"])
	if i := sort.SearchStrings(cmds, "sync-log"); i == len(cmds) || cmds[i] != "sync-log" {
		t.Errorf("APIdelegation commands %v: the scan does not see sync-log", cmds)
	}
	if got := RequiredApiRole("/api/v1/delegation", "sync-log", "", false); got != RoleAdmin {
		t.Errorf("delegation sync-log needs %s, want admin", got)
	}
	if got := ApiAppScopeOf("/api/v1/delegation", "sync-log", ""); got != AppRefused {
		t.Errorf("delegation sync-log for an application client: %s, want refused", got)
	}
}

// Every command of the zone handler that acts on a named zone: an
// application client is refused another application's zone, an api zone
// and a config zone, each with its own text, and a zone that is not there
// with the same text as another application's. Its own zone, and a
// config-file zone granted to it, get past the check.
func TestAppClientZoneScope(t *testing.T) {
	z := scopeZones(t)
	me := "cert:provisioner"
	for cmd, scope := range apiAppScopes["/api/v1/zone"] {
		if scope != AppOwnZone || cmd == "delete" || cmd == "modify" {
			continue // delete and modify: TestAppClientZoneDelete, TestAppClientZoneModify
		}
		for kind, want := range map[string][]string{
			"other":   {"zone other.example.: not a zone of API owner " + me},
			"missing": {"zone missing.example.: not a zone of API owner " + me},
			"api":     {"API owner is api, not " + me, "zone setowner"},
			"config":  {"API owner is config, not " + me, "api-owner: " + me + " in the config"},
		} {
			resp := postZone(t, ZonePost{Command: cmd, Zone: z[kind]}, &appCaller)
			for _, w := range want {
				if !resp.Error || !strings.Contains(resp.ErrorMsg, w) {
					t.Errorf("%s on %s zone: error=%v %q, want it to say %q", cmd, kind, resp.Error, resp.ErrorMsg, w)
				}
			}
			if strings.Contains(resp.ErrorMsg, "cert:other") {
				t.Errorf("%s on %s zone: the refusal names the other owner: %q", cmd, kind, resp.ErrorMsg)
			}
		}
		other := postZone(t, ZonePost{Command: cmd, Zone: z["other"]}, &appCaller)
		missing := postZone(t, ZonePost{Command: cmd, Zone: z["missing"]}, &appCaller)
		if !sameModuloName(other.ErrorMsg, z["other"], missing.ErrorMsg, z["missing"]) {
			t.Errorf("%s: another's zone says %q, a missing one %q: an application can tell them apart", cmd, other.ErrorMsg, missing.ErrorMsg)
		}
	}

	// Past the check: the next thing update has to say is about the zone.
	for _, kind := range []string{"own", "granted"} {
		resp := postZone(t, ZonePost{Command: "update", Zone: z[kind], UpdateVerb: "addrr"}, &appCaller)
		if refusedForApp(resp.ErrorMsg) || !strings.Contains(resp.ErrorMsg, "allow updates via the management API") {
			t.Errorf("update of the %s zone: %q, want it past the API owner check", kind, resp.ErrorMsg)
		}
	}
	// An operator, by certificate, the socket or the key: as before.
	for _, id := range []*ApiIdentity{&certCaller, &socketCaller, &keyCaller} {
		for _, kind := range []string{"other", "api", "config"} {
			resp := postZone(t, ZonePost{Command: "update", Zone: z[kind], UpdateVerb: "addrr"}, id)
			if refusedForApp(resp.ErrorMsg) {
				t.Errorf("%s: update of the %s zone refused: %q", id.Via, kind, resp.ErrorMsg)
			}
		}
		if resp := postZone(t, ZonePost{Command: "update", Zone: z["missing"]}, id); !strings.Contains(resp.ErrorMsg, "is unknown") {
			t.Errorf("%s: a missing zone says %q, want the old text", id.Via, resp.ErrorMsg)
		}
	}
}

// list-zones and list-dynamic show an application client its own zones
// only: the ones it added, a config-file zone granted to it, and the
// members of a catalog zone of its own. An operator sees them all.
func TestAppClientListsAreFiltered(t *testing.T) {
	z := scopeZones(t)
	cat := &ZoneData{ZoneName: "cat.example.", Options: map[ZoneOption]bool{OptCatalogZone: true}}
	cat.setApiOwner("cert:provisioner")
	Zones.Set("cat.example.", cat)
	member := &ZoneData{ZoneName: "member.example.", ZoneType: Secondary, SourceCatalog: "cat.example.",
		Options: map[ZoneOption]bool{OptAutomaticZone: true}}
	Zones.Set("member.example.", member)

	names := func(zones map[string]ZoneConf) []string {
		var out []string
		for n := range zones {
			out = append(out, n)
		}
		sort.Strings(out)
		return out
	}
	got := names(postZone(t, ZonePost{Command: "list-zones"}, &appCaller).Zones)
	want := []string{"cat.example.", z["granted"], "member.example.", z["own"]}
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("list-zones for the application: %v, want %v", got, want)
	}
	if got := names(postZone(t, ZonePost{Command: "list-dynamic"}, &appCaller).Zones); strings.Join(got, " ") != z["own"] {
		t.Errorf("list-dynamic for the application: %v, want [%s]", got, z["own"])
	}
	if got := names(postZone(t, ZonePost{Command: "list-zones"}, &otherApp).Zones); strings.Join(got, " ") != z["other"] {
		t.Errorf("list-zones for the other application: %v", got)
	}
	all := postZone(t, ZonePost{Command: "list-zones"}, &certCaller).Zones
	if len(all) != 7 {
		t.Errorf("list-zones for an operator: %v, want all 7 zones", names(all))
	}
	if dyn := postZone(t, ZonePost{Command: "list-dynamic"}, &socketCaller).Zones; len(dyn) < 3 {
		t.Errorf("list-dynamic for the socket: %v, want the 3 added zones", names(dyn))
	}

	// zone desc (list-zones of one zone): own zone only, the same answer
	// for a zone that is not there.
	if resp := postZone(t, ZonePost{Command: "list-zones", Zone: z["own"]}, &appCaller); resp.Error || len(resp.Zones) != 1 {
		t.Errorf("desc of the own zone: %q %v", resp.ErrorMsg, names(resp.Zones))
	}
	other := postZone(t, ZonePost{Command: "list-zones", Zone: z["other"]}, &appCaller)
	missing := postZone(t, ZonePost{Command: "list-zones", Zone: z["missing"]}, &appCaller)
	if !other.Error || len(other.Zones) != 0 || !sameModuloName(other.ErrorMsg, z["other"], missing.ErrorMsg, z["missing"]) {
		t.Errorf("desc of another's zone: %q, of a missing one %q; want the same refusal", other.ErrorMsg, missing.ErrorMsg)
	}
}

// insertLeftoverKeys puts a DNSSEC and a SIG(0) key of zone into the
// keystore, as a zone deleted with --keep-keys leaves them.
func insertLeftoverKeys(t *testing.T, kdb *KeyDB, zone string) {
	t.Helper()
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO Sig0KeyStore (zonename, state, keyid, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		zone, "active", 1, "ED25519", "test", "x", zone+" KEY 256 3 15 AAAA"); err != nil {
		t.Fatal(err)
	}
	if err := insertKeyRowTx(tx, KeyRow{Zone: zone, State: DnskeyStatePublished, Keyid: 2, Flags: 257,
		Algorithm: "ED25519", Creator: "test", PrivateKey: "x", KeyRR: zone + " DNSKEY 257 3 15 AAAA"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// zone add by an application client: a new zone is its own; an existing one
// is refused as such; a name whose earlier zone left keys in the keystore is
// refused, saying how an operator clears it. An operator's add of that name
// goes through.
func TestAppClientZoneAdd(t *testing.T) {
	z := scopeZones(t)
	if resp := postZone(t, secondaryAdd("new.example."), &appCaller); resp.Error {
		t.Fatalf("add of a new zone: %s", resp.ErrorMsg)
	}
	if zd, _ := Zones.Get("new.example."); zd == nil || zd.EffectiveApiOwner() != "cert:provisioner" {
		t.Errorf("the added zone's API owner is not the application")
	}
	if resp := postZone(t, secondaryAdd(z["other"]), &appCaller); !resp.Error || !strings.Contains(resp.ErrorMsg, "already exists") {
		t.Errorf("add of an existing zone: %q, want already exists", resp.ErrorMsg)
	}

	insertLeftoverKeys(t, Conf.Internal.KeyDB, "kept.example.")
	resp := postZone(t, secondaryAdd("kept.example."), &appCaller)
	for _, w := range []string{"zone kept.example.: not added: 2 key(s) of an earlier zone remain", "zone setowner"} {
		if !resp.Error || !strings.Contains(resp.ErrorMsg, w) {
			t.Errorf("re-add with leftover keys: %q, want it to say %q", resp.ErrorMsg, w)
		}
	}
	if _, ok := Zones.Get("kept.example."); ok {
		t.Error("the refused re-add registered the zone")
	}
	if got := persistedOwners(t); got["kept.example."] != "" {
		t.Errorf("the refused re-add is in the dynamic config: %v", got)
	}
	if resp := postZone(t, secondaryAdd("kept.example."), &certCaller); resp.Error {
		t.Errorf("an operator's re-add with leftover keys: %s", resp.ErrorMsg)
	}
}

// zone delete by an application client: its own zone goes; another's, an
// api and a config zone stay, and a missing one says what another's says.
// --keep-keys is refused to it, with the zone left in place, and still works
// for an operator. A config-file zone granted to it is not deleted over the
// API.
func TestAppClientZoneDelete(t *testing.T) {
	z := scopeZones(t)
	del := func(zone string, keep bool, id *ApiIdentity) ZoneResponse {
		t.Helper()
		return postZone(t, ZonePost{Command: "delete", Zone: zone, KeepKeys: keep}, id)
	}
	for _, kind := range []string{"other", "api", "config"} {
		if resp := del(z[kind], false, &appCaller); !resp.Error || !refusedForApp(resp.ErrorMsg) {
			t.Errorf("delete of the %s zone: %q, want an API owner refusal", kind, resp.ErrorMsg)
		}
		if _, ok := Zones.Get(z[kind]); !ok {
			t.Errorf("the refused delete removed the %s zone", kind)
		}
	}
	other, missing := del(z["other"], false, &appCaller), del(z["missing"], false, &appCaller)
	if !sameModuloName(other.ErrorMsg, z["other"], missing.ErrorMsg, z["missing"]) {
		t.Errorf("delete: another's zone says %q, a missing one %q", other.ErrorMsg, missing.ErrorMsg)
	}
	if resp := del(z["granted"], false, &appCaller); !resp.Error || !strings.Contains(resp.ErrorMsg, "not API-managed") {
		t.Errorf("delete of a granted config-file zone: %q, want it refused as not API-managed", resp.ErrorMsg)
	}

	resp := del(z["own"], true, &appCaller)
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "--keep-keys: not available to application clients") {
		t.Errorf("delete --keep-keys by the application: %q", resp.ErrorMsg)
	}
	if _, ok := Zones.Get(z["own"]); !ok {
		t.Error("the refused --keep-keys delete removed the zone")
	}
	if resp := del(z["own"], false, &appCaller); resp.Error {
		t.Errorf("delete of the own zone: %s", resp.ErrorMsg)
	}
	if _, ok := Zones.Get(z["own"]); ok {
		t.Error("the own zone is still there after its delete")
	}
	if resp := del(z["other"], true, &certCaller); resp.Error {
		t.Errorf("delete --keep-keys by an operator: %s", resp.ErrorMsg)
	}
}

// addTsigKey puts a TSIG key with the given API owner into the keystore
// and the live store.
func addTsigKey(t *testing.T, name, owner string) {
	t.Helper()
	kdb := Conf.Internal.KeyDB
	resp, err := kdb.TsigKeyMgmt(&Conf, nil, KeystorePost{SubCommand: "add", TsigKeyname: name,
		TsigAlgorithm: "hmac-sha256", TsigSecret: b64Secret16, Owner: owner, Creator: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTsigCacheDelta(Conf.Internal.TsigKeyStore, kdb, resp.TsigCacheDelta); err != nil {
		t.Fatal(err)
	}
}

// zone modify by an application client: its own zone only. A primary's TSIG
// key must be its own key or the inline one of the same request, for modify
// and add alike; an operator may name any key.
func TestAppClientZoneModify(t *testing.T) {
	z := scopeZones(t)
	addTsigKey(t, "mine.", "cert:provisioner")
	addTsigKey(t, "theirs.", "cert:other")
	modify := func(zone, key string, id *ApiIdentity) ZoneResponse {
		t.Helper()
		return postZone(t, ZonePost{Command: "modify", Zone: zone,
			Primaries: []PeerConf{{Addr: "192.0.2.7:53", Key: key}}}, id)
	}
	for _, kind := range []string{"other", "api", "config", "missing"} {
		if resp := modify(z[kind], NOKEY, &appCaller); !resp.Error || !refusedForApp(resp.ErrorMsg) {
			t.Errorf("modify of the %s zone: %q, want an API owner refusal", kind, resp.ErrorMsg)
		}
	}
	if resp := modify(z["own"], "mine.", &appCaller); resp.Error {
		t.Errorf("modify of the own zone with its own key: %s", resp.ErrorMsg)
	}
	for _, key := range []string{"theirs.", "nosuchkey."} {
		resp := modify(z["own"], key, &appCaller)
		if !resp.Error || !strings.Contains(resp.ErrorMsg, "TSIG key "+key+" is not a key of API owner cert:provisioner") {
			t.Errorf("modify with key %s: %q, want it refused", key, resp.ErrorMsg)
		}
	}
	inline := ZonePost{Command: "modify", Zone: z["own"], Primaries: []PeerConf{{Addr: "192.0.2.7:53", Key: NOKEY}},
		TsigName: "inline.", TsigSecret: b64Secret16}
	if resp := postZone(t, inline, &appCaller); resp.Error {
		t.Errorf("modify with an inline key: %s", resp.ErrorMsg)
	}
	// Its own inline key again, identical: still fine.
	if resp := postZone(t, inline, &appCaller); resp.Error {
		t.Errorf("modify with its own inline key again: %s", resp.ErrorMsg)
	}
	// Another owner's key given inline, identical secret and all: refused
	// (Johan, 2026-11-24), for add and modify; an operator's is a no-op.
	theirsInline := inline
	theirsInline.TsigName = "theirs."
	if resp := postZone(t, theirsInline, &appCaller); !resp.Error || !strings.Contains(resp.ErrorMsg, "TSIG key theirs. exists and is not a key of API owner cert:provisioner") {
		t.Errorf("modify with another's key inline: %q, want it refused", resp.ErrorMsg)
	}
	inlineAdd := secondaryAdd("inline-theirs.example.")
	inlineAdd.TsigName, inlineAdd.TsigSecret = "theirs.", b64Secret16
	if resp := postZone(t, inlineAdd, &appCaller); !resp.Error || !strings.Contains(resp.ErrorMsg, "exists and is not a key of API owner") {
		t.Errorf("add with another's key inline: %q, want it refused", resp.ErrorMsg)
	}
	if _, ok := Zones.Get("inline-theirs.example."); ok {
		t.Error("the refused add left its zone")
	}
	if resp := postZone(t, theirsInline, &certCaller); resp.Error {
		t.Errorf("an operator's modify with another's key inline: %s", resp.ErrorMsg)
	}
	add := secondaryAdd("withkey.example.")
	add.Primaries[0].Key = "theirs."
	if resp := postZone(t, add, &appCaller); !resp.Error || !strings.Contains(resp.ErrorMsg, "not a key of API owner") {
		t.Errorf("add with another's key: %q, want it refused", resp.ErrorMsg)
	}
	if resp := postZone(t, add, &certCaller); resp.Error {
		t.Errorf("an operator's add with any key: %s", resp.ErrorMsg)
	}
}

// zone update: own zone only, and an update with one RR outside the zone is
// refused whole, before anything is applied.
func TestAppClientZoneUpdateStaysInTheZone(t *testing.T) {
	z := scopeZones(t)
	zd, _ := Zones.Get(z["own"])
	zd.mu.Lock()
	zd.Options[OptAllowApiUpdates] = true
	zd.mu.Unlock()
	resp := postZone(t, ZonePost{Command: "update", Zone: z["own"], UpdateVerb: "addrr",
		UpdateRRs: []string{"www.own.example. 300 IN A 192.0.2.10", "www.other.example. 300 IN A 192.0.2.11"}}, &appCaller)
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "www.other.example.") {
		t.Errorf("update with an RR of another zone: %q, want it refused naming it", resp.ErrorMsg)
	}

	// The application's own check, on what is about to be applied.
	in := []dns.RR{}
	for _, s := range []string{"own.example. 300 IN TXT \"apex\"", "a.b.own.example. 300 IN A 192.0.2.1"} {
		rr, _ := dns.NewRR(s)
		in = append(in, rr)
	}
	out, _ := dns.NewRR("own.example.other.example. 300 IN A 192.0.2.1")
	if err := appUpdateRefusal("provisioner", "own.example.", in); err != nil {
		t.Errorf("RRs at and below the apex: %v", err)
	}
	err := appUpdateRefusal("provisioner", "own.example.", append(in, out))
	if err == nil || !strings.Contains(err.Error(), "nothing was applied") {
		t.Errorf("one RR outside the zone: %v, want the whole update refused", err)
	}
	if err := appUpdateRefusal("", "own.example.", append(in, out)); err != nil {
		t.Errorf("no application client: %v", err)
	}
}

// postAs runs handler on a request with body (a JSON value, or nil) as id.
func postAs(t *testing.T, handler http.HandlerFunc, method, target string, body any, id *ApiIdentity) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, target, &buf)
	if id != nil {
		req = req.WithContext(context.WithValue(req.Context(), apiIdentityKey{}, *id))
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// parentsync, childsync, delegation and rollover act on the application
// client's own zone only; for each, its own zone gets past the check (to
// the handler's next answer), the others are refused, and a missing zone
// reads like another's.
func TestAppClientZoneSyncAndRolloverScope(t *testing.T) {
	z := scopeZones(t)
	app := &AppDetails{Name: "tdns-auth"}
	errMsg := func(rec *httptest.ResponseRecorder) string {
		var r struct {
			ErrorMsg  string
			ErrorMsg2 string `json:"error_msg"`
		}
		if json.Unmarshal(rec.Body.Bytes(), &r) == nil && r.ErrorMsg+r.ErrorMsg2 != "" {
			return r.ErrorMsg + r.ErrorMsg2
		}
		return rec.Body.String()
	}
	type call func(zone string, id *ApiIdentity) *httptest.ResponseRecorder
	for _, tc := range []struct {
		name    string
		call    call
		ownSays string // what the handler says past the check, about the own zone
	}{
		{"parentsync status", func(zone string, id *ApiIdentity) *httptest.ResponseRecorder {
			return postAs(t, APIzoneParentSyncWith(context.Background(), app, nil, Conf.Internal.KeyDB, nil), "POST", "/api/v1/zone/parentsync",
				ZoneParentSyncPost{Command: "status", Zone: zone}, id)
		}, "does not have parentsync"},
		{"childsync publish", func(zone string, id *ApiIdentity) *httptest.ResponseRecorder {
			return postAs(t, APIzoneChildSync(context.Background(), app), "POST", "/api/v1/zone/childsync",
				ZoneChildSyncPost{Command: "publish", Zone: zone}, id)
		}, "does not have the childsync option"},
		{"delegation status", func(zone string, id *ApiIdentity) *httptest.ResponseRecorder {
			return postAs(t, APIdelegation(nil), "POST", "/api/v1/delegation", DelegationPost{Command: "status", Zone: zone}, id)
		}, "delegation sync not available"},
		{"rollover status", func(zone string, id *ApiIdentity) *httptest.ResponseRecorder {
			return postAs(t, APIRolloverStatus(&Conf), "GET", "/api/v1/rollover/status?zone="+zone, nil, id)
		}, ""},
		{"rollover when", func(zone string, id *ApiIdentity) *httptest.ResponseRecorder {
			return postAs(t, APIRolloverWhen(&Conf), "GET", "/api/v1/rollover/when?zone="+zone, nil, id)
		}, ""},
		{"rollover asap", func(zone string, id *ApiIdentity) *httptest.ResponseRecorder {
			return postAs(t, APIRolloverAsap(&Conf), "POST", "/api/v1/rollover/asap", RolloverAsapRequest{Zone: zone}, id)
		}, "has no DNSSEC policy"},
		{"rollover unstick", func(zone string, id *ApiIdentity) *httptest.ResponseRecorder {
			return postAs(t, APIRolloverUnstick(&Conf), "POST", "/api/v1/rollover/unstick", RolloverUnstickRequest{Zone: zone}, id)
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			own := errMsg(tc.call(z["own"], &appCaller))
			if refusedForApp(own) || (tc.ownSays != "" && !strings.Contains(own, tc.ownSays)) {
				t.Errorf("own zone: %q, want it past the check (%q)", own, tc.ownSays)
			}
			for _, kind := range []string{"other", "api", "config", "missing"} {
				if got := errMsg(tc.call(z[kind], &appCaller)); !refusedForApp(got) {
					t.Errorf("%s zone: %q, want an API owner refusal", kind, got)
				}
				if got := errMsg(tc.call(z[kind], &certCaller)); refusedForApp(got) {
					t.Errorf("%s zone, for an operator: %q", kind, got)
				}
			}
			other, missing := errMsg(tc.call(z["other"], &appCaller)), errMsg(tc.call(z["missing"], &appCaller))
			if !sameModuloName(other, z["other"], missing, z["missing"]) {
				t.Errorf("another's zone says %q, a missing one %q", other, missing)
			}
		})
	}
}

// catalog: create makes a catalog zone of the caller's own; the commands on
// a catalog zone need it to be the caller's, and those on a member need the
// member and the catalog zone both to be. A config-file catalog zone granted
// to the application is not deleted over the API.
func TestAppClientCatalogScope(t *testing.T) {
	z := scopeZones(t)
	catalog := func(id *ApiIdentity, cp CatalogPost) string {
		t.Helper()
		rec := postAs(t, APICatalog(&AppDetails{Name: "tdns-auth"}), "POST", "/api/v1/catalog", cp, id)
		var resp CatalogResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: %v %s", cp.Command, err, rec.Body.String())
		}
		return resp.ErrorMsg
	}
	if msg := catalog(&appCaller, CatalogPost{Command: "create", CatalogZone: "cat.example."}); msg != "" {
		t.Fatalf("create by the application: %s", msg)
	}
	if owner, _ := ZoneApiOwner("cat.example."); owner != "cert:provisioner" {
		t.Errorf("the created catalog zone has API owner %q", owner)
	}
	if msg := catalog(&otherApp, CatalogPost{Command: "create", CatalogZone: "ocat.example."}); msg != "" {
		t.Fatalf("create by the other application: %s", msg)
	}

	for _, tc := range []struct {
		cp      CatalogPost
		refused bool
	}{
		{CatalogPost{Command: "group-add", CatalogZone: "cat.example.", Group: "g1"}, false},
		{CatalogPost{Command: "group-add", CatalogZone: "ocat.example.", Group: "g1"}, true},
		{CatalogPost{Command: "group-add", CatalogZone: z["api"], Group: "g1"}, true},
		{CatalogPost{Command: "group-list", CatalogZone: "cat.example."}, false},
		{CatalogPost{Command: "group-list", CatalogZone: "ocat.example."}, true},
		{CatalogPost{Command: "zone-add", CatalogZone: "cat.example.", Zone: z["own"]}, false},
		{CatalogPost{Command: "zone-add", CatalogZone: "cat.example.", Zone: z["other"]}, true},
		{CatalogPost{Command: "zone-add", CatalogZone: "cat.example.", Zone: z["missing"]}, true},
		{CatalogPost{Command: "zone-add", CatalogZone: "ocat.example.", Zone: z["own"]}, true},
		{CatalogPost{Command: "zone-group-add", CatalogZone: "cat.example.", Zone: z["own"], Group: "g1"}, false},
		{CatalogPost{Command: "zone-group-add", CatalogZone: "cat.example.", Zone: z["api"], Group: "g1"}, true},
		{CatalogPost{Command: "zone-list", CatalogZone: "cat.example."}, false},
		{CatalogPost{Command: "zone-list", CatalogZone: "ocat.example."}, true},
		{CatalogPost{Command: "notify-list", CatalogZone: z["missing"]}, true},
		{CatalogPost{Command: "zone-delete", CatalogZone: "cat.example.", Zone: z["own"]}, false},
		// The catalog zone's owner may remove any member; adding needs both.
		{CatalogPost{Command: "zone-delete", CatalogZone: "cat.example.", Zone: z["other"]}, false},
		{CatalogPost{Command: "zone-delete", CatalogZone: "cat.example.", Zone: z["missing"]}, false},
		{CatalogPost{Command: "zone-group-delete", CatalogZone: "cat.example.", Zone: z["api"], Group: "g1"}, false},
		{CatalogPost{Command: "zone-delete", CatalogZone: "ocat.example.", Zone: z["own"]}, true},
		{CatalogPost{Command: "zone-group-delete", CatalogZone: "ocat.example.", Zone: z["own"], Group: "g1"}, true},
		{CatalogPost{Command: "delete", CatalogZone: "ocat.example."}, true},
		{CatalogPost{Command: "delete", CatalogZone: "cat.example."}, false},
	} {
		msg := catalog(&appCaller, tc.cp)
		if got := refusedForApp(msg); got != tc.refused {
			t.Errorf("%s %s %s: %q, want refused=%v", tc.cp.Command, tc.cp.CatalogZone, tc.cp.Zone, msg, tc.refused)
		}
	}
	if _, ok := Zones.Get("ocat.example."); !ok {
		t.Error("the refused delete removed the other application's catalog zone")
	}
	if msg := catalog(&certCaller, CatalogPost{Command: "group-add", CatalogZone: "ocat.example.", Group: "g2"}); msg != "" {
		t.Errorf("an operator's group-add: %s", msg)
	}

	// An operator puts its own zone into the application's catalog zone
	// (or did before a setowner handed the catalog over); the application
	// may take it out. The zone itself stays: only an automatic member the
	// catalog created goes with its entry.
	if msg := catalog(&appCaller, CatalogPost{Command: "create", CatalogZone: "cat3.example."}); msg != "" {
		t.Fatalf("create: %s", msg)
	}
	if msg := catalog(&certCaller, CatalogPost{Command: "zone-add", CatalogZone: "cat3.example.", Zone: z["api"]}); msg != "" {
		t.Fatalf("an operator's zone-add to the application's catalog: %s", msg)
	}
	if msg := catalog(&appCaller, CatalogPost{Command: "zone-delete", CatalogZone: "cat3.example.", Zone: z["api"]}); msg != "" {
		t.Errorf("the catalog owner removing an operator's member: %s", msg)
	}
	if _, ok := Zones.Get(z["api"]); !ok {
		t.Error("removing the member from the catalog deleted the operator's zone")
	}

	granted := &ZoneData{ZoneName: "scat.example.", Options: map[ZoneOption]bool{OptCatalogZone: true}}
	granted.fromStaticConfig.Store(true)
	granted.setApiOwner("cert:provisioner")
	Zones.Set("scat.example.", granted)
	if msg := catalog(&appCaller, CatalogPost{Command: "delete", CatalogZone: "scat.example."}); !strings.Contains(msg, "config-file zone and cannot be deleted") {
		t.Errorf("delete of a granted config-file catalog zone: %q", msg)
	}
	if _, ok := Zones.Get("scat.example."); !ok {
		t.Error("the granted config-file catalog zone was deleted")
	}
}

// writeAccess writes an access file of clients (name: role) with pins
// from pins.
func writeAccess(t *testing.T, path string, pins map[string]string, keyauth bool, clients ...[2]string) {
	t.Helper()
	s := "keyauth: false\n"
	if keyauth {
		s = "keyauth: true\n"
	}
	s += "clients:\n"
	for _, c := range clients {
		s += "  - {name: " + c[0] + ", pin: " + pins[c[0]] + ", role: " + c[1] + "}\n"
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// End to end over TLS: a certificate client named in app-clients is an
// application client (ping says so); the middleware refuses it what the
// application table does not open, after the role check; the zone handler
// scopes what is open. An operator's certificate and the key are as before,
// and taking a name out of app-clients makes it an operator again.
func TestAppClientsOverTheNetwork(t *testing.T) {
	z := scopeZones(t)
	certs, pins := clientCerts(t, "provisioner", "reader", "ops")
	access := "keyauth: true\nclients:\n" +
		"  - {name: provisioner, pin: " + pins["provisioner"] + ", role: read-write}\n" +
		"  - {name: reader, pin: " + pins["reader"] + ", role: read-only}\n" +
		"  - {name: ops, pin: " + pins["ops"] + ", role: read-write}\n"
	e := newAuthEnv(t, access, certs)
	e.conf.ApiServer.AppClients = []string{"provisioner", "reader", "ghost"}
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "app-clients provisioner reader ghost") {
		t.Fatalf("reload: %q", msg)
	}
	e.rtr.HandleFunc("/api/v1/zone", APIzone(&AppDetails{Name: "tdns-auth"}, Conf.Internal.RefreshZoneCh, Conf.Internal.KeyDB)).Methods("POST")

	for _, tc := range []struct {
		name, path, cert string
		key              bool
		body             string
		want             int
		wantBody         string
	}{
		{"ping is open", "/api/v1/ping", "provisioner", false, "", 200, "provisioner (read-write, application client) by certificate"},
		{"config status is refused", "/api/v1/config", "provisioner", false, `{"Command":"status"}`, 403, "config status: not available to application clients"},
		{"command status is refused", "/api/v1/command", "provisioner", false, `{"Command":"status"}`, 403, "command status: not available to application clients"},
		{"a route of an add-on is refused", "/api/v1/t-rw", "provisioner", false, "", 403, "t-rw: not available to application clients"},
		// By the role check, which comes first: such a command needs admin.
		{"an unreadable command is refused", "/api/v1/zone", "provisioner", false, `{"command":"list-zones"}{}`, 403, "needs admin"},
		{"the role comes first", "/api/v1/zone", "reader", false, `{"Command":"update","Zone":"own.example."}`, 403, "needs read-write; reader is read-only"},
		{"another's zone, in the handler", "/api/v1/zone", "provisioner", false, `{"Command":"get-name","Zone":"other.example."}`, 200, "not a zone of API owner cert:provisioner"},
		{"an operator: config status", "/api/v1/config", "ops", false, `{"Command":"status"}`, 200, ""},
		{"an operator: another's zone", "/api/v1/zone", "ops", false, `{"Command":"list-zones","Zone":"other.example."}`, 200, "other.example."},
		{"the key: config status", "/api/v1/config", "", true, `{"Command":"status"}`, 200, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, body := e.call(t, tc.path, tc.cert, tc.key, tc.body)
			if st != tc.want || !strings.Contains(body, tc.wantBody) {
				t.Errorf("%d %q, want %d containing %q", st, body, tc.want, tc.wantBody)
			}
		})
	}
	_, body := e.call(t, "/api/v1/zone", "provisioner", false, `{"Command":"list-zones"}`)
	var resp ZoneResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil || len(resp.Zones) != 2 || resp.Zones[z["own"]].Name == "" {
		t.Errorf("list-zones over the network: %v %s, want the own and the granted zone", err, body)
	}
	if st, _ := e.callSocket(t, "/api/v1/config", `{"Command":"status"}`); st != 200 {
		t.Errorf("the socket: config status %d", st)
	}

	e.conf.ApiServer.AppClients = nil
	e.conf.reloadApiAccess()
	if st, body := e.call(t, "/api/v1/config", "provisioner", false, `{"Command":"status"}`); st != 200 {
		t.Errorf("out of app-clients, config status: %d %q, want 200 as an operator", st, body)
	}
}

// A server whose config names no application clients behaves as before:
// every certificate client is an operator.
func TestNoAppClientsNoChange(t *testing.T) {
	certs, pins := clientCerts(t, "provisioner")
	e := newAuthEnv(t, "clients:\n  - {name: provisioner, pin: "+pins["provisioner"]+", role: read-write}\n", certs)
	if st, body := e.call(t, "/api/v1/ping", "provisioner", false, ""); st != 200 || strings.Contains(body, "application") {
		t.Errorf("ping: %d %q", st, body)
	}
	if st, body := e.call(t, "/api/v1/config", "provisioner", false, `{"Command":"status"}`); st != 200 {
		t.Errorf("config status: %d %q", st, body)
	}
	if st, _ := e.call(t, "/api/v1/t-rw", "provisioner", false, ""); st != 200 {
		t.Errorf("an add-on's read-write route: %d", st)
	}
	if a := e.conf.apiAccessStatus(); a == nil || len(a.AppClients) != 0 {
		t.Errorf("config status access: %+v", a)
	}
}

// app-clients goes into force with the access file, as one policy: a reload
// whose file does not load keeps the running list and says so; one that
// loads applies both; and a request never sees a list of one reload with a
// file of another.
func TestAppClientsSwapWithTheAccessFile(t *testing.T) {
	certs, pins := clientCerts(t, "anna")
	e := newAuthEnv(t, "-", certs)
	path := filepath.Join(t.TempDir(), "access.yaml")
	e.conf.ApiServer.AccessFile = path
	writeAccess(t, path, pins, false, [2]string{"anna", "read-only"})
	e.conf.ApiServer.AppClients = []string{"anna"}
	e.conf.reloadApiAccess()
	h := e.conf.Internal.ApiAccess
	if st := h.load(); !st.appClients["anna"] {
		t.Fatalf("anna is not an application client after the reload: %+v", st)
	}

	if err := os.WriteFile(path, []byte("clients:\n  - {name: anna, pin: x, role: read-only}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.conf.ApiServer.AppClients = nil
	msg := e.conf.reloadApiAccess()
	if !strings.Contains(msg, AccessFileNotReloaded) || !strings.Contains(msg, "app-clients is NOT applied either") {
		t.Errorf("reload with a broken file: %q", msg)
	}
	if st := h.load(); !st.appClients["anna"] || len(st.AppClients) != 1 {
		t.Errorf("the broken reload changed the application clients: %+v", st.AppClients)
	}
	writeAccess(t, path, pins, false, [2]string{"anna", "read-only"})
	e.conf.reloadApiAccess()
	if st := h.load(); st.appClients["anna"] {
		t.Errorf("the good reload did not apply the new list: %+v", st.AppClients)
	}

	// Two policies in turn: anna read-only and an application client, and
	// anna read-write and an operator. Every request sees one of them, and
	// the requests go on until each policy has been published by the
	// writer and seen by a request at least twice (seen counts the
	// changes a request saw), so that the check is not made against the
	// first policy alone.
	writeAccess(t, path, pins, false, [2]string{"anna", "read-write"})
	e.conf.ApiServer.AppClients = nil
	e.conf.reloadApiAccess()
	leaf, _ := x509.ParseCertificate(certs["anna"].Certificate[0])
	req := func() (ApiIdentity, int, string) {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/ping", nil)
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}}
		return e.conf.authenticateApiRequest(r, e.key)
	}
	var stop atomic.Bool
	var published atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			if i%2 == 0 {
				writeAccess(t, path, pins, false, [2]string{"anna", "read-only"})
				e.conf.ApiServer.AppClients = []string{"anna"}
			} else {
				writeAccess(t, path, pins, false, [2]string{"anna", "read-write"})
				e.conf.ApiServer.AppClients = nil
			}
			e.conf.reloadApiAccess()
			published.Add(1)
		}
	}()
	const wantSeen = 4 // read-only, read-write, read-only, read-write
	deadline := time.Now().Add(20 * time.Second)
	seen, lastApp := 0, false
	for i := 0; i < 2000 || seen < wantSeen; i++ {
		id, status, msg := req()
		if status != 0 {
			t.Errorf("request %d refused (%d %q): every policy authenticates anna", i, status, msg)
			break
		}
		if id.App != (id.Role == RoleReadOnly) {
			t.Errorf("a request saw role %s with App=%v: a list and a file of different reloads", id.Role, id.App)
			break
		}
		if id.App != lastApp {
			seen++
			lastApp = id.App
		}
		if seen < wantSeen && time.Now().After(deadline) {
			t.Errorf("after %d requests and %d policies published, the requests saw %d policy changes, want %d",
				i+1, published.Load(), seen, wantSeen)
			break
		}
		if seen < wantSeen && i%100 == 99 {
			runtime.Gosched() // let the writer publish the next policy
		}
	}
	stop.Store(true)
	wg.Wait()
}

// A daemon with no access file in force has no application clients. When a
// reload brings an access file and app-clients together, and the file does
// not load, the reply says that app-clients is not applied either, and the
// running policy (none) stays as it was. The same after a start whose file
// did not load.
func TestAppClientsNoteWhenTheFirstAccessFileDoesNotLoad(t *testing.T) {
	certs, _ := clientCerts(t, "anna")
	e := newAuthEnv(t, "-", certs)
	h := e.conf.Internal.ApiAccess
	e.conf.ApiServer.AccessFile = filepath.Join(t.TempDir(), "absent.yaml")
	e.conf.ApiServer.AppClients = []string{"anna"}
	msg := e.conf.reloadApiAccess()
	if !strings.Contains(msg, "(the running policy is unchanged)") || !strings.Contains(msg, "app-clients is NOT applied either") {
		t.Errorf("a first access file that does not load, with app-clients: %q", msg)
	}
	if st := h.load(); st == nil || st.Enabled || len(st.AppClients) != 0 {
		t.Errorf("the running policy changed: %+v", st)
	}
	e.conf.ApiServer.AppClients = nil
	if msg := e.conf.reloadApiAccess(); strings.Contains(msg, "app-clients") {
		t.Errorf("no app-clients configured or running, yet the reply says %q", msg)
	}

	// After a start whose file did not load: in force but closed (503),
	// with no application clients.
	broken := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(broken, []byte("clients:\n  - {name: anna, pin: x, role: read-only}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.conf.ApiServer.AccessFile = broken
	e.conf.initApiAccess()
	if st := h.load(); st == nil || !st.Enabled || st.Err == nil {
		t.Fatalf("a start with a broken file: %+v, want the policy closed", st)
	}
	e.conf.ApiServer.AppClients = []string{"anna"}
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "app-clients is NOT applied either") {
		t.Errorf("after a failed start, a reload with app-clients: %q", msg)
	}
}

// apiserver.app-clients names access-file clients, so a name an API owner
// could not spell is a config error.
func TestAppClientsNamesAreChecked(t *testing.T) {
	a := ApiServerConf{AppClients: []string{"provisioner", "two words"}}
	if err := a.validateAccessSettings(); err == nil || !strings.Contains(err.Error(), "app-clients") {
		t.Errorf("a name with a space: %v", err)
	}
	a.AppClients = []string{"provisioner"}
	if err := a.validateAccessSettings(); err != nil {
		t.Errorf("a good name: %v", err)
	}
}

// A plain-text refusal reaches a CLI as an ApiRefusal, and prints as the
// verdict, then the daemon's words, no line over 72 columns after the
// "Error from <daemon>: " prefix.
func TestApiRefusalReport(t *testing.T) {
	ref := &ApiRefusal{Status: 403, Msg: "zone a-rather-long-zone-name.example.: API owner is config, not cert:provisioner\n  an operator grants it with api-owner: cert:provisioner in the config"}
	out := `Error from "tdns-auth": ` + ref.Report()
	lines := strings.Split(out, "\n")
	if lines[0] != `Error from "tdns-auth": refused (HTTP 403):` {
		t.Errorf("first line %q", lines[0])
	}
	for _, l := range lines {
		if len(l) > 72 {
			t.Errorf("line over 72 columns: %q", l)
		}
	}
	if !strings.Contains(out, "an operator grants it with api-owner: cert:provisioner") {
		t.Errorf("the hint is lost: %q", out)
	}
	if got := (&ApiRefusal{Status: 400}).Report(); got != "HTTP 400 from the daemon:\n  Bad Request" {
		t.Errorf("an empty 400: %q", got)
	}
}

// A refusal names the command once: "imr flush", not "imr imr-flush".
func TestApiCommandNameDropsTheRepeatedRouteName(t *testing.T) {
	for _, tc := range []struct{ route, cmd, want string }{
		{"/api/v1/imr", "imr-flush", "imr flush"},
		{"/api/v1/zone", "bump", "zone bump"},
		{"/api/v1/scanner/poll", "status", "scanner poll status"},
		{"/api/v1/config/paths", "", "config paths"},
	} {
		if got := apiCommandName(tc.route, tc.cmd, ""); got != tc.want {
			t.Errorf("apiCommandName(%q, %q) = %q, want %q", tc.route, tc.cmd, got, tc.want)
		}
	}
}

// The same refusal on the primary path (template-provisioned), which
// stages the inline key apart from the secondary path: an application's
// primary add whose inline key exists under another API owner is refused,
// identical secret and all, and leaves no zone.
func TestAppPrimaryAddRefusesAnotherOwnersInlineKey(t *testing.T) {
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	conf, _ := newTestConfigForCores(t)
	conf.Internal.KeyDB = newTestKeyDB(t)
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": dynPrimaryTestTemplate(t.TempDir())})
	if _, err := conf.Internal.KeyDB.TsigKeyMgmt(conf, nil, KeystorePost{SubCommand: "add", TsigKeyname: "theirs.",
		TsigAlgorithm: "hmac-sha256", TsigSecret: b64Secret16, Owner: "cert:other", Creator: "test"}); err != nil {
		t.Fatal(err)
	}
	_, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
		Name: "p2.example", Type: Primary, Template: "dyn-test",
		TsigName: "theirs.", TsigSecret: b64Secret16,
		AppClient: "provisioner", ApiOwner: "cert:provisioner",
	}, true)
	if err == nil || !strings.Contains(err.Error(), "TSIG key theirs. exists and is not a key of API owner cert:provisioner") {
		t.Errorf("an application's primary add with another's key inline: %v, want it refused", err)
	}
	if _, ok := Zones.Get("p2.example."); ok {
		t.Error("the refused primary add left its zone")
	}
}

// An application's add checks its inline TSIG key again under
// templateApplyMu: another application's add that registers the same key
// name and secret after the first check, and before this add takes the
// lock, makes the key that application's, and this add is refused rather
// than attached to it (commitStagedTsigKey takes an identical existing key
// as it is). testHookAddLocking runs that other add in between, on the
// secondary path and on the primary path.
func TestAppAddRechecksTheInlineKeyUnderTheLock(t *testing.T) {
	t.Cleanup(func() { testHookAddLocking = nil })

	ownerTestConf(t)
	testHookAddLocking = func() {
		testHookAddLocking = nil
		theirs := secondaryAdd("theirs.example.")
		theirs.TsigName, theirs.TsigSecret = "race.", b64Secret16
		if resp := postZone(t, theirs, &otherApp); resp.Error {
			t.Fatalf("the other application's add: %s", resp.ErrorMsg)
		}
	}
	mine := secondaryAdd("mine.example.")
	mine.TsigName, mine.TsigSecret = "race.", b64Secret16
	resp := postZone(t, mine, &appCaller)
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "TSIG key race. exists and is not a key of API owner cert:provisioner") {
		t.Errorf("a secondary add whose inline key another application registered meanwhile: %q, want it refused", resp.ErrorMsg)
	}
	if _, ok := Zones.Get("mine.example."); ok {
		t.Error("the refused secondary add left its zone")
	}
	if row, err := getTsigKeystoreByName(Conf.Internal.KeyDB, "race."); err != nil || tsigKeystoreEffectiveOwner(row) != "cert:other" {
		t.Errorf("the key: %+v, %v; want it the other application's", row, err)
	}

	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	conf, _ := newTestConfigForCores(t)
	conf.Internal.KeyDB = newTestKeyDB(t)
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": dynPrimaryTestTemplate(t.TempDir())})
	testHookAddLocking = func() {
		testHookAddLocking = nil
		r, err := conf.Internal.KeyDB.TsigKeyMgmt(conf, nil, KeystorePost{SubCommand: "add", TsigKeyname: "race.",
			TsigAlgorithm: "hmac-sha256", TsigSecret: b64Secret16, Owner: "cert:other", Creator: "inline-zone"})
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplyTsigCacheDelta(conf.Internal.TsigKeyStore, conf.Internal.KeyDB, r.TsigCacheDelta); err != nil {
			t.Fatal(err)
		}
	}
	_, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
		Name: "p3.example", Type: Primary, Template: "dyn-test",
		TsigName: "race.", TsigSecret: b64Secret16,
		AppClient: "provisioner", ApiOwner: "cert:provisioner",
	}, true)
	if err == nil || !strings.Contains(err.Error(), "TSIG key race. exists and is not a key of API owner cert:provisioner") {
		t.Errorf("a primary add whose inline key another application registered meanwhile: %v, want it refused", err)
	}
	if _, ok := Zones.Get("p3.example."); ok {
		t.Error("the refused primary add left its zone")
	}
}

// An application client's update is applied to the zone instance it was
// authorized against, or not at all. While it waits in the update queue its
// zone may be deleted and another application add a zone of the same name:
// the update must not reach that zone. Nor a zone whose removal has
// started, nor one that is no longer the client's. An operator's update
// still goes to the zone of its name.
func TestAppUpdateGoesOnlyToTheZoneItWasAuthorizedFor(t *testing.T) {
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	const name = "race.example."
	const zoneText = `race.example.	3600	IN	SOA	ns1.race.example. hostmaster.race.example. 1 7200 1800 604800 7200
race.example.	3600	IN	NS	ns1.race.example.
ns1.race.example.	3600	IN	A	192.0.2.1
`
	kdb := newTestKeyDB(t)
	kdb.UpdateQ = make(chan UpdateRequest, 4)
	// Each zone of the name at a serial of its own: the journal the KeyDB
	// keeps under the name must see the second zone's serials advance.
	serial := 0
	newZone := func(owner string) *ZoneData {
		serial += 100
		zd := testZone(t, name, strings.Replace(zoneText, " 1 7200", fmt.Sprintf(" %d 7200", serial), 1))
		zd.ZoneType = Primary
		zd.Options = map[ZoneOption]bool{OptAllowApiUpdates: true}
		zd.KeyDB = kdb
		zd.setApiOwner(owner)
		return zd
	}
	hasA := func(zd *ZoneData, ip string) bool {
		od, err := zd.GetOwner("www." + name)
		if err != nil || od == nil {
			return false
		}
		for _, rr := range od.RRtypes.GetOnlyRRSet(dns.TypeA).RRs {
			if a, ok := rr.(*dns.A); ok && a.A.String() == ip {
				return true
			}
		}
		return false
	}
	asApp := context.WithValue(context.Background(), apiIdentityKey{}, appCaller)
	// update sends one addrr through ApiZoneUpdate on zd, the zone the
	// handler resolved and checked, as id (nil: an operator), runs between
	// (the queue wait) once the update is queued, and then applies it.
	update := func(zd *ZoneData, ctx context.Context, ip string, between func()) error {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			_, err := zd.ApiZoneUpdate(ctx, ZonePost{Command: "update", Zone: name, UpdateVerb: VerbAddRR,
				UpdateRRs: []string{"www." + name + " 3600 IN A " + ip}})
			done <- err
		}()
		var ur UpdateRequest
		select {
		case ur = <-kdb.UpdateQ:
		case err := <-done:
			t.Fatalf("the update was not queued: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("the update was not queued")
		}
		between()
		kdb.applyUpdate(context.Background(), ur)
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("no answer to the update")
		}
		return nil
	}

	mine := newZone("cert:provisioner")
	Zones.Set(name, mine)
	if err := update(mine, asApp, "192.0.2.10", func() {}); err != nil || !hasA(mine, "192.0.2.10") {
		t.Fatalf("an update of the own zone: %v", err)
	}

	// Deleted while queued, and re-added by another application.
	theirs := newZone("cert:other")
	err := update(mine, asApp, "192.0.2.11", func() { Zones.Set(name, theirs) })
	if err == nil || !strings.Contains(err.Error(), "was removed or replaced while the update waited") {
		t.Errorf("an update whose zone another application has re-added: %v, want it refused", err)
	}
	if hasA(theirs, "192.0.2.11") || hasA(mine, "192.0.2.11") {
		t.Error("the refused update was applied")
	}

	// The same, at the check under zd.mu (applyZoneUpdate), which a
	// replacement after the updater resolved the zone meets.
	ur := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: name, PreAuthorized: true, AppClient: "provisioner", AppZone: mine,
		Actions: []dns.RR{withdrawalRR(t, "www."+name+" 3600 IN A 192.0.2.12")}}
	if _, _, err := mine.applyZoneUpdate(ur, kdb, func() {}); err == nil || !strings.Contains(err.Error(), "was removed or replaced") {
		t.Errorf("the locked check, with the zone replaced: %v, want it refused", err)
	}

	// Its removal has started (RemoveDynamicZone marks it under zd.mu).
	Zones.Set(name, mine)
	err = update(mine, asApp, "192.0.2.13", func() {
		mine.mu.Lock()
		mine.signalPassRetired = true
		mine.mu.Unlock()
	})
	if err == nil || !strings.Contains(err.Error(), "was removed or replaced") || hasA(mine, "192.0.2.13") {
		t.Errorf("an update of a zone whose removal started: %v, want it refused", err)
	}
	mine.mu.Lock()
	mine.signalPassRetired = false
	mine.mu.Unlock()

	// Handed to another application meanwhile (zone setowner).
	err = update(mine, asApp, "192.0.2.14", func() { mine.setApiOwner("cert:other") })
	if err == nil || !strings.Contains(err.Error(), "not a zone of API owner cert:provisioner") || hasA(mine, "192.0.2.14") {
		t.Errorf("an update of a zone handed over meanwhile: %v, want it refused", err)
	}

	// An operator's update goes to the zone of its name, as before.
	Zones.Set(name, theirs)
	if err := update(mine, context.Background(), "192.0.2.15", func() {}); err != nil || !hasA(theirs, "192.0.2.15") {
		t.Errorf("an operator's update: %v, want it applied to the zone served under the name", err)
	}
}
