/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// The keystore's application table covers the handler: every command
// APIkeystore switches on has an entry, every subcommand of the *KeyMgmt
// function a command calls has one, and nothing listed is gone. So a new
// keystore command or subcommand is refused to application clients until
// someone decides otherwise (design R2).
func TestApiAppKeystoreTableMatchesTheHandlers(t *testing.T) {
	const route = "/api/v1/keystore"
	if got := apiAppScopes[route]["*"]; got != AppBySubCommand {
		t.Fatalf("apiAppScopes[%s][*] = %s, want by subcommand", route, got)
	}
	table := apiAppSubScopes[route]
	_, funcs := parseApiRoutes(t)
	handler := funcs["APIkeystore"]
	if handler == nil {
		t.Fatal("APIkeystore not found")
	}

	// Each command case of the handler, and the *KeyMgmt function it calls.
	mgmt := map[string]string{}
	ast.Inspect(handler, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || sw.Tag == nil || !readsField(sw.Tag, "Command") {
			return true
		}
		for _, st := range sw.Body.List {
			cc, ok := st.(*ast.CaseClause)
			if !ok {
				continue
			}
			fn := ""
			ast.Inspect(cc, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && strings.HasSuffix(sel.Sel.Name, "KeyMgmt") {
					fn = sel.Sel.Name
				}
				return fn == ""
			})
			for _, c := range caseStrings(cc) {
				mgmt[c] = fn
			}
		}
		return false
	})
	if len(mgmt) < 5 {
		t.Fatalf("found only %v in APIkeystore; the parse is broken", mgmt)
	}

	for cmd, fn := range mgmt {
		subs, ok := table[cmd]
		if !ok {
			t.Errorf("keystore command %q has no entry in apiAppSubScopes", cmd)
			continue
		}
		if fn == "" {
			continue // a command with no subcommands: "*" and "" decide
		}
		fd := funcs[fn]
		if fd == nil {
			t.Errorf("%s (keystore %s) not found", fn, cmd)
			continue
		}
		if _, ok := subs["*"]; ok {
			t.Errorf("keystore %s: \"*\" in apiAppSubScopes; list the subcommands of %s instead", cmd, fn)
		}
		have := map[string]bool{}
		for _, s := range switchCases(fd, "SubCommand") {
			have[s] = true
			if _, ok := subs[s]; !ok {
				t.Errorf("keystore %s %s (in %s) has no entry in apiAppSubScopes", cmd, s, fn)
			}
		}
		for s := range subs {
			if !have[s] {
				t.Errorf("apiAppSubScopes lists keystore %s %s, which %s does not have", cmd, s, fn)
			}
		}
	}
	for cmd := range table {
		if _, ok := mgmt[cmd]; !ok {
			t.Errorf("apiAppSubScopes lists keystore %s, which APIkeystore does not have", cmd)
		}
	}

	// Design 4.6, by name.
	for _, tc := range []struct {
		cmd, sub string
		want     AppScope
	}{
		{"tsig-mgmt", "list", AppOwnList}, {"sig0-mgmt", "list", AppOwnList}, {"dnssec-mgmt", "list", AppOwnList},
		{"tsig-mgmt", "bulk-export", AppOwnList}, {"dnssec-mgmt", "export", AppOwnKey},
		{"tsig-mgmt", "add", AppNewKey}, {"sig0-mgmt", "bulk-import", AppNewKey},
		{"dnssec-mgmt", "rollover", AppOwnKey}, {"sig0-mgmt", "setparentstate", AppOwnKey},
		{"list-algorithms", "", AppOpen}, {"list-policies", "", AppOpen},
		{"tsig-mgmt", "setowner", AppRefused}, {"tsig-mgmt", "purge", AppRefused},
		{"dnssec-mgmt", "clear", AppRefused}, {"dnssec-mgmt", "policy-cleanup", AppRefused},
		{"dnssec-mgmt", "purge", AppRefused}, {"dnssec-mgmt", "check", AppRefused},
		{"child-sig0-mgmt", "add", AppRefused}, {"tsig-mgmt", "", AppRefused},
		{"tsig-mgmt", "no-such-subcommand", AppRefused}, {"tsig-mgmt", unknownCommand, AppRefused},
		{" TSIG-MGMT ", " List ", AppOwnList},
	} {
		if got := ApiAppScopeOf(route, tc.cmd, tc.sub); got != tc.want {
			t.Errorf("keystore %q %q: %s, want %s", tc.cmd, tc.sub, got, tc.want)
		}
	}
	for _, r := range []string{"/api/v1/truststore", "/api/v1/dsync-api/credential", "/api/v1/dsync-api/cert-credential"} {
		for _, cmd := range []string{"list-dnskey", "child-sig0-mgmt", "list", "issue", ""} {
			if got := ApiAppScopeOf(r, cmd, "list"); got != AppRefused {
				t.Errorf("%s %q: %s, want refused", r, cmd, got)
			}
		}
	}
}

// The role check learns SubCommand for the keystore, for an application
// client only: what the application table opens needs read-write, the rest
// admin. Every other caller needs admin for all of it, as before.
func TestKeystoreRoleBySubCommand(t *testing.T) {
	for _, tc := range []struct {
		route, cmd, sub string
		app             bool
		want            ApiRole
	}{
		{"/api/v1/keystore", "tsig-mgmt", "list", true, RoleReadWrite},
		{"/api/v1/keystore", "dnssec-mgmt", "export", true, RoleReadWrite},
		{"/api/v1/keystore", "sig0-mgmt", "bulk-import", true, RoleReadWrite},
		{"/api/v1/keystore", "list-algorithms", "", true, RoleReadWrite},
		{"/api/v1/keystore", "tsig-mgmt", "purge", true, RoleAdmin},
		{"/api/v1/keystore", "dnssec-mgmt", "clear", true, RoleAdmin},
		{"/api/v1/keystore", "tsig-mgmt", "", true, RoleAdmin},
		{"/api/v1/keystore", "tsig-mgmt", unknownCommand, true, RoleAdmin},
		{"/api/v1/keystore", unknownCommand, "list", true, RoleAdmin},
		{"/api/v1/keystore", "tsig-mgmt", "list", false, RoleAdmin},
		{"/api/v1/keystore", "list-algorithms", "", false, RoleAdmin},
		{"/api/v1/truststore", "list-dnskey", "", true, RoleAdmin},
		{"/api/v1/zone", "list-zones", "purge", true, RoleReadOnly}, // sub means nothing elsewhere
	} {
		if got := RequiredApiRole(tc.route, tc.cmd, tc.sub, tc.app); got != tc.want {
			t.Errorf("RequiredApiRole(%s, %q, %q, app=%v) = %s, want %s", tc.route, tc.cmd, tc.sub, tc.app, got, tc.want)
		}
	}
	if got := apiCommandName("/api/v1/keystore", "tsig-mgmt", "PURGE"); got != "keystore tsig-mgmt purge" {
		t.Errorf("apiCommandName: %q", got)
	}
}

// peekCommand reads SubCommand from the same single read of the body, the
// way the handler's decoder does; one that is not a string cannot be
// checked.
func TestPeekCommandReadsTheSubCommand(t *testing.T) {
	for _, tc := range []struct{ body, cmd, sub string }{
		{`{"Command":"tsig-mgmt","SubCommand":"list"}`, "tsig-mgmt", "list"},
		{`{"command":"tsig-mgmt","subcommand":"list","SUBCOMMAND":"purge"}`, "tsig-mgmt", "purge"}, // last one wins, as in the handler
		{`{"Command":"tsig-mgmt","SubCommand":5}`, "tsig-mgmt", unknownCommand},
		{`{"Command":"tsig-mgmt","SubCommand":null}`, "tsig-mgmt", ""},
		{`{"Command":"list-algorithms"}`, "list-algorithms", ""},
		{`{"Command":"tsig-mgmt","SubCommand":"list"}{}`, unknownCommand, unknownCommand},
	} {
		r, _ := http.NewRequest(http.MethodPost, "/api/v1/keystore", strings.NewReader(tc.body))
		cmd, sub, _ := peekCommand(r)
		if cmd != tc.cmd || sub != tc.sub {
			t.Errorf("peekCommand(%s) = %q %q, want %q %q", tc.body, cmd, sub, tc.cmd, tc.sub)
		}
		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		if buf.String() != tc.body {
			t.Errorf("peekCommand(%s) left the handler %q", tc.body, buf.String())
		}
	}
}

// keystoreKinds are the zones of scopeZones that carry keys, and one more:
// "gone", a zone served nowhere whose keys an operator kept.
var keystoreKinds = []string{"own", "other", "api", "config", "granted", "gone"}

// keystoreScope sets up scopeZones' zones with a DNSSEC and a SIG(0) key in
// each one and in a zone that is not served, and TSIG keys of four API
// owners: the application's ("mine."), another application's
// ("theirs."), an operator's ("ops.") and the config's ("cfg.").
func keystoreScope(t *testing.T) map[string]string {
	t.Helper()
	z := scopeZones(t)
	z["gone"] = "gone.example."
	kdb := Conf.Internal.KeyDB
	var dks []BulkDnssecKey
	var sks []BulkSig0Key
	for _, kind := range keystoreKinds {
		dks = append(dks, testDnssecKey(t, z[kind], 257))
		sks = append(sks, testBulkSig0Key(t, z[kind]))
	}
	if _, err := kdb.BulkImportDnssec(nil, dks, false); err != nil {
		t.Fatal(err)
	}
	if _, err := kdb.BulkImportSig0(nil, sks, false); err != nil {
		t.Fatal(err)
	}
	addTsigKey(t, "mine.", "cert:provisioner")
	addTsigKey(t, "theirs.", "cert:other")
	addTsigKey(t, "ops.", ApiOwnerApi)
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{Keyname: "cfg.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "config"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return z
}

// postKeystore sends kp to the /keystore handler as id (nil: no identity),
// and returns the answer and its raw body.
func postKeystore(t *testing.T, kp KeystorePost, id *ApiIdentity) (KeystoreResponse, string) {
	t.Helper()
	rec := postAs(t, Conf.Internal.KeyDB.APIkeystore(&Conf), http.MethodPost, "/api/v1/keystore", kp, id)
	var resp KeystoreResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v\n%s", err, rec.Body.String())
	}
	return resp, rec.Body.String()
}

// keyZones are the zones of the SIG(0) or DNSSEC keys in a list answer.
func keyZones(resp KeystoreResponse) (sig0, dnssec []string) {
	for _, k := range resp.Sig0keys {
		sig0 = append(sig0, k.Name)
	}
	for _, k := range resp.Dnskeys {
		dnssec = append(dnssec, k.Name)
	}
	sort.Strings(sig0)
	sort.Strings(dnssec)
	return sig0, dnssec
}

// keyCount is the number of key rows of table (DnssecKeyStore,
// Sig0KeyStore) stored under zone. A failed read fails the test, so that a
// count of zero is a count.
func keyCount(t *testing.T, table, zone string) int {
	t.Helper()
	var n int
	if err := Conf.Internal.KeyDB.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE zonename=?`, zone).Scan(&n); err != nil {
		t.Fatalf("counting the keys of %s in %s: %v", zone, table, err)
	}
	return n
}

func zoneKeyID(t *testing.T, kind, zone string) uint16 {
	t.Helper()
	q := `SELECT keyid FROM DnssecKeyStore WHERE zonename=?`
	if kind == "sig0" {
		q = `SELECT keyid FROM Sig0KeyStore WHERE zonename=?`
	}
	var id int
	if err := Conf.Internal.KeyDB.QueryRow(q, zone).Scan(&id); err != nil {
		t.Fatalf("%s key of %s: %v", kind, zone, err)
	}
	return uint16(id)
}

// The lists show an application client its own keys only: TSIG keys of
// its API owner, the SIG(0) and DNSSEC keys of its zones (the granted
// config-file zone's included). They show no secret and no private key,
// and carry the API owner. Another application sees its own; the socket
// sees them all. list-algorithms and list-policies are open.
func TestAppKeystoreListsShowOwnKeysOnly(t *testing.T) {
	z := keystoreScope(t)
	mine := []string{z["granted"], z["own"]}
	sort.Strings(mine)

	tsig, body := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "list"}, &appCaller)
	if tsig.Error || len(tsig.TsigKeys) != 1 || tsig.TsigKeys[0].Name != "mine." || tsig.TsigKeys[0].Owner != "cert:provisioner" {
		t.Errorf("tsig list for the application: %q %+v, want mine. alone", tsig.ErrorMsg, tsig.TsigKeys)
	}
	if strings.Contains(body, b64Secret16) {
		t.Errorf("tsig list shows a secret: %s", body)
	}
	for _, cmd := range []string{"sig0-mgmt", "dnssec-mgmt"} {
		resp, body := postKeystore(t, KeystorePost{Command: cmd, SubCommand: "list"}, &appCaller)
		sig0, dnssec := keyZones(resp)
		got := append(sig0, dnssec...)
		if resp.Error || strings.Join(got, " ") != strings.Join(mine, " ") {
			t.Errorf("%s list for the application: %q %v, want %v", cmd, resp.ErrorMsg, got, mine)
		}
		if strings.Contains(body, "PRIVATE KEY") {
			t.Errorf("%s list shows a private key", cmd)
		}
		for _, k := range resp.Sig0keys {
			if k.ApiOwner != "cert:provisioner" || k.PrivateKey != "-***-" {
				t.Errorf("%s list row %s: owner %q private %q", cmd, k.Name, k.ApiOwner, k.PrivateKey)
			}
		}
		for _, k := range resp.Dnskeys {
			if k.ApiOwner != "cert:provisioner" || k.PrivateKey != "-***-" {
				t.Errorf("%s list row %s: owner %q private %q", cmd, k.Name, k.ApiOwner, k.PrivateKey)
			}
		}
	}

	other, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "list"}, &otherApp)
	if _, d := keyZones(other); strings.Join(d, " ") != z["other"] {
		t.Errorf("dnssec list for the other application: %v", d)
	}
	if theirs, _ := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "list"}, &otherApp); len(theirs.TsigKeys) != 1 || theirs.TsigKeys[0].Name != "theirs." {
		t.Errorf("tsig list for the other application: %+v", theirs.TsigKeys)
	}
	all, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "list"}, &socketCaller)
	if _, d := keyZones(all); len(d) != len(keystoreKinds) {
		t.Errorf("dnssec list on the socket: %v, want all %d", d, len(keystoreKinds))
	}
	if all, _ := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "list"}, &socketCaller); len(all.TsigKeys) != 4 {
		t.Errorf("tsig list on the socket: %+v, want all 4", all.TsigKeys)
	}

	for _, cmd := range []string{"list-algorithms", "list-policies"} {
		if resp, _ := postKeystore(t, KeystorePost{Command: cmd}, &appCaller); resp.Error {
			t.Errorf("%s for the application: %s", cmd, resp.ErrorMsg)
		}
	}
}

// captureApiLog swaps lgApi for one writing into a buffer.
func captureApiLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := lgApi
	lgApi = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	t.Cleanup(func() { lgApi = prev })
	return &buf
}

// export: the private keys of an application's own zones, DNSSEC included
// (design 4.6, decision 3), each export logged with the client and the key
// (R9). Another's key, an operator's, the config's and a key of a zone not
// served here are not handed out, and read like a key of its own zone that
// does not exist: one status and one answer, but for the zone and key ID it
// names. A TSIG key of another API owner reads like one that does not exist.
func TestAppKeystoreExportsOwnKeysOnly(t *testing.T) {
	z := keystoreScope(t)
	logbuf := captureApiLog(t)
	for _, kind := range []string{"sig0", "dnssec"} {
		cmd := kind + "-mgmt"
		for _, zk := range []string{"own", "granted"} {
			id := zoneKeyID(t, kind, z[zk])
			resp, body := postKeystore(t, KeystorePost{Command: cmd, SubCommand: "export", Zone: z[zk], Keyid: id}, &appCaller)
			if resp.Error || !strings.Contains(body, "PRIVATE KEY") {
				t.Errorf("%s export of the %s zone's key: %q, want the private key", kind, zk, resp.ErrorMsg)
			}
			want := "kind=" + kind + " zone=" + z[zk] + " keyid=" + itoa(int(id))
			if log := logbuf.String(); !strings.Contains(log, "private key exported") || !strings.Contains(log, "client=provisioner") || !strings.Contains(log, want) {
				t.Errorf("%s export of the %s zone's key is not logged with %q:\n%s", kind, zk, want, log)
			}
		}
		// The answer to each, with its zone and key ID taken out.
		answer := func(zone string, keyid uint16) string {
			t.Helper()
			rec := postAs(t, Conf.Internal.KeyDB.APIkeystore(&Conf), http.MethodPost, "/api/v1/keystore",
				KeystorePost{Command: cmd, SubCommand: "export", Zone: zone, Keyid: keyid}, &appCaller)
			var resp KeystoreResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decoding response: %v\n%s", err, rec.Body.String())
			}
			if !resp.Error || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
				t.Errorf("%s export of %s keyid %d: %q, want no key handed out", kind, zone, keyid, resp.ErrorMsg)
			}
			msg := strings.ReplaceAll(resp.ErrorMsg, zone, "ZONE")
			msg = strings.ReplaceAll(msg, itoa(int(keyid)), "KEYID")
			return fmt.Sprintf("%d %s %q", rec.Code, msg, resp.Msg)
		}
		want := answer(z["own"], 4711) // no such key in its own zone
		if !strings.Contains(want, "not found") {
			t.Errorf("%s export of a missing key of its own zone: %s", kind, want)
		}
		for _, zk := range []string{"other", "api", "config", "gone", "missing"} {
			id := uint16(4711)
			if zk != "missing" {
				id = zoneKeyID(t, kind, z[zk])
			}
			if got := answer(z[zk], id); got != want {
				t.Errorf("%s export of the %s zone's key: %s, but a missing key of its own zone: %s", kind, zk, got, want)
			}
		}
		if resp, _ := postKeystore(t, KeystorePost{Command: cmd, SubCommand: "export", Zone: z["other"], Keyid: zoneKeyID(t, kind, z["other"])}, &socketCaller); resp.Error {
			t.Errorf("%s export on the socket: %s", kind, resp.ErrorMsg)
		}
	}

	if resp, _ := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "export", TsigKeyname: "mine."}, &appCaller); resp.Error || resp.TsigExport == nil || resp.TsigExport.Secret != b64Secret16 {
		t.Errorf("tsig export of the own key: %q", resp.ErrorMsg)
	}
	if !strings.Contains(logbuf.String(), "TSIG secret exported") {
		t.Errorf("the TSIG export is not logged:\n%s", logbuf.String())
	}
	theirs, _ := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "export", TsigKeyname: "theirs."}, &appCaller)
	nokey, _ := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "export", TsigKeyname: "nokey."}, &appCaller)
	if !theirs.Error || theirs.TsigExport != nil || !sameModuloName(theirs.ErrorMsg, "theirs.", nokey.ErrorMsg, "nokey.") {
		t.Errorf("tsig export of another's key: %q, of none %q; want the same answer", theirs.ErrorMsg, nokey.ErrorMsg)
	}
	for _, name := range []string{"ops.", "cfg."} {
		if resp, _ := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "export", TsigKeyname: name}, &appCaller); !resp.Error || resp.TsigExport != nil {
			t.Errorf("tsig export of %s: %+v", name, resp)
		}
	}
}

// bulk-export returns an application client's own keys only, whatever its
// selectors match: a subtree over every zone gives its own, and an exact
// name of another's zone gives nothing. Every key exported is logged.
func TestAppKeystoreBulkExportReturnsOwnKeysOnly(t *testing.T) {
	z := keystoreScope(t)
	logbuf := captureApiLog(t)
	mine := []string{z["granted"], z["own"]}
	sort.Strings(mine)
	for _, cmd := range []string{"sig0-mgmt", "dnssec-mgmt"} {
		for _, sel := range []KeystorePost{
			{},
			{SelectSubtree: []string{"example."}},
			{SelectExact: []string{z["own"], z["other"], z["api"], z["config"], z["granted"], z["gone"]}},
		} {
			sel.Command, sel.SubCommand = cmd, "bulk-export"
			resp, _ := postKeystore(t, sel, &appCaller)
			var got []string
			for _, k := range resp.BulkSig0Keys {
				got = append(got, k.Zone)
			}
			for _, k := range resp.BulkDnssecKeys {
				got = append(got, k.Zone)
				if !strings.Contains(k.PrivateKey, "PRIVATE KEY") {
					t.Errorf("%s bulk-export: %s without its private key", cmd, k.Zone)
				}
			}
			sort.Strings(got)
			if resp.Error || strings.Join(got, " ") != strings.Join(mine, " ") {
				t.Errorf("%s bulk-export %v %v: %q %v, want %v", cmd, sel.SelectExact, sel.SelectSubtree, resp.ErrorMsg, got, mine)
			}
		}
		resp, _ := postKeystore(t, KeystorePost{Command: cmd, SubCommand: "bulk-export", SelectExact: []string{z["other"]}}, &appCaller)
		if resp.Error || len(resp.BulkSig0Keys)+len(resp.BulkDnssecKeys) != 0 {
			t.Errorf("%s bulk-export of another's zone: %q %d key(s), want none", cmd, resp.ErrorMsg, len(resp.BulkSig0Keys)+len(resp.BulkDnssecKeys))
		}
		all, _ := postKeystore(t, KeystorePost{Command: cmd, SubCommand: "bulk-export"}, &socketCaller)
		if n := len(all.BulkSig0Keys) + len(all.BulkDnssecKeys); n != len(keystoreKinds) {
			t.Errorf("%s bulk-export on the socket: %d key(s), want %d", cmd, n, len(keystoreKinds))
		}
	}
	if n := strings.Count(logbuf.String(), "client=provisioner"); n != 3*2*2 {
		t.Errorf("logged %d exports by the application, want one per key (12):\n%s", n, logbuf.String())
	}
	resp, _ := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "bulk-export"}, &appCaller)
	if len(resp.BulkTsigKeys) != 1 || resp.BulkTsigKeys[0].Keyname != "mine." {
		t.Errorf("tsig bulk-export for the application: %+v", resp.BulkTsigKeys)
	}
}

// add and generate of SIG(0) and DNSSEC keys: the zone must be the
// application's own (design 4.7); in another's, an operator's, the
// config's or a zone not served, nothing is added.
func TestAppKeystoreAddsKeysToOwnZonesOnly(t *testing.T) {
	z := keystoreScope(t)
	count := func(table, zone string) int { return keyCount(t, table, zone) }
	for _, kind := range []string{"other", "api", "config", "gone", "missing"} {
		zone := z[kind]
		before := count("Sig0KeyStore", zone) + count("DnssecKeyStore", zone)
		gen, _ := postKeystore(t, KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: zone, Algorithm: 15, State: "created"}, &appCaller)
		dgen, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "generate", Zone: zone, Algorithm: 15, KeyType: "ZSK"}, &appCaller)
		sk := testBulkSig0Key(t, zone)
		pkc, err := PrepareKeyCache(sk.PrivateKey, sk.KeyRR)
		if err != nil {
			t.Fatal(err)
		}
		add, _ := postKeystore(t, KeystorePost{Command: "sig0-mgmt", SubCommand: "add", Zone: z["own"], PrivateKeyCache: pkc, State: "created"}, &appCaller)
		dk := testDnssecKey(t, zone, 256)
		dpkc, err := PrepareKeyCache(dk.PrivateKey, dk.KeyRR)
		if err != nil {
			t.Fatal(err)
		}
		dadd, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "add", Zone: z["own"], PrivateKeyCache: dpkc, State: "created"}, &appCaller)
		for what, resp := range map[string]KeystoreResponse{"sig0 generate": gen, "dnssec generate": dgen, "sig0 add": add, "dnssec add": dadd} {
			if !resp.Error || !refusedForApp(resp.ErrorMsg) {
				t.Errorf("%s in the %s zone: %q, want an API owner refusal", what, kind, resp.ErrorMsg)
			}
		}
		if after := count("Sig0KeyStore", zone) + count("DnssecKeyStore", zone); after != before {
			t.Errorf("refused adds in the %s zone left %d key(s), had %d", kind, after, before)
		}
	}
	if resp, _ := postKeystore(t, KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z["own"], Algorithm: 15, State: "created"}, &appCaller); resp.Error {
		t.Errorf("sig0 generate in the own zone: %s", resp.ErrorMsg)
	}
	sk := testBulkSig0Key(t, z["granted"])
	pkc, err := PrepareKeyCache(sk.PrivateKey, sk.KeyRR)
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := postKeystore(t, KeystorePost{Command: "sig0-mgmt", SubCommand: "add", PrivateKeyCache: pkc, State: "created"}, &appCaller); resp.Error {
		t.Errorf("sig0 add in the granted zone: %s", resp.ErrorMsg)
	}
	if n := count("Sig0KeyStore", z["own"]); n != 2 {
		t.Errorf("the own zone has %d SIG(0) keys, want 2", n)
	}
	if resp, _ := postKeystore(t, KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z["other"], Algorithm: 15, State: "created"}, &socketCaller); resp.Error {
		t.Errorf("sig0 generate in another's zone on the socket: %s", resp.ErrorMsg)
	}
}

// setstate, setparentstate, rollover and delete act on the application's
// own keys only. A SIG(0) delete may name its zone twice (Zone and
// Keyname): both must be the application's.
func TestAppKeystoreKeyCommandsOnOwnKeysOnly(t *testing.T) {
	z := keystoreScope(t)
	sig0 := func(sub, kind string) KeystorePost {
		return KeystorePost{Command: "sig0-mgmt", SubCommand: sub, Zone: z[kind], Keyname: z[kind],
			Keyid: zoneKeyID(t, "sig0", z[kind]), State: Sig0StateRetired, ParentState: 1}
	}
	dnssec := func(sub, kind string) KeystorePost {
		return KeystorePost{Command: "dnssec-mgmt", SubCommand: sub, Zone: z[kind], Keyname: z[kind],
			Keyid: zoneKeyID(t, "dnssec", z[kind]), State: DnskeyStateRetired, KeyType: "KSK"}
	}
	for _, kind := range []string{"other", "api", "config", "gone"} {
		for _, kp := range []KeystorePost{
			sig0("setstate", kind), sig0("setparentstate", kind), sig0("delete", kind),
			dnssec("setstate", kind), dnssec("rollover", kind), dnssec("delete", kind),
		} {
			if resp, _ := postKeystore(t, kp, &appCaller); !resp.Error || !refusedForApp(resp.ErrorMsg) {
				t.Errorf("%s %s on the %s zone's key: %q, want an API owner refusal", kp.Command, kp.SubCommand, kind, resp.ErrorMsg)
			}
		}
		var state string
		Conf.Internal.KeyDB.QueryRow(`SELECT state FROM Sig0KeyStore WHERE zonename=?`, z[kind]).Scan(&state)
		if state != Sig0StateActive {
			t.Errorf("the %s zone's SIG(0) key is %q after refused commands", kind, state)
		}
	}

	// Zone naming the own zone and Keyname another's: refused, as two
	// names for one key (keyWriteZone), and neither key goes.
	split := sig0("delete", "own")
	split.Keyname = z["other"]
	ownID, otherID := zoneKeyID(t, "sig0", z["own"]), zoneKeyID(t, "sig0", z["other"])
	if resp, _ := postKeystore(t, split, &appCaller); !resp.Error || !strings.Contains(resp.ErrorMsg, "but the request names zone") {
		t.Errorf("sig0 delete with Keyname in another's zone: %q, want refused", resp.ErrorMsg)
	}
	// zoneKeyID fails the test when the row is gone.
	if zoneKeyID(t, "sig0", z["own"]) != ownID || zoneKeyID(t, "sig0", z["other"]) != otherID {
		t.Error("a refused sig0 delete changed a zone's SIG(0) key")
	}

	// setstate checks the key by Keyname and add by its DNSKEY, and the
	// gate checks Zone: an own key with someone else's Zone is refused, and
	// nothing changes.
	for _, kind := range []string{"other", "api", "config", "gone"} {
		mixed := dnssec("setstate", "own")
		mixed.Zone = z[kind]
		if resp, _ := postKeystore(t, mixed, &appCaller); !resp.Error || !refusedForApp(resp.ErrorMsg) {
			t.Errorf("dnssec setstate of an own key naming the %s zone: %q, want refused", kind, resp.ErrorMsg)
		}
		dk := testDnssecKey(t, z["own"], 256)
		dpkc, err := PrepareKeyCache(dk.PrivateKey, dk.KeyRR)
		if err != nil {
			t.Fatal(err)
		}
		add := KeystorePost{Command: "dnssec-mgmt", SubCommand: "add", Zone: z[kind], PrivateKeyCache: dpkc, State: DnskeyStateCreated}
		if resp, _ := postKeystore(t, add, &appCaller); !resp.Error || !refusedForApp(resp.ErrorMsg) {
			t.Errorf("dnssec add of an own-zone key naming the %s zone: %q, want refused", kind, resp.ErrorMsg)
		}
	}
	var ownState string
	Conf.Internal.KeyDB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, z["own"], zoneKeyID(t, "dnssec", z["own"])).Scan(&ownState)
	if ownState == DnskeyStateRetired {
		t.Error("a refused setstate with another's Zone changed the own key's state")
	}

	for _, kp := range []KeystorePost{sig0("setstate", "own"), sig0("setparentstate", "own"), sig0("delete", "granted"), dnssec("setstate", "own")} {
		if resp, _ := postKeystore(t, kp, &appCaller); resp.Error {
			t.Errorf("%s %s on an own key: %s", kp.Command, kp.SubCommand, resp.ErrorMsg)
		}
	}
	if resp, _ := postKeystore(t, sig0("setstate", "other"), &socketCaller); resp.Error {
		t.Errorf("sig0 setstate of another's key on the socket: %s", resp.ErrorMsg)
	}
}

// The keystore commands that act across API owners are refused to an
// application client by the handler too, not only by the middleware.
func TestAppKeystoreRefusesCommandsAcrossOwners(t *testing.T) {
	z := keystoreScope(t)
	for _, kp := range []KeystorePost{
		{Command: "tsig-mgmt", SubCommand: "setowner", TsigKeyname: "theirs.", Owner: "cert:provisioner"},
		{Command: "tsig-mgmt", SubCommand: "purge", Force: true},
		{Command: "dnssec-mgmt", SubCommand: "clear", Zone: z["own"]},
		{Command: "dnssec-mgmt", SubCommand: "policy-cleanup", Zone: z["own"]},
		{Command: "dnssec-mgmt", SubCommand: "purge", Zone: z["own"], Force: true},
		{Command: "dnssec-mgmt", SubCommand: "check"},
		{Command: "child-sig0-mgmt", SubCommand: "list"},
	} {
		resp, _ := postKeystore(t, kp, &appCaller)
		if !resp.Error || !strings.Contains(resp.ErrorMsg, "not available to application clients") {
			t.Errorf("%s %s: %q, want refused", kp.Command, kp.SubCommand, resp.ErrorMsg)
		}
	}
	row, err := getTsigKeystoreByName(Conf.Internal.KeyDB, "theirs.")
	if err != nil || row.Owner != "cert:other" {
		t.Errorf("theirs. after a refused setowner: %v %q", err, row.Owner)
	}
}

// TSIG keys (design 4.7): a new key is the application's whatever owner the
// request names; an identical key of another API owner is a no-op that
// keeps its owner, and says so; another secret under such a name is
// refused, force or not. delete and export of another's key read like a
// key that does not exist; delete of an own key keeps the rule that a key
// in use stays.
func TestAppKeystoreTsigKeys(t *testing.T) {
	keystoreScope(t)
	owner := func(name string) string {
		t.Helper()
		row, err := getTsigKeystoreByName(Conf.Internal.KeyDB, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return row.Owner
	}
	tsig := func(sub, name, secret string, force bool) KeystorePost {
		return KeystorePost{Command: "tsig-mgmt", SubCommand: sub, TsigKeyname: name, TsigAlgorithm: "hmac-sha256",
			TsigSecret: secret, Owner: ApiOwnerApi, Force: force}
	}
	other16 := "QUJDREVGR0hJSktMTU5PUA=="

	if resp, _ := postKeystore(t, tsig("add", "new.", b64Secret16, false), &appCaller); resp.Error || owner("new.") != "cert:provisioner" {
		t.Errorf("add of a new key naming owner api: %q, owner %q, want cert:provisioner", resp.ErrorMsg, owner("new."))
	}
	if resp, _ := postKeystore(t, tsig("generate", "gen.", "", false), &appCaller); resp.Error || owner("gen.") != "cert:provisioner" {
		t.Errorf("generate: %q, owner %q", resp.ErrorMsg, owner("gen."))
	}
	resp, _ := postKeystore(t, tsig("add", "theirs.", b64Secret16, false), &appCaller)
	if resp.Error || !strings.Contains(resp.Msg, "unchanged") || !strings.Contains(resp.Msg, "API owner stays") || owner("theirs.") != "cert:other" {
		t.Errorf("add of an identical key of another owner: %q %q, owner %q", resp.ErrorMsg, resp.Msg, owner("theirs."))
	}
	for _, name := range []string{"theirs.", "ops.", "cfg."} {
		resp, _ := postKeystore(t, tsig("add", name, other16, true), &appCaller)
		row, _ := getTsigKeystoreByName(Conf.Internal.KeyDB, name)
		if !resp.Error || !strings.Contains(resp.ErrorMsg, "not a key of API owner cert:provisioner") || row.Secret != b64Secret16 {
			t.Errorf("forced add of another secret under %s: %q, secret now %q", name, resp.ErrorMsg, row.Secret)
		}
	}
	if resp, _ := postKeystore(t, tsig("add", "new.", other16, true), &appCaller); resp.Error {
		t.Errorf("forced add of another secret under an own key: %s", resp.ErrorMsg)
	}

	del := func(name string) KeystoreResponse {
		resp, _ := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "delete", TsigKeyname: name}, &appCaller)
		return resp
	}
	theirs, nokey := del("theirs."), del("nokey.")
	if !theirs.Error || !sameModuloName(theirs.ErrorMsg, "theirs.", nokey.ErrorMsg, "nokey.") {
		t.Errorf("delete of another's key: %q, of none %q; want the same answer", theirs.ErrorMsg, nokey.ErrorMsg)
	}
	for _, name := range []string{"theirs.", "ops.", "cfg."} {
		if _, err := getTsigKeystoreByName(Conf.Internal.KeyDB, name); err != nil {
			t.Errorf("%s gone after a refused delete: %v", name, err)
		}
	}
	if resp := del("mine."); resp.Error {
		t.Errorf("delete of an own key: %s", resp.ErrorMsg)
	}
}

// tsig import (a bind or nsd file) by an application client: new keys are
// its own; an identical key of another owner is unchanged and keeps its
// owner; another secret under such a name is refused with the reason,
// force or not, while the rest are imported.
func TestAppKeystoreTsigImport(t *testing.T) {
	keystoreScope(t)
	other16 := "QUJDREVGR0hJSktMTU5PUA=="
	data := `key "fresh." { algorithm hmac-sha256; secret "` + b64Secret16 + `"; };
key "theirs." { algorithm hmac-sha256; secret "` + b64Secret16 + `"; };
key "ops." { algorithm hmac-sha256; secret "` + other16 + `"; };`
	resp, _ := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "import", TsigImportFormat: "bind",
		TsigImportData: data, Owner: ApiOwnerApi, Force: true}, &appCaller)
	got := map[string]TsigKeyDisposition{}
	for _, d := range resp.TsigImport {
		got[d.Name] = d
	}
	if got["fresh."].Status != "imported" || got["theirs."].Status != "unchanged" || got["ops."].Status != TsigImportRefused ||
		!strings.Contains(got["ops."].Detail, "not a key of API owner cert:provisioner") {
		t.Errorf("import dispositions: %+v", resp.TsigImport)
	}
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "1 key(s) refused") {
		t.Errorf("import with a refused key: error=%v %q", resp.Error, resp.ErrorMsg)
	}
	for name, want := range map[string]string{"fresh.": "cert:provisioner", "theirs.": "cert:other", "ops.": ApiOwnerApi} {
		if row, err := getTsigKeystoreByName(Conf.Internal.KeyDB, name); err != nil || row.Owner != want || row.Secret != b64Secret16 {
			t.Errorf("%s after the import: %v owner %q secret %q", name, err, row.Owner, row.Secret)
		}
	}
}

// bulk-import by an application client, with keys of mixed owners: the
// keys of its own zones (TSIG: new names and its own keys) are imported,
// and every other key is refused, with the reason, whatever force says.
// The TSIG keys it adds are its own, whatever the payload says.
func TestAppKeystoreBulkImportMixedOwners(t *testing.T) {
	z := keystoreScope(t)
	kinds := []string{"own", "granted", "other", "api", "config", "gone", "missing"}
	want := map[string]string{"own": BulkStatusImported, "granted": BulkStatusImported}
	// Each offered key with a key tag other than keystoreScope's key in
	// its zone: one with the same tag would replace that key (force), not
	// add a second, which TestSig0BulkImportMirrorsTheStoredKey covers.
	fixtureTag := func(table, zone string) (uint16, bool) {
		var id int
		err := Conf.Internal.KeyDB.QueryRow(`SELECT keyid FROM `+table+` WHERE zonename=?`, zone).Scan(&id)
		return uint16(id), err == nil
	}
	var dks []BulkDnssecKey
	var sks []BulkSig0Key
	for _, kind := range kinds {
		dtag, dok := fixtureTag("DnssecKeyStore", z[kind])
		dk := testDnssecKey(t, z[kind], 256)
		for dok && dk.Keyid == dtag {
			dk = testDnssecKey(t, z[kind], 256)
		}
		stag, sok := fixtureTag("Sig0KeyStore", z[kind])
		sk := testBulkSig0Key(t, z[kind])
		for sok && sk.Keyid == stag {
			sk = testBulkSig0Key(t, z[kind])
		}
		dks = append(dks, dk)
		sks = append(sks, sk)
	}
	check := func(what string, resp KeystoreResponse) {
		t.Helper()
		if resp.Error || len(resp.BulkDispositions) != len(kinds) {
			t.Fatalf("%s: %q %+v", what, resp.ErrorMsg, resp.BulkDispositions)
		}
		for i, d := range resp.BulkDispositions {
			kind := kinds[i]
			w := want[kind]
			if w == "" {
				w = BulkStatusRefused
			}
			if d.Name != z[kind] || d.Status != w {
				t.Errorf("%s: the %s zone's key: %s %s, want %s", what, kind, d.Name, d.Status, w)
			}
			if w == BulkStatusRefused && d.Detail != "not a zone of API owner cert:provisioner" {
				t.Errorf("%s: the %s zone's refusal says %q", what, kind, d.Detail)
			}
		}
		if !strings.Contains(resp.Msg, "5 REFUSED") {
			t.Errorf("%s: summary %q", what, resp.Msg)
		}
	}
	dresp, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "bulk-import", BulkDnssecKeys: dks, Force: true}, &appCaller)
	check("dnssec bulk-import", dresp)
	sresp, _ := postKeystore(t, KeystorePost{Command: "sig0-mgmt", SubCommand: "bulk-import", BulkSig0Keys: sks, Force: true}, &appCaller)
	check("sig0 bulk-import", sresp)
	for _, kind := range kinds {
		for _, table := range []string{"DnssecKeyStore", "Sig0KeyStore"} {
			n := keyCount(t, table, z[kind])
			wantN := 1 // keystoreScope's
			switch kind {
			case "own", "granted":
				wantN = 2
			case "missing":
				wantN = 0
			}
			if n != wantN {
				t.Errorf("%s: the %s zone has %d key(s), want %d", table, kind, n, wantN)
			}
		}
	}

	other16 := "QUJDREVGR0hJSktMTU5PUA=="
	tsig := []BulkTsigKey{
		{Keyname: "fresh.", Algorithm: "hmac-sha256", Secret: b64Secret16, Owner: ApiOwnerApi, Origin: "config"},
		{Keyname: "mine.", Algorithm: "hmac-sha256", Secret: other16},
		{Keyname: "theirs.", Algorithm: "hmac-sha256", Secret: b64Secret16, Owner: "cert:other", Comment: "differs"},
		{Keyname: "ops.", Algorithm: "hmac-sha256", Secret: other16},
		{Keyname: "cfg.", Algorithm: "hmac-sha256", Secret: other16},
	}
	resp, _ := postKeystore(t, KeystorePost{Command: "tsig-mgmt", SubCommand: "bulk-import", BulkTsigKeys: tsig, Force: true}, &appCaller)
	got := map[string]BulkKeyDisposition{}
	for _, d := range resp.BulkDispositions {
		got[d.Name] = d
	}
	for name, w := range map[string]string{"fresh.": BulkStatusImported, "mine.": BulkStatusReplaced, "theirs.": BulkStatusUnchanged,
		"ops.": BulkStatusRefused, "cfg.": BulkStatusRefused} {
		if got[name].Status != w {
			t.Errorf("tsig bulk-import: %s %s (%s), want %s", name, got[name].Status, got[name].Detail, w)
		}
	}
	for name, w := range map[string][2]string{
		"fresh.":  {"cert:provisioner", b64Secret16},
		"mine.":   {"cert:provisioner", other16},
		"theirs.": {"cert:other", b64Secret16},
		"ops.":    {ApiOwnerApi, b64Secret16},
	} {
		row, err := getTsigKeystoreByName(Conf.Internal.KeyDB, name)
		if err != nil || row.Owner != w[0] || row.Secret != w[1] || row.Origin != "api" {
			t.Errorf("tsig %s after the bulk-import: %v owner %q origin %q secret %q, want %v", name, err, row.Owner, row.Origin, row.Secret, w)
		}
	}
}

// End to end over TLS: an application client's certificate reaches the
// keystore (read-write), its own keys only; a read-only application client
// does not; what acts across owners needs admin and says which command; an
// operator's certificate and the key still need admin for all of it, and
// the socket keeps everything. The truststore stays admin for all.
func TestAppKeystoreOverTheNetwork(t *testing.T) {
	keystoreScope(t)
	certs, pins := clientCerts(t, "provisioner", "reader", "ops")
	access := "keyauth: true\nclients:\n" +
		"  - {name: provisioner, pin: " + pins["provisioner"] + ", role: read-write}\n" +
		"  - {name: reader, pin: " + pins["reader"] + ", role: read-only}\n" +
		"  - {name: ops, pin: " + pins["ops"] + ", role: read-write}\n"
	e := newAuthEnv(t, access, certs)
	e.conf.ApiServer.AppClients = []string{"provisioner", "reader"}
	e.conf.reloadApiAccess()
	e.rtr.HandleFunc("/api/v1/keystore", Conf.Internal.KeyDB.APIkeystore(&Conf)).Methods("POST")
	e.rtr.HandleFunc("/api/v1/truststore", Conf.Internal.KeyDB.APItruststore()).Methods("POST")

	list := `{"Command":"tsig-mgmt","SubCommand":"list"}`
	for _, tc := range []struct {
		name, path, cert string
		key              bool
		body             string
		want             int
		wantBody         string
	}{
		{"an application lists its keys", "/api/v1/keystore", "provisioner", false, list, 200, `"mine."`},
		{"list-algorithms is open", "/api/v1/keystore", "provisioner", false, `{"Command":"list-algorithms"}`, 200, "Algorithms"},
		{"purge needs admin", "/api/v1/keystore", "provisioner", false, `{"Command":"tsig-mgmt","SubCommand":"purge","Force":true}`, 403, "/api/v1/keystore tsig-mgmt purge needs admin"},
		{"clear needs admin", "/api/v1/keystore", "provisioner", false, `{"Command":"dnssec-mgmt","SubCommand":"clear","Zone":"own.example."}`, 403, "dnssec-mgmt clear needs admin"},
		{"an unreadable subcommand", "/api/v1/keystore", "provisioner", false, `{"Command":"tsig-mgmt","SubCommand":7}`, 403, "a subcommand that cannot be read"},
		{"a read-only application", "/api/v1/keystore", "reader", false, list, 403, "tsig-mgmt list needs read-write; reader is read-only"},
		{"an operator's certificate", "/api/v1/keystore", "ops", false, list, 403, "tsig-mgmt list needs admin"},
		{"the key", "/api/v1/keystore", "", true, list, 403, "needs admin"},
		{"the truststore", "/api/v1/truststore", "provisioner", false, `{"Command":"list-dnskey"}`, 403, "needs admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, body := e.call(t, tc.path, tc.cert, tc.key, tc.body)
			if st != tc.want || !strings.Contains(body, tc.wantBody) {
				t.Errorf("%d %q, want %d containing %q", st, body, tc.want, tc.wantBody)
			}
		})
	}
	_, body := e.call(t, "/api/v1/keystore", "provisioner", false, list)
	if strings.Contains(body, `"theirs."`) || strings.Contains(body, `"ops."`) {
		t.Errorf("the application's list shows others' keys: %s", body)
	}
	st, body := e.callSocket(t, "/api/v1/keystore", list)
	if st != 200 || !strings.Contains(body, `"theirs."`) || !strings.Contains(body, `"ops."`) {
		t.Errorf("the socket: %d %s, want every key", st, body)
	}
}

// An export whose commit fails hands out nothing and logs nothing: the
// answer is the error, without the private keys or TSIG secrets that were
// read. One that commits logs each key it hands out, once.
func TestKeystoreExportWhoseCommitFailsHandsOutNothing(t *testing.T) {
	z := keystoreScope(t)
	logbuf := captureApiLog(t)
	exported := func() int {
		return strings.Count(logbuf.String(), `msg="keystore: private key exported"`) +
			strings.Count(logbuf.String(), `msg="keystore: TSIG secret exported"`)
	}
	exports := []KeystorePost{
		{Command: "sig0-mgmt", SubCommand: "export", Zone: z["own"], Keyid: zoneKeyID(t, "sig0", z["own"])},
		{Command: "dnssec-mgmt", SubCommand: "export", Zone: z["own"], Keyid: zoneKeyID(t, "dnssec", z["own"])},
		{Command: "tsig-mgmt", SubCommand: "export", TsigKeyname: "mine."},
		{Command: "sig0-mgmt", SubCommand: "bulk-export"},
		{Command: "dnssec-mgmt", SubCommand: "bulk-export"},
		{Command: "tsig-mgmt", SubCommand: "bulk-export"},
	}

	prev := commitKeystoreTx
	t.Cleanup(func() { commitKeystoreTx = prev })
	commitKeystoreTx = func(tx *Tx) error {
		tx.Rollback()
		return errors.New("injected commit failure")
	}
	for _, id := range []*ApiIdentity{&appCaller, &socketCaller} {
		for _, kp := range exports {
			resp, body := postKeystore(t, kp, id)
			if !resp.Error || !strings.Contains(resp.ErrorMsg, "injected commit failure") {
				t.Errorf("%s %s as %s, commit failing: %q, want the commit's error", kp.Command, kp.SubCommand, id.Name, resp.ErrorMsg)
			}
			if strings.Contains(body, "PRIVATE KEY") || strings.Contains(body, b64Secret16) {
				t.Errorf("%s %s as %s, commit failing, hands out key material: %s", kp.Command, kp.SubCommand, id.Name, body)
			}
		}
	}
	if n := exported(); n != 0 {
		t.Errorf("exports whose commit failed logged %d key(s) as exported:\n%s", n, logbuf.String())
	}

	commitKeystoreTx = prev
	for _, kp := range exports {
		logbuf.Reset()
		resp, _ := postKeystore(t, kp, &socketCaller)
		keys := len(resp.Sig0keys) + len(resp.Dnskeys) + len(resp.BulkSig0Keys) + len(resp.BulkDnssecKeys) + len(resp.BulkTsigKeys)
		if resp.TsigExport != nil {
			keys++
		}
		if resp.Error || keys == 0 || exported() != keys {
			t.Errorf("%s %s: %q, %d key(s) handed out, %d logged; want one line per key",
				kp.Command, kp.SubCommand, resp.ErrorMsg, keys, exported())
		}
	}
}

// A DNSSEC add or setstate changes the zone its key is written under (the
// DNSKEY's owner name; Keyname), and that zone is republished and re-signed
// after the commit, an add whatever state it gives the key. A request whose Zone names another zone is refused
// before anything is written, for an operator too. An empty Zone is the
// written zone's. A SIG(0) delete looks up and deletes one name.
func TestKeystoreWriteZoneDecidesTheRepublish(t *testing.T) {
	z := keystoreScope(t)
	q := make(chan ResignRequest, 16)
	prevQ := Conf.Internal.ResignQ
	Conf.Internal.ResignQ = q
	t.Cleanup(func() { Conf.Internal.ResignQ = prevQ })
	resigned := func() []string {
		var out []string
		for {
			select {
			case r := <-q:
				out = append(out, r.Zd.ZoneName)
				r.Zd.resignQueued.Store(false)
			default:
				sort.Strings(out)
				return out
			}
		}
	}
	gens := func() map[string]uint64 {
		m := map[string]uint64{}
		for _, kind := range []string{"own", "other", "api"} {
			zd, _ := Zones.Get(z[kind])
			m[kind] = zd.signingKeysGen.Load()
		}
		return m
	}
	republished := func(before map[string]uint64) []string {
		var out []string
		for kind, g := range gens() {
			if g != before[kind] {
				out = append(out, kind)
			}
		}
		sort.Strings(out)
		return out
	}
	state := func(zone string) string {
		var s string
		Conf.Internal.KeyDB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, zoneKeyID(t, "dnssec", zone)).Scan(&s)
		return s
	}
	count := func(table, zone string) int { return keyCount(t, table, zone) }
	setstate := func(keyname, zone, st string) KeystorePost {
		return KeystorePost{Command: "dnssec-mgmt", SubCommand: "setstate", Keyname: keyname, Zone: zone,
			Keyid: zoneKeyID(t, "dnssec", z["own"]), State: st}
	}
	resigned()

	// setstate: the key in one zone, Zone naming another.
	before := gens()
	resp, _ := postKeystore(t, setstate(z["own"], z["api"], DnskeyStateRetired), &socketCaller)
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "the key is in zone "+z["own"]+", but the request names zone "+z["api"]) {
		t.Errorf("setstate of an own-zone key naming another zone: %q, want refused", resp.ErrorMsg)
	}
	if s := state(z["own"]); s == DnskeyStateRetired {
		t.Error("the refused setstate changed the key's state")
	}
	if r, p := resigned(), republished(before); len(r)+len(p) != 0 {
		t.Errorf("the refused setstate re-signed %v and republished %v", r, p)
	}

	// setstate with no Zone, and with Zone as the CLI sends it: the key's
	// zone is republished and re-signed.
	for _, zone := range []string{"", z["own"]} {
		before = gens()
		st := DnskeyStateRetired
		if zone != "" {
			st = DnskeyStateActive
		}
		if resp, _ := postKeystore(t, setstate(z["own"], zone, st), &socketCaller); resp.Error {
			t.Fatalf("setstate with Zone %q: %s", zone, resp.ErrorMsg)
		}
		if s := state(z["own"]); s != st {
			t.Errorf("setstate with Zone %q: the key is %q, want %q", zone, s, st)
		}
		if r, p := resigned(), republished(before); strings.Join(r, " ") != z["own"] || strings.Join(p, " ") != "own" {
			t.Errorf("setstate with Zone %q re-signed %v and republished %v, want the own zone", zone, r, p)
		}
	}

	// add: the DNSKEY's owner name is the zone.
	addOf := func(zone string) KeystorePost {
		dk := testDnssecKey(t, z["own"], 256)
		dpkc, err := PrepareKeyCache(dk.PrivateKey, dk.KeyRR)
		if err != nil {
			t.Fatal(err)
		}
		return KeystorePost{Command: "dnssec-mgmt", SubCommand: "add", Zone: zone, PrivateKeyCache: dpkc, State: DnskeyStateActive}
	}
	keys := count("DnssecKeyStore", z["own"])
	before = gens()
	resp, _ = postKeystore(t, addOf(z["other"]), &socketCaller)
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "the DNSKEY's owner name is "+z["own"]+", but the request names zone "+z["other"]) {
		t.Errorf("add of an own-zone DNSKEY naming another zone: %q, want refused", resp.ErrorMsg)
	}
	if n := count("DnssecKeyStore", z["own"]) + count("DnssecKeyStore", z["other"]); n != keys+1 {
		t.Errorf("the refused add left %d key(s) in the two zones, had %d", n, keys+1)
	}
	if p := republished(before); len(p) != 0 {
		t.Errorf("the refused add republished %v", p)
	}
	if r := resigned(); len(r) != 0 {
		t.Errorf("the refused add re-signed %v", r)
	}
	for _, zone := range []string{"", z["own"]} {
		before = gens()
		if resp, _ := postKeystore(t, addOf(zone), &socketCaller); resp.Error {
			t.Fatalf("add with Zone %q: %s", zone, resp.ErrorMsg)
		}
		if r, p := resigned(), republished(before); strings.Join(r, " ") != z["own"] || strings.Join(p, " ") != "own" {
			t.Errorf("add with Zone %q re-signed %v and republished %v, want the own zone", zone, r, p)
		}
	}
	if n := count("DnssecKeyStore", z["own"]); n != keys+2 {
		t.Errorf("the own zone has %d DNSSEC keys after two adds, want %d", n, keys+2)
	}

	// A published key re-imported as active: the served DNSKEYs stay the
	// same, the signing keys change, and the zone is re-signed.
	reimport := addOf(z["own"])
	reimport.State = DnskeyStatePublished
	if resp, _ := postKeystore(t, reimport, &socketCaller); resp.Error {
		t.Fatalf("add of a published key: %s", resp.ErrorMsg)
	}
	resigned()
	reimport.State = DnskeyStateActive
	if resp, _ := postKeystore(t, reimport, &socketCaller); resp.Error {
		t.Fatalf("re-import of the published key as active: %s", resp.ErrorMsg)
	}
	var reState string
	Conf.Internal.KeyDB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, z["own"], reimport.PrivateKeyCache.DnskeyRR.KeyTag()).Scan(&reState)
	if r := resigned(); reState != DnskeyStateActive || strings.Join(r, " ") != z["own"] {
		t.Errorf("re-import of a published key as active: state %q, re-signed %v; want active and the own zone", reState, r)
	}

	// An application is refused another's zone whichever field names it.
	for _, kp := range []KeystorePost{setstate(z["own"], z["other"], DnskeyStateRetired), setstate(z["other"], z["own"], DnskeyStateRetired), addOf(z["other"])} {
		if resp, _ := postKeystore(t, kp, &appCaller); !resp.Error || !refusedForApp(resp.ErrorMsg) {
			t.Errorf("an application's %s naming zone %q, key %q: %q, want an API owner refusal", kp.SubCommand, kp.Zone, kp.Keyname, resp.ErrorMsg)
		}
	}
	other := addOf("")
	other.PrivateKeyCache.DnskeyRR.Hdr.Name = z["other"]
	if resp, _ := postKeystore(t, other, &appCaller); !resp.Error || !refusedForApp(resp.ErrorMsg) {
		t.Errorf("an application's add of another zone's DNSKEY: %q, want an API owner refusal", resp.ErrorMsg)
	}

	// SIG(0) delete: Zone and Keyname naming two zones is refused, and
	// both keys stay; one name alone deletes that key.
	split := KeystorePost{Command: "sig0-mgmt", SubCommand: "delete", Zone: z["own"], Keyname: z["api"], Keyid: zoneKeyID(t, "sig0", z["own"])}
	if resp, _ := postKeystore(t, split, &socketCaller); !resp.Error || !strings.Contains(resp.ErrorMsg, "but the request names zone") {
		t.Errorf("sig0 delete naming two zones: %q, want refused", resp.ErrorMsg)
	}
	if count("Sig0KeyStore", z["own"]) != 1 || count("Sig0KeyStore", z["api"]) != 1 {
		t.Error("the refused sig0 delete deleted a key")
	}
	byZone := KeystorePost{Command: "sig0-mgmt", SubCommand: "delete", Zone: z["own"], Keyid: zoneKeyID(t, "sig0", z["own"])}
	if resp, _ := postKeystore(t, byZone, &socketCaller); resp.Error || count("Sig0KeyStore", z["own"]) != 0 {
		t.Errorf("sig0 delete by Zone alone: %q, %d key(s) left", resp.ErrorMsg, count("Sig0KeyStore", z["own"]))
	}
}

// An application names the zone of every key command: an empty name is
// refused before it can become the root, which an application may own (a
// rollover given no zone would pick keys from every zone). "." still names
// the root. An operator's rollover with no zone is refused too. A SIG(0)
// delete may name its key by Zone or by Keyname alone, and that one name is
// checked.
func TestAppKeyCommandsNeedAZone(t *testing.T) {
	z := keystoreScope(t)
	root := &ZoneData{ZoneName: ".", ZoneType: Primary, Options: map[ZoneOption]bool{}}
	root.fromStaticConfig.Store(true)
	root.setApiOwner("cert:provisioner")
	Zones.Set(".", root)

	states := func() string {
		rows, err := Conf.Internal.KeyDB.Query(`SELECT zonename, keyid, state FROM DnssecKeyStore ORDER BY zonename, keyid`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var zone, state string
			var keyid int
			rows.Scan(&zone, &keyid, &state)
			out = append(out, fmt.Sprintf("%s/%d/%s", zone, keyid, state))
		}
		return strings.Join(out, " ")
	}
	before := states()
	did, sid := zoneKeyID(t, "dnssec", z["own"]), zoneKeyID(t, "sig0", z["own"])
	for _, kp := range []KeystorePost{
		{Command: "dnssec-mgmt", SubCommand: "rollover", KeyType: "KSK"},
		{Command: "dnssec-mgmt", SubCommand: "rollover", KeyType: "ZSK"},
		{Command: "dnssec-mgmt", SubCommand: "generate", Algorithm: 15, KeyType: "ZSK"},
		{Command: "dnssec-mgmt", SubCommand: "export", Keyid: did},
		{Command: "dnssec-mgmt", SubCommand: "delete", Keyid: did},
		{Command: "dnssec-mgmt", SubCommand: "setstate", Keyid: did, State: DnskeyStateRetired},
		{Command: "sig0-mgmt", SubCommand: "generate", Algorithm: 15, State: "created"},
		{Command: "sig0-mgmt", SubCommand: "export", Keyid: sid},
		{Command: "sig0-mgmt", SubCommand: "setstate", Keyid: sid, State: Sig0StateRetired},
		{Command: "sig0-mgmt", SubCommand: "setparentstate", Keyid: sid, ParentState: 1},
		{Command: "sig0-mgmt", SubCommand: "delete", Keyid: sid},
	} {
		if resp, _ := postKeystore(t, kp, &appCaller); !resp.Error || !strings.Contains(resp.ErrorMsg, "no zone named") {
			t.Errorf("%s %s with no zone: %q, want refused for naming no zone", kp.Command, kp.SubCommand, resp.ErrorMsg)
		}
	}
	nozone := testDnssecKey(t, ".", 257)
	nozone.Zone = ""
	bulk, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "bulk-import", BulkDnssecKeys: []BulkDnssecKey{nozone}}, &appCaller)
	if len(bulk.BulkDispositions) != 1 || bulk.BulkDispositions[0].Status != BulkStatusRefused {
		t.Errorf("an application's bulk import of a key with no zone: %q %+v, want it refused", bulk.ErrorMsg, bulk.BulkDispositions)
	}
	if after := states(); after != before {
		t.Errorf("commands naming no zone changed the keys:\n%s\nwas\n%s", after, before)
	}

	// "." names the root zone: past the name check (no root keys to roll).
	if resp, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "rollover", Zone: ".", KeyType: "ZSK"}, &appCaller); !resp.Error ||
		strings.Contains(resp.ErrorMsg, "no zone named") || refusedForApp(resp.ErrorMsg) {
		t.Errorf("rollover of the root zone it owns: %q, want past the zone checks", resp.ErrorMsg)
	}
	if resp, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "rollover", KeyType: "ZSK"}, &socketCaller); !resp.Error || !strings.Contains(resp.ErrorMsg, "rollover: no zone named") {
		t.Errorf("an operator's rollover with no zone: %q, want refused", resp.ErrorMsg)
	}

	// SIG(0) delete by Zone alone, and by Keyname alone.
	byZone := KeystorePost{Command: "sig0-mgmt", SubCommand: "delete", Zone: z["own"], Keyid: sid}
	if resp, _ := postKeystore(t, byZone, &appCaller); resp.Error {
		t.Errorf("an application's sig0 delete by Zone alone: %s", resp.ErrorMsg)
	}
	byName := KeystorePost{Command: "sig0-mgmt", SubCommand: "delete", Keyname: z["granted"], Keyid: zoneKeyID(t, "sig0", z["granted"])}
	if resp, _ := postKeystore(t, byName, &appCaller); resp.Error {
		t.Errorf("an application's sig0 delete by Keyname alone: %s", resp.ErrorMsg)
	}
	if left := keyCount(t, "Sig0KeyStore", z["own"]) + keyCount(t, "Sig0KeyStore", z["granted"]); left != 0 {
		t.Errorf("%d SIG(0) key(s) left after deleting both", left)
	}
	if resp, _ := postKeystore(t, KeystorePost{Command: "sig0-mgmt", SubCommand: "delete", Keyname: z["other"], Keyid: zoneKeyID(t, "sig0", z["other"])}, &appCaller); !resp.Error || !refusedForApp(resp.ErrorMsg) {
		t.Errorf("an application's sig0 delete of another's key by Keyname alone: %q, want refused", resp.ErrorMsg)
	}
}

// Key rows are stored under the zone's canonical name, which the signing
// reads use: a DNSKEY added in upper case reaches the zone's signing keys,
// a SIG(0) key added so is stored in lower case, and setstate given the
// name in upper case finds the key. A row stored in another case before
// writes were canonical can still be changed, exported and deleted.
func TestKeystoreStoresCanonicalZoneNames(t *testing.T) {
	z := keystoreScope(t)
	own := z["own"]
	upper := strings.ToUpper(own)
	zoneOf := func(table string, keyid uint16) string {
		var zone string
		Conf.Internal.KeyDB.QueryRow(`SELECT zonename FROM `+table+` WHERE keyid=?`, int(keyid)).Scan(&zone)
		return zone
	}
	stateOf := func(zone string, keyid uint16) string {
		var state string
		Conf.Internal.KeyDB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, int(keyid)).Scan(&state)
		return state
	}

	dk := testDnssecKey(t, upper, 256)
	dpkc, err := PrepareKeyCache(dk.PrivateKey, dk.KeyRR)
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "add", Zone: upper, PrivateKeyCache: dpkc, State: DnskeyStateActive}, &socketCaller); resp.Error {
		t.Fatalf("add of a DNSKEY owned by %s: %s", upper, resp.ErrorMsg)
	}
	if got := zoneOf("DnssecKeyStore", dk.Keyid); got != own {
		t.Errorf("the DNSKEY added as %s is stored under %q, want %s", upper, got, own)
	}
	zd, _ := Zones.Get(own)
	signs := false
	for _, k := range zd.ActiveDnssecKeys().ZSKs {
		signs = signs || k.KeyId == dk.Keyid
	}
	if !signs {
		t.Errorf("the DNSKEY added as %s is not among %s's signing keys", upper, own)
	}
	if resp, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "setstate", Keyname: upper, Zone: upper, Keyid: dk.Keyid, State: DnskeyStateRetired}, &socketCaller); resp.Error || stateOf(own, dk.Keyid) != DnskeyStateRetired {
		t.Errorf("setstate naming %s: %q, state %q", upper, resp.ErrorMsg, stateOf(own, dk.Keyid))
	}

	sk := testBulkSig0Key(t, upper)
	spkc, err := PrepareKeyCache(sk.PrivateKey, sk.KeyRR)
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := postKeystore(t, KeystorePost{Command: "sig0-mgmt", SubCommand: "add", Zone: upper, PrivateKeyCache: spkc, State: Sig0StateActive}, &socketCaller); resp.Error {
		t.Fatalf("sig0 add of a KEY owned by %s: %s", upper, resp.ErrorMsg)
	}
	if got := zoneOf("Sig0KeyStore", sk.Keyid); got != own {
		t.Errorf("the SIG(0) key added as %s is stored under %q, want %s", upper, got, own)
	}

	// A row stored in mixed case, as before writes were canonical.
	legacyName := "Own.Example."
	legacy := testDnssecKey(t, legacyName, 256)
	tx, err := Conf.Internal.KeyDB.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertKeyRowTx(tx, KeyRow{Zone: legacyName, State: DnskeyStatePublished, Keyid: legacy.Keyid, Flags: 256,
		Algorithm: "ED25519", Creator: "test", PrivateKey: legacy.PrivateKey, KeyRR: legacy.KeyRR}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if resp, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "setstate", Keyname: own, Keyid: legacy.Keyid, State: DnskeyStateStandby}, &socketCaller); resp.Error || stateOf(legacyName, legacy.Keyid) != DnskeyStateStandby {
		t.Errorf("setstate of a key stored as %s: %q, state %q", legacyName, resp.ErrorMsg, stateOf(legacyName, legacy.Keyid))
	}
	if resp, body := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "export", Zone: own, Keyid: legacy.Keyid}, &socketCaller); resp.Error || !strings.Contains(body, "PRIVATE KEY") {
		t.Errorf("export of a key stored as %s: %q", legacyName, resp.ErrorMsg)
	}
	if resp, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "delete", Zone: own, Keyname: own, Keyid: legacy.Keyid}, &socketCaller); resp.Error || stateOf(legacyName, legacy.Keyid) != DnskeyStateRemoved {
		t.Errorf("delete of a key stored as %s: %q, state %q", legacyName, resp.ErrorMsg, stateOf(legacyName, legacy.Keyid))
	}
}

// The keystore handler makes zone names canonical, never a keyword: dnssec
// purge's "all" (any case) still purges every zone, and "all." is the zone
// of that name.
func TestKeystorePurgeAllIsASelector(t *testing.T) {
	z := keystoreScope(t)
	fixture := map[string]uint16{z["own"]: zoneKeyID(t, "dnssec", z["own"]), z["other"]: zoneKeyID(t, "dnssec", z["other"])}
	tx, err := Conf.Internal.KeyDB.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []string{z["own"], z["other"]} {
		used := map[uint16]bool{fixture[zone]: true}
		for n := 0; n < 4; {
			k := testDnssecKey(t, zone, 256)
			if used[k.Keyid] {
				continue
			}
			used[k.Keyid] = true
			if err := insertKeyRowTx(tx, KeyRow{Zone: zone, State: DnskeyStateRemoved, Keyid: k.Keyid, Flags: 256,
				Algorithm: "ED25519", Creator: "test", PrivateKey: k.PrivateKey, KeyRR: k.KeyRR}); err != nil {
				t.Fatal(err)
			}
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// A dry run: what would go, one key per zone beyond the three kept.
	purge := func(zone string) []string {
		t.Helper()
		resp, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "purge", Zone: zone}, &socketCaller)
		if resp.Error {
			t.Fatalf("purge %q: %s", zone, resp.ErrorMsg)
		}
		var zones []string
		for _, k := range resp.Dnskeys {
			zones = append(zones, k.Name)
		}
		sort.Strings(zones)
		return zones
	}
	both := []string{z["other"], z["own"]}
	sort.Strings(both)
	for _, sel := range []string{"all", "ALL", " all "} {
		if got := purge(sel); strings.Join(got, " ") != strings.Join(both, " ") {
			t.Errorf("purge %q would purge in %v, want %v", sel, got, both)
		}
	}
	if got := purge("all."); len(got) != 0 {
		t.Errorf("purge of the zone all. would purge in %v, want nothing", got)
	}
	if got := purge(strings.ToUpper(z["own"])); strings.Join(got, " ") != z["own"] {
		t.Errorf("purge of %s would purge in %v", strings.ToUpper(z["own"]), got)
	}
}

// An add whose commit succeeds and whose signing-key republish then fails
// says so: the row is committed and the answer is an error that says the
// zone does not serve the change yet. The re-sign still goes, and cannot
// sign with the keys from before: the failed republish leaves the snapshot
// unbuilt, so the re-sign reads the keystore, and fails while it cannot.
func TestKeystoreAddReportsAFailedRepublish(t *testing.T) {
	z := keystoreScope(t)
	own := z["own"]
	q := make(chan ResignRequest, 16)
	prevQ := Conf.Internal.ResignQ
	Conf.Internal.ResignQ = q
	t.Cleanup(func() { Conf.Internal.ResignQ = prevQ })

	// A signing row with no private key: the zone's signing keys cannot be
	// loaded until it is fixed.
	broken := testDnssecKey(t, own, 256)
	tx, err := Conf.Internal.KeyDB.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertKeyRowTx(tx, KeyRow{Zone: own, State: DnskeyStateActive, Keyid: broken.Keyid, Flags: 256,
		Algorithm: "ED25519", Creator: "test", KeyRR: broken.KeyRR}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	keys := keyCount(t, "DnssecKeyStore", own)
	dk := testDnssecKey(t, own, 256)
	dpkc, err := PrepareKeyCache(dk.PrivateKey, dk.KeyRR)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := postKeystore(t, KeystorePost{Command: "dnssec-mgmt", SubCommand: "add", Zone: own, PrivateKeyCache: dpkc, State: DnskeyStateActive}, &socketCaller)
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "the change is committed, but the signing keys of zone "+own+" could not be republished") {
		t.Errorf("add whose republish fails: %q, want the failure reported", resp.ErrorMsg)
	}
	if n := keyCount(t, "DnssecKeyStore", own); n != keys+1 {
		t.Errorf("the zone has %d key(s) after the add, want %d: the row is committed", n, keys+1)
	}
	resigned := false
	for len(q) > 0 {
		r := <-q
		resigned = resigned || r.Zd.ZoneName == own
		r.Zd.resignQueued.Store(false)
	}
	if !resigned {
		t.Error("the add did not ask for the zone's re-sign")
	}
	zd, _ := Zones.Get(own)
	if zd.SigningKeys().built {
		t.Error("the failed republish left a built snapshot")
	}
	if _, err := zd.activeKeysCAS(Conf.Internal.KeyDB); err == nil {
		t.Error("the re-sign's keys came from somewhere other than the keystore it cannot read")
	}
	if _, err := Conf.Internal.KeyDB.DB.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, own, int(broken.Keyid)); err != nil {
		t.Fatal(err)
	}
	active, err := zd.activeKeysCAS(Conf.Internal.KeyDB)
	found := false
	for _, k := range active.ZSKs {
		found = found || k.KeyId == dk.Keyid
	}
	if err != nil || !found {
		t.Errorf("once the keystore can be read, the re-sign's keys: %v, the added key among them: %v", err, found)
	}
}
