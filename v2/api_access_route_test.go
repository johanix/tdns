package tdns

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testApiCertFiles writes an API key pair, as the daemon makes at its first
// start, and returns its files and pin.
func testApiCertFiles(t *testing.T) (cert, key, pin string) {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "tdns-auth.yaml")
	pin, _, err := EnsureDefaultApiCert(cfg, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, key = ApiCertPaths(cfg)
	return cert, key, pin
}

// accessCall posts an /access request over e's local socket.
func (e *authEnv) accessCall(t *testing.T, ap AccessPost) AccessResponse {
	t.Helper()
	body, _ := json.Marshal(ap)
	st, out := e.callSocket(t, "/api/v1/access", string(body))
	var resp AccessResponse
	if err := json.Unmarshal([]byte(out), &resp); st != http.StatusOK || err != nil {
		t.Fatalf("/access %s: %d %v %q", ap.Command, st, err, out)
	}
	return resp
}

// The daemon writes into the access file the operator created (touch): a
// change keeps the previous file as .prev and the file's mode, an add that is
// there already writes nothing, a change the validator refuses writes
// nothing, a dry run writes nothing. Each change is in force when /access
// answers, and every answer says what is in force.
func TestAccessRouteWritesTheFile(t *testing.T) {
	certs, pins := clientCerts(t, "anna", "bob", "carl")
	e := newAuthEnv(t, "", certs) // touched: empty
	e.conf.Internal.CfgFile = filepath.Join(filepath.Dir(e.sock), "tdns-auth.yaml")
	path := e.conf.ApiServer.AccessFile
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		t.Helper()
		b, _ := os.ReadFile(path)
		return string(b)
	}
	ok := func(resp AccessResponse, want string) {
		t.Helper()
		if resp.Error || !strings.Contains(resp.Msg, want) {
			t.Errorf("answer %+v, want %q", resp, want)
		}
		if resp.File != path || resp.ConfigFile != e.conf.Internal.CfgFile {
			t.Errorf("answer names file %q and config %q, want %s and %s", resp.File, resp.ConfigFile, path, e.conf.Internal.CfgFile)
		}
	}
	refused := func(ap AccessPost, want string) {
		t.Helper()
		before := read()
		if resp := e.accessCall(t, ap); !resp.Error || !strings.Contains(resp.ErrorMsg, want) {
			t.Errorf("%+v: %+v, want a refusal with %q", ap, resp, want)
		}
		if read() != before {
			t.Errorf("%+v: refused, but the file changed", ap)
		}
	}
	running := func() *accessState { return e.conf.Internal.ApiAccess.load() }

	add := AccessPost{Command: "add", Name: "anna", Pin: pins["anna"], Role: "read-write", Comment: "laptop"}
	resp := e.accessCall(t, add)
	ok(resp, "Added anna (read-write).")
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("written file: %v %v, want the touched file's mode 0644 kept", fi, err)
	}
	if af, err := LoadAccessFile(path); err != nil || len(af.Clients) != 1 || !strings.Contains(read(), "Written by the daemon") || strings.Contains(read(), "keyauth") {
		t.Errorf("written file: %v\n%s", err, read())
	}
	if len(resp.Clients) != 1 || resp.Clients[0].Comment != "laptop" {
		t.Errorf("in force after the add: %+v", resp)
	}
	// config status answers read-only callers too: no comments there.
	if st := e.conf.apiAccessStatus().withoutComments(); st == nil || len(st.Clients) != 1 || st.Clients[0].Name != "anna" || st.Clients[0].Comment != "" {
		t.Errorf("config status: %+v, want anna without her comment", st)
	}
	if c, found := running().byPin[pins["anna"]]; !found || c.Role != "read-write" {
		t.Errorf("anna not in the running policy: %+v", running())
	}

	// The same add again: there already, nothing written.
	before := read()
	ok(e.accessCall(t, add), "already there")
	if read() != before {
		t.Error("an add of what is there rewrote the file")
	}
	refused(AccessPost{Command: "add", Name: "anna", Pin: pins["bob"], Role: "read-write"}, "another pin:\nuse another name")
	refused(AccessPost{Command: "add", Name: "anna", Pin: pins["anna"], Role: "read-only"}, "set-role")
	refused(AccessPost{Command: "add", Name: "an na", Pin: pins["bob"], Role: "read-only"}, "no spaces")
	refused(AccessPost{Command: "add", Name: "bob", Pin: pins["anna"], Role: "read-only"}, "also \"anna\"'s")
	refused(AccessPost{Command: "set-role", Name: "anna", Role: "admin"}, "only on the local socket")
	refused(AccessPost{Command: "disable", Name: "nobody"}, "no client \"nobody\"")
	refused(AccessPost{Command: "keyauth"}, "keyauth is gone")
	refused(AccessPost{Command: "drop"}, "unknown /access command")

	// A change keeps the previous file as .prev, and the file's mode.
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	ok(e.accessCall(t, AccessPost{Command: "add", Name: "bob", Pin: pins["bob"], Role: "read-only"}), "Added bob")
	if prev, err := os.ReadFile(path + ".prev"); err != nil || string(prev) != before {
		t.Errorf(".prev: %v\n%s\nwant the file before bob was added", err, prev)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("changed file: %v %v, want its mode 0640 kept", fi, err)
	}

	ok(e.accessCall(t, AccessPost{Command: "set-role", Name: "bob", Role: "read-write"}), "bob is now read-write")
	ok(e.accessCall(t, AccessPost{Command: "disable", Name: "bob"}), "bob: disabled")
	if !running().byPin[pins["bob"]].Disabled || running().byPin[pins["bob"]].Role != "read-write" {
		t.Errorf("bob in force: %+v, want read-write and disabled", running().byPin[pins["bob"]])
	}
	if st, _ := e.call(t, "/api/v1/ping", "bob", `{}`); st != http.StatusForbidden {
		t.Errorf("disabled bob over TCP: %d, want 403", st)
	}
	ok(e.accessCall(t, AccessPost{Command: "disable", Name: "bob"}), "already disabled")
	ok(e.accessCall(t, AccessPost{Command: "enable", Name: "bob"}), "bob: enabled")

	// A dry run renders, and writes and loads nothing.
	before = read()
	resp = e.accessCall(t, AccessPost{Command: "add", Name: "carl", Pin: pins["carl"], Role: "read-only", DryRun: true})
	if resp.Error || !strings.Contains(resp.Rendered, pins["carl"]) || read() != before {
		t.Errorf("dry run: %+v; want carl rendered, the file unchanged", resp)
	}
	if _, found := running().byPin[pins["carl"]]; found {
		t.Error("a dry run put carl in force")
	}

	resp = e.accessCall(t, AccessPost{Command: "list"})
	if resp.Error || resp.Msg != "In force: 2 client(s)." || len(resp.Clients) != 2 {
		t.Errorf("list: %+v", resp)
	}

	// /access is admin, list included: refused on TCP to a read-write client.
	if st, body := e.call(t, "/api/v1/access", "anna", `{"Command":"list"}`); st != http.StatusForbidden || !strings.Contains(body, "needs admin") {
		t.Errorf("/access over TCP as anna (read-write): %d %q, want 403 needing admin", st, body)
	}
}

// A command that needs no change in the file still loads it: a hand edit
// not yet reloaded is in force when /access answers success.
func TestAccessNoChangeLoadsTheFile(t *testing.T) {
	certs, pins := clientCerts(t, "anna")
	anna := "clients:\n  - {name: anna, pin: " + pins["anna"] + ", role: read-write"
	e := newAuthEnv(t, anna+"}\n", certs)
	running := func() AccessClient { return e.conf.Internal.ApiAccess.load().byPin[pins["anna"]] }
	if running().Disabled {
		t.Fatal("anna is disabled at start")
	}
	if err := os.WriteFile(e.conf.ApiServer.AccessFile, []byte(anna+", disabled: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if resp := e.accessCall(t, AccessPost{Command: "disable", Name: "anna"}); resp.Error || !strings.Contains(resp.Msg, "already disabled") {
		t.Errorf("disable anna: %+v, want already disabled", resp)
	}
	if !running().Disabled {
		t.Error("disable anna answered success, but the running policy has anna enabled")
	}
}

// An access file with the obsolete keyauth: line loads, and the daemon's
// next write drops the line, even when nothing else changes.
func TestAccessDropsTheObsoleteKeyauthLine(t *testing.T) {
	_, pins := clientCerts(t, "anna")
	e := newAuthEnv(t, "keyauth: true\nclients:\n  - {name: anna, pin: "+pins["anna"]+", role: read-write}\n", nil)
	path := e.conf.ApiServer.AccessFile
	if resp := e.accessCall(t, AccessPost{Command: "enable", Name: "anna"}); resp.Error || !strings.Contains(resp.Msg, "already enabled") {
		t.Fatalf("enable anna: %+v", resp)
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "keyauth") {
		t.Errorf("the file after a write:\n%s\nwant the keyauth: line gone", b)
	}
}

// A dangling symlink as the access file is refused, not replaced by a
// file: the link and its missing target stay as they are.
func TestAccessFileDanglingSymlink(t *testing.T) {
	_, pins := clientCerts(t, "anna")
	e := newAuthEnv(t, "clients: []\n", nil)
	path := e.conf.ApiServer.AccessFile
	target := filepath.Join(filepath.Dir(path), "policy.yaml")
	os.Remove(path)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	resp := e.accessCall(t, AccessPost{Command: "add", Name: "anna", Pin: pins["anna"], Role: "read-write"})
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "does not resolve") {
		t.Errorf("add on a dangling symlink: %+v, want refused", resp)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link: %v %v, want it kept", fi, err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("the link's target was created")
	}
	if err := writeAccessFile(path, nil, []byte("clients: []\n")); err == nil {
		t.Error("writeAccessFile replaced a dangling symlink")
	}
}

// A replaced access file, and its .prev, keep the file's group, so a file
// written for the daemon's user stays readable to it. (Another of the test
// user's own groups: the one change of owner an unprivileged test can make.)
func TestAccessFileKeepsItsGroup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.yaml")
	if err := writeAccessFile(path, nil, []byte("clients: []\n")); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	_, gid, ok := fileOwner(fi)
	if !ok {
		t.Skip("no file owners on this platform")
	}
	alt := -1
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g != gid {
			alt = g
			break
		}
	}
	if alt < 0 || os.Chown(path, -1, alt) != nil {
		t.Skip("the test user has no second group to give a file")
	}
	if err := writeAccessFile(path, []byte("clients: []\n"), []byte("clients: []\n# changed\n")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + ".prev"} {
		fi, _ := os.Stat(p)
		if _, g, _ := fileOwner(fi); g != alt {
			t.Errorf("%s has group %d, want the file's %d", p, g, alt)
		}
	}
}

// With no access file every write is refused: the daemon never creates it.
// The refusal names the file and gives the touch line, in lines of at most
// 72 apart from the path's, and list says the same. Once the file is
// touched, the next call loads it and the add is done, with no reload.
func TestAccessRouteWithoutAccessFile(t *testing.T) {
	_, pins := clientCerts(t, "anna")
	e := newAuthEnv(t, "-", nil)
	path := e.conf.ApiServer.AccessFile
	add := AccessPost{Command: "add", Name: "anna", Pin: pins["anna"], Role: "read-write"}
	resp := e.accessCall(t, add)
	if !resp.Error || !resp.Missing || resp.File != path {
		t.Fatalf("add without an access file: %+v, want a refusal naming the missing file", resp)
	}
	for _, want := range []string{"access file " + path + " is missing", "takes no TLS clients", "\n   touch " + path} {
		if !strings.Contains(resp.ErrorMsg, want) {
			t.Errorf("refusal lacks %q:\n%s", want, resp.ErrorMsg)
		}
	}
	for _, l := range strings.Split(resp.ErrorMsg, "\n") {
		if len(l) > 72 && !strings.Contains(l, path) {
			t.Errorf("line over 72 columns: %q", l)
		}
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the daemon created the access file")
	}
	resp = e.accessCall(t, AccessPost{Command: "list"})
	if resp.Error || !resp.Missing || !strings.Contains(resp.Msg, "No access file, so no TLS clients") || !strings.Contains(resp.Msg, "touch "+path) {
		t.Errorf("list without an access file: %+v", resp)
	}

	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if resp = e.accessCall(t, add); resp.Error || resp.Missing || len(resp.Clients) != 1 {
		t.Errorf("add once the file is touched: %+v, want it written and in force", resp)
	}
}

// An access file that group or others can write is refused before a write,
// with the chmod that fixes it; nothing is written.
func TestAccessRouteRefusesAWritableFile(t *testing.T) {
	_, pins := clientCerts(t, "anna")
	e := newAuthEnv(t, "clients: []\n", nil)
	path := e.conf.ApiServer.AccessFile
	os.Chmod(path, 0o666)
	resp := e.accessCall(t, AccessPost{Command: "add", Name: "anna", Pin: pins["anna"], Role: "read-write"})
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "chmod go-w "+path) {
		t.Errorf("add to a world-writable file: %+v, want refused with the chmod line", resp)
	}
	if b, _ := os.ReadFile(path); string(b) != "clients: []\n" {
		t.Errorf("the file was written:\n%s", b)
	}
}

// The pins /access reports are of the certificate the TCP API serves, which
// APIdispatcher loads once for its listeners; none without a listener.
func TestAccessReportsTheServedPins(t *testing.T) {
	resetApiDispatch(t)
	addr := freeTCPAddr(t)
	conf, pin := tlsApiConf(t, addr)
	startDispatcher(t, conf)

	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	served := SPKISHA256(c.ConnectionState().PeerCertificates[0])
	c.Close()
	if served != pin {
		t.Fatalf("served pin %s, want the pair's %s", served, pin)
	}
	if got := conf.runAccessCommand(AccessPost{Command: "list"}).ServerPins; !slices.Equal(got, []string{pin}) {
		t.Errorf("ServerPins %v, want [%s]", got, pin)
	}

	// No listener, no certificate served.
	resetApiDispatch(t)
	apiTCPServers.Lock()
	apiTCPServers.srvs = nil
	apiTCPServers.Unlock()
	if got := conf.runAccessCommand(AccessPost{Command: "list"}).ServerPins; len(got) != 0 {
		t.Errorf("no TCP listener: ServerPins %v, want none", got)
	}
}
