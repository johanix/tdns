package tdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// testClientCert makes a self-signed client certificate and returns it with
// its SPKI pin.
func testClientCert(t *testing.T, cn string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, SPKISHA256(leaf)
}

// The test routes are registered once for the package: the role registry is
// global, as it is for the routes a daemon's add-ons declare.
func init() {
	RegisterApiRouteRoles("/api/v1/t-ro", map[string]ApiRole{"": RoleReadOnly})
	RegisterApiRouteRoles("/api/v1/t-rw", map[string]ApiRole{"": RoleReadWrite})
	// /api/v1/t-admin is declared nowhere: default deny makes it admin.
}

type authEnv struct {
	conf  *Config
	rtr   *mux.Router
	srv   *httptest.Server
	sock  string
	certs map[string]tls.Certificate
}

// newAuthEnv builds a router whose access file holds accessYAML (is not
// there if accessYAML is "-"), serves it over TLS as the daemon would and on
// a socket, and adds three test routes that echo who they were reached as.
func newAuthEnv(t *testing.T, accessYAML string, certs map[string]tls.Certificate) *authEnv {
	t.Helper()
	dir := shortTempDir(t)
	e := &authEnv{conf: &Config{}, sock: filepath.Join(dir, "admin.sock"), certs: certs}
	e.conf.ApiServer.Socket = e.sock
	e.conf.ApiServer.AccessFile = filepath.Join(dir, "access.yaml")
	e.conf.Internal.ServerErrors = NewServerErrorRegistry()
	if accessYAML != "-" {
		if err := os.WriteFile(e.conf.ApiServer.AccessFile, []byte(accessYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rtr, err := e.conf.SetupSimpleAPIRouter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	echo := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		id, _ := ApiIdentityFrom(r.Context())
		fmt.Fprintf(w, "%s; body %d bytes", id.Describe(), len(body))
	}
	for _, p := range []string{"/api/v1/t-ro", "/api/v1/t-rw", "/api/v1/t-admin"} {
		rtr.HandleFunc(p, echo).Methods("POST")
	}
	e.rtr = rtr

	e.srv = httptest.NewUnstartedServer(rtr)
	e.srv.TLS = apiServerTLSConfig()
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	if err := serveApiSocket(e.sock, rtr, done, nil); err != nil {
		t.Fatal(err)
	}
	return e
}

// call posts body to path over TCP, presenting the named client certificate
// ("" for none).
func (e *authEnv) call(t *testing.T, path, cert string, body string) (int, string) {
	t.Helper()
	tc := &tls.Config{InsecureSkipVerify: true}
	if cert != "" {
		tc.Certificates = []tls.Certificate{e.certs[cert]}
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(body))
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *authEnv) callSocket(t *testing.T, path, body string) (int, string) {
	t.Helper()
	status, b, err := NewClientWithOptions("local", "unix://"+e.sock, ClientOptions{}).Post(strings.TrimPrefix(path, "/api/v1"), []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return status, string(b)
}

func clientCerts(t *testing.T, names ...string) (map[string]tls.Certificate, map[string]string) {
	certs, pins := map[string]tls.Certificate{}, map[string]string{}
	for _, n := range names {
		certs[n], pins[n] = testClientCert(t, n)
	}
	return certs, pins
}

// Without an access file the daemon takes no TLS clients: every TCP
// request is refused, saying which file to create and how. The socket is
// admin. A missing file is a normal state, not a server error.
func TestApiAuthWithoutAccessFile(t *testing.T) {
	certs, _ := clientCerts(t, "anna")
	e := newAuthEnv(t, "-", certs)
	path := e.conf.ApiServer.AccessFile
	st, body := e.call(t, "/api/v1/t-ro", "anna", "")
	if st != 403 || !strings.Contains(body, "access file "+path+" is missing") || !strings.Contains(body, "   touch "+path) {
		t.Errorf("TCP without an access file: %d %q, want 403 with the touch line", st, body)
	}
	if st, body := e.callSocket(t, "/api/v1/t-admin", ""); st != 200 || !strings.Contains(body, "on the local socket (admin)") {
		t.Errorf("socket: %d %q, want 200 as admin", st, body)
	}
	if errs := e.conf.Internal.ServerErrors.List(); len(errs) != 0 {
		t.Errorf("server errors = %+v, want none", errs)
	}
	if a := e.conf.apiAccessStatus(); a == nil || !a.Missing || a.File != path {
		t.Errorf("config status access = %+v, want the file reported missing", a)
	}
}

// touch is all it takes: an empty file is an empty policy, which the next
// load (a reload, or any /access call) puts in force with no restart.
func TestApiAuthTouchedAccessFile(t *testing.T) {
	e := newAuthEnv(t, "-", nil)
	path := e.conf.ApiServer.AccessFile
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "No access file") || !strings.Contains(msg, "touch "+path) {
		t.Errorf("reload without the file: %q, want the touch line", msg)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "reloaded: 0 client(s)") {
		t.Errorf("reload after touch: %q", msg)
	}
	if st, body := e.call(t, "/api/v1/t-ro", "", ""); st != 403 || !strings.Contains(body, "no client certificate") {
		t.Errorf("no certificate after touch: %d %q, want 403 asking for one", st, body)
	}
}

// Anyone who can write the access file can grant themselves access, so one
// that group or others may write is refused, with the command that fixes it.
func TestApiAuthAccessFileWritableByOthers(t *testing.T) {
	e := newAuthEnv(t, "clients: []\n", nil)
	path := e.conf.ApiServer.AccessFile
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAccessFile(path)
	if err == nil || !strings.Contains(err.Error(), "writable by group or others") || !strings.Contains(err.Error(), "   chmod go-w "+path) {
		t.Fatalf("a group-writable access file: %v, want refused with the chmod line", err)
	}
	e.conf.Internal.ApiAccess = &apiAccessHolder{}
	e.conf.initApiAccess() // as a start-up
	if st, _ := e.call(t, "/api/v1/t-ro", "", ""); st != 503 {
		t.Errorf("TCP with a group-writable access file: %d, want 503", st)
	}
	os.Chmod(path, 0o644)
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "reloaded") {
		t.Errorf("after chmod go-w: %q", msg)
	}
}

func TestApiAuthRoles(t *testing.T) {
	certs, pins := clientCerts(t, "anna", "bob", "carol", "mallory")
	access := "clients:\n" +
		"  - {name: anna, pin: " + pins["anna"] + ", role: read-only}\n" +
		"  - {name: bob, pin: " + pins["bob"] + ", role: read-write}\n" +
		"  - {name: carol, pin: " + pins["carol"] + ", role: read-write, disabled: true}\n"
	e := newAuthEnv(t, access, certs)

	for _, tc := range []struct {
		name     string
		path     string
		cert     string
		want     int
		wantBody string
	}{
		{"read-only client, read-only route", "/api/v1/t-ro", "anna", 200, "authenticated as anna (read-only) by certificate"},
		{"read-only client, read-write route", "/api/v1/t-rw", "anna", 403, "needs read-write"},
		{"read-write client, read-write route", "/api/v1/t-rw", "bob", 200, "authenticated as bob (read-write) by certificate"},
		{"read-write client, admin route", "/api/v1/t-admin", "bob", 403, "local admin socket"},
		{"disabled client", "/api/v1/t-ro", "carol", 403, "not an\nenabled client"},
		{"unknown certificate", "/api/v1/t-ro", "mallory", 403, "not an\nenabled client"},
		{"no certificate", "/api/v1/t-ro", "", 403, "no client certificate"},
		// Real routes go through the same table.
		{"config status is read-only", "/api/v1/config", "anna", 200, ""},
		{"reload-tsig is admin", "/api/v1/config", "bob", 403, "local admin socket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := ""
			if tc.path == "/api/v1/config" {
				body = `{"Command":"status"}`
				if strings.Contains(tc.name, "reload-tsig") {
					body = `{"Command":"reload-tsig"}`
				}
			}
			st, got := e.call(t, tc.path, tc.cert, body)
			if st != tc.want || !strings.Contains(got, tc.wantBody) {
				t.Errorf("%s: %d %q, want %d containing %q", tc.path, st, got, tc.want, tc.wantBody)
			}
		})
	}

	// Admin is on the socket, with no credentials at all.
	if st, body := e.callSocket(t, "/api/v1/t-admin", ""); st != 200 || !strings.Contains(body, "on the local socket (admin)") {
		t.Errorf("socket: %d %q, want 200 as admin", st, body)
	}
}

// A file that cannot be used at start-up closes the TCP API; DNS and the
// socket are unaffected.
func TestApiAuthBrokenAccessFileAtStart(t *testing.T) {
	e := newAuthEnv(t, "clients:\n  - {name: anna, pin: x, role: read-only}\n", nil)
	if st, body := e.call(t, "/api/v1/t-ro", "", ""); st != 503 || !strings.Contains(body, "local admin socket") {
		t.Errorf("TCP with a broken access file: %d %q, want 503", st, body)
	}
	if st, _ := e.callSocket(t, "/api/v1/t-admin", ""); st != 200 {
		t.Errorf("socket with a broken access file: %d, want 200", st)
	}
	errs := e.conf.Internal.ServerErrors.List()
	if len(errs) != 1 || errs[0].Subtype != ErrSubApiAccess {
		t.Errorf("server errors = %v, want one ApiAccess error", errs)
	}
	if a := e.conf.apiAccessStatus(); a == nil || a.Error == "" {
		t.Errorf("config status access = %+v, want the error reported", a)
	}
}

// A reload replaces the policy whole, or not at all.
func TestApiAccessReload(t *testing.T) {
	certs, pins := clientCerts(t, "anna", "bob")
	two := "clients:\n  - {name: anna, pin: " + pins["anna"] + ", role: read-only}\n  - {name: bob, pin: " + pins["bob"] + ", role: read-write}\n"
	e := newAuthEnv(t, two, certs)
	write := func(s string) {
		if err := os.WriteFile(e.conf.ApiServer.AccessFile, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("clients:\n  - {name: anna, pin: " + pins["anna"] + ", role: read-only}\n")
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "reloaded: 1 client") {
		t.Errorf("reload message = %q", msg)
	}
	if st, _ := e.call(t, "/api/v1/t-ro", "bob", ""); st != 403 {
		t.Errorf("bob after being removed: %d, want 403", st)
	}

	// A bad file changes nothing.
	write("clients:\n  - {name: anna, pin: " + pins["anna"] + ", role: admin}\n")
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "NOT reloaded") {
		t.Errorf("reload message = %q, want NOT reloaded", msg)
	}
	if st, _ := e.call(t, "/api/v1/t-ro", "anna", ""); st != 200 {
		t.Errorf("anna after a refused reload: %d, want 200 (the old policy)", st)
	}

	// Removing the file takes TLS access away.
	os.Remove(e.conf.ApiServer.AccessFile)
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "No access file, so no TLS clients") {
		t.Errorf("reload message = %q", msg)
	}
	if st, _ := e.call(t, "/api/v1/t-ro", "anna", ""); st != 403 {
		t.Errorf("anna after the access file is gone: %d, want 403", st)
	}
	if errs := e.conf.Internal.ServerErrors.List(); len(errs) != 0 {
		t.Errorf("server errors after the file went: %+v, want none (the refused reload's goes)", errs)
	}
}

// An access file written before API keys went may say keyauth:. It loads
// (the line is ignored), so the daemon's policy does not close over a line
// that no longer means anything.
func TestAccessFileObsoleteKeyauthLoads(t *testing.T) {
	certs, pins := clientCerts(t, "bob")
	e := newAuthEnv(t, "keyauth: false\nclients:\n  - {name: bob, pin: "+pins["bob"]+", role: read-write}\n", certs)
	if st, body := e.call(t, "/api/v1/t-rw", "bob", ""); st != 200 {
		t.Errorf("bob with an obsolete keyauth: line: %d %q, want 200", st, body)
	}
}

// The TCP API is TLS 1.3 only: an older client is turned away at the
// handshake.
func TestTCPApiIsTLS13Only(t *testing.T) {
	e := newAuthEnv(t, "clients: []\n", nil)
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}}}
	resp, err := cl.Post(e.srv.URL+"/api/v1/ping", "application/json", nil)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("a TLS 1.2 client got HTTP %d, want the handshake refused", resp.StatusCode)
	}
}

// The middleware reads the body to find the command and must hand the
// handler all of it. A body too long to judge needs admin.
func TestPeekCommandKeepsTheBody(t *testing.T) {
	certs, pins := clientCerts(t, "bob")
	e := newAuthEnv(t, "clients:\n  - {name: bob, pin: "+pins["bob"]+", role: read-write}\n", certs)

	// No Command: the route's "" entry (read-write) applies. A command the
	// route does not declare would need admin, by default deny.
	small := `{"Pad":"` + strings.Repeat("x", 1000) + `"}`
	if st, body := e.call(t, "/api/v1/t-rw", "bob", small); st != 200 || !strings.Contains(body, fmt.Sprintf("body %d bytes", len(small))) {
		t.Errorf("small body: %d %q, want all %d bytes passed on", st, body, len(small))
	}

	// A large write (over the old 1 MiB cap) is judged like any other.
	large := `{"Pad":"` + strings.Repeat("x", 2<<20) + `"}`
	if st, body := e.call(t, "/api/v1/t-rw", "bob", large); st != 200 || !strings.Contains(body, fmt.Sprintf("body %d bytes", len(large))) {
		t.Errorf("2 MiB body as read-write: %d %.80q, want all %d bytes passed on", st, body, len(large))
	}

	// Over the cap the command cannot be checked: 413 to a network client,
	// saying so, while the socket (admin, no check needed) passes it whole.
	saved := maxPeekBody
	t.Cleanup(func() { maxPeekBody = saved })
	maxPeekBody = 4096
	big := `{"Pad":"` + strings.Repeat("x", maxPeekBody) + `"}`
	if st, body := e.call(t, "/api/v1/t-rw", "bob", big); st != http.StatusRequestEntityTooLarge || !strings.Contains(body, "local admin socket") {
		t.Errorf("oversized body as read-write: %d %q, want 413 naming the socket", st, body)
	}
	if st, body := e.callSocket(t, "/api/v1/t-rw", big); st != 200 || !strings.Contains(body, fmt.Sprintf("body %d bytes", len(big))) {
		t.Errorf("oversized body on the socket: %d %.80q, want all %d bytes passed on", st, body, len(big))
	}
}

func TestRequiredApiRole(t *testing.T) {
	for _, tc := range []struct {
		route, cmd string
		want       ApiRole
	}{
		{"/api/v1/ping", "", RoleReadOnly},
		{"/api/v1/config", "status", RoleReadOnly},
		{"/api/v1/config", " RELOAD ", RoleReadWrite}, // case and space do not matter
		{"/api/v1/config", "reload-tsig", RoleAdmin},
		{"/api/v1/config", "no-such-command", RoleAdmin},
		{"/api/v1/command", "stop", RoleAdmin},
		{"/api/v1/zone", "add", RoleReadWrite},
		{"/api/v1/zone", "list-zones", RoleReadOnly},
		{"/api/v1/keystore", "list", RoleAdmin},
		{"/api/v1/rollover/status", "", RoleReadOnly},
		{"/api/v1/rollover/asap", "", RoleReadWrite},
		{"/api/v1/no-such-route", "", RoleAdmin},
	} {
		if got := RequiredApiRole(tc.route, tc.cmd); got != tc.want {
			t.Errorf("RequiredApiRole(%q, %q) = %s, want %s", tc.route, tc.cmd, got, tc.want)
		}
	}
}

// A body that is not one JSON value is not a commandless request: the
// handler's Decoder would run the first value's command.
func TestPeekCommandMalformedBody(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"command":"off"}{}`, unknownCommand}, // the handler would run "off"
		{`{"command":`, unknownCommand},
		{`{"command":5}`, unknownCommand},
		{" \n", ""}, // empty: the commandless request it looks like
		{`{"Command":"status"}` + "\n", "status"},
		{`{}`, ""},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scanner/poll", strings.NewReader(tc.body))
		if got, _ := peekCommand(r); got != tc.want {
			t.Errorf("peekCommand(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

// A refused full reload puts the running apiserver: block back. The decode
// resets the block first, so a refused file without an access-file: line
// would otherwise leave AccessFile at another path, and the next SIGHUP
// (which reloads the access file from conf.ApiServer.AccessFile) would load
// another policy, from a config that was refused.
func TestARefusedReloadKeepsTheAccessFile(t *testing.T) {
	keepLiveConfig(t)
	access := filepath.Join(t.TempDir(), "access.yaml")
	if err := os.WriteFile(access, []byte("clients: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.KeyDB = newTestKeyDB(t)
	conf.Internal.ApiAccess = &apiAccessHolder{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	conf.ApiServer = ApiServerConf{Socket: "/var/run/tdns/tdns-auth.sock", AccessFile: access}
	if msg := conf.reloadApiAccess(); !strings.Contains(msg, "Access file reloaded") {
		t.Fatalf("access file at start: %q", msg)
	}
	conf.publishRuntimeConfig()
	// No access-file: line, and a debug address that is refused (it must be
	// loopback) after the decode.
	conf.Internal.CfgFile = writeCfg(t, `apiserver:
   socket: /var/run/tdns/tdns-auth.sock
listeners:
   imr-debug-address: "192.0.2.1:5353"
`)
	if _, err := conf.ReloadConfig(); err == nil || !strings.Contains(err.Error(), "imr-debug-address") {
		t.Fatalf("the reload was not refused for its debug address: %v", err)
	}
	if conf.ApiServer.AccessFile != access || conf.ApiServer.Socket != "/var/run/tdns/tdns-auth.sock" {
		t.Errorf("the refused reload left access-file %q, socket %q", conf.ApiServer.AccessFile, conf.ApiServer.Socket)
	}
	// What a SIGHUP does next: the access file stays in force.
	if msg := conf.reloadApiAccess(); !strings.Contains(msg, "Access file reloaded") {
		t.Errorf("SIGHUP after the refused reload: %q, want the access file still in force", msg)
	}
	if st := conf.Internal.ApiAccess.load(); st == nil || st.Missing || st.Err != nil {
		t.Errorf("running policy after the refused reload and a SIGHUP: %+v", st)
	}
}

// A reload cannot move a listener; it says which listener settings it left
// for the next restart.
func TestApiListenerReloadNote(t *testing.T) {
	saved := apiListenersStarted.Load()
	t.Cleanup(func() { apiListenersStarted.Store(saved) })

	conf := &Config{}
	conf.ApiServer.Addresses = []string{"127.0.0.1:8989"}
	conf.ApiServer.Socket = "/var/run/tdns/tdns-auth.sock"
	apiListenersStarted.Store(listenerSettingsOf(conf.ApiServer))
	if note := conf.apiListenerReloadNote(); note != "" {
		t.Errorf("nothing changed, note = %q", note)
	}
	conf.ApiServer.Socket = "/var/run/tdns/other.sock"
	note := conf.apiListenerReloadNote()
	for _, want := range []string{"NOT applied", "apiserver.socket", "restart"} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q does not say %q", note, want)
		}
	}
	if strings.Contains(note, "apiserver.addresses") {
		t.Errorf("note %q names addresses, which did not change", note)
	}
	// A changed access file needs no restart: the reload loads it.
	conf.ApiServer.AccessFile = "/etc/tdns/access.yaml"
	apiListenersStarted.Store(listenerSettingsOf(conf.ApiServer))
	conf.ApiServer.AccessFile = "/etc/tdns/other-access.yaml"
	if note := conf.apiListenerReloadNote(); note != "" {
		t.Errorf("access file moved: note %q, want none", note)
	}
}

// A socket client that names the config it means (tdns-ncli, which found the
// socket through that config) is refused, before anything runs, by a daemon
// that runs another: the check rides on the request that does the work.
func TestRequestForAnotherConfigIsRefused(t *testing.T) {
	e := newAuthEnv(t, "-", nil)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tdns-auth.yaml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.conf.Internal.CfgFile = cfg
	post := func(expect string) (int, string) {
		c := NewClientWithOptions("local", "unix://"+e.sock, ClientOptions{ExpectConfigFile: expect})
		status, b, err := c.Post("/t-admin", nil)
		if err != nil && status == 0 {
			t.Fatal(err)
		}
		return status, string(b)
	}
	if st, body := post(cfg); st != 200 {
		t.Errorf("for this daemon's config: %d %q, want 200", st, body)
	}
	if st, body := post(filepath.Join(dir, "other.yaml")); st != http.StatusPreconditionFailed || !strings.Contains(body, "this daemon runs "+cfg) {
		t.Errorf("for another config: %d %q, want 412 naming this daemon's config", st, body)
	}
	// Through a symlink: the same file.
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(cfg, link); err == nil {
		if st, body := post(link); st != 200 {
			t.Errorf("through a symlink: %d %q, want 200", st, body)
		}
	}
	// A relative config-file:, as the client's working directory reads it:
	// the client sends it absolute, so the daemon (whose working directory
	// is its own) compares like with like.
	t.Chdir(dir)
	if st, body := post("tdns-auth.yaml"); st != 200 {
		t.Errorf("a relative path from the client's directory: %d %q, want 200", st, body)
	}
	// No header: as before.
	if st, body := e.callSocket(t, "/api/v1/t-admin", ""); st != 200 {
		t.Errorf("no expected config: %d %q, want 200", st, body)
	}
}

// Every TCP request checks the access file: one removed, created or
// rewritten is in force at the next request, with no reload and no client
// command.
func TestApiAuthSeesTheFileChange(t *testing.T) {
	certs, pins := clientCerts(t, "anna", "bob")
	e := newAuthEnv(t, "clients:\n  - {name: anna, pin: "+pins["anna"]+", role: read-only}\n", certs)
	path := e.conf.ApiServer.AccessFile
	if st, _ := e.call(t, "/api/v1/t-ro", "anna", ""); st != 200 {
		t.Fatalf("anna at start: %d", st)
	}
	os.Remove(path)
	if st, body := e.call(t, "/api/v1/t-ro", "anna", ""); st != 403 || !strings.Contains(body, "is missing") {
		t.Errorf("anna once the file is gone: %d %q, want 403 with the touch line", st, body)
	}
	if err := os.WriteFile(path, []byte("clients:\n  - {name: bob, pin: "+pins["bob"]+", role: read-only}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, body := e.call(t, "/api/v1/t-ro", "bob", ""); st != 200 {
		t.Errorf("bob once the file names him: %d %q, want 200", st, body)
	}
	if st, _ := e.call(t, "/api/v1/t-ro", "anna", ""); st != 403 {
		t.Errorf("anna, whom the new file does not name: %d, want 403", st)
	}
}
