package tdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
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
	key   string
	sock  string
	certs map[string]tls.Certificate
}

// newAuthEnv builds a router with the access file accessYAML (none if
// accessYAML is "-"), serves it over TLS as the daemon would and on a socket,
// and adds three test routes that echo who they were reached as.
func newAuthEnv(t *testing.T, accessYAML string, certs map[string]tls.Certificate) *authEnv {
	t.Helper()
	dir := shortTempDir(t)
	e := &authEnv{conf: &Config{}, key: "the-api-key", sock: filepath.Join(dir, "admin.sock"), certs: certs}
	e.conf.ApiServer.ApiKey = SensitiveString(e.key)
	e.conf.ApiServer.Socket = e.sock
	e.conf.Internal.ServerErrors = NewServerErrorRegistry()
	if accessYAML != "-" {
		e.conf.ApiServer.AccessFile = filepath.Join(dir, "access.yaml")
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
	e.srv.TLS = apiServerTLSConfig(e.conf, e.conf.ApiServer.AccessFile != "")
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
// ("" for none) and the API key if sendKey.
func (e *authEnv) call(t *testing.T, path, cert string, sendKey bool, body string) (int, string) {
	t.Helper()
	tc := &tls.Config{InsecureSkipVerify: true}
	if cert != "" {
		tc.Certificates = []tls.Certificate{e.certs[cert]}
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(body))
	if sendKey {
		req.Header.Set("X-API-Key", e.key)
	}
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
	status, b, err := NewClient("local", "unix://"+e.sock, "", "none", "").Post(strings.TrimPrefix(path, "/api/v1"), []byte(body))
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

// Without an access file nothing changes: the key, as admin, over TCP.
func TestApiAuthWithoutAccessFile(t *testing.T) {
	e := newAuthEnv(t, "-", nil)
	if st, body := e.call(t, "/api/v1/t-admin", "", true, ""); st != 200 || !strings.Contains(body, "apikey (admin) by api key") {
		t.Errorf("key without an access file: %d %q, want 200 as admin", st, body)
	}
	if st, _ := e.call(t, "/api/v1/t-ro", "", false, ""); st != 403 {
		t.Errorf("no key: %d, want 403", st)
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
		key      bool
		want     int
		wantBody string
	}{
		{"read-only client, read-only route", "/api/v1/t-ro", "anna", false, 200, "authenticated as anna (read-only) by certificate"},
		{"read-only client, read-write route", "/api/v1/t-rw", "anna", false, 403, "needs read-write"},
		{"read-write client, read-write route", "/api/v1/t-rw", "bob", false, 200, "authenticated as bob (read-write) by certificate"},
		{"read-write client, admin route", "/api/v1/t-admin", "bob", false, 403, "local admin socket"},
		{"disabled client", "/api/v1/t-ro", "carol", false, 403, ""},
		// A certificate is the identity: an unknown one does not fall back
		// to the key it was sent with.
		{"unknown certificate with the key", "/api/v1/t-ro", "mallory", true, 403, ""},
		{"key alone is read-write", "/api/v1/t-rw", "", true, 200, "apikey (read-write) by api key"},
		{"key alone is not admin", "/api/v1/t-admin", "", true, 403, "local admin socket"},
		{"nothing", "/api/v1/t-ro", "", false, 403, ""},
		// Real routes go through the same table.
		{"config status is read-only", "/api/v1/config", "anna", false, 200, ""},
		{"reload-tsig is admin", "/api/v1/config", "bob", false, 403, "local admin socket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := ""
			if tc.path == "/api/v1/config" {
				body = `{"Command":"status"}`
				if strings.Contains(tc.name, "reload-tsig") {
					body = `{"Command":"reload-tsig"}`
				}
			}
			st, got := e.call(t, tc.path, tc.cert, tc.key, body)
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

func TestApiAuthKeyOff(t *testing.T) {
	certs, pins := clientCerts(t, "bob")
	e := newAuthEnv(t, "keyauth: false\nclients:\n  - {name: bob, pin: "+pins["bob"]+", role: read-write}\n", certs)
	if st, _ := e.call(t, "/api/v1/t-ro", "", true, ""); st != 403 {
		t.Errorf("key with keyauth off: %d, want 403", st)
	}
	if st, _ := e.call(t, "/api/v1/t-rw", "bob", false, ""); st != 200 {
		t.Errorf("certificate with keyauth off: %d, want 200", st)
	}
}

// A file that cannot be used at start-up closes the TCP API rather than
// falling back to the key; DNS and the socket are unaffected.
func TestApiAuthBrokenAccessFileAtStart(t *testing.T) {
	e := newAuthEnv(t, "clients:\n  - {name: anna, pin: x, role: read-only}\n", nil)
	if st, body := e.call(t, "/api/v1/t-ro", "", true, ""); st != 503 || !strings.Contains(body, "local socket") {
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
	if st, _ := e.call(t, "/api/v1/t-ro", "bob", false, ""); st != 403 {
		t.Errorf("bob after being removed: %d, want 403", st)
	}

	// A bad file changes nothing.
	write("clients:\n  - {name: anna, pin: " + pins["anna"] + ", role: admin}\n")
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "NOT reloaded") {
		t.Errorf("reload message = %q, want NOT reloaded", msg)
	}
	if st, _ := e.call(t, "/api/v1/t-ro", "anna", false, ""); st != 200 {
		t.Errorf("anna after a refused reload: %d, want 200 (the old policy)", st)
	}

	// Taking the access file out of the config goes back to key-as-admin.
	e.conf.ApiServer.AccessFile = ""
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "no longer configured") {
		t.Errorf("reload message = %q", msg)
	}
	if st, _ := e.call(t, "/api/v1/t-admin", "", true, ""); st != 200 {
		t.Errorf("key after the access file is gone: %d, want 200", st)
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
	if st, body := e.call(t, "/api/v1/t-rw", "bob", false, small); st != 200 || !strings.Contains(body, fmt.Sprintf("body %d bytes", len(small))) {
		t.Errorf("small body: %d %q, want all %d bytes passed on", st, body, len(small))
	}

	// A large write (over the old 1 MiB cap) is judged like any other.
	large := `{"Pad":"` + strings.Repeat("x", 2<<20) + `"}`
	if st, body := e.call(t, "/api/v1/t-rw", "bob", false, large); st != 200 || !strings.Contains(body, fmt.Sprintf("body %d bytes", len(large))) {
		t.Errorf("2 MiB body as read-write: %d %.80q, want all %d bytes passed on", st, body, len(large))
	}

	// Over the cap the command cannot be checked: 413 to a network client,
	// saying so, while the socket (admin, no check needed) passes it whole.
	saved := maxPeekBody
	t.Cleanup(func() { maxPeekBody = saved })
	maxPeekBody = 4096
	big := `{"Pad":"` + strings.Repeat("x", maxPeekBody) + `"}`
	if st, body := e.call(t, "/api/v1/t-rw", "bob", false, big); st != http.StatusRequestEntityTooLarge || !strings.Contains(body, "local admin socket") {
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

// With an access file in force, a request over TLS older than 1.3 is
// refused, whatever the listener let through: a reload can add the access
// file to a listener started without the TLS 1.3 minimum.
func TestAccessFileRequiresTLS13(t *testing.T) {
	af, err := ParseAccessFile([]byte("clients: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.ApiAccess = &apiAccessHolder{}
	conf.Internal.ApiAccess.p.Store(newAccessState("/etc/tdns/access.yaml", af))
	for _, tc := range []struct {
		name string
		tls  *tls.ConnectionState
		want int
	}{
		{"TLS 1.2", &tls.ConnectionState{Version: tls.VersionTLS12}, http.StatusForbidden},
		{"TLS 1.3", &tls.ConnectionState{Version: tls.VersionTLS13}, 0},
		{"no TLS", nil, http.StatusForbidden},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/ping", nil)
		r.TLS = tc.tls
		r.Header.Set("X-API-Key", "the-key")
		_, status, msg := conf.authenticateApiRequest(r, "the-key")
		if status != tc.want {
			t.Errorf("%s: status %d (%s), want %d", tc.name, status, msg, tc.want)
		}
	}
}

// A listener started plaintext with no access file (usetls: false then), and
// a reload that adds an access file (and usetls: true, which the running
// listener cannot take up): the reload closes that listener before the policy
// is in force, so no client can send its key to it in clear any more; refusing
// the requests would still have had the key sent. config status says so. A
// TLS listener is left alone.
func TestReloadedAccessFileStopsAPlaintextListener(t *testing.T) {
	t.Cleanup(func() {
		apiTCPServers.Lock()
		apiTCPServers.srvs, apiTCPServers.plaintext, apiTCPServers.stopped = nil, false, nil
		apiTCPServers.Unlock()
	})
	conf := &Config{}
	conf.Internal.ApiAccess = &apiAccessHolder{}
	conf.Internal.ApiAccess.p.Store(&accessState{}) // no access file at start
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Addr: ln.Addr().String(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, status, msg := conf.authenticateApiRequest(r, "the-key"); status != 0 {
			http.Error(w, msg, status)
		}
	})}
	go srv.Serve(ln)
	registerApiTCPServers([]apiTCPServer{{srv: srv, ln: ln}}, true)
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	call := func() (int, error) {
		req, _ := http.NewRequest(http.MethodPost, "http://"+srv.Addr+"/api/v1/ping", nil)
		req.Header.Set("X-API-Key", "the-key")
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if st, err := call(); err != nil || st != http.StatusOK {
		t.Fatalf("plaintext key request before the access file: %d, %v", st, err)
	}

	path := filepath.Join(t.TempDir(), "access.yaml")
	if err := os.WriteFile(path, []byte("clients: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf.ApiServer.AccessFile = path
	conf.ApiServer.UseTLS = true // the new config says TLS; the listener does not
	msg := conf.reloadApiAccess()
	if !strings.Contains(msg, "Access file reloaded") || !strings.Contains(msg, "STOPPED") || !strings.Contains(msg, srv.Addr) {
		t.Fatalf("reload: %q, want it to say the plaintext listener is stopped", msg)
	}
	if st, err := call(); err == nil {
		t.Errorf("the plaintext listener still answered after the reload (%d): the key was sent in clear", st)
	}
	if got := stoppedPlaintextApiListeners(); len(got) != 1 || got[0] != srv.Addr {
		t.Errorf("stopped listeners = %v, want [%s]", got, srv.Addr)
	}

	// A TLS listener is not touched by an access file coming into force.
	tlsSrv := &http.Server{Addr: "127.0.0.1:1"}
	registerApiTCPServers([]apiTCPServer{{srv: tlsSrv}}, false)
	if addrs := stopPlaintextApiListeners(); addrs != nil {
		t.Errorf("TLS listeners stopped: %v", addrs)
	}
}

// Removing the access file again does not reopen the plaintext listener it
// closed: the reload that removes it says the listener stays stopped until a
// restart, and config status (here over the socket, as tdns-cli asks) still
// reports it, now with no access policy beside it.
func TestStoppedListenerOutlivesTheAccessFile(t *testing.T) {
	t.Cleanup(func() {
		apiTCPServers.Lock()
		apiTCPServers.srvs, apiTCPServers.plaintext, apiTCPServers.stopped = nil, false, nil
		apiTCPServers.Unlock()
	})
	e := newAuthEnv(t, "-", nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Addr: ln.Addr().String(), Handler: e.rtr}
	go srv.Serve(ln)
	registerApiTCPServers([]apiTCPServer{{srv: srv, ln: ln}}, true)
	status := func(when string) *ConfigResponse {
		t.Helper()
		st, body := e.callSocket(t, "/api/v1/config", `{"Command":"status"}`)
		var cr ConfigResponse
		if err := json.Unmarshal([]byte(body), &cr); st != http.StatusOK || err != nil {
			t.Fatalf("%s: config status: %d %v %q", when, st, err, body)
		}
		return &cr
	}

	path := filepath.Join(t.TempDir(), "access.yaml")
	if err := os.WriteFile(path, []byte("clients: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.conf.ApiServer.AccessFile = path
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "STOPPED") || !strings.Contains(msg, srv.Addr) {
		t.Fatalf("reload with the access file: %q, want %s stopped", msg, srv.Addr)
	}
	if cr := status("access file in force"); cr.Access == nil || !slices.Equal(cr.ApiTCPStopped, []string{srv.Addr}) {
		t.Errorf("access file in force: status access %+v, stopped %v; want a policy and [%s]", cr.Access, cr.ApiTCPStopped, srv.Addr)
	}

	e.conf.ApiServer.AccessFile = ""
	msg := e.conf.reloadApiAccess()
	if !strings.Contains(msg, "no longer configured") || !strings.Contains(msg, srv.Addr) ||
		!strings.Contains(msg, "stay stopped until the daemon restarts") {
		t.Errorf("reload without the access file: %q, want it to say %s stays stopped until a restart", msg, srv.Addr)
	}
	if cr := status("access file removed"); cr.Access != nil || !slices.Equal(cr.ApiTCPStopped, []string{srv.Addr}) {
		t.Errorf("access file removed: status access %+v, stopped %v; want no policy and [%s]", cr.Access, cr.ApiTCPStopped, srv.Addr)
	}
	if listening(srv.Addr) {
		t.Errorf("the plaintext listener on %s answers again after the access file was removed", srv.Addr)
	}

	// With nothing stopped, removing the file says nothing about listeners.
	apiTCPServers.Lock()
	apiTCPServers.stopped = nil
	apiTCPServers.Unlock()
	e.conf.ApiServer.AccessFile = path
	e.conf.reloadApiAccess()
	e.conf.ApiServer.AccessFile = ""
	if msg := e.conf.reloadApiAccess(); !strings.Contains(msg, "no longer configured") || strings.Contains(msg, "STOPPED") {
		t.Errorf("reload without the access file, nothing stopped: %q", msg)
	}
}

// A listener started without an access file, which a reload then adds: from
// the reload on, a client that cannot do TLS 1.3 fails the handshake itself,
// before it can send a request. A TLS 1.3 client still gets through.
func TestReloadedAccessFileRequiresTLS13AtTheHandshake(t *testing.T) {
	conf := &Config{}
	conf.Internal.ApiAccess = &apiAccessHolder{} // no access file at start
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = apiServerTLSConfig(conf, conf.ApiServer.AccessFile != "")
	srv.StartTLS()
	defer srv.Close()

	handshake := func(maxVersion uint16) error {
		c, err := tls.Dial("tcp", srv.Listener.Addr().String(),
			&tls.Config{InsecureSkipVerify: true, MaxVersion: maxVersion})
		if err != nil {
			return err
		}
		defer c.Close()
		return c.Handshake()
	}
	if err := handshake(tls.VersionTLS12); err != nil {
		t.Fatalf("TLS 1.2 before any access file: %v", err)
	}

	path := filepath.Join(t.TempDir(), "access.yaml")
	if err := os.WriteFile(path, []byte("clients: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf.ApiServer.AccessFile = path
	if msg := conf.reloadApiAccess(); !strings.Contains(msg, "Access file reloaded") {
		t.Fatalf("reload: %q", msg)
	}
	// Refused the way a listener started with the access file refuses it:
	// protocol_version, not internal_error.
	if err := handshake(tls.VersionTLS12); err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Errorf("TLS 1.2 handshake after a reload added the access file: %v, want a protocol version alert", err)
	}
	if err := handshake(tls.VersionTLS13); err != nil {
		t.Errorf("TLS 1.3 after the reload: %v", err)
	}
}

// A reload decodes the file into the running Config, and mapstructure keeps a
// key the new file leaves out. apiserver: is reset before the decode, so
// taking the access-file: line out takes the access file out (rig F5): the
// reload says so and the policy goes back to key-as-admin.
func TestReloadForgetsARemovedAccessFile(t *testing.T) {
	access := filepath.Join(t.TempDir(), "access.yaml")
	if err := os.WriteFile(access, []byte("clients: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.ApiAccess = &apiAccessHolder{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	decode := func(doc string) {
		t.Helper()
		var raw map[string]interface{}
		if err := yaml.Unmarshal([]byte(doc), &raw); err != nil {
			t.Fatal(err)
		}
		if err := decodeConfigMap(raw, conf, nil); err != nil {
			t.Fatal(err)
		}
	}

	decode("apiserver:\n   apikey: k\n   socket: /var/run/tdns/tdns-auth.sock\n   access-file: " + access + "\n")
	if msg := conf.reloadApiAccess(); !strings.Contains(msg, "Access file reloaded") {
		t.Fatalf("first reload: %q", msg)
	}

	decode("apiserver:\n   apikey: k\n") // access-file: and socket: taken out
	if conf.ApiServer.AccessFile != "" || conf.ApiServer.Socket != "" {
		t.Errorf("after the reload: access-file %q, socket %q; want both gone", conf.ApiServer.AccessFile, conf.ApiServer.Socket)
	}
	if !conf.ApiServer.UseTLS {
		t.Error("the usetls default was lost in the reset")
	}
	if msg := conf.reloadApiAccess(); !strings.Contains(msg, "no longer configured") {
		t.Errorf("reload without access-file: %q, want it to say the access file is gone", msg)
	}
	if st := conf.Internal.ApiAccess.load(); st == nil || st.Enabled {
		t.Errorf("running policy after the reload: %+v, want no access file", st)
	}
}

// A refused full reload puts the running apiserver: block back. The decode
// resets the block first, so a refused file without an access-file: line
// would otherwise leave AccessFile empty, and the next SIGHUP (which reloads
// the access file from conf.ApiServer.AccessFile) would drop the policy and
// make the key admin again, from a config that was refused.
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
	conf.ApiServer = ApiServerConf{ApiKey: "k", Socket: "/var/run/tdns/tdns-auth.sock", AccessFile: access, UseTLS: true}
	if msg := conf.reloadApiAccess(); !strings.Contains(msg, "Access file reloaded") {
		t.Fatalf("access file at start: %q", msg)
	}
	conf.publishRuntimeConfig()
	// No access-file: line, and a debug address that is refused (it must be
	// loopback) after the decode.
	conf.Internal.CfgFile = writeCfg(t, `apiserver:
   apikey: k
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
	if st := conf.Internal.ApiAccess.load(); st == nil || !st.Enabled {
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
	conf.ApiServer.UseTLS = true
	apiListenersStarted.Store(listenerSettingsOf(conf.ApiServer))
	if note := conf.apiListenerReloadNote(); note != "" {
		t.Errorf("nothing changed, note = %q", note)
	}
	conf.ApiServer.Socket = "/var/run/tdns/other.sock"
	conf.ApiServer.UseTLS = false
	note := conf.apiListenerReloadNote()
	for _, want := range []string{"NOT applied", "apiserver.socket", "apiserver.usetls", "restart"} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q does not say %q", note, want)
		}
	}
	if strings.Contains(note, "apiserver.addresses") {
		t.Errorf("note %q names addresses, which did not change", note)
	}

	// Started with an access file: the listeners are TLS 1.3 only until a
	// restart, so a reload that takes the access file out says so. Adding
	// one needs no note: the handshake check applies it at once.
	conf.ApiServer.AccessFile = "/etc/tdns/access.yaml"
	apiListenersStarted.Store(listenerSettingsOf(conf.ApiServer))
	conf.ApiServer.AccessFile = ""
	if note := conf.apiListenerReloadNote(); !strings.Contains(note, "access-file") || !strings.Contains(note, "TLS 1.3") {
		t.Errorf("access file removed: note %q, want it to say the listeners stay TLS 1.3 only", note)
	}
	apiListenersStarted.Store(listenerSettingsOf(conf.ApiServer))
	conf.ApiServer.AccessFile = "/etc/tdns/access.yaml"
	if note := conf.apiListenerReloadNote(); note != "" {
		t.Errorf("access file added: note %q, want none", note)
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
		c := NewClientWithOptions("local", "unix://"+e.sock, ClientOptions{AuthMethod: "none", ExpectConfigFile: expect})
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
