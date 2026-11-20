package cli

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

func pinOf(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TestEnsureClientCert(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "sub", "c.crt"), filepath.Join(dir, "sub", "c.key")
	pin, created, err := ensureClientCert(cert, key, "anna")
	if err != nil || !created || len(pin) != 44 {
		t.Fatalf("first: %q %v %v", pin, created, err)
	}
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode: %v %v", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(filepath.Dir(key)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode: %v %v", fi.Mode().Perm(), err)
	}
	if _, err := loadClientCert(CliClientConf{Cert: cert, Key: key}); err != nil {
		t.Errorf("the pair does not load: %v", err)
	}
	// Never overwritten: the same pin again.
	pin2, created, err := ensureClientCert(cert, key, "anna")
	if err != nil || created || pin2 != pin {
		t.Errorf("second: %q %v %v, want %q unchanged", pin2, created, err, pin)
	}
	// A key without its certificate is not replaced.
	os.Remove(cert)
	if _, _, err := ensureClientCert(cert, key, "anna"); err == nil || !strings.Contains(err.Error(), "not overwriting") {
		t.Errorf("key without cert: err = %v", err)
	}
}

// accessEnv is a daemon config (with a socket, and an access file if wanted)
// and a CLI config entry naming it.
type accessEnv struct {
	dir, daemonCfg, access string
}

func newAccessEnv(t *testing.T, withAccessFile bool, apiURL string) *accessEnv {
	t.Helper()
	withCleanRoleRegistry(t)
	RegisterRole("auth", "tdns-auth")
	e := &accessEnv{dir: t.TempDir()}
	e.daemonCfg = filepath.Join(e.dir, "tdns-auth.yaml")
	e.access = filepath.Join(e.dir, "tdns-auth-access.yaml")
	cfg := "service:\n   name: TDNS-AUTH\napiserver:\n   addresses: [ 127.0.0.1:8989 ]\n   apikey: k\n   socket: /var/run/tdns/tdns-auth.sock\n"
	if withAccessFile {
		cfg += "   access-file: " + e.access + "\n"
	}
	if err := os.WriteFile(e.daemonCfg, []byte(cfg), 0o640); err != nil {
		t.Fatal(err)
	}
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })
	if apiURL == "" {
		apiURL = "https://127.0.0.1:8989/api/v1"
	}
	apiConfig = &CliConf{ApiServers: []ApiDetails{{Name: "tdns-auth", BaseURL: apiURL, ApiKey: "k", AuthMethod: "X-API-Key", ConfigFile: e.daemonCfg}}}
	return e
}

func (e *accessEnv) read(t *testing.T) *tdns.AccessFile {
	t.Helper()
	data, err := os.ReadFile(e.access)
	if err != nil {
		t.Fatal(err)
	}
	af, err := tdns.ParseAccessFile(data)
	if err != nil {
		t.Fatalf("written file does not parse: %v\n%s", err, data)
	}
	if err := tdns.ValidateAccessFile(af); err != nil {
		t.Fatalf("written file does not validate: %v\n%s", err, data)
	}
	return af
}

func TestClientCommandsEditTheAccessFile(t *testing.T) {
	e := newAccessEnv(t, true, "")
	o := accessEditOpts{NoReload: true}
	add := func(name, pin, role string) error {
		return editAccessFile("auth", o, true, func(af *tdns.AccessFile) (string, error) {
			if findClient(af, name) != nil {
				return "", os.ErrExist
			}
			af.Clients = append(af.Clients, tdns.AccessClient{Name: name, Pin: pin, Role: role})
			return "added", nil
		})
	}

	if err := add("anna", pinOf("anna"), "read-write"); err != nil {
		t.Fatal(err)
	}
	// A new file takes the daemon config's mode, so the daemon can read it.
	if fi, err := os.Stat(e.access); err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("new access file mode %v, want the daemon config's 0640", fi.Mode().Perm())
	}
	if err := add("bob", pinOf("bob"), "read-only"); err != nil {
		t.Fatal(err)
	}
	if err := add("anna", pinOf("anna2"), "read-only"); err == nil {
		t.Error("adding anna twice succeeded")
	}
	if af := e.read(t); len(af.Clients) != 2 || !af.KeyAuthOn() {
		t.Errorf("after two adds: %+v", af)
	}

	// The previous file is kept.
	if prev, err := os.ReadFile(e.access + ".prev"); err != nil || !strings.Contains(string(prev), "anna") || strings.Contains(string(prev), "bob") {
		t.Errorf(".prev should hold the file before bob was added: %v\n%s", err, prev)
	}

	// The daemon's validator refuses what the daemon would: nothing written.
	before, _ := os.ReadFile(e.access)
	err := editAccessFile("auth", o, false, func(af *tdns.AccessFile) (string, error) {
		findClient(af, "anna").Role = "admin"
		return "", nil
	})
	if err == nil || !strings.Contains(err.Error(), "only on the local socket") {
		t.Errorf("role admin: err = %v", err)
	}
	if after, _ := os.ReadFile(e.access); string(after) != string(before) {
		t.Error("a refused change was written")
	}

	// disable, keyauth off.
	if err := editAccessFile("auth", o, false, func(af *tdns.AccessFile) (string, error) {
		findClient(af, "bob").Disabled = true
		off := false
		af.KeyAuth = &off
		return "", nil
	}); err != nil {
		t.Fatal(err)
	}
	if af := e.read(t); !findClient(af, "bob").Disabled || af.KeyAuthOn() {
		t.Errorf("after disable and keyauth off: %+v", af)
	}

	// --dry-run writes nothing.
	before, _ = os.ReadFile(e.access)
	if err := editAccessFile("auth", accessEditOpts{DryRun: true}, false, func(af *tdns.AccessFile) (string, error) {
		af.Clients = nil
		return "", nil
	}); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(e.access); string(after) != string(before) {
		t.Error("--dry-run changed the file")
	}
}

// A daemon config with no access-file: add creates the file at the
// conventional path, and the daemon does not read it yet.
func TestClientAddWithoutAccessFileConfigured(t *testing.T) {
	e := newAccessEnv(t, false, "")
	tg, err := resolveAccessTarget("auth")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Configured || tg.File != e.access {
		t.Errorf("target = %+v, want the unconfigured %s", tg, e.access)
	}
	if err := editAccessFile("auth", accessEditOpts{}, true, func(af *tdns.AccessFile) (string, error) {
		af.Clients = append(af.Clients, tdns.AccessClient{Name: "anna", Pin: pinOf("anna"), Role: "read-only"})
		return "added", nil
	}); err != nil {
		t.Fatal(err)
	}
	if af := e.read(t); len(af.Clients) != 1 {
		t.Errorf("file: %+v", af)
	}
	// Other edits need the file to exist.
	os.Remove(e.access)
	if err := editAccessFile("auth", accessEditOpts{}, false, func(*tdns.AccessFile) (string, error) { return "", nil }); err == nil {
		t.Error("an edit of a missing file succeeded")
	}
}

// After a change the daemon is asked to reload, through the entry's client.
func TestClientEditReloadsTheDaemon(t *testing.T) {
	var got []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var cp tdns.ConfigPost
		json.NewDecoder(r.Body).Decode(&cp)
		got = append(got, r.URL.Path+" "+cp.Command)
		json.NewEncoder(w).Encode(tdns.ConfigResponse{Msg: "Config reloaded. Access file reloaded: 1 client(s), keyauth on."})
	}))
	defer srv.Close()
	e := newAccessEnv(t, true, srv.URL+"/api/v1")
	apiConfig.ApiServers[0].TLSAuth = "pin"
	apiConfig.ApiServers[0].Pins = []string{tdns.SPKISHA256(srv.Certificate())}
	if err := InitApiClients(apiConfig); err != nil {
		t.Fatal(err)
	}
	if err := editAccessFile("auth", accessEditOpts{}, true, func(af *tdns.AccessFile) (string, error) {
		af.Clients = append(af.Clients, tdns.AccessClient{Name: "anna", Pin: pinOf("anna"), Role: "read-only"})
		return "added", nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "/api/v1/config reload" {
		t.Errorf("daemon saw %v, want one config reload", got)
	}
	_ = e
}

func TestNewApiClientForVerification(t *testing.T) {
	saved := RequireServerVerification
	t.Cleanup(func() { RequireServerVerification = saved })
	RequireServerVerification = true

	for _, tc := range []struct {
		name     string
		e        ApiDetails
		wantErr  string
		wantWarn bool
	}{
		{name: "https verifying nothing", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1"}, wantErr: "does not verify the daemon"},
		{name: "insecure said out loud", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", RootCA: "insecure"}, wantWarn: true},
		{name: "pinned", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", TLSAuth: "pin", Pins: []string{pinOf("d")}}},
		{name: "pin without pins", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", TLSAuth: "pin"}, wantErr: "no pins"},
		{name: "pkix, system roots", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", TLSAuth: "pkix"}},
		{name: "unknown tlsauth", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", TLSAuth: "dane"}, wantErr: "unknown tlsauth"},
		{name: "plain http needs nothing", e: ApiDetails{Name: "a", BaseURL: "http://127.0.0.1:1/api/v1"}},
		{name: "the socket needs nothing", e: ApiDetails{Name: "a", BaseURL: "unix:///var/run/tdns/x.sock", AuthMethod: "none"}},
		{name: "certificate without one", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", TLSAuth: "pin", Pins: []string{pinOf("d")}, AuthMethod: "certificate"}, wantErr: "client init"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, warn, err := newApiClientFor(tc.e, CliClientConf{Cert: "/nonexistent/c.crt", Key: "/nonexistent/c.key"})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || api == nil {
				t.Fatalf("err = %v", err)
			}
			if (warn != "") != tc.wantWarn {
				t.Errorf("warning = %q, want one: %v", warn, tc.wantWarn)
			}
		})
	}

	// tdns-cli (verification not required) keeps its old default.
	RequireServerVerification = false
	if _, warn, err := newApiClientFor(ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1"}, CliClientConf{}); err != nil || warn != "" {
		t.Errorf("tdns-cli default: %q %v, want no error and no warning", warn, err)
	}
}

// config add pins the daemon's own certificate on a TCP entry.
func TestAddPinsTheDaemonCertificate(t *testing.T) {
	saved := runningAsRoot
	t.Cleanup(func() { runningAsRoot = saved })
	runningAsRoot = func() bool { return false }

	env := newAddEnv(t)
	srv := httptest.NewTLSServer(http.NotFoundHandler()) // only for a certificate
	srv.Close()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	certFile := filepath.Join(env.dir, "api.crt")
	writeFile(t, certFile, string(certPEM))
	leaf, _ := x509.ParseCertificate(srv.Certificate().Raw)
	want := tdns.SPKISHA256(leaf)

	d := filepath.Join(env.dir, "tdns-auth.yaml")
	writeFile(t, d, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "k", "   certfile: "+certFile+"\n"))
	res, err := env.add(t, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry.TLSAuth != "pin" || len(res.Entry.Pins) != 1 || res.Entry.Pins[0] != want {
		t.Errorf("entry = %+v, want tlsauth pin with %s", res.Entry, want)
	}
	got := env.entries(t)
	if len(got) != 1 || got[0].TLSAuth != "pin" || len(got[0].Pins) != 1 || got[0].Pins[0] != want {
		t.Errorf("read back: %+v", got)
	}

	// An unreadable certificate: the entry is written without pins, and a note
	// says what to add.
	env2 := newAddEnv(t)
	d2 := filepath.Join(env2.dir, "tdns-auth.yaml")
	writeFile(t, d2, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "k", "   certfile: /nonexistent/api.crt\n"))
	res, err = env2.add(t, d2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entry.Pins) != 0 || !strings.Contains(strings.Join(res.Notes, " "), "could not pin") {
		t.Errorf("unreadable cert: entry %+v notes %q", res.Entry, res.Notes)
	}
}

func TestAccessMatchesRunning(t *testing.T) {
	on := true
	af := &tdns.AccessFile{KeyAuth: &on, Clients: []tdns.AccessClient{{Name: "anna", Pin: pinOf("a"), Role: "read-only"}}}
	run := &tdns.ApiAccessStatus{KeyAuth: true, Clients: []tdns.ApiAccessStatusClient{{Name: "anna", Pin: pinOf("a"), Role: "read-only"}}}
	if !accessMatchesRunning(af, run) {
		t.Error("identical policies differ")
	}
	run.Clients[0].Role = "read-write"
	if accessMatchesRunning(af, run) {
		t.Error("a changed role was not noticed")
	}
}

func TestDuplicatePins(t *testing.T) {
	a, b := pinOf("a"), pinOf("b")
	if w := duplicatePins([]ApiDetails{{Name: "x", Pins: []string{a}}, {Name: "y", Pins: []string{b}}}); len(w) != 0 {
		t.Errorf("distinct pins warned: %v", w)
	}
	w := duplicatePins([]ApiDetails{{Name: "x", Pins: []string{a}}, {Name: "y", Pins: []string{b, a}}})
	if len(w) != 1 || !strings.Contains(w[0], "x and y") {
		t.Errorf("shared pin: %v", w)
	}
}
