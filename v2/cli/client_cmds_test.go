package cli

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
	// A certificate whose key is another one, or gone, is not a pair: no
	// pin, and neither file touched.
	goodKey, _ := os.ReadFile(key)
	other := filepath.Join(dir, "other")
	if _, _, err := ensureClientCert(filepath.Join(other, "o.crt"), filepath.Join(other, "o.key"), "otto"); err != nil {
		t.Fatal(err)
	}
	otherKey, _ := os.ReadFile(filepath.Join(other, "o.key"))
	certBefore, _ := os.ReadFile(cert)
	os.WriteFile(key, otherKey, 0o600)
	if _, _, err := ensureClientCert(cert, key, "anna"); err == nil || !strings.Contains(err.Error(), "not a usable pair") {
		t.Errorf("mismatched key: err = %v", err)
	}
	if k, _ := os.ReadFile(key); string(k) != string(otherKey) {
		t.Error("the mismatched key was overwritten")
	}
	if c, _ := os.ReadFile(cert); string(c) != string(certBefore) {
		t.Error("the certificate was overwritten")
	}
	os.Remove(key)
	if _, _, err := ensureClientCert(cert, key, "anna"); err == nil || !strings.Contains(err.Error(), "not a usable pair") {
		t.Errorf("missing key: err = %v", err)
	}
	os.WriteFile(key, goodKey, 0o600)

	// A key without its certificate is not replaced.
	os.Remove(cert)
	if _, _, err := ensureClientCert(cert, key, "anna"); err == nil || !strings.Contains(err.Error(), "not overwriting") {
		t.Errorf("key without cert: err = %v", err)
	}
}

// createNewFile never replaces a file: the second of two client inits fails
// instead of overwriting the first one's key.
func TestCreateNewFileIsExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.key")
	if err := createNewFile(p, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createNewFile(p, []byte("second"), 0o600); err == nil {
		t.Error("a second create succeeded")
	}
	if b, _ := os.ReadFile(p); string(b) != "first" {
		t.Errorf("content %q, want the first write kept", b)
	}
}

// Every access-file edit holds the lock from its read to its write: while
// another edit has it, this one waits (here until its context ends) and
// writes nothing.
func TestAccessFileEditWaitsForTheLock(t *testing.T) {
	e := newAccessEnv(t, true, "")
	unlock, err := lockCliConfig(context.Background(), e.access)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	before, _ := os.ReadFile(e.access)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err = editAccessFile(ctx, "auth", accessEditOpts{NoReload: true}, true, func(af *tdns.AccessFile) (string, error) {
		af.Clients = append(af.Clients, tdns.AccessClient{Name: "late", Pin: pinOf("late"), Role: "read-only"})
		return "added", nil
	})
	if err == nil || !strings.Contains(err.Error(), "waiting for the lock") {
		t.Errorf("edit while the lock is held: err = %v, want it to wait for the lock", err)
	}
	if after, _ := os.ReadFile(e.access); string(after) != string(before) {
		t.Error("the access file changed while another edit held the lock")
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
	// The socket is in the test's own directory and does not exist: a reload
	// tries the socket first, and must never reach a daemon running on this
	// host. (A short directory: a socket path has a length limit.)
	sockDir, err := os.MkdirTemp("/tmp", "ncli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	cfg := "service:\n   name: TDNS-AUTH\napiserver:\n   addresses: [ 127.0.0.1:8989 ]\n   apikey: k\n   socket: " + filepath.Join(sockDir, "tdns-auth.sock") + "\n"
	if withAccessFile {
		cfg += "   access-file: " + e.access + "\n"
	}
	if err := os.WriteFile(e.daemonCfg, []byte(cfg), 0o640); err != nil {
		t.Fatal(err)
	}
	// Explicitly: the umask applied to WriteFile (0077 would give 0600),
	// and the tests compare a new access file's mode with this one.
	if err := os.Chmod(e.daemonCfg, 0o640); err != nil {
		t.Fatal(err)
	}
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })
	if apiURL == "" {
		// Port 1: nothing listens there, so an edit's check of the running
		// daemon finds none, whatever runs on this host.
		apiURL = "https://127.0.0.1:1/api/v1"
	}
	apiConfig = &CliConf{ApiServers: []ApiDetails{{Name: "tdns-auth", BaseURL: apiURL, ApiKey: "k", AuthMethod: "X-API-Key", ConfigFile: e.daemonCfg}}}
	// As the CLI does at start: an edit asks the entry's daemon which
	// config it runs, through the client built here.
	if err := InitApiClients(apiConfig); err != nil {
		t.Fatal(err)
	}
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
		return editAccessFile(context.Background(), "auth", o, true, func(af *tdns.AccessFile) (string, error) {
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
	err := editAccessFile(context.Background(), "auth", o, false, func(af *tdns.AccessFile) (string, error) {
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
	if err := editAccessFile(context.Background(), "auth", o, false, func(af *tdns.AccessFile) (string, error) {
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
	if err := editAccessFile(context.Background(), "auth", accessEditOpts{DryRun: true}, false, func(af *tdns.AccessFile) (string, error) {
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
	if err := editAccessFile(context.Background(), "auth", accessEditOpts{}, true, func(af *tdns.AccessFile) (string, error) {
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
	if err := editAccessFile(context.Background(), "auth", accessEditOpts{}, false, func(*tdns.AccessFile) (string, error) { return "", nil }); err == nil {
		t.Error("an edit of a missing file succeeded")
	}
}

// After a change the daemon is asked to reload, through the entry's client.
func TestClientEditReloadsTheDaemon(t *testing.T) {
	var got []string
	var runs string // the config the fake daemon says it runs
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var cp tdns.ConfigPost
		json.NewDecoder(r.Body).Decode(&cp)
		got = append(got, r.URL.Path+" "+cp.Command)
		json.NewEncoder(w).Encode(tdns.ConfigResponse{ConfigFile: runs,
			Msg: "Config reloaded. Access file reloaded: 1 client(s), keyauth on."})
	}))
	defer srv.Close()
	e := newAccessEnv(t, true, srv.URL+"/api/v1")
	apiConfig.ApiServers[0].TLSAuth = "pin"
	apiConfig.ApiServers[0].Pins = []string{tdns.SPKISHA256(srv.Certificate())}
	if err := InitApiClients(apiConfig); err != nil {
		t.Fatal(err)
	}
	add := func(name string) error {
		return editAccessFile(context.Background(), "auth", accessEditOpts{}, true, func(af *tdns.AccessFile) (string, error) {
			af.Clients = append(af.Clients, tdns.AccessClient{Name: name, Pin: pinOf(name), Role: "read-only"})
			return "added", nil
		})
	}

	// The daemon that answers says it runs this config: checked, written,
	// reloaded.
	runs = e.daemonCfg
	if err := add("anna"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "/api/v1/config status" || got[1] != "/api/v1/config reload" {
		t.Errorf("daemon saw %v, want a status check, then one config reload", got)
	}

	// Another daemon answers (one that holds this config's address, say):
	// refused before anything is written, and nothing is reloaded.
	before, _ := os.ReadFile(e.access)
	got, runs = nil, filepath.Join(e.dir, "other-daemon.yaml")
	if err := add("bob"); err == nil || !strings.Contains(err.Error(), "runs "+runs) {
		t.Errorf("another daemon answering: err = %v, want a refusal naming its config", err)
	}
	if after, _ := os.ReadFile(e.access); string(after) != string(before) {
		t.Error("the access file was written though another daemon answered")
	}
	if len(got) != 1 {
		t.Errorf("daemon saw %v, want only the status check", got)
	}

	// A daemon that does not say which config it runs is refused too.
	runs = ""
	if err := add("carl"); err == nil || !strings.Contains(err.Error(), "does not say") {
		t.Errorf("a daemon that does not say: err = %v", err)
	}

	// --no-reload as well: writing the file of a daemon that is not the one
	// that answers changes nothing the operator meant, reload or not.
	runs = filepath.Join(e.dir, "other-daemon.yaml")
	err := editAccessFile(context.Background(), "auth", accessEditOpts{NoReload: true}, true, func(af *tdns.AccessFile) (string, error) {
		af.Clients = append(af.Clients, tdns.AccessClient{Name: "dora", Pin: pinOf("dora"), Role: "read-only"})
		return "added", nil
	})
	if err == nil || !strings.Contains(err.Error(), "runs "+runs) {
		t.Errorf("--no-reload with another daemon answering: err = %v, want a refusal", err)
	}
}

// client list says what the daemon runs only when the daemon that answered
// is this config's: another daemon with the same policy is not "running this
// file".
func TestClientListChecksWhoAnswered(t *testing.T) {
	var runs string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(tdns.ConfigResponse{ConfigFile: runs,
			Access: &tdns.ApiAccessStatus{KeyAuth: true, Clients: []tdns.ApiAccessStatusClient{}}})
	}))
	defer srv.Close()
	e := newAccessEnv(t, true, srv.URL+"/api/v1")
	apiConfig.ApiServers[0].TLSAuth = "pin"
	apiConfig.ApiServers[0].Pins = []string{tdns.SPKISHA256(srv.Certificate())}
	if err := InitApiClients(apiConfig); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.access, "keyauth: true\nclients: []\n")

	runs = e.daemonCfg
	if out := captureStdout(t, func() { listAccessClients("auth") }); !strings.Contains(out, "The daemon runs this file") {
		t.Errorf("this config's daemon with this policy:\n%s", out)
	}
	runs = filepath.Join(e.dir, "other-daemon.yaml")
	out := captureStdout(t, func() { listAccessClients("auth") })
	if strings.Contains(out, "runs this file") || !strings.Contains(out, "Running policy unknown") {
		t.Errorf("another daemon with the same policy:\n%s", out)
	}
	if strings.Contains(out, "not editing") {
		t.Errorf("a read-only list says it is not editing:\n%s", out)
	}
}

// An entry that cannot be built (here: a CA file that is gone) is not the
// same as no entry: its daemon may be running, so the edit is refused and
// nothing is written.
func TestUnbuildableEntryRefusesTheEdit(t *testing.T) {
	e := newAccessEnv(t, true, "")
	apiConfig.ApiServers[0].TLSAuth = "pkix"
	apiConfig.ApiServers[0].RootCA = filepath.Join(e.dir, "gone-ca.pem")
	if err := InitApiClients(apiConfig); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(e.access)
	err := editAccessFile(context.Background(), "auth", accessEditOpts{NoReload: true}, true, func(af *tdns.AccessFile) (string, error) {
		af.Clients = append(af.Clients, tdns.AccessClient{Name: "anna", Pin: pinOf("anna"), Role: "read-only"})
		return "added", nil
	})
	if err == nil || !strings.Contains(err.Error(), "cannot ask the daemon of auth's entry") {
		t.Errorf("entry with an unreadable CA file: err = %v, want a refusal", err)
	}
	if after, _ := os.ReadFile(e.access); string(after) != string(before) {
		t.Error("the access file was written though the entry's daemon was not identified")
	}
}

// A socket that is there but not ours to open is someone we cannot ask:
// not "nothing running". No socket file and a refused connection are.
func TestVerifyRunningDaemonNeedsAnAnswer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens any socket")
	}
	dir, err := os.MkdirTemp("/tmp", "ncli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	withCleanRoleRegistry(t)
	RegisterRole("auth", "tdns-auth")
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })
	apiConfig = &CliConf{ApiServers: []ApiDetails{{Name: "tdns-auth", BaseURL: "https://127.0.0.1:1/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: "insecure"}}}
	if err := InitApiClients(apiConfig); err != nil {
		t.Fatal(err)
	}

	locked := filepath.Join(dir, "locked.sock")
	ln, err := net.Listen("unix", locked)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	os.Chmod(locked, 0)
	tg := &accessTarget{Socket: locked, DaemonConfig: "/etc/tdns/tdns-auth.yaml", File: "/etc/tdns/tdns-auth-access.yaml"}
	if err := verifyRunningDaemon("auth", tg); err == nil || !strings.Contains(err.Error(), "cannot ask") {
		t.Errorf("a socket we may not open: err = %v, want a refusal", err)
	}

	// No socket file, and the entry's port refuses: nothing is running.
	tg.Socket = filepath.Join(dir, "absent.sock")
	if err := verifyRunningDaemon("auth", tg); err != nil {
		t.Errorf("nothing running: %v, want the edit allowed", err)
	}
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
		{name: "the refusal says how to pin", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", ConfigFile: "/etc/tdns/tdns-imr.yaml"}, wantErr: "Pin it with: tdns-ncli config add /etc/tdns/tdns-imr.yaml"},
		{name: "insecure said out loud", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", RootCA: "insecure"}, wantWarn: true},
		{name: "pinned", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", TLSAuth: "pin", Pins: []string{pinOf("d")}}},
		{name: "pin without pins", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", TLSAuth: "pin"}, wantErr: "no pins"},
		{name: "pkix, system roots", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", TLSAuth: "pkix"}},
		{name: "unknown tlsauth", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", TLSAuth: "dane"}, wantErr: "unknown tlsauth"},
		{name: "plain http on loopback", e: ApiDetails{Name: "a", BaseURL: "http://127.0.0.1:1/api/v1"}},
		{name: "plain http on localhost", e: ApiDetails{Name: "a", BaseURL: "http://localhost:1/api/v1"}},
		{name: "plain http on ::1", e: ApiDetails{Name: "a", BaseURL: "http://[::1]:1/api/v1"}},
		{name: "plain http elsewhere warns", e: ApiDetails{Name: "a", BaseURL: "http://192.0.2.1:1/api/v1"}, wantWarn: true},
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
	if _, warn, err := newApiClientFor(ApiDetails{Name: "a", BaseURL: "http://192.0.2.1:1/api/v1"}, CliClientConf{}); err != nil || warn != "" {
		t.Errorf("tdns-cli plain http: %q %v, want no error and no warning", warn, err)
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

	// A relative certfile is opened from the daemon's working directory,
	// which config add cannot know: no pin, even though a file of that name
	// sits next to the daemon config, and the note says why.
	env3 := newAddEnv(t)
	writeFile(t, filepath.Join(env3.dir, "api.crt"), string(certPEM))
	d3 := filepath.Join(env3.dir, "tdns-auth.yaml")
	writeFile(t, d3, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "k", "   certfile: api.crt\n"))
	res, err = env3.add(t, d3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if notes := strings.Join(res.Notes, " "); len(res.Entry.Pins) != 0 || !strings.Contains(notes, "relative path") || !strings.Contains(notes, "could not pin") {
		t.Errorf("relative certfile: entry %+v notes %q", res.Entry, res.Notes)
	}
}

// An entry with no pin is broken (tdns-ncli refuses it), and config add of the
// same daemon fixes it in place: tlsauth: pin and the pin added, a rootca:
// line removed, the rest of the file as it was. An entry pinning an earlier
// certificate keeps its pins and gets the current one too. Run again, the add
// changes nothing.
func TestAddPinsAKnownEntry(t *testing.T) {
	saved := runningAsRoot
	t.Cleanup(func() { runningAsRoot = saved })
	runningAsRoot = func() bool { return false }

	srv := httptest.NewTLSServer(http.NotFoundHandler()) // only for a certificate
	srv.Close()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	leaf, _ := x509.ParseCertificate(srv.Certificate().Raw)
	pin := tdns.SPKISHA256(leaf)

	setup := func(t *testing.T, entry string) (*addEnv, string) {
		env := newAddEnv(t)
		certFile := filepath.Join(env.dir, "api.crt")
		writeFile(t, certFile, string(certPEM))
		d := filepath.Join(env.dir, "tdns-imr.yaml")
		writeFile(t, d, daemonYAML("TDNS-IMR", "127.0.0.1:8085", "k", "   certfile: "+certFile+"\n"))
		writeFile(t, env.cli, strings.ReplaceAll(entry, "@D@", d))
		return env, d
	}

	t.Run("no pin, rootca insecure", func(t *testing.T) {
		const head = "# CLI config\ncli:\n   tdns-imr:\n      foo: bar\n\napiservers:\n   # the auth server\n   - name:          tdns-auth\n     baseurl:       https://127.0.0.1:8989/api/v1\n     apikey:        a\n     authmethod:    X-API-Key\n\n"
		const imr = "   - name:          tdns-imr\n     baseurl:       https://127.0.0.1:8085/api/v1\n     apikey:        k\n     authmethod:    X-API-Key\n     rootca:        insecure\n     config-file:   @D@\n"
		const tail = "\n# end\n"
		env, d := setup(t, head+imr+tail)

		res, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true })
		if err != nil || !res.Pinned || res.Wrote {
			t.Fatalf("dry run: %+v, %v; want it pinned, nothing written", res, err)
		}
		if got, _ := os.ReadFile(env.cli); !strings.Contains(string(got), "rootca:        insecure") {
			t.Fatalf("the dry run wrote:\n%s", got)
		}

		res, err = env.add(t, d, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.AlreadyKnown != "tdns-imr" || !res.Pinned || !res.Wrote || !res.Canonical {
			t.Errorf("result = %+v", res)
		}
		want := head + "   - name:          tdns-imr\n     baseurl:       https://127.0.0.1:8085/api/v1\n     apikey:        k\n     authmethod:    X-API-Key\n     config-file:   " + d + "\n     tlsauth:       pin\n     pins:          [ \"" + pin + "\" ]\n" + tail
		if got, _ := os.ReadFile(env.cli); string(got) != want {
			t.Errorf("file =\n%s\nwant\n%s", got, want)
		}
		got := env.entries(t)
		if len(got) != 2 || got[1].TLSAuth != "pin" || len(got[1].Pins) != 1 || got[1].Pins[0] != pin || got[1].RootCA != "" {
			t.Errorf("entries = %+v", got)
		}
		if _, _, err := newApiClientFor(got[1], CliClientConf{}); err != nil {
			t.Errorf("the pinned entry is still refused: %v", err)
		}

		var sb strings.Builder
		printAddResult(&sb, res, false, env.cli)
		if !strings.Contains(sb.String(), "pinned the daemon's certificate") || strings.Contains(sb.String(), "nothing changed") {
			t.Errorf("printed:\n%s", sb.String())
		}

		res, err = env.add(t, d, nil)
		if err != nil || res.Pinned || res.Wrote || res.AlreadyKnown != "tdns-imr" {
			t.Errorf("second add: %+v, %v; want already known, nothing changed", res, err)
		}
	})

	t.Run("an earlier pin, in block style", func(t *testing.T) {
		env, d := setup(t, "apiservers:\n   -\n     name: tdns-imr\n     baseurl: https://127.0.0.1:8085/api/v1\n     apikey: k\n     authmethod: X-API-Key\n     tlsauth: pin\n     pins:\n       - \""+pinOf("old")+"\"\n     config-file: @D@\n")
		res, err := env.add(t, d, nil)
		if err != nil || !res.Pinned {
			t.Fatalf("%+v, %v", res, err)
		}
		got := env.entries(t)
		if len(got) != 1 || len(got[0].Pins) != 2 || got[0].Pins[0] != pinOf("old") || got[0].Pins[1] != pin {
			t.Errorf("entries = %+v; want the old pin kept and the new one added", got)
		}
		if !strings.Contains(strings.Join(res.Notes, " "), "earlier certificate") {
			t.Errorf("notes = %q", res.Notes)
		}
	})

	t.Run("an unreadable certificate: a note, nothing changed", func(t *testing.T) {
		env, d := setup(t, "apiservers:\n   - name: tdns-imr\n     baseurl: https://127.0.0.1:8085/api/v1\n     apikey: k\n     authmethod: X-API-Key\n     config-file: @D@\n")
		writeFile(t, d, daemonYAML("TDNS-IMR", "127.0.0.1:8085", "k", "   certfile: /nonexistent/api.crt\n"))
		before, _ := os.ReadFile(env.cli)
		res, err := env.add(t, d, nil)
		if err != nil || res.Pinned || res.Wrote || !strings.Contains(strings.Join(res.Notes, " "), "has no pin") {
			t.Errorf("%+v, %v", res, err)
		}
		if after, _ := os.ReadFile(env.cli); string(after) != string(before) {
			t.Errorf("the file changed:\n%s", after)
		}
	})
}

// An entry with config-file: reaches its daemon over the local admin socket
// when that answers: the socket the daemon config names, or by default the one
// named after the config file. Over TCP when it does not answer, when the
// daemon config says socket: none, or with --tcp (ForceTCP). The CLI config
// holds no socket path.
func TestEntryUsesTheDaemonSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ncli") // short: a socket path has a limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	savedDir, savedTCP := tdns.DefaultApiSocketDir, ForceTCP
	t.Cleanup(func() { tdns.DefaultApiSocketDir, ForceTCP = savedDir, savedTCP })
	tdns.DefaultApiSocketDir = dir

	cfg := filepath.Join(dir, "tdns-imr.yaml")
	writeFile(t, cfg, daemonYAML("", "127.0.0.1:8085", "k", "")) // no socket: line
	sock := filepath.Join(dir, "tdns-imr.sock")
	if got, addrs := daemonSocket(cfg); got != sock || len(addrs) != 1 || addrs[0] != "127.0.0.1:8085" {
		t.Fatalf("daemonSocket = %q %q, want the default %s and 127.0.0.1:8085", got, addrs, sock)
	}
	e := ApiDetails{Name: "tdns-imr", BaseURL: "https://127.0.0.1:8085/api/v1", ApiKey: "k", AuthMethod: "X-API-Key",
		TLSAuth: "pin", Pins: []string{pinOf("x")}, ConfigFile: cfg}
	socketOf := func(t *testing.T, e ApiDetails) string {
		t.Helper()
		c, _, err := newApiClientFor(e, CliClientConf{})
		if err != nil {
			t.Fatal(err)
		}
		return c.Socket
	}

	if s := socketOf(t, e); s != "" {
		t.Errorf("nothing listening: socket %q, want TCP", s)
	}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if s := socketOf(t, e); s != sock {
		t.Errorf("socket answering: socket %q, want %s", s, sock)
	}
	ForceTCP = true
	if s := socketOf(t, e); s != "" {
		t.Errorf("--tcp: socket %q, want TCP", s)
	}
	ForceTCP = false

	// An entry for a daemon on another host whose config-file: path happens
	// to exist here too is not this daemon.
	elsewhere := e
	elsewhere.BaseURL = "https://192.0.2.1:8085/api/v1"
	if s := socketOf(t, elsewhere); s != "" {
		t.Errorf("an entry for another address: socket %q, want TCP", s)
	}
	// An entry with no TCP address at all is the socket's.
	if s := socketOf(t, ApiDetails{Name: "tdns-imr", AuthMethod: "none", ConfigFile: cfg}); s != sock {
		t.Errorf("a socket-only entry: socket %q, want %s", s, sock)
	}

	noCfg := e
	noCfg.ConfigFile = ""
	if s := socketOf(t, noCfg); s != "" {
		t.Errorf("no config-file: socket %q, want TCP", s)
	}

	writeFile(t, cfg, daemonYAML("", "127.0.0.1:8085", "k", "   socket: none\n"))
	if s := socketOf(t, e); s != "" {
		t.Errorf("socket: none: socket %q, want TCP", s)
	}
	// A socket-only entry (no baseurl) whose socket is off cannot be used.
	sockOnly := ApiDetails{Name: "tdns-imr", AuthMethod: "none", ConfigFile: cfg}
	if _, _, err := newApiClientFor(sockOnly, CliClientConf{}); err == nil || !strings.Contains(err.Error(), "no baseurl") {
		t.Errorf("socket-only entry, socket off: err = %v, want one saying it has no baseurl", err)
	}
}

// With pins, the client ignores rootca, so a rootca: file that is gone does
// not fail an entry that verifies by pin.
func TestPinnedEntryIgnoresRootCA(t *testing.T) {
	e := ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", TLSAuth: "pin", Pins: []string{pinOf("a")},
		RootCA: "/nonexistent/ca.pem", AuthMethod: "none"}
	if _, _, err := newApiClientFor(e, CliClientConf{}); err != nil {
		t.Errorf("pinned entry with a stale rootca: %v", err)
	}
	e.TLSAuth, e.Pins = "pkix", nil
	if _, _, err := newApiClientFor(e, CliClientConf{}); err == nil {
		t.Error("a pkix entry with a missing rootca file was accepted")
	}
}

// ReadCliClientConf sees what the CLI loads: a client: block that lives only
// in an include: file, or in cli.localconfig.
func TestReadCliClientConfMerges(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "tdns-ncli.yaml")
	writeFile(t, filepath.Join(dir, "client.yaml"), "client:\n   cert: /etc/tdns/inc.crt\n   key: /etc/tdns/inc.key\n")
	writeFile(t, main, "include:\n   - client.yaml\n")
	if cc := ReadCliClientConf(main); cc.Cert != "/etc/tdns/inc.crt" || cc.Key != "/etc/tdns/inc.key" {
		t.Errorf("client: from an include: %+v", cc)
	}

	local := filepath.Join(dir, "local.yaml")
	writeFile(t, local, "client:\n   cert: /etc/tdns/local.crt\n   key: /etc/tdns/local.key\n")
	writeFile(t, main, "cli:\n   localconfig: "+local+"\n")
	if cc := ReadCliClientConf(main); cc.Cert != "/etc/tdns/local.crt" {
		t.Errorf("client: from cli.localconfig: %+v", cc)
	}

	if cc := ReadCliClientConf(filepath.Join(dir, "absent.yaml")); cc != (CliClientConf{}) {
		t.Errorf("no file: %+v, want the zero value", cc)
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

// The reload after an access-file edit goes over the daemon's local socket
// when it can, not over the role's TCP entry: a daemon that started with a
// broken access file answers 503 on TCP until this very reload. And a reply
// saying the access file was NOT reloaded is a failure, not "Reloaded".
func TestAccessReloadPrefersTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ncli") // short: a socket path has a length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	reply := "Config reloaded. Access file reloaded: 1 client(s), keyauth on."
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(tdns.ConfigResponse{Msg: reply})
	})}
	go srv.Serve(ln)
	defer srv.Close()

	// The role's own entry reaches nothing: only the socket can answer.
	withCleanRoleRegistry(t)
	RegisterRole("auth", "tdns-auth")
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })
	apiConfig = &CliConf{ApiServers: []ApiDetails{{Name: "tdns-auth", BaseURL: "https://127.0.0.1:1/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: "insecure"}}}
	if err := InitApiClients(apiConfig); err != nil {
		t.Fatal(err)
	}

	if err := reloadForAccess("auth", sock); err != nil {
		t.Errorf("reload with the socket there: %v", err)
	}
	mu.Lock()
	reply = "Config reloaded. " + tdns.AccessFileNotReloaded + " (the running policy is unchanged): bad pin"
	mu.Unlock()
	if err := reloadForAccess("auth", sock); err == nil || !strings.Contains(err.Error(), "did NOT apply") {
		t.Errorf("a reply saying the access file was not reloaded: err = %v, want a failure", err)
	}
	// No socket file: the role's entry gets the reload, and here it fails.
	if err := reloadForAccess("auth", filepath.Join(dir, "absent.sock")); err == nil || !strings.Contains(err.Error(), "reload failed") {
		t.Errorf("no socket: err = %v, want the TCP entry's failure", err)
	}
}

// A replaced access file keeps its owner and group, and a new one takes the
// daemon config's, so the daemon can still read it after root edits it.
// Exercised with a second group of the test's user: the one change of owner
// an unprivileged process may make.
func TestAccessFileKeepsItsGroup(t *testing.T) {
	dir := t.TempDir()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, dirGid, ok := fileOwner(fi)
	if !ok {
		t.Skip("no file owners on this platform")
	}
	groups, _ := os.Getgroups()
	alt := -1
	for _, g := range groups {
		if g != dirGid && g != os.Getegid() {
			alt = g
			break
		}
	}
	if alt < 0 {
		t.Skip("the test user has no second group to give a file")
	}
	daemonCfg := filepath.Join(dir, "tdns-auth.yaml")
	writeFile(t, daemonCfg, "service:\n   name: TDNS-AUTH\n")
	os.Chmod(daemonCfg, 0o640)
	if err := os.Chown(daemonCfg, -1, alt); err != nil {
		t.Skipf("cannot give the daemon config group %d: %v", alt, err)
	}
	gidOf := func(p string) int {
		t.Helper()
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		_, gid, _ := fileOwner(fi)
		return gid
	}

	access := filepath.Join(dir, "access.yaml")
	if err := writeAccessFile(access, nil, []byte("clients: []\n"), daemonCfg); err != nil {
		t.Fatal(err)
	}
	if g := gidOf(access); g != alt {
		t.Errorf("new access file has group %d, want the daemon config's %d", g, alt)
	}
	if err := writeAccessFile(access, []byte("clients: []\n"), []byte("keyauth: false\nclients: []\n"), daemonCfg); err != nil {
		t.Fatal(err)
	}
	if g := gidOf(access); g != alt {
		t.Errorf("replaced access file has group %d, want the old file's %d", g, alt)
	}
}

// A socket entry has no TLS and sends no credentials, so a leftover rootca:
// or authmethod: certificate does not stop it. A pinned entry with a leftover
// rootca: tlsa is checked, not skipped as a TLSA entry.
func TestLeftoverSettingsDoNotStopAnEntry(t *testing.T) {
	sockEntry := ApiDetails{Name: "s", BaseURL: "unix:///var/run/tdns/tdns-auth.sock", AuthMethod: "certificate", RootCA: "/nonexistent/ca.pem"}
	if _, _, err := newApiClientFor(sockEntry, CliClientConf{Cert: "/nonexistent/c.crt", Key: "/nonexistent/c.key"}); err != nil {
		t.Errorf("socket entry with leftover TLS settings: %v", err)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(tdns.PingResponse{Msg: "pong", Pings: 1, Pongs: 1})
	}))
	defer srv.Close()
	pinned := ApiDetails{Name: "p", BaseURL: srv.URL + "/api/v1", AuthMethod: "none", TLSAuth: "pin",
		Pins: []string{tdns.SPKISHA256(srv.Certificate())}, RootCA: "tlsa"}
	if res := CheckEntries([]ApiDetails{pinned}, CliClientConf{}, 5*time.Second); !strings.HasPrefix(res[0], "ok") {
		t.Errorf("pinned entry with a leftover rootca: tlsa: %q, want it checked", res[0])
	}
}

// client init with a pair outside the default place says where it is: the
// client loads the default pair unless client: names another.
func TestClientInitNamesACustomPair(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "me.crt"), filepath.Join(dir, "me.key")
	out := captureStdout(t, func() {
		c := newClientInitCmd()
		c.SetArgs([]string{"--cert", cert, "--key", key, "--name", "me"})
		if err := c.Execute(); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{"client:", "cert: " + cert, "key:  " + key} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not say %q:\n%s", want, out)
		}
	}
}

// The client commands edit the local daemon's files, so a role entry without
// config-file: must be that daemon's own socket. A TCP address identifies no
// daemon by itself (another may hold it while this one serves its socket
// alone), not even this host's loopback on the daemon's configured port.
func TestEntryIsDaemonSocket(t *testing.T) {
	info := &DaemonApi{Socket: "/var/run/tdns/tdns-auth.sock", Addresses: []string{"127.0.0.1:8989"}}
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"unix:///var/run/tdns/tdns-auth.sock", true},
		{"UNIX:///var/run/tdns/tdns-auth.sock", true},
		{"unix:///var/run/tdns/other.sock", false},
		{"https://127.0.0.1:8989/api/v1", false},
		{"https://localhost:8989/api/v1", false},
		{"https://192.0.2.99:8989/api/v1", false},
	} {
		if got := entryIsDaemonSocket(ApiDetails{Name: "tdns-auth", BaseURL: tc.url}, info); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.url, got, tc.want)
		}
	}
	if entryIsDaemonSocket(ApiDetails{BaseURL: "unix:///var/run/tdns/tdns-auth.sock"}, &DaemonApi{}) {
		t.Error("a daemon config with no socket matched a socket entry")
	}
}

// configToDaemon asks the socket first, so `client list` still sees the
// running policy after `client keyauth off` has made the role's key entry
// useless.
func TestStatusGoesOverTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ncli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var cp tdns.ConfigPost
		json.NewDecoder(r.Body).Decode(&cp)
		json.NewEncoder(w).Encode(tdns.ConfigResponse{Msg: "via the socket: " + cp.Command})
	})}
	go srv.Serve(ln)
	defer srv.Close()
	withCleanRoleRegistry(t)
	RegisterRole("auth", "tdns-auth")
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })
	apiConfig = &CliConf{ApiServers: []ApiDetails{{Name: "tdns-auth", BaseURL: "https://127.0.0.1:1/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: "insecure"}}}
	if err := InitApiClients(apiConfig); err != nil {
		t.Fatal(err)
	}
	resp, err := configToDaemon("auth", sock, tdns.ConfigPost{Command: "status"})
	if err != nil || resp.Msg != "via the socket: status" {
		t.Errorf("status: %q, %v; want it over the socket", resp.Msg, err)
	}
}

// A socket URL spelled with another case is still the socket: the client
// knows only "unix://", and taking it for TCP would read its rootca.
func TestUnixSchemeAnyCase(t *testing.T) {
	e := ApiDetails{Name: "s", BaseURL: "UNIX:///var/run/tdns/Admin.sock", AuthMethod: "none", RootCA: "/nonexistent/ca.pem"}
	api, _, err := newApiClientFor(e, CliClientConf{})
	if err != nil {
		t.Fatalf("UNIX:// entry: %v", err)
	}
	if api.Socket != "/var/run/tdns/Admin.sock" {
		t.Errorf("socket %q, want the path with its case kept", api.Socket)
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

	// A key entry and a certificate entry of ONE daemon pin its key; that
	// is not two daemons sharing a key.
	one := []ApiDetails{
		{Name: "tdns-auth", BaseURL: "https://192.0.2.1:8989/api/v1", Pins: []string{a}},
		{Name: "authkey", BaseURL: "https://192.0.2.1:8989/api/v1", Pins: []string{a}},
	}
	if w := duplicatePins(one); len(w) != 0 {
		t.Errorf("two entries of one daemon warned: %v", w)
	}
	// A third entry for another daemon with the same key still warns, and
	// names each daemon once.
	w = duplicatePins(append(one, ApiDetails{Name: "other", BaseURL: "https://192.0.2.2:8989/api/v1", Pins: []string{a}}))
	if len(w) != 1 || !strings.Contains(w[0], "tdns-auth and other") {
		t.Errorf("two daemons sharing a key: %v", w)
	}
}
