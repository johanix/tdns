package cli

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

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

// testClientPair writes a client pair for the test and returns the client:
// block that names it: an https entry presents it.
func testClientPair(t *testing.T) CliClientConf {
	t.Helper()
	dir := t.TempDir()
	cc := CliClientConf{Cert: filepath.Join(dir, "c.crt"), Key: filepath.Join(dir, "c.key")}
	if _, _, err := ensureClientCert(cc.Cert, cc.Key, "test"); err != nil {
		t.Fatal(err)
	}
	return cc
}

// An https entry verifies the daemon by its pins and presents the client
// certificate; anything less is refused with the command that fixes it.
// Plain http is refused: the management API is TLS only. The socket needs
// nothing.
func TestNewApiClientForVerification(t *testing.T) {
	asNcli(t)
	cc := testClientPair(t)
	for _, tc := range []struct {
		name    string
		e       ApiDetails
		cc      CliClientConf
		wantErr string
	}{
		{name: "https with no pins", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1"}, cc: cc, wantErr: "no pin of the daemon's certificate"},
		{name: "the refusal says how to pin", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", ConfigFile: "/etc/tdns/tdns-imr.yaml"}, cc: cc, wantErr: "fix: tdns-ncli config update a --cert"},
		{name: "no config-file: the likely daemon config", e: ApiDetails{Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:1/api/v1"}, cc: cc, wantErr: "fix: tdns-ncli config update auth2 --cert --daemon-config /etc/tdns/tdns-auth2.yaml"},
		{name: "pinned", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", Pins: []string{pinOf("d")}}, cc: cc},
		{name: "plain http", e: ApiDetails{Name: "a", BaseURL: "http://127.0.0.1:1/api/v1", ConfigFile: "/etc/tdns/tdns-auth.yaml"}, cc: cc, wantErr: "TLS only; fix: tdns-ncli config update a --cert"},
		{name: "neither https nor unix", e: ApiDetails{Name: "a", BaseURL: "ftp://127.0.0.1:1/"}, cc: cc, wantErr: "neither https:// nor unix://"},
		{name: "the socket needs nothing", e: ApiDetails{Name: "a", BaseURL: "unix:///var/run/tdns/x.sock"}, cc: CliClientConf{Cert: "/nonexistent/c.crt", Key: "/nonexistent/c.key"}},
		{name: "no client certificate", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", Pins: []string{pinOf("d")}},
			cc: CliClientConf{Cert: "/nonexistent/c.crt", Key: "/nonexistent/c.key"}, wantErr: "fix: tdns-ncli client init"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, warn, err := newApiClientFor(tc.e, tc.cc)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || api == nil || warn != "" {
				t.Fatalf("err = %v, warning %q", err, warn)
			}
		})
	}
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
	// Outside /etc/tdns the default is named after the whole path.
	sock := tdns.ApiSocketPath("", cfg)
	if filepath.Dir(sock) != dir || !strings.HasSuffix(sock, "_tdns-imr.yaml.sock") {
		t.Fatalf("default socket %q, want one in %s named after %s", sock, dir, cfg)
	}
	if got, addrs := daemonSocket(cfg); got != sock || len(addrs) != 1 || addrs[0] != "127.0.0.1:8085" {
		t.Fatalf("daemonSocket = %q %q, want the default %s and 127.0.0.1:8085", got, addrs, sock)
	}
	cc := testClientPair(t)
	e := ApiDetails{Name: "imr", BaseURL: "https://127.0.0.1:8085/api/v1", Pins: []string{pinOf("x")}, ConfigFile: cfg}
	socketOf := func(t *testing.T, e ApiDetails) string {
		t.Helper()
		c, _, err := newApiClientFor(e, cc)
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
	// The daemon on the socket says which config it runs (identity).
	var mu sync.Mutex
	runs := cfg
	var sent []string // the expected config each request named
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, r.Header.Get(tdns.ExpectConfigFileHeader))
		json.NewEncoder(w).Encode(tdns.ConfigResponse{ConfigFile: runs})
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	if s := socketOf(t, e); s != sock {
		t.Errorf("socket answering: socket %q, want %s", s, sock)
	}
	// A command over the chosen socket names the entry's config, so that a
	// daemon that took the socket since the check refuses it.
	c, _, err := newApiClientFor(e, cc)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	sent = nil
	mu.Unlock()
	if _, err := SendConfigCommand(c, tdns.ConfigPost{Command: "status"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(sent) != 1 || sent[0] != cfg {
		t.Errorf("the command named %q, want %s", sent, cfg)
	}
	mu.Unlock()

	// Another daemon holds the socket: its identity is not this entry's
	// config, so the entry goes over TCP and says why; one with no TCP
	// address is refused.
	mu.Lock()
	runs = "/etc/tdns/other.yaml"
	mu.Unlock()
	if c, warn, err := newApiClientFor(e, cc); err != nil || c.Socket != "" || !strings.Contains(warn, "runs /etc/tdns/other.yaml") {
		t.Errorf("another daemon on the socket: socket %q, warning %q, err %v; want TCP and a warning naming it", c.Socket, warn, err)
	}
	if _, _, err := newApiClientFor(ApiDetails{Name: "imr", ConfigFile: cfg}, cc); err == nil || !strings.Contains(err.Error(), "runs /etc/tdns/other.yaml") {
		t.Errorf("another daemon, socket-only entry: err = %v, want a refusal naming it", err)
	}
	mu.Lock()
	runs = cfg
	mu.Unlock()

	// --tcp with an entry written as a socket entry: no TCP address to use.
	ForceTCP = true
	if _, _, err := newApiClientFor(ApiDetails{Name: "old", BaseURL: "unix://" + sock}, CliClientConf{}); err == nil || !strings.Contains(err.Error(), "no TCP address for --tcp") {
		t.Errorf("--tcp, socket entry: err = %v, want a refusal", err)
	}
	ForceTCP = false
	// ping says which way it went: the socket is chosen at run time.
	if c, _, err := newApiClientFor(e, cc); err != nil || pingHow(c, tdns.PingResponse{}) != sock {
		t.Errorf("ping's parentheses: %v", err)
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
	if s := socketOf(t, ApiDetails{Name: "imr", ConfigFile: cfg}); s != sock {
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
	sockOnly := ApiDetails{Name: "imr", ConfigFile: cfg}
	if _, _, err := newApiClientFor(sockOnly, cc); err == nil || !strings.Contains(err.Error(), "no baseurl") {
		t.Errorf("socket-only entry, socket off: err = %v, want one saying it has no baseurl", err)
	}
}

// Pins are written escaped, so one read from a hand-written file with a quote
// or a backslash in it reads back as itself.
func TestPinsFlowEscapes(t *testing.T) {
	pins := []string{pinOf("a"), `odd"pin\x`}
	var got struct{ Pins []string }
	if err := yaml.Unmarshal([]byte("pins: "+pinsFlow(pins)), &got); err != nil || !reflect.DeepEqual(got.Pins, pins) {
		t.Errorf("pinsFlow %s read back as %q (%v)", pinsFlow(pins), got.Pins, err)
	}
}

// A URL without a port has its scheme's, so it matches a daemon address
// that spells the port out; other ports stay apart.
func TestHostPortDefaultPorts(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"https://127.0.0.1/api/v1", "127.0.0.1:443"},
		{"https://127.0.0.1:443/api/v1", "127.0.0.1:443"},
		{"http://Localhost/api/v1", "localhost:80"},
		{"https://[::1]/api/v1", "[::1]:443"},
		{"https://127.0.0.1:8989/api/v1", "127.0.0.1:8989"},
		{"unix:///var/run/tdns/x.sock", ""},
		{"", ""},
	} {
		if got := hostPort(tc.url); got != tc.want {
			t.Errorf("hostPort(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

// ping's one line says in its parentheses how the CLI reached the daemon and
// who the daemon took it for.
func TestPingHow(t *testing.T) {
	sock := tdns.NewClientWithOptions("a", "unix:///var/run/tdns/etc-tdns-tdns-auth.sock", tdns.ClientOptions{})
	tlsc := tdns.NewClientWithOptions("a", "https://127.0.0.1:8989/api/v1", tdns.ClientOptions{Pins: []string{pinOf("a")}})
	for _, tc := range []struct {
		name string
		api  *tdns.ApiClient
		pr   tdns.PingResponse
		want string
	}{
		{"socket", sock, tdns.PingResponse{Role: "admin", Via: "local socket", Identity: "local"}, "/var/run/tdns/etc-tdns-tdns-auth.sock"},
		{"certificate", tlsc, tdns.PingResponse{Role: "read-write", Via: "certificate", Identity: "anna"}, "TLS, read-write, certificate anna"},
		{"older daemon", tlsc, tdns.PingResponse{Auth: "authenticated as anna (read-write) by certificate"}, "TLS, authenticated as anna (read-write) by certificate"},
		{"oldest daemon", tlsc, tdns.PingResponse{}, "TLS"},
	} {
		if got := pingHow(tc.api, tc.pr); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A refusal is an error with its fix, found as such through the wrapping
// GetApiClient may add.
// asNcli makes this a tdns-ncli run for the test: its default CLI config is
// tdns-ncli's own, as its root sets it.
func asNcli(t *testing.T) {
	t.Helper()
	saved := DefaultCliConfigFile
	t.Cleanup(func() { DefaultCliConfigFile = saved })
	DefaultCliConfigFile = tdns.DefaultNcliCfgFile
}

func TestPinRefusal(t *testing.T) {
	asNcli(t)
	err := fmt.Errorf("wrapped: %w", pinRefusal(ApiDetails{Name: "auth", ConfigFile: "/etc/tdns/tdns-auth.yaml"}, "its entry has no pin"))
	var r clientRefusal
	if !errors.As(err, &r) || r.entry != "auth" || r.fix != "tdns-ncli config update auth --cert" {
		t.Errorf("refusal = %+v from %v", r, err)
	}
	if !strings.Contains(err.Error(), "not connecting to auth: its entry has no pin; fix: tdns-ncli config update") {
		t.Errorf("one-line form: %v", err)
	}
	if r := pinRefusal(ApiDetails{Name: "old"}, "x"); r.fix != "tdns-ncli config update old --cert --daemon-config /etc/tdns/tdns-old.yaml" {
		t.Errorf("no config-file: fix = %q", r.fix)
	}
	// Read from another CLI config, the fix names it.
	defer func(was *CliConf) { apiConfig = was }(apiConfig)
	apiConfig = &CliConf{File: "/x/my cli.yaml"}
	if r := pinRefusal(ApiDetails{Name: "a", ConfigFile: "/x/d.yaml"}, "x"); r.fix != "tdns-ncli --config '/x/my cli.yaml' config update a --cert" {
		t.Errorf("another CLI config: fix = %q", r.fix)
	}
}

// A refusal made while InitApiClients builds the clients names the CLI
// config of this run, not one from before.
func TestInitApiClientsRefusalNamesTheCliConfig(t *testing.T) {
	withCleanRoleRegistry(t)
	RegisterRole("auth", "auth")
	// InitApiClients changes the client tables: as they were afterwards.
	errs, warns, pending := maps.Clone(apiClientErrors), maps.Clone(apiClientWarnings), maps.Clone(socketPending)
	clients, api, was := maps.Clone(tdns.Globals.ApiClients), tdns.Globals.Api, apiConfig
	t.Cleanup(func() {
		apiClientErrors, apiClientWarnings, socketPending = errs, warns, pending
		tdns.Globals.ApiClients, tdns.Globals.Api, apiConfig = clients, api, was
	})
	apiConfig = &CliConf{File: "/x/old.yaml"}
	conf := &CliConf{File: "/x/my cli.yaml", ApiServers: []ApiDetails{
		{Name: "auth", BaseURL: "https://127.0.0.1:1/api/v1"},
	}}
	if err := InitApiClients(conf); err != nil {
		t.Fatal(err)
	}
	var r clientRefusal
	if err := apiClientErrors["auth"]; !errors.As(err, &r) || !strings.HasPrefix(r.fix, "tdns-ncli --config '/x/my cli.yaml' config update auth --cert") {
		t.Errorf("refusal = %+v (%v), want this run's CLI config named", r, err)
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

// config list --check pings a pinned entry with the client certificate.
func TestCheckEntriesPingsAPinnedEntry(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(tdns.PingResponse{Msg: "pong", Pings: 1, Pongs: 1})
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	pinned := ApiDetails{Name: "p", BaseURL: srv.URL + "/api/v1", Pins: []string{tdns.SPKISHA256(srv.Certificate())}}
	if res := CheckEntries([]ApiDetails{pinned}, testClientPair(t), 5*time.Second); !strings.HasPrefix(res[0], "ok") {
		t.Errorf("pinned entry: %q, want it checked", res[0])
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

// A socket URL spelled with another case is still the socket: the client
// knows only "unix://", and taking it for TCP would refuse it.
func TestUnixSchemeAnyCase(t *testing.T) {
	e := ApiDetails{Name: "s", BaseURL: "UNIX:///var/run/tdns/Admin.sock"}
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
	if len(w) != 1 || !strings.Contains(w[0], "x and y have the same certificate pin") || strings.Contains(w[0], "key") {
		t.Errorf("shared pin: %v", w)
	}

	// Two entries of ONE daemon have its pin; that is not two daemons
	// sharing a certificate.
	one := []ApiDetails{
		{Name: "auth", BaseURL: "https://192.0.2.1:8989/api/v1", Pins: []string{a}},
		{Name: "authtoo", BaseURL: "https://192.0.2.1:8989/api/v1", Pins: []string{a}},
	}
	if w := duplicatePins(one); len(w) != 0 {
		t.Errorf("two entries of one daemon warned: %v", w)
	}
	// A third entry for another daemon with the same pin still warns, and
	// names each daemon once.
	w = duplicatePins(append(one, ApiDetails{Name: "other", BaseURL: "https://192.0.2.2:8989/api/v1", Pins: []string{a}}))
	if len(w) != 1 || !strings.Contains(w[0], "auth and other") {
		t.Errorf("two daemons sharing a certificate: %v", w)
	}
}

// A daemon's local admin socket is asked which config it runs when its entry
// is first used, not when the CLI starts: a command uses one entry, and asking
// every daemon in the CLI config first cost a round trip each (and printed a
// status line each under -v).
func TestSocketCheckedOnFirstUse(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ncli") // short: a socket path has a limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	savedDir, savedTCP, savedVerbose := tdns.DefaultApiSocketDir, ForceTCP, tdns.Globals.Verbose
	savedClients, savedPending, savedConfig := tdns.Globals.ApiClients, socketPending, apiConfig
	t.Cleanup(func() {
		tdns.DefaultApiSocketDir, ForceTCP, tdns.Globals.Verbose = savedDir, savedTCP, savedVerbose
		tdns.Globals.ApiClients, socketPending, apiConfig = savedClients, savedPending, savedConfig
	})
	tdns.DefaultApiSocketDir, ForceTCP, tdns.Globals.Verbose = dir, false, true
	tdns.Globals.ApiClients, socketPending = map[string]*tdns.ApiClient{}, map[string]pendingClient{}

	var mu sync.Mutex
	asked := map[string]int{}
	serve := func(cfg, addr string) {
		writeFile(t, cfg, daemonYAML("", addr, "k", ""))
		ln, err := net.Listen("unix", tdns.ApiSocketPath("", cfg))
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			asked[cfg]++
			mu.Unlock()
			json.NewEncoder(w).Encode(tdns.ConfigResponse{ConfigFile: cfg})
		})}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
	}
	authCfg, imrCfg := filepath.Join(dir, "tdns-auth.yaml"), filepath.Join(dir, "tdns-imr.yaml")
	serve(authCfg, "127.0.0.1:8989")
	serve(imrCfg, "127.0.0.1:8085")
	count := func(cfg string) int {
		mu.Lock()
		defer mu.Unlock()
		return asked[cfg]
	}

	withCleanRoleRegistry(t)
	RegisterRole("auth", "auth")
	RegisterRole("imr", "imr")
	conf := &CliConf{Client: testClientPair(t), ApiServers: []ApiDetails{
		{Name: "auth", BaseURL: "https://127.0.0.1:8989/api/v1", Pins: []string{pinOf("a")}, ConfigFile: authCfg},
		{Name: "imr", ConfigFile: imrCfg}, // no baseurl: the socket or nothing
	}}
	out := captureStdout(t, func() {
		if err := InitApiClients(conf); err != nil {
			t.Fatal(err)
		}
	})
	if n, m := count(authCfg), count(imrCfg); n != 0 || m != 0 {
		t.Fatalf("at start: %d and %d identity requests, want none", n, m)
	}
	// Until first use, code reading the client table directly has the TCP
	// client; an entry with no TCP address has none yet.
	if c := tdns.Globals.ApiClients["auth"]; c == nil || c.Socket != "" {
		t.Errorf("before use: auth client %+v, want the TCP one", c)
	}
	if c := tdns.Globals.ApiClients["imr"]; c != nil {
		t.Errorf("before use: imr client over %q, want none", c.BaseUrl)
	}

	out += captureStdout(t, func() {
		for range 2 {
			c, err := GetApiClient("auth", false)
			if err != nil || c.Socket != tdns.ApiSocketPath("", authCfg) {
				t.Errorf("auth: client %+v, err %v; want the socket", c, err)
			}
		}
	})
	if n, m := count(authCfg), count(imrCfg); n != 1 || m != 0 {
		t.Errorf("after two uses of auth: %d and %d identity requests, want 1 and 0", n, m)
	}
	if c := ApiClientByName("imr"); c == nil || c.Socket != tdns.ApiSocketPath("", imrCfg) {
		t.Errorf("imr by name: %+v, want the socket", c)
	}
	if m := count(imrCfg); m != 1 {
		t.Errorf("imr: %d identity requests, want 1", m)
	}
	if strings.Contains(out, "Status:") {
		t.Errorf("the socket check printed under -v: %q", out)
	}
}

// The operator's pair defaults to a certs/ directory, where certificates and
// keys are looked for, never loose next to the configs.
func TestDefaultClientCertPathsAreInCerts(t *testing.T) {
	cert, key := DefaultClientCertPaths()
	for _, p := range []string{cert, key} {
		if filepath.Base(filepath.Dir(p)) != "certs" {
			t.Errorf("default %s is not in a certs/ directory", p)
		}
	}
}

// fakeDaemon is a daemon on a local admin socket that runs config: it
// answers /access with reply, and /config, and refuses a request that names
// another config (412), as a daemon does. It records the requests.
type fakeDaemon struct {
	mu     sync.Mutex
	config string // the config it runs
	reply  tdns.AccessResponse
	posts  []tdns.AccessPost
	seen   []string // per request: path, and the config it named
}

func newFakeDaemon(t *testing.T, sock, config string) *fakeDaemon {
	t.Helper()
	d := &fakeDaemon{config: config}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		want := r.Header.Get(tdns.ExpectConfigFileHeader)
		d.seen = append(d.seen, r.URL.Path+" "+want)
		if want != d.config {
			http.Error(w, "this daemon runs "+d.config+", not "+want, http.StatusPreconditionFailed)
			return
		}
		if r.URL.Path == "/api/v1/config" {
			json.NewEncoder(w).Encode(tdns.ConfigResponse{Msg: "Config reloaded.", ConfigFile: d.config})
			return
		}
		var ap tdns.AccessPost
		json.NewDecoder(r.Body).Decode(&ap)
		d.posts = append(d.posts, ap)
		json.NewEncoder(w).Encode(d.reply)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return d
}

func (d *fakeDaemon) last(t *testing.T) (tdns.AccessPost, string) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.posts) == 0 {
		t.Fatal("the daemon got no /access request")
	}
	return d.posts[len(d.posts)-1], d.seen[len(d.seen)-1]
}

// The client commands keep their arguments and flags, and send each change
// to the daemon of the daemon config (--daemon-config, else the role's
// entry's config-file:), over its local socket, naming that config so that
// another daemon there refuses it. They print the daemon's words. Nothing
// else is touched: no access file, no reload.
func TestClientCommandsCallTheDaemon(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ncli") // short: a socket path has a limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "auth.sock")
	cfg := filepath.Join(dir, "tdns-auth.yaml")
	writeFile(t, cfg, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "k", "   socket: "+sock+"\n"))
	withCleanRoleRegistry(t)
	RegisterRole("auth", "auth")
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })
	apiConfig = nil // root with no CLI config: --daemon-config names the daemon

	d := newFakeDaemon(t, sock, cfg)
	d.mu.Lock()
	d.reply = tdns.AccessResponse{Msg: "Added anna (read-write).\nIn force: 1 client(s).", File: filepath.Join(dir, "access.yaml"),
		Clients:    []tdns.ApiAccessStatusClient{{Name: "anna", Pin: pinOf("anna"), Role: "read-write", Comment: "laptop"}},
		ServerPins: []string{pinOf("server")}}
	d.mu.Unlock()
	count := func() int {
		d.mu.Lock()
		defer d.mu.Unlock()
		return len(d.seen)
	}
	run := func(t *testing.T, args ...string) string {
		t.Helper()
		return captureStdout(t, func() {
			c := NewClientCmd("auth")
			c.SetArgs(args)
			if err := c.Execute(); err != nil {
				t.Error(err)
			}
		})
	}

	out := run(t, "add", "anna", "--pin", pinOf("anna"), "--role", "read-write", "--comment", "laptop", "--daemon-config", cfg, "--no-reload")
	ap, seen := d.last(t)
	if want := (tdns.AccessPost{Command: "add", Name: "anna", Pin: pinOf("anna"), Role: "read-write", Comment: "laptop"}); ap != want || seen != "/api/v1/access "+cfg {
		t.Errorf("add sent %+v to %q, want %+v naming %s", ap, seen, want, cfg)
	}
	if !strings.HasPrefix(out, "Added anna (read-write).\nIn force:") {
		t.Errorf("add printed %q, want the daemon's verdict first", out)
	}
	for _, tc := range []struct {
		args []string
		want tdns.AccessPost
	}{
		{[]string{"disable", "anna"}, tdns.AccessPost{Command: "disable", Name: "anna"}},
		{[]string{"enable", "anna"}, tdns.AccessPost{Command: "enable", Name: "anna"}},
		{[]string{"set-role", "anna", "read-only", "--dry-run"}, tdns.AccessPost{Command: "set-role", Name: "anna", Role: "read-only", DryRun: true}},
	} {
		run(t, append(tc.args, "--daemon-config", cfg)...)
		if ap, _ := d.last(t); ap != tc.want {
			t.Errorf("%v sent %+v, want %+v", tc.args, ap, tc.want)
		}
	}
	out = run(t, "list", "--daemon-config", cfg)
	for _, want := range []string{"Access file: " + d.reply.File, "anna", "# laptop", "Server pins", pinOf("server")} {
		if !strings.Contains(out, want) {
			t.Errorf("list does not print %q:\n%s", want, out)
		}
	}

	// Without --daemon-config: the role's entry's config-file:.
	apiConfig = &CliConf{ApiServers: []ApiDetails{{Name: "auth", BaseURL: "https://127.0.0.1:1/api/v1", ConfigFile: cfg}}}
	sent := count()
	run(t, "enable", "anna")
	if got := count() - sent; got != 1 {
		t.Fatalf("from the entry: %d requests sent, want one", got)
	}
	if ap, seen := d.last(t); ap != (tdns.AccessPost{Command: "enable", Name: "anna"}) || seen != "/api/v1/access "+cfg {
		t.Errorf("from the entry: sent %+v naming %q, want enable anna naming %s", ap, seen, cfg)
	}

	// An entry without config-file: names no daemon, unless it is the
	// default daemon's own socket: refused, nothing sent. --daemon-config
	// settles it.
	apiConfig = &CliConf{ApiServers: []ApiDetails{{Name: "auth", BaseURL: "https://127.0.0.1:1/api/v1"}}}
	sent = count()
	if err := runAccess("auth", "", tdns.AccessPost{Command: "enable", Name: "anna"}); err == nil || !strings.Contains(err.Error(), "has no config-file:") {
		t.Errorf("entry without config-file:: %v, want refused", err)
	} else {
		// A default daemon config that cannot be read says why, too.
		if _, serr := os.Stat(tdns.DefaultAuthCfgFile); serr != nil && !strings.Contains(err.Error(), "Reading the default daemon config failed:") {
			t.Errorf("entry without config-file:, no default config: %v, want the read error", err)
		}
		for _, l := range strings.Split(err.Error(), "\n") {
			if len("Error: "+l) > 72 {
				t.Errorf("refusal line over 72: %q", l)
			}
		}
	}
	if got := count() - sent; got != 0 {
		t.Errorf("entry without config-file:: %d requests sent, want none", got)
	}
	if err := runAccess("auth", cfg, tdns.AccessPost{Command: "enable", Name: "anna"}); err != nil {
		t.Errorf("entry without config-file:, --daemon-config: %v", err)
	}

	// A refusal is the daemon's words; config reload --daemon-config goes
	// over the same socket, naming the config.
	d.mu.Lock()
	d.reply = tdns.AccessResponse{Error: true, ErrorMsg: "\"anna\" is already there with another pin"}
	d.mu.Unlock()
	if err := runAccess("auth", cfg, tdns.AccessPost{Command: "add", Name: "anna"}); err == nil || err.Error() != d.reply.ErrorMsg {
		t.Errorf("refusal: %v, want the daemon's words", err)
	}
	if resp, err := configAtDaemon("auth", cfg, tdns.ConfigPost{Command: "reload"}); err != nil || resp.Msg != "Config reloaded." {
		t.Errorf("config reload --daemon-config: %+v %v", resp, err)
	}

	// Another daemon on the socket refuses before acting; no socket at all
	// says what the commands need.
	d.mu.Lock()
	d.config = "/etc/tdns/other.yaml"
	n := len(d.posts)
	d.mu.Unlock()
	err = runAccess("auth", cfg, tdns.AccessPost{Command: "list"})
	d.mu.Lock()
	handled := len(d.posts) != n
	d.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "this daemon runs /etc/tdns/other.yaml") || handled {
		t.Errorf("another daemon on the socket: %v (handled: %v), want its 412, the request not handled", err, handled)
	}
	other := filepath.Join(dir, "tdns-auth2.yaml")
	writeFile(t, other, daemonYAML("TDNS-AUTH", "127.0.0.1:8990", "k", "   socket: "+filepath.Join(dir, "absent.sock")+"\n"))
	if err := runAccess("auth", other, tdns.AccessPost{Command: "list"}); err == nil || !strings.Contains(err.Error(), "no daemon answers there") {
		t.Errorf("no daemon on the socket: %v", err)
	}
	writeFile(t, other, daemonYAML("TDNS-AUTH", "127.0.0.1:8990", "k", "   socket: none\n"))
	if err := runAccess("auth", other, tdns.AccessPost{Command: "list"}); err == nil || !strings.Contains(err.Error(), "serves no local admin socket") {
		t.Errorf("socket: none: %v", err)
	}
}

// The socket of an entry is its raw path, as the client dials it: not
// URL-decoded, and the scheme in any case.
func TestEntryIsDaemonSocketRawPath(t *testing.T) {
	info := &DaemonApi{Socket: "/var/run/tdns/auth%5Fwest.sock"}
	for _, c := range []struct {
		url  string
		want bool
	}{
		{"unix:///var/run/tdns/auth%5Fwest.sock", true},
		{"UNIX:///var/run/tdns/auth%5Fwest.sock", true},
		{"unix:///var/run/tdns/auth_west.sock", false},
		{"https://127.0.0.1:8989/api/v1", false},
		{"unix://", false},
	} {
		if got := entryIsDaemonSocket(ApiDetails{BaseURL: c.url}, info); got != c.want {
			t.Errorf("%s: %v, want %v", c.url, got, c.want)
		}
	}
	if entryIsDaemonSocket(ApiDetails{BaseURL: "unix://"}, &DaemonApi{}) {
		t.Error("no socket: want false")
	}
}

// A file that is not a socket at the socket path is a socket that cannot be
// used, as the BSDs say it (ENOTSOCK) and as Linux does (ECONNREFUSED): a
// plain refusal, not Go's raw dial error.
func TestSocketErrnoNotASocket(t *testing.T) {
	file := filepath.Join(t.TempDir(), "d.sock")
	writeFile(t, file, "not a socket\n")
	for _, c := range []struct {
		errno syscall.Errno
		sock  string
		want  string
	}{
		{syscall.ENOTSOCK, file, "Remove that\nfile, then start the daemon"},     // the BSDs
		{syscall.ECONNREFUSED, file, "Remove that\nfile, then start the daemon"}, // Linux
		{syscall.ECONNREFUSED, file + ".none", "no daemon answers there"},
		{syscall.ENOENT, file + ".none", "no daemon answers there"},
		{syscall.EACCES, file, "as root on the daemon's host"},
	} {
		err := fmt.Errorf("Post: %w", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", c.errno)})
		if got := socketErrno(err); got != c.errno {
			t.Errorf("%v: socketErrno = %v", c.errno, got)
		}
		msg := socketError(c.sock, err).Error()
		if !strings.HasPrefix(msg, "cannot use the daemon's local socket\n   "+c.sock+"\n") || !strings.Contains(msg, c.want) {
			t.Errorf("%v at %s: %q, want %q", c.errno, c.sock, msg, c.want)
		}
		for _, l := range strings.Split(msg, "\n") {
			if len(l) > 72 && !strings.Contains(l, c.sock) {
				t.Errorf("%v: line over 72 columns: %q", c.errno, l)
			}
		}
	}
}

// A plain-http entry is refused with the command that switches it to https
// with pins, config update --cert (config add writes new entries only), with
// --daemon-config when the entry has no config-file:.
func TestPlainHttpRefusalNamesConfigUpdate(t *testing.T) {
	asNcli(t)
	e := ApiDetails{Name: "remote", BaseURL: "http://192.0.2.1:8989/api/v1", ConfigFile: "/etc/tdns/tdns-auth.yaml"}
	var r clientRefusal
	if _, _, err := buildApiClient(e, CliClientConf{}, "", ""); !errors.As(err, &r) || r.fix != "tdns-ncli config update remote --cert" {
		t.Errorf("refusal %+v (%v)", r, err)
	}
	e.ConfigFile = ""
	if _, _, err := buildApiClient(e, CliClientConf{}, "", ""); !errors.As(err, &r) || r.fix != "tdns-ncli config update remote --cert --daemon-config /etc/tdns/tdns-remote.yaml" {
		t.Errorf("no config-file: refusal %+v (%v)", r, err)
	}
}
