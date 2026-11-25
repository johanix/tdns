package cli

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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
		{name: "https verifying nothing", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1"}, wantErr: "no pin of the daemon's certificate"},
		{name: "the refusal says how to pin", e: ApiDetails{Name: "a", BaseURL: "https://127.0.0.1:1/api/v1", ConfigFile: "/etc/tdns/tdns-imr.yaml"}, wantErr: "fix: tdns-ncli config add /etc/tdns/tdns-imr.yaml"},
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

	// A certificate config add cannot read: the new entry is refused, with a
	// fix, and nothing is written (the owner's ruling: no new https entry it
	// cannot pin).
	refused := func(t *testing.T, env *addEnv, d string, want ...string) {
		t.Helper()
		res, err := env.add(t, d, nil)
		if err == nil {
			t.Fatalf("added %+v; want a refusal", res.Entry)
		}
		for _, w := range append([]string{"not adding " + d + ": ", "\n  Fix: "}, want...) {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("refusal lacks %q:\n%v", w, err)
			}
		}
		if _, serr := os.Stat(env.cli); serr == nil {
			t.Error("the refused add wrote the CLI config")
		}
	}
	env2 := newAddEnv(t)
	d2 := filepath.Join(env2.dir, "tdns-auth.yaml")
	writeFile(t, d2, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "k", "   certfile: /nonexistent/api.crt\n"))
	refused(t, env2, d2, "cannot be pinned", "put the daemon's certificate at /nonexistent/api.crt")

	// A relative certfile is opened from the daemon's working directory,
	// which config add cannot know: refused, even though a file of that name
	// sits next to the daemon config, and the refusal says why.
	env3 := newAddEnv(t)
	writeFile(t, filepath.Join(env3.dir, "api.crt"), string(certPEM))
	d3 := filepath.Join(env3.dir, "tdns-auth.yaml")
	writeFile(t, d3, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "k", "   certfile: api.crt\n"))
	refused(t, env3, d3, "relative path", "absolute path")
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

	t.Run("an unreadable certificate, a pkix entry: its verification unchanged", func(t *testing.T) {
		env, d := setup(t, "apiservers:\n   - name: tdns-imr\n     baseurl: https://127.0.0.1:8085/api/v1\n     apikey: k\n     authmethod: X-API-Key\n     tlsauth: pkix\n     config-file: @D@\n")
		writeFile(t, d, daemonYAML("TDNS-IMR", "127.0.0.1:8085", "k", "   certfile: /nonexistent/api.crt\n"))
		res, err := env.add(t, d, nil)
		notes := strings.Join(res.Notes, " ")
		if err != nil || res.Pinned || strings.Contains(notes, "refuses") || !strings.Contains(notes, "verification is unchanged") {
			t.Errorf("%+v, %v; want a note that the pkix entry is unchanged, not that it is refused", res, err)
		}
	})

	t.Run("an unreadable certificate: a note, nothing changed", func(t *testing.T) {
		env, d := setup(t, "apiservers:\n   - name: tdns-imr\n     baseurl: https://127.0.0.1:8085/api/v1\n     apikey: k\n     authmethod: X-API-Key\n     config-file: @D@\n")
		writeFile(t, d, daemonYAML("TDNS-IMR", "127.0.0.1:8085", "k", "   certfile: /nonexistent/api.crt\n"))
		before, _ := os.ReadFile(env.cli)
		res, err := env.add(t, d, nil)
		if err != nil || res.Pinned || res.Wrote || !strings.Contains(strings.Join(res.Notes, " "), "refuses it over TCP (root may still reach the daemon over its local admin socket, while the daemon serves one and --tcp is not given)") {
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
	// Outside /etc/tdns the default is named after the whole path.
	sock := tdns.ApiSocketPath("", cfg)
	if filepath.Dir(sock) != dir || !strings.HasSuffix(sock, "_tdns-imr.yaml.sock") {
		t.Fatalf("default socket %q, want one in %s named after %s", sock, dir, cfg)
	}
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
	c, _, err := newApiClientFor(e, CliClientConf{})
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
	if c, warn, err := newApiClientFor(e, CliClientConf{}); err != nil || c.Socket != "" || !strings.Contains(warn, "runs /etc/tdns/other.yaml") {
		t.Errorf("another daemon on the socket: socket %q, warning %q, err %v; want TCP and a warning naming it", c.Socket, warn, err)
	}
	if _, _, err := newApiClientFor(ApiDetails{Name: "tdns-imr", AuthMethod: "none", ConfigFile: cfg}, CliClientConf{}); err == nil || !strings.Contains(err.Error(), "runs /etc/tdns/other.yaml") {
		t.Errorf("another daemon, socket-only entry: err = %v, want a refusal naming it", err)
	}
	mu.Lock()
	runs = cfg
	mu.Unlock()

	// --tcp with an entry written as a socket entry: no TCP address to use.
	ForceTCP = true
	if _, _, err := newApiClientFor(ApiDetails{Name: "old", BaseURL: "unix://" + sock, AuthMethod: "none"}, CliClientConf{}); err == nil || !strings.Contains(err.Error(), "no TCP address for --tcp") {
		t.Errorf("--tcp, socket entry: err = %v, want a refusal", err)
	}
	ForceTCP = false
	// ping says which way it went: the socket is chosen at run time.
	if c, _, err := newApiClientFor(e, CliClientConf{}); err != nil || pingHow(c, tdns.PingResponse{}) != sock {
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
	tlsc := tdns.NewClientWithOptions("a", "https://127.0.0.1:8989/api/v1", tdns.ClientOptions{Pins: []string{pinOf("a")}, AuthMethod: "X-API-Key", ApiKey: "k"})
	plain := tdns.NewClientWithOptions("a", "http://127.0.0.1:8989/api/v1", tdns.ClientOptions{RootCA: "insecure", AuthMethod: "X-API-Key", ApiKey: "k"})
	for _, tc := range []struct {
		name string
		api  *tdns.ApiClient
		pr   tdns.PingResponse
		want string
	}{
		{"socket", sock, tdns.PingResponse{Role: "admin", Via: "local socket", Identity: "local"}, "/var/run/tdns/etc-tdns-tdns-auth.sock"},
		{"key over TLS", tlsc, tdns.PingResponse{Role: "admin", Via: "api key", Identity: "apikey"}, "TLS, admin"},
		{"certificate", tlsc, tdns.PingResponse{Role: "read-write", Via: "certificate", Identity: "anna"}, "TLS, read-write, certificate anna"},
		{"plain http", plain, tdns.PingResponse{Role: "admin", Via: "api key", Identity: "apikey"}, "no TLS, admin"},
		{"older daemon", tlsc, tdns.PingResponse{Auth: "authenticated as apikey (admin) by api key"}, "TLS, authenticated as apikey (admin) by api key"},
		{"oldest daemon", tlsc, tdns.PingResponse{}, "TLS"},
	} {
		if got := pingHow(tc.api, tc.pr); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A refusal is an error with its fix, found as such through the wrapping
// GetApiClient may add.
func TestPinRefusal(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", pinRefusal(ApiDetails{Name: "tdns-auth", ConfigFile: "/etc/tdns/tdns-auth.yaml"}, "its entry has no pin"))
	var r clientRefusal
	if !errors.As(err, &r) || r.entry != "tdns-auth" || r.fix != "tdns-ncli config add /etc/tdns/tdns-auth.yaml" {
		t.Errorf("refusal = %+v from %v", r, err)
	}
	if !strings.Contains(err.Error(), "not connecting to tdns-auth: its entry has no pin; fix: tdns-ncli config add") {
		t.Errorf("one-line form: %v", err)
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

// A daemon config with no certfile/keyfile: the daemon serves its default
// API pair, which it writes at its first start. config add pins it, and
// before the first start makes it itself, exactly as the daemon would
// (tdns.EnsureDefaultApiCert): the daemon then uses it when it starts. A dry
// run says it would, and makes nothing. Half a pair, or a pair config add
// cannot write, is refused, and nothing is written.
func TestAddPinsTheDefaultApiCert(t *testing.T) {
	saved := runningAsRoot
	t.Cleanup(func() { runningAsRoot = saved })
	runningAsRoot = func() bool { return false }

	setup := func(t *testing.T) (*addEnv, string, string, string) {
		env := newAddEnv(t)
		d := filepath.Join(env.dir, "tdns-auth.yaml")
		writeFile(t, d, daemonYAMLDefaultCert("TDNS-AUTH", "127.0.0.1:8989", "k", ""))
		info, err := ReadDaemonApi(d, "")
		if err != nil {
			t.Fatal(err)
		}
		cert, key := tdns.ApiCertPaths(d)
		if info.CertFile != cert || !info.CertDefault {
			t.Fatalf("CertFile %q (default %v), want %s", info.CertFile, info.CertDefault, cert)
		}
		return env, d, cert, key
	}
	absent := func(t *testing.T, paths ...string) {
		t.Helper()
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				t.Errorf("%s was written", p)
			}
		}
	}
	refusal := func(t *testing.T, err error, want ...string) {
		t.Helper()
		if err == nil {
			t.Fatal("added; want a refusal")
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("refusal lacks %q:\n%v", w, err)
			}
		}
	}

	t.Run("before the first start: made, pinned", func(t *testing.T) {
		env, d, cert, key := setup(t)
		res, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true })
		if err != nil || res.ApiCertWould != cert || len(res.Entry.Pins) != 0 {
			t.Fatalf("dry run: %+v, %v; want it to say it would make the pair", res, err)
		}
		var sb strings.Builder
		printAddResult(&sb, res, true, env.cli)
		if !strings.Contains(sb.String(), "Would create the daemon's API certificate "+cert) {
			t.Errorf("dry run printed:\n%s", sb.String())
		}
		absent(t, cert, key, env.cli)

		res, err = env.add(t, d, nil)
		if err != nil || res.ApiCertCreated != cert {
			t.Fatalf("%+v, %v; want the pair made", res, err)
		}
		// The umask narrows the modes (077 leaves the certificate 0600): no
		// bit outside 0644, and the key no group or other bit at all, and
		// readable and writable by its owner.
		if fi, err := os.Stat(cert); err != nil || fi.Mode().Perm()&^0o644 != 0 {
			t.Errorf("%s: %v, want mode 0644 or narrower", cert, err)
		}
		if fi, err := os.Stat(key); err != nil || fi.Mode().Perm()&0o077 != 0 || fi.Mode().Perm()&0o600 != 0o600 {
			t.Errorf("%s: %v, want mode 0600", key, err)
		}
		data, _ := os.ReadFile(cert)
		block, _ := pem.Decode(data)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if got := env.entries(t); len(got) != 1 || got[0].TLSAuth != "pin" || len(got[0].Pins) != 1 || got[0].Pins[0] != tdns.SPKISHA256(leaf) {
			t.Errorf("entries %+v; want the pair made pinned", got)
		}
		sb.Reset()
		printAddResult(&sb, res, false, env.cli)
		if want := "Created the daemon's API certificate " + cert + "\n(key " + key + ", mode 0600); the daemon uses it when it starts."; !strings.Contains(sb.String(), want) {
			t.Errorf("printed:\n%s\nwant %q", sb.String(), want)
		}

		// After the first start (here: the pair as made): already known.
		if res, err := env.add(t, d, nil); err != nil || res.AlreadyKnown == "" || res.Wrote || res.ApiCertCreated != "" {
			t.Errorf("again: %+v, %v; want it already known, nothing made", res, err)
		}
	})

	t.Run("half a pair: refused", func(t *testing.T) {
		env, d, cert, key := setup(t)
		if _, _, err := tdns.EnsureDefaultApiCert(d, nil); err != nil {
			t.Fatal(err)
		}
		os.Remove(key)
		for _, dry := range []bool{true, false} {
			_, err := env.add(t, d, func(o *AddOptions) { o.DryRun = dry })
			refusal(t, err, "not adding "+d+": ", "without its key", "\n  Fix: put back the missing file")
		}
		absent(t, key, env.cli)
		if _, err := os.Stat(cert); err != nil {
			t.Error("the remaining certificate was removed")
		}
	})

	// A dry run refuses either half from what is there, in
	// EnsureDefaultApiCert's words, and writes nothing: it never calls
	// EnsureDefaultApiCert, which writes a pair if the remaining file went
	// meanwhile.
	t.Run("half a pair, dry run: refused from what is there", func(t *testing.T) {
		for _, certThere := range []bool{true, false} {
			env, d, cert, key := setup(t)
			if _, _, err := tdns.EnsureDefaultApiCert(d, nil); err != nil {
				t.Fatal(err)
			}
			kept, gone := cert, key
			if !certThere {
				kept, gone = key, cert
			}
			os.Remove(gone)
			before, _ := os.ReadFile(kept)
			_, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true })
			refusal(t, err, "not adding "+d+": ", tdns.HalfApiCertPairError(cert, key, certThere).Error(), "Fix: put back the missing file")
			absent(t, gone, env.cli)
			if after, rerr := os.ReadFile(kept); rerr != nil || string(after) != string(before) {
				t.Errorf("certThere %v: the remaining %s was changed or removed (%v)", certThere, kept, rerr)
			}
		}
	})

	t.Run("not writable here: refused", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes anywhere")
		}
		env, d, cert, key := setup(t)
		os.Chmod(env.dir, 0o555)
		t.Cleanup(func() { os.Chmod(env.dir, 0o755) })
		_, err := env.add(t, d, func(o *AddOptions) { o.TargetFile = filepath.Join(t.TempDir(), "cli.yaml"); o.CliConfig = o.TargetFile })
		refusal(t, err, "cannot be created at "+cert, "\n  Fix: run config add as root on the daemon's host")
		absent(t, cert, key)
	})

	// The pair is written only with the entry that pins it: an add refused
	// before its write leaves none, and says that nothing was written.
	t.Run("a hidden list: refused, no pair", func(t *testing.T) {
		env, d, cert, key := setup(t)
		local := filepath.Join(env.dir, "local.yaml")
		// cli.localconfig has a list of its own, which hides the main one.
		writeFile(t, local, "apiservers:\n   - name: tdns-imr\n     baseurl: http://192.0.2.1:8085/api/v1\n     apikey: k\n     authmethod: X-API-Key\n")
		writeFile(t, env.cli, "cli:\n   localconfig: "+local+"\napiservers:\n   - name: other\n     baseurl: http://192.0.2.2:8085/api/v1\n     apikey: k\n     authmethod: X-API-Key\n")
		_, err := env.add(t, d, nil)
		if err == nil || !strings.Contains(err.Error(), "Nothing was written") {
			t.Fatalf("err = %v, want a refusal saying nothing was written", err)
		}
		absent(t, cert, key)
	})

	t.Run("the CLI config cannot be written: the pair removed again", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes anywhere")
		}
		env, d, cert, key := setup(t)
		cliDir := filepath.Join(env.dir, "cli")
		os.Mkdir(cliDir, 0o755)
		env.cli = filepath.Join(cliDir, "tdns-ncli.yaml")
		// The lock file is there, so the add gets as far as its write.
		unlock, err := lockCliConfig(context.Background(), env.cli)
		if err != nil {
			t.Fatal(err)
		}
		unlock()
		os.Chmod(cliDir, 0o555)
		t.Cleanup(func() { os.Chmod(cliDir, 0o755) })
		_, err = env.add(t, d, nil)
		if err == nil || !strings.Contains(err.Error(), "is removed again") {
			t.Errorf("err = %v, want the write's failure, and the pair said removed", err)
		}
		absent(t, cert, key)
	})

	t.Run("a flow-style list: refused, no pair", func(t *testing.T) {
		env, d, cert, key := setup(t)
		writeFile(t, env.cli, "apiservers: []\n")
		_, err := env.add(t, d, nil)
		if err == nil || !strings.Contains(err.Error(), "nothing was written") || strings.Contains(err.Error(), "by hand") {
			t.Fatalf("err = %v, want a refusal saying nothing was written, and no entry to add by hand (its pin would be of a pair nobody has)", err)
		}
		absent(t, cert, key)
	})
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
	RegisterRole("auth", "tdns-auth")
	RegisterRole("imr", "tdns-imr")
	conf := &CliConf{ApiServers: []ApiDetails{
		{Name: "tdns-auth", BaseURL: "https://127.0.0.1:8989/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", TLSAuth: "pin", Pins: []string{pinOf("a")}, ConfigFile: authCfg},
		{Name: "tdns-imr", AuthMethod: "none", ConfigFile: imrCfg}, // no baseurl: the socket or nothing
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
	if c := tdns.Globals.ApiClients["tdns-auth"]; c == nil || c.Socket != "" {
		t.Errorf("before use: tdns-auth client %+v, want the TCP one", c)
	}
	if c := tdns.Globals.ApiClients["tdns-imr"]; c != nil {
		t.Errorf("before use: tdns-imr client over %q, want none", c.BaseUrl)
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
	if c := ApiClientByName("tdns-imr"); c == nil || c.Socket != tdns.ApiSocketPath("", imrCfg) {
		t.Errorf("tdns-imr by name: %+v, want the socket", c)
	}
	if m := count(imrCfg); m != 1 {
		t.Errorf("tdns-imr: %d identity requests, want 1", m)
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
	RegisterRole("auth", "tdns-auth")
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })
	apiConfig = nil // root with no CLI config: --daemon-config names the daemon

	d := newFakeDaemon(t, sock, cfg)
	d.reply = tdns.AccessResponse{Msg: "Added anna (read-write).\nIn force: 1 client(s), keyauth on.", File: filepath.Join(dir, "access.yaml"), KeyAuth: true,
		Clients:    []tdns.ApiAccessStatusClient{{Name: "anna", Pin: pinOf("anna"), Role: "read-write", Comment: "laptop"}},
		ServerPins: []string{pinOf("server")}}
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
		{[]string{"keyauth", "off"}, tdns.AccessPost{Command: "keyauth", KeyAuth: "off"}},
	} {
		run(t, append(tc.args, "--daemon-config", cfg)...)
		if ap, _ := d.last(t); ap != tc.want {
			t.Errorf("%v sent %+v, want %+v", tc.args, ap, tc.want)
		}
	}
	out = run(t, "list", "--daemon-config", cfg)
	for _, want := range []string{"Access file: " + d.reply.File, "keyauth: on", "anna", "# laptop", "Server pins", pinOf("server")} {
		if !strings.Contains(out, want) {
			t.Errorf("list does not print %q:\n%s", want, out)
		}
	}

	// Without --daemon-config: the role's entry's config-file:.
	apiConfig = &CliConf{ApiServers: []ApiDetails{{Name: "tdns-auth", BaseURL: "https://127.0.0.1:1/api/v1", ConfigFile: cfg}}}
	run(t, "enable", "anna")
	if _, seen := d.last(t); seen != "/api/v1/access "+cfg {
		t.Errorf("from the entry: sent naming %q, want %s", seen, cfg)
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
	if err := runAccess("auth", other, tdns.AccessPost{Command: "list"}); err == nil || !strings.Contains(err.Error(), "run them as root on the daemon's host") {
		t.Errorf("no daemon on the socket: %v", err)
	}
	writeFile(t, other, daemonYAML("TDNS-AUTH", "127.0.0.1:8990", "k", "   socket: none\n"))
	if err := runAccess("auth", other, tdns.AccessPost{Command: "list"}); err == nil || !strings.Contains(err.Error(), "serves no local admin socket") {
		t.Errorf("socket: none: %v", err)
	}
}
