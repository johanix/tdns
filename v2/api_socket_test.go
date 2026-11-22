package tdns

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortTempDir is a 0700 directory with a short path: a unix socket path is
// limited to about 100 bytes, and t.TempDir() on macOS is longer than that.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tdnssock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPrepareApiSocket(t *testing.T) {
	dir := shortTempDir(t)

	if err := prepareApiSocket("relative/admin.sock"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("relative path: err = %v", err)
	}
	if err := prepareApiSocket("/" + strings.Repeat("x", maxApiSocketPathLen)); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Errorf("long path: err = %v", err)
	}

	// A directory others can enter is refused: whoever opens the socket is admin.
	open := filepath.Join(dir, "open")
	os.Mkdir(open, 0o755)
	os.Chmod(open, 0o755)
	if err := prepareApiSocket(filepath.Join(open, "a.sock")); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Errorf("0755 directory: err = %v", err)
	}

	// A symlinked directory is refused.
	link := filepath.Join(dir, "link")
	priv := filepath.Join(dir, "priv")
	os.Mkdir(priv, 0o700)
	os.Symlink(priv, link)
	if err := prepareApiSocket(filepath.Join(link, "a.sock")); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("symlinked directory: err = %v", err)
	}

	// A missing directory is created 0700.
	fresh := filepath.Join(dir, "fresh")
	if err := prepareApiSocket(filepath.Join(fresh, "a.sock")); err != nil {
		t.Fatalf("missing directory: %v", err)
	}
	if fi, err := os.Stat(fresh); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("created directory: %v, mode %v", err, fi.Mode().Perm())
	}

	// A regular file in the way is left alone.
	file := filepath.Join(priv, "file.sock")
	os.WriteFile(file, []byte("x"), 0o600)
	if err := prepareApiSocket(file); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("regular file: err = %v", err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("the regular file was removed: %v", err)
	}

	// A live socket belongs to someone else.
	live := filepath.Join(priv, "live.sock")
	ln, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareApiSocket(live); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("live socket: err = %v", err)
	}
	ln.Close()

	// A stale socket (no listener behind it) is removed.
	stale := filepath.Join(priv, "stale.sock")
	sl, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	sl.SetUnlinkOnClose(false)
	sl.Close()
	if err := prepareApiSocket(stale); err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Errorf("stale socket still there: %v", err)
	}

	// A probe that fails for any other reason than a refused connection
	// proves nothing, so the socket stays. Here: no permission to connect.
	if os.Geteuid() != 0 {
		odd := filepath.Join(priv, "odd.sock")
		ol, err := net.ListenUnix("unix", &net.UnixAddr{Name: odd, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		ol.SetUnlinkOnClose(false)
		ol.Close()
		os.Chmod(odd, 0)
		if err := prepareApiSocket(odd); err == nil || !strings.Contains(err.Error(), "could not be probed") {
			t.Errorf("unprobeable socket: err = %v", err)
		}
		if _, err := os.Lstat(odd); err != nil {
			t.Errorf("a socket the probe could not judge was removed: %v", err)
		}
	}
}

// The socket serves the same router with no key; the same router over TCP
// still wants one. A client made from a unix:/// base URL reaches it.
func TestApiSocketServesWithoutKey(t *testing.T) {
	conf := &Config{}
	conf.ApiServer.ApiKey = "the-api-key"
	rtr, err := conf.SetupSimpleAPIRouter(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(shortTempDir(t), "admin.sock")
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	if err := serveApiSocket(sock, rtr, done); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket file: %v, mode %v", err, fi.Mode().Perm())
	}

	api := NewClient("local", "unix://"+sock, "", "none", "")
	if api.Socket != sock {
		t.Errorf("client socket = %q", api.Socket)
	}

	// A unix:// URL with a relative path is still a socket URL: it fails,
	// saying why, and is not sent on as an ordinary URL.
	rel := NewClient("local", "unix://admin.sock", "", "none", "")
	if _, _, err := rel.Post("/ping", []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "unix:///absolute/path") {
		t.Errorf("relative socket URL: err = %v, want one naming the unix:///absolute/path form", err)
	}
	status, body, err := api.Post("/ping", []byte(`{"Msg":"hello"}`))
	if err != nil || status != http.StatusOK {
		t.Fatalf("ping over the socket, no key: status %d, err %v, body %s", status, err, body)
	}

	// Over TCP the same router refuses a request without the key, and no
	// header can make a TCP request look like a socket one.
	srv := httptest.NewServer(rtr)
	defer srv.Close()
	for _, hdr := range []map[string]string{nil, {"X-Local-Socket": "true"}} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/ping", strings.NewReader(`{}`))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("TCP without a key (%v): status %d, want 403", hdr, resp.StatusCode)
		}
	}
}

func TestUnixSocketPath(t *testing.T) {
	for in, want := range map[string]string{
		"unix:///var/run/tdns/tdns-auth.sock": "/var/run/tdns/tdns-auth.sock",
		"unix://relative.sock":                "",
		"https://127.0.0.1:8989/api/v1":       "",
		"unix:/var/run/tdns/tdns-auth.sock":   "",
	} {
		got, ok := unixSocketPath(in)
		if got != want || ok != (want != "") {
			t.Errorf("unixSocketPath(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

// APIdispatcher serves the socket even with no TCP addresses (it is the way in
// that does not depend on anything else), and a socket it cannot serve is a
// server error the operator sees, not a reason to stop.
func TestAPIdispatcherServesTheSocket(t *testing.T) {
	newConf := func(sock string) *Config {
		conf := &Config{}
		conf.ApiServer.ApiKey = "the-api-key"
		conf.ApiServer.Socket = sock
		conf.Internal.ServerErrors = NewServerErrorRegistry()
		return conf
	}

	dir := shortTempDir(t)
	sock := filepath.Join(dir, "admin.sock")
	conf := newConf(sock)
	rtr, err := conf.SetupSimpleAPIRouter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	if err := APIdispatcher(conf, rtr, done); err != nil {
		t.Fatal(err)
	}
	status, body, err := NewClient("local", "unix://"+sock, "", "none", "").Post("/ping", []byte(`{}`))
	if err != nil || status != http.StatusOK {
		t.Fatalf("ping over the socket with no TCP addresses: status %d, err %v, body %s", status, err, body)
	}
	// An entry that says X-API-Key but has no key still works on the socket:
	// a socket client sends no key and asks for none.
	keyless := NewClient("local", "unix://"+sock, "", "X-API-Key", "")
	if keyless.AuthMethod != "none" || keyless.apiKey != "" {
		t.Errorf("socket client: authmethod %q, key set %v; want none and no key", keyless.AuthMethod, keyless.apiKey != "")
	}
	if status, body, err := keyless.Post("/ping", []byte(`{}`)); err != nil || status != http.StatusOK {
		t.Errorf("ping over the socket from an X-API-Key entry with no key: status %d, err %v, body %s", status, err, body)
	}
	if n := len(conf.Internal.ServerErrors.List()); n != 0 {
		t.Errorf("%d server errors, want none: %v", n, conf.Internal.ServerErrors.List())
	}

	// A directory others can enter: no socket, and a server error saying so.
	open := filepath.Join(dir, "open")
	os.Mkdir(open, 0o755)
	os.Chmod(open, 0o755)
	bad := newConf(filepath.Join(open, "admin.sock"))
	if err := APIdispatcher(bad, rtr, done); err != nil {
		t.Fatal(err)
	}
	errs := bad.Internal.ServerErrors.List()
	if len(errs) != 1 || errs[0].Subtype != ErrSubApiSocket {
		t.Errorf("server errors = %v, want one ApiSocket error", errs)
	}
	if _, err := os.Lstat(filepath.Join(open, "admin.sock")); !os.IsNotExist(err) {
		t.Errorf("a socket was created in a 0755 directory: %v", err)
	}
}
