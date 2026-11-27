package tdns

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// A daemon that stops leaves no socket file behind. After a signal only ctx is
// cancelled, and after an API stop the process exits as MainLoop returns; in
// neither case does the socket server's own shutdown get to run, so MainLoop
// closes the socket itself. Then the server's late Shutdown is harmless.
func TestMainLoopRemovesTheAdminSocket(t *testing.T) {
	for _, how := range []string{"signal", "api stop"} {
		t.Run(how, func(t *testing.T) {
			dir := shortTempDir(t)
			sock := filepath.Join(dir, "admin.sock")
			conf := &Config{}
			conf.ApiServer.Socket = sock
			conf.Internal.ServerErrors = NewServerErrorRegistry()
			conf.Internal.APIStopCh = make(chan struct{})
			rtr, err := conf.SetupSimpleAPIRouter(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			// The server's own shutdown waits on a channel nothing closes
			// until after the check, as when the process has already gone.
			late := make(chan struct{})
			if err := serveApiSocket(sock, rtr, late, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(sock); err != nil {
				t.Fatalf("no socket while serving: %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			if how == "signal" {
				cancel()
			} else {
				close(conf.Internal.APIStopCh)
			}
			conf.MainLoop(ctx, cancel)
			if _, err := os.Lstat(sock); !os.IsNotExist(err) {
				t.Errorf("socket file still there after MainLoop returned: %v", err)
			}
			close(late) // Shutdown on an already closed listener
			cancel()
		})
	}
}

// acceptFails is a listener whose Accept fails for good.
type acceptFails struct{}

func (acceptFails) Accept() (net.Conn, error) { return nil, errors.New("accept failed for good") }
func (acceptFails) Close() error              { return nil }
func (acceptFails) Addr() net.Addr            { return &net.UnixAddr{Name: "fails", Net: "unix"} }

// A socket that stops serving because Accept failed is a failure: a server
// error (Transport/ApiSocket) that `config status` shows, even though Serve
// closes the listener on its way out. Only a stop asked for by
// closeApiSockets leaves no error.
func TestApiSocketServeFailureIsReported(t *testing.T) {
	newConf := func() *Config {
		conf := &Config{}
		conf.Internal.ServerErrors = NewServerErrorRegistry()
		return conf
	}

	failing := newConf()
	ln := &apiSocketListener{Listener: acceptFails{}}
	serveOn(&http.Server{}, ln, "fails", apiSocketFailed(failing, "fails"))
	errs := failing.Internal.ServerErrors.List()
	if len(errs) != 1 || errs[0].Category != ErrCatTransport || errs[0].Subtype != ErrSubApiSocket {
		t.Errorf("after Accept failed for good: server errors = %v, want one Transport/ApiSocket", errs)
	}

	stopping := newConf()
	dir := shortTempDir(t)
	raw, err := net.Listen("unix", filepath.Join(dir, "stop.sock"))
	if err != nil {
		t.Fatal(err)
	}
	stopped := &apiSocketListener{Listener: raw}
	apiSockets.Lock()
	apiSockets.lns = append(apiSockets.lns, stopped)
	apiSockets.Unlock()
	served := make(chan struct{})
	go func() {
		serveOn(&http.Server{}, stopped, "stop.sock", apiSocketFailed(stopping, "stop.sock"))
		close(served)
	}()
	closeApiSockets()
	select {
	case <-served:
		if errs := stopping.Internal.ServerErrors.List(); len(errs) != 0 {
			t.Errorf("a stop asked for by closeApiSockets left server errors: %v", errs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after closeApiSockets")
	}
}

// The socket serves the router with no credential; the same router over TCP
// wants a client certificate. A client made from a unix:/// base URL reaches
// it.
func TestApiSocketServesWithoutCredentials(t *testing.T) {
	conf := &Config{}
	rtr, err := conf.SetupSimpleAPIRouter(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(shortTempDir(t), "admin.sock")
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	if err := serveApiSocket(sock, rtr, done, nil); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket file: %v, mode %v", err, fi.Mode().Perm())
	}

	api := NewClientWithOptions("local", "unix://"+sock, ClientOptions{})
	if api.Socket != sock {
		t.Errorf("client socket = %q", api.Socket)
	}

	// A unix:// URL with a relative path is still a socket URL: it fails,
	// saying why, and is not sent on as an ordinary URL.
	rel := NewClientWithOptions("local", "unix://admin.sock", ClientOptions{})
	if _, _, err := rel.Post("/ping", []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "unix:///absolute/path") {
		t.Errorf("relative socket URL: err = %v, want one naming the unix:///absolute/path form", err)
	}
	status, body, err := api.Post("/ping", []byte(`{"Msg":"hello"}`))
	if err != nil || status != http.StatusOK {
		t.Fatalf("ping over the socket, no credential: status %d, err %v, body %s", status, err, body)
	}

	// Over TCP the same router refuses a request without a certificate,
	// and no header can make a TCP request look like a socket one.
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
			t.Errorf("TCP without a certificate (%v): status %d, want 403", hdr, resp.StatusCode)
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
	status, body, err := NewClientWithOptions("local", "unix://"+sock, ClientOptions{}).Post("/ping", []byte(`{}`))
	if err != nil || status != http.StatusOK {
		t.Fatalf("ping over the socket with no TCP addresses: status %d, err %v, body %s", status, err, body)
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

// Every daemon has the admin socket unless its config says socket: none: by
// default one named after the config file's whole path, extension included,
// which says which config it belongs to, and which no other config path
// gives (testor: three tdns-auth.yaml in different directories).
func TestApiSocketPath(t *testing.T) {
	saved := DefaultApiSocketDir
	t.Cleanup(func() { DefaultApiSocketDir = saved })
	DefaultApiSocketDir = "/var/run/tdns"
	for _, tc := range []struct {
		configured, cfgfile, want string
	}{
		{"", "/etc/tdns/tdns-auth.yaml", "/var/run/tdns/etc_tdns_tdns-auth.yaml.sock"},
		{"", "/etc/tdns/auth-enc.yaml", "/var/run/tdns/etc_tdns_auth-enc.yaml.sock"},
		{"", "/etc/tdns-site/tdns-auth.yaml", "/var/run/tdns/etc_tdns-site_tdns-auth.yaml.sock"},
		{"", "/etc/tdns-enc/tdns-auth.yaml", "/var/run/tdns/etc_tdns-enc_tdns-auth.yaml.sock"},
		{"", "/etc/tdns/noext", "/var/run/tdns/etc_tdns_noext.sock"},
		{"", "/etc/tdns_x/a b.yaml", "/var/run/tdns/etc_tdns%5Fx_a%20b.yaml.sock"},
		{"/run/x.sock", "/etc/tdns/tdns-auth.yaml", "/run/x.sock"},
		{"none", "/etc/tdns/tdns-auth.yaml", ""},
		{"NONE", "/etc/tdns/tdns-auth.yaml", ""},
		{"", "", ""}, // no config file: nothing to name it after
	} {
		if got := ApiSocketPath(tc.configured, tc.cfgfile); got != tc.want {
			t.Errorf("ApiSocketPath(%q, %q) = %q, want %q", tc.configured, tc.cfgfile, got, tc.want)
		}
	}

	// Paths that "/" -> "-", or dropping the extension, or "/" -> "_"
	// without escaping "_", would give one name: each gets its own.
	for _, pair := range [][2]string{
		{"/etc/tdns-site/server.yaml", "/etc/tdns/site/server.yaml"},
		{"/etc/tdns/server.yaml", "/etc/tdns/server.yml"},
		{"/etc/tdns/server.yaml", "/etc/tdns/server"},
		{"/etc/tdns_site/server.yaml", "/etc/tdns/site/server.yaml"},
		{"/etc/a%5Fb/x.yaml", "/etc/a_b/x.yaml"},
	} {
		if a, b := ApiSocketPath("", pair[0]), ApiSocketPath("", pair[1]); a == b {
			t.Errorf("%s and %s both get %s", pair[0], pair[1], a)
		}
	}

	// Too long for a socket: the file name, %% and a hash of the path,
	// short enough, and different for two such paths.
	deep := "/" + strings.Repeat("very-long-directory-name/", 5)
	a := ApiSocketPath("", deep+"a/tdns-auth.yaml")
	b := ApiSocketPath("", deep+"b/tdns-auth.yaml")
	if a == b || CheckApiSocketPath(a) != nil || CheckApiSocketPath(b) != nil ||
		!strings.HasPrefix(a, "/var/run/tdns/tdns-auth.yaml%%") || !strings.HasSuffix(a, ".sock") {
		t.Errorf("long paths: %q and %q, want two short, distinct tdns-auth.yaml%%%%<hash>.sock", a, b)
	}
	// Two paths whose SHA-256 share their first 32 bits (de311e32), which
	// the fallback once used alone, still get two sockets.
	long := "/etc/tdns/" + strings.Repeat("long-directory-", 6)
	a = ApiSocketPath("", long+"009357/server.yaml")
	b = ApiSocketPath("", long+"01b313/server.yaml")
	if a == b || CheckApiSocketPath(a) != nil || CheckApiSocketPath(b) != nil || !strings.Contains(a, "%%de311e32") {
		t.Errorf("paths sharing 32 bits of hash: %q and %q, want two sockets", a, b)
	}

	DefaultApiSocketDir = ""
	if got := ApiSocketPath("", "/etc/tdns/tdns-auth.yaml"); got != "" {
		t.Errorf("default off: %q, want none", got)
	}
}
