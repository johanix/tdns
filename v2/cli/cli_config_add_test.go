package cli

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// addDaemon is a daemon for config add: /access on its local admin socket
// (an access file in memory), and /ping on a TLS listener that knows a
// client by the pin of its certificate, as the daemon's access check does,
// or by its key (k).
type addDaemon struct {
	cfg, cli, sock, certPath string
	srvPin, url              string

	mu           sync.Mutex
	noAccessFile bool
	refuseAdd    string
	refusePing   bool
	dropAdd      bool              // enrol, then lose the answer
	stall        bool              // never answer
	stallAfter   int               // with stall: this status's headers first
	onAdd        func() error      // after an add is enrolled: what happens meanwhile
	hookErr      error             // onAdd's, checked on the test goroutine (add)
	clients      map[string]string // name -> pin
	posts        []tdns.AccessPost
}

func newAddDaemon(t *testing.T, running bool) *addDaemon {
	t.Helper()
	withCleanRoleRegistry(t)
	// The fixture's own pair, whatever the caller's environment says: an
	// empty value is no override (viper). A test of an override sets it
	// after this.
	for _, k := range []string{"CLIENT.CERT", "CLIENT.KEY", "CLI.LOCALCONFIG"} {
		t.Setenv(k, "")
	}
	dir, err := os.MkdirTemp("/tmp", "ncli") // short: a socket path has a limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	d := &addDaemon{clients: map[string]string{}}
	tcp := httptest.NewUnstartedServer(http.HandlerFunc(d.ping))
	tcp.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	tcp.StartTLS()
	t.Cleanup(tcp.Close)
	d.srvPin, d.url = tdns.SPKISHA256(tcp.Certificate()), tcp.URL+"/api/v1"

	os.Mkdir(filepath.Join(dir, "run"), 0o700)
	d.sock = filepath.Join(dir, "run", "d.sock")
	d.cfg = filepath.Join(dir, "tdns-auth.yaml")
	writeFile(t, d.cfg, "service:\n   name: TDNS-AUTH\napiserver:\n   addresses: [ "+tcp.Listener.Addr().String()+" ]\n   socket: "+d.sock+"\n")
	// The operator's pair goes where the CLI config's client: block says,
	// never into the home directory of whoever runs the tests.
	d.certPath = filepath.Join(dir, "certs", "me.crt")
	d.cli = filepath.Join(dir, "tdns-ncli.yaml")
	writeFile(t, d.cli, "client:\n   cert: "+d.certPath+"\n   key: "+filepath.Join(dir, "certs", "me.key")+"\n")
	if running {
		d.start(t)
	}
	return d
}

// start serves the local admin socket: the daemon is up.
func (d *addDaemon) start(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("unix", d.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(d.access)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

func (d *addDaemon) access(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	if d.stall {
		status := d.stallAfter
		d.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()
		return
	}
	defer d.mu.Unlock()
	if r.Header.Get(tdns.ExpectConfigFileHeader) != d.cfg {
		http.Error(w, "this daemon runs "+d.cfg, http.StatusPreconditionFailed)
		return
	}
	var ap tdns.AccessPost
	json.NewDecoder(r.Body).Decode(&ap)
	d.posts = append(d.posts, ap)
	resp := tdns.AccessResponse{File: "/etc/tdns/tdns-auth-access.yaml",
		ServerPins: []string{d.srvPin}, ConfigFile: d.cfg}
	switch {
	case d.noAccessFile:
		resp.Missing, resp.Msg = true, "No access file, so no remote clients."
		if ap.Command != "list" {
			resp.Error, resp.ErrorMsg = true, "access file /etc/tdns/tdns-auth-access.yaml is missing"
		}
	case ap.Command == "add" && d.refuseAdd != "":
		resp.Error, resp.ErrorMsg = true, d.refuseAdd
	case ap.Command == "add" && d.clients[ap.Name] == ap.Pin:
		resp.Msg = ap.Name + " is already there (read-write)."
	case ap.Command == "add":
		d.clients[ap.Name] = ap.Pin
		resp.Msg = "Added " + ap.Name + " (read-write)."
		if d.onAdd != nil {
			// Synchronous, before the answer; its error is the test's.
			d.hookErr = d.onAdd()
		}
		if d.dropAdd {
			panic(http.ErrAbortHandler) // the connection closes, no answer
		}
	}
	json.NewEncoder(w).Encode(resp)
}

func (d *addDaemon) ping(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Header.Get("X-API-Key") == "k" && !d.refusePing {
		json.NewEncoder(w).Encode(tdns.PingResponse{Msg: "pong", Role: "read-write", Via: "key"})
		return
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && !d.refusePing {
		pin := tdns.SPKISHA256(r.TLS.PeerCertificates[0])
		for name, p := range d.clients {
			if p == pin {
				json.NewEncoder(w).Encode(tdns.PingResponse{Msg: "pong", Role: "read-write", Via: "certificate", Identity: name})
				return
			}
		}
	}
	http.Error(w, "unknown client certificate", http.StatusForbidden)
}

func (d *addDaemon) add(t *testing.T, mod func(*AddOptions)) (*AddResult, error) {
	t.Helper()
	o := AddOptions{CliConfig: d.cli, DaemonConfig: d.cfg, ClientName: "tester"}
	if mod != nil {
		mod(&o)
	}
	res, err := AddDaemonConfig(o)
	d.checkHook(t)
	return res, err
}

// checkHook fails the test, on its own goroutine, when onAdd failed.
func (d *addDaemon) checkHook(t *testing.T) {
	t.Helper()
	d.mu.Lock()
	herr := d.hookErr
	d.mu.Unlock()
	if herr != nil {
		t.Fatalf("the daemon's onAdd: %v", herr)
	}
}

// state is what the daemon has enrolled, and was asked.
func (d *addDaemon) state() (map[string]string, []tdns.AccessPost) {
	d.mu.Lock()
	defer d.mu.Unlock()
	clients := map[string]string{}
	for k, v := range d.clients {
		clients[k] = v
	}
	return clients, append([]tdns.AccessPost(nil), d.posts...)
}

// commands is what the daemon was asked, in order.
func (d *addDaemon) commands() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var c []string
	for _, p := range d.posts {
		c = append(c, p.Command)
	}
	return strings.Join(c, " ")
}

func (d *addDaemon) unchanged(t *testing.T, before string) {
	t.Helper()
	if after, _ := os.ReadFile(d.cli); string(after) != before {
		t.Errorf("the CLI config changed:\n%s", after)
	}
}

// A running daemon gets one certificate entry: its pin enrolled over the
// socket, checked over TCP, then written with the server pins and
// config-file:, and no key. Run again, the entry is left alone, and the
// daemon is not asked anything.
func TestAddRunningDaemonWritesACertEntry(t *testing.T) {
	d := newAddDaemon(t, true)
	res, err := d.add(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := ApiDetails{Name: "auth", Role: "auth", BaseURL: d.url, Pins: []string{d.srvPin}, ConfigFile: d.cfg}
	if got := mustEntries(t, d.cli); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("entries = %+v\nwant      [%+v]", got, want)
	}
	if raw, _ := os.ReadFile(d.cli); strings.Contains(string(raw), "apikey") {
		t.Errorf("the entry has a key:\n%s", raw)
	}
	pin, _, err := ensureClientCert(d.certPath, strings.TrimSuffix(d.certPath, ".crt")+".key", "x")
	clients, posts := d.state()
	if err != nil || clients["tester"] != pin || posts[1].Role != "read-write" || d.commands() != "list add" {
		t.Errorf("the daemon was asked %q, enrolled %v (pin %s, %v)", d.commands(), clients, pin, err)
	}
	var sb strings.Builder
	printAddResult(&sb, res, false, d.cli)
	out := sb.String()
	for _, w := range []string{"Made your client certificate " + d.certPath, "The daemon: Added tester (read-write).",
		"TCP check: ok (TLS, read-write, certificate tester)", "Try it:"} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	if !strings.HasPrefix(out, "Added \"auth\" (the auth entry) to "+d.cli+":") {
		t.Errorf("verdict not first:\n%s", out)
	}

	before, _ := os.ReadFile(d.cli)
	res, err = d.add(t, nil)
	if err != nil || res.AlreadyKnown != "auth" || res.Wrote || !strings.HasSuffix(res.Update, "config update auth --repin") {
		t.Errorf("again: %+v, %v; want it left alone, --repin named", res, err)
	}
	if d.commands() != "list add" {
		t.Errorf("again: the daemon was asked %q", d.commands())
	}
	d.unchanged(t, string(before))
}

// A refusal stops config add with the daemon's words, and nothing is
// written: no access file (said by list, before anything is enrolled or
// made), or a refused add.
func TestAddStopsWhenTheDaemonRefuses(t *testing.T) {
	d := newAddDaemon(t, true)
	before, _ := os.ReadFile(d.cli)
	d.noAccessFile = true
	_, err := d.add(t, nil)
	if err == nil || !strings.Contains(err.Error(), "access file /etc/tdns/tdns-auth-access.yaml is missing, so\ntdns-auth takes no remote clients") ||
		!strings.Contains(err.Error(), "\n   touch /etc/tdns/tdns-auth-access.yaml\nthen run this again:\n") ||
		!strings.Contains(unwrapCommands(err.Error()), "\n   "+ncliFor(d.cli)+" config add --client-name tester "+d.cfg) {
		t.Errorf("no access file: %v, want the touch line and the command to run again", err)
	}
	if _, err := os.Stat(d.certPath); err == nil || d.commands() != "list" {
		t.Errorf("no access file: asked %q, client pair made: %v", d.commands(), err == nil)
	}
	d.unchanged(t, string(before))

	d.mu.Lock()
	d.noAccessFile, d.refuseAdd = false, "\"tester\" is already there with another pin"
	d.mu.Unlock()
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), d.refuseAdd) || !strings.Contains(err.Error(), "nothing was written") || !strings.Contains(unwrapCommands(err.Error()), "\n   "+ncliFor(d.cli)+" config add --client-name tester "+d.cfg) {
		t.Errorf("refused add: %v", err)
	}
	d.unchanged(t, string(before))
}

// The TCP request fails: nothing is written, and the pin stays enrolled.
// The next run reuses it (the daemon says "already there") and writes the
// entry.
func TestAddTCPCheckFailsThenARerunReusesThePin(t *testing.T) {
	d := newAddDaemon(t, true)
	before, _ := os.ReadFile(d.cli)
	d.refusePing = true
	_, err := d.add(t, nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), "Nothing was written") || !strings.Contains(unwrapCommands(err.Error()), "reuses it:\n   "+ncliFor(d.cli)+" config add --client-name tester "+d.cfg) {
		t.Fatalf("err = %v", err)
	}
	// What the daemon said stays (a disabled pin: "enable it").
	if !strings.HasPrefix(err.Error(), "The daemon: Added tester (read-write).\nbut a request over TCP") {
		t.Errorf("the daemon's answer is lost: %v", err)
	}
	d.unchanged(t, string(before))
	clients, _ := d.state()
	enrolled := clients["tester"]

	d.mu.Lock()
	d.refusePing = false
	d.mu.Unlock()
	res, err := d.add(t, nil)
	if err != nil || !res.Wrote {
		t.Fatalf("rerun: %+v, %v", res, err)
	}
	clients, posts := d.state()
	if len(clients) != 1 || clients["tester"] != enrolled || posts[3].Pin != enrolled {
		t.Errorf("rerun enrolled %v, sent %q; want the first pin reused", clients, posts[3].Pin)
	}
	if !strings.Contains(strings.Join(res.Steps, "\n"), "tester is already there") {
		t.Errorf("steps = %q", res.Steps)
	}
}

// A stopped daemon gets the config-file:-only entry, and the command that
// completes it once the daemon is up. A dry run of a running daemon asks
// what it runs, and enrols, makes and writes nothing.
func TestAddStoppedDaemonAndDryRun(t *testing.T) {
	d := newAddDaemon(t, false)
	res, err := d.add(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := ApiDetails{Name: "auth", Role: "auth", ConfigFile: d.cfg}
	if got := mustEntries(t, d.cli); len(got) != 1 || !reflect.DeepEqual(got[0], want) || res.Running {
		t.Errorf("entries = %+v, running %v; want [%+v]", got, res.Running, want)
	}
	var sb strings.Builder
	printAddResult(&sb, res, false, d.cli)
	if hint := ncliFor(d.cli) + " config update auth --cert"; res.Update != hint || !strings.Contains(sb.String(), "not running") || strings.Contains(sb.String(), "Try it") {
		t.Errorf("update %q, printed:\n%s", res.Update, sb.String())
	}
	if _, err := os.Stat(d.certPath); err == nil {
		t.Error("a stopped daemon's add made the client pair")
	}

	r := newAddDaemon(t, true)
	before, _ := os.ReadFile(r.cli)
	res, err = r.add(t, func(o *AddOptions) { o.DryRun = true })
	if err != nil || res.Wrote || !res.Running || len(res.Steps) != 3 || res.Entry.BaseURL != r.url {
		t.Fatalf("dry run: %+v, %v", res, err)
	}
	if _, err := os.Stat(r.certPath); err == nil || r.commands() != "list" {
		t.Errorf("dry run: asked %q, client pair made: %v", r.commands(), err == nil)
	}
	r.unchanged(t, string(before))
	sb.Reset()
	printAddResult(&sb, res, true, r.cli)
	if out := sb.String(); !strings.HasPrefix(out, "Would add") || !strings.Contains(out, "First it would:\n - make your client certificate") {
		t.Errorf("dry run printed:\n%s", out)
	}
}

// An entry for the daemon is left alone, and the daemon not asked: one
// without pins, or with no address, gets them with --cert; one with pins is
// re-pinned with --repin; one without config-file: needs it named; one with
// an old name is renamed too.
func TestAddLeavesAnExistingEntryAlone(t *testing.T) {
	d := newAddDaemon(t, true)
	for _, tc := range []struct{ name, entry, flag string }{
		{"auth", "baseurl: @U@\n     apikey: k\n     authmethod: X-API-Key\n     config-file: @D@", "--cert"},
		{"auth", "config-file: @D@", "--cert"},
		{"auth", "baseurl: @U@\n     pins: [ \"p\" ]\n     config-file: @D@", "--repin"},
		{"auth", "baseurl: @U@\n     apikey: k\n     authmethod: X-API-Key", "--cert --daemon-config " + d.cfg},
		{"auth", "baseurl: unix://@S@", "--cert --daemon-config " + d.cfg},
		{"tdns-auth", "baseurl: @U@\n     pins: [ \"p\" ]\n     config-file: @D@", "--rename auth --repin"},
		{"tdns-auth", "config-file: @D@", "--rename auth --cert"},
	} {
		body := "client:\n   cert: " + d.certPath + "\napiservers:\n   - name: " + tc.name + "\n     " +
			strings.NewReplacer("@U@", d.url, "@D@", d.cfg, "@S@", d.sock).Replace(tc.entry) + "\n"
		writeFile(t, d.cli, body)
		res, err := d.add(t, nil)
		if err != nil || res.AlreadyKnown != tc.name || !strings.HasSuffix(res.Update, "config update "+tc.name+" "+tc.flag) {
			t.Errorf("%s %s: %+v, %v; want %s named", tc.name, tc.flag, res, err, tc.flag)
		}
		d.unchanged(t, body)
	}
	if d.commands() != "" {
		t.Errorf("the daemon was asked %q", d.commands())
	}
}

// An entry for the daemon that appears while the pin is enrolled (another
// config add) is left alone, and the output says the pin was enrolled.
func TestAddEntryAppearsAfterTheEnrolment(t *testing.T) {
	d := newAddDaemon(t, true)
	body := "client:\n   cert: " + d.certPath + "\napiservers:\n   - name: auth\n     config-file: " + d.cfg + "\n"
	d.onAdd = func() error { return os.WriteFile(d.cli, []byte(body), 0o600) }
	res, err := d.add(t, nil)
	if err != nil || res.AlreadyKnown != "auth" || res.Wrote {
		t.Fatalf("%+v, %v; want the entry that appeared left alone", res, err)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "enrolled as tester just now") {
		t.Errorf("notes %q: want the enrolment named", res.Notes)
	}
	d.unchanged(t, body)
}

// Refused before anything is enrolled, and nothing written: a TCP API
// without TLS, the daemon stopped or not; an apiservers: list in flow
// style, with no entry to paste (it would hold a pin not enrolled).
func TestAddRefusesBeforeTheEnrolment(t *testing.T) {
	d := newAddDaemon(t, true)
	body := "client:\n   cert: " + d.certPath + "\napiservers: []\n"
	writeFile(t, d.cli, body)
	_, err := d.add(t, nil)
	if err == nil || !strings.Contains(err.Error(), "then run config add again") || strings.Contains(err.Error(), "tlsauth") || d.commands() != "list" {
		t.Errorf("flow style: %v, asked %q", err, d.commands())
	}
	d.unchanged(t, body)
}

// After the pin is sent: no answer (lost, or none in time) says the pin may
// be enrolled; a client pair changed meanwhile is not the one enrolled.
// Nothing is written.
func TestAddAfterTheEnrolmentIsSent(t *testing.T) {
	d := newAddDaemon(t, true)
	before, _ := os.ReadFile(d.cli)
	d.dropAdd = true
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "No answer that the daemon added your pin") {
		t.Errorf("answer lost: %v", err)
	}
	if clients, _ := d.state(); clients["tester"] == "" {
		t.Errorf("answer lost: enrolled %v", clients)
	}
	d.unchanged(t, string(before))

	d = newAddDaemon(t, true)
	body := "client:\n   cert: " + d.certPath + ".new\n   key: " + d.certPath + ".key.new\n"
	d.onAdd = func() error { return os.WriteFile(d.cli, []byte(body), 0o600) }
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "changed while config add") || !strings.Contains(err.Error(), "enrolled as tester") || !strings.Contains(err.Error(), "another --client-name") {
		t.Errorf("client pair changed: %v", err)
	}
	d.unchanged(t, body)

	d = newAddDaemon(t, true)
	d.stall = true
	defer func(was time.Duration) { accessTimeout = was }(accessTimeout)
	accessTimeout = 200 * time.Millisecond
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "did not answer on its local socket") || !strings.Contains(err.Error(), d.sock) {
		t.Errorf("no answer in time: %v", err)
	}
	// Headers, even a 404's, then no body: still no answer in time.
	d = newAddDaemon(t, true)
	d.stall, d.stallAfter = true, http.StatusNotFound
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "did not answer on its local socket") || !strings.Contains(err.Error(), d.sock) {
		t.Errorf("a 404's headers, no body in time: %v", err)
	}
}

// config add needs the daemon's local admin socket: one it cannot open (not
// root) or none at all is a refusal, and nothing is written.
func TestAddNeedsTheSocket(t *testing.T) {
	d := newAddDaemon(t, true)
	before, _ := os.ReadFile(d.cli)
	if os.Geteuid() != 0 {
		os.Chmod(filepath.Dir(d.sock), 0)
		_, err := d.add(t, nil)
		os.Chmod(filepath.Dir(d.sock), 0o700)
		if err == nil || !strings.Contains(err.Error(), "run it as root") {
			t.Errorf("a socket not ours: %v", err)
		}
	}
	writeFile(t, d.cfg, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "k", "   socket: none\n"))
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "\nsocket: none.") {
		t.Errorf("socket: none: %v", err)
	}
	// A path the daemon refuses is no socket either, and the refusal says
	// why, not "socket: none".
	writeFile(t, d.cfg, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "k", "   socket: run/d.sock\n"))
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "serves no local admin socket") || strings.Contains(err.Error(), "socket: none") {
		t.Errorf("a relative socket path: %v", err)
	} else {
		for _, l := range strings.Split(err.Error(), "\n")[1:] { // the first names the config
			if len("Error: "+l) > 72 {
				t.Errorf("a relative socket path: line over 72: %q", l)
			}
		}
	}
	d.unchanged(t, string(before))
}

func mustEntries(t *testing.T, cli string) []ApiDetails {
	t.Helper()
	got, err := ReadApiServers(cli)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A file that is not a socket at the socket path is no stopped daemon: no
// daemon could serve its socket there. Refused; nothing is written.
func TestAddRefusesANonSocketAtTheSocketPath(t *testing.T) {
	d := newAddDaemon(t, false)
	writeFile(t, d.sock, "not a socket\n")
	before, _ := os.ReadFile(d.cli)
	// ENOTSOCK on the BSDs, ECONNREFUSED on Linux: the same refusal.
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "is there but is\nnot a socket:\n   "+d.sock+"\n") {
		t.Fatalf("a regular file at the socket path: %v, want the plain refusal", err)
	}
	d.unchanged(t, string(before))
	if stopped, err := refusedSocketStopped(syscall.ECONNREFUSED, d.sock); stopped || err != nil {
		t.Errorf("a file: %v, %v; want not stopped", stopped, err)
	}
	if stopped, err := refusedSocketStopped(syscall.ECONNREFUSED, d.sock+".none"); !stopped || err != nil {
		t.Errorf("nothing there: %v, %v; want stopped", stopped, err)
	}
}

// A socket path that cannot be looked at (EACCES) is no stopped daemon: the
// error, not a config-file:-only entry or "no daemon answers there".
func TestRefusedSocketStoppedCannotLook(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root looks at anything")
	}
	dir := filepath.Join(t.TempDir(), "run")
	os.Mkdir(dir, 0o700)
	ln, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	// A stale socket: its file stays when the listener closes (Go removes
	// it by default).
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	if _, err := os.Lstat(filepath.Join(dir, "s")); err != nil {
		t.Fatalf("the stale socket is gone: %v", err)
	}
	if stopped, err := refusedSocketStopped(syscall.ECONNREFUSED, filepath.Join(dir, "s")); !stopped || err != nil {
		t.Errorf("a stale socket: %v, %v; want stopped", stopped, err)
	}
	os.Chmod(dir, 0)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	sock := filepath.Join(dir, "s")
	if stopped, err := refusedSocketStopped(syscall.ECONNREFUSED, sock); stopped || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("a path not ours to look at: %v, %v; want the error", stopped, err)
	}
	refused := fmt.Errorf("Post: %w", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})
	if msg := socketError(sock, refused).Error(); !strings.Contains(msg, "(connection refused): the path cannot be looked at\n(permission denied)") || strings.Contains(msg, "no daemon answers") {
		t.Errorf("socketError: %q, want the path's error", msg)
	}
}

// No CLI config yet, and a cli.localconfig with its own client: block: the
// pair enrolled is the local config's, the one the CLI will use.
func TestAddUsesTheClientPairOfTheConfigWritten(t *testing.T) {
	d := newAddDaemon(t, true)
	os.Remove(d.cli)
	dir := filepath.Dir(d.cli)
	local := filepath.Join(dir, "local.yaml")
	lcert, lkey := filepath.Join(dir, "certs", "local.crt"), filepath.Join(dir, "certs", "local.key")
	writeFile(t, local, "client:\n   cert: "+lcert+"\n   key: "+lkey+"\n")
	t.Setenv("CLI.LOCALCONFIG", local)
	res, err := d.add(t, nil)
	if err != nil || !res.Wrote || !res.Created {
		t.Fatalf("%+v, %v; want the CLI config made", res, err)
	}
	pin, made, err := ensureClientCert(lcert, lkey, "x")
	clients, _ := d.state()
	if err != nil || made || clients["tester"] != pin {
		t.Errorf("enrolled %v; want the local config's pair %s (pin %s, made %v, %v)", clients, lcert, pin, made, err)
	}
}

// A client: block that does not decode is refused before the enrolment: the
// default pair would be enrolled in its place. Nothing is written.
func TestAddRefusesAClientBlockThatDoesNotDecode(t *testing.T) {
	d := newAddDaemon(t, true)
	body := "client:\n   cert: { path: /etc/tdns/client.crt }\n"
	writeFile(t, d.cli, body)
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "client:") {
		t.Errorf("a client: block that does not decode: %v, want a refusal", err)
	}
	if c := d.commands(); strings.Contains(c, "add") {
		t.Errorf("the daemon was asked %q, want no add", c)
	}
	d.unchanged(t, body)
}

// An entry written before config-file: by the daemon's second API address
// is the daemon's entry too: left alone, not a second entry.
func TestAddKnowsAnEntryByAnyAddress(t *testing.T) {
	d := newAddDaemon(t, true)
	raw, _ := os.ReadFile(d.cfg)
	second := "127.0.0.1:1"
	writeFile(t, d.cfg, strings.Replace(string(raw), " ]\n   socket:", ", "+second+" ]\n   socket:", 1))
	body := "client:\n   cert: " + d.certPath + "\napiservers:\n   - name: old\n     role: auth\n     baseurl: https://" + second + "/api/v1\n     apikey: k\n     authmethod: X-API-Key\n"
	writeFile(t, d.cli, body)
	res, err := d.add(t, nil)
	if err != nil || res.AlreadyKnown != "old" || res.Wrote {
		t.Fatalf("%+v, %v; want the entry by the second address left alone", res, err)
	}
	d.unchanged(t, body)
}

// unwrapCommands joins the lines of a command broken between flags (a
// trailing backslash, then the indented rest), so a test can look for the
// command whole, however long the temporary paths in it make it.
func unwrapCommands(s string) string {
	return regexp.MustCompile(` \\\n +`).ReplaceAllString(s, " ")
}
