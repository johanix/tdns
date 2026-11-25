package cli

import (
	"crypto/tls"
	"encoding/json"
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
	onAdd        func()            // after an add is enrolled: what happens meanwhile
	clients      map[string]string // name -> pin
	posts        []tdns.AccessPost
}

func newAddDaemon(t *testing.T, running bool) *addDaemon {
	t.Helper()
	withCleanRoleRegistry(t)
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
	writeFile(t, d.cfg, "service:\n   name: TDNS-AUTH\napiserver:\n   addresses: [ "+tcp.Listener.Addr().String()+" ]\n   apikey: k\n   socket: "+d.sock+"\n")
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
	resp := tdns.AccessResponse{File: "/etc/tdns/access.yaml", ServerPins: []string{d.srvPin}, ConfigFile: d.cfg}
	switch {
	case d.noAccessFile:
		resp.File, resp.Msg = "", "No access file: add access-file: under apiserver:"
		if ap.Command != "list" {
			resp.Error, resp.ErrorMsg = true, resp.Msg
		}
	case ap.Command == "add" && d.refuseAdd != "":
		resp.Error, resp.ErrorMsg = true, d.refuseAdd
	case ap.Command == "add" && d.clients[ap.Name] == ap.Pin:
		resp.Msg = ap.Name + " is already there (read-write)."
	case ap.Command == "add":
		d.clients[ap.Name] = ap.Pin
		resp.Msg = "Added " + ap.Name + " (read-write)."
		if d.onAdd != nil {
			d.onAdd()
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
	return AddDaemonConfig(o)
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
	want := ApiDetails{Name: "tdns-auth", BaseURL: d.url, AuthMethod: "certificate",
		TLSAuth: "pin", Pins: []string{d.srvPin}, ConfigFile: d.cfg}
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
	if !strings.HasPrefix(out, "Added \"tdns-auth\" (canonical) to "+d.cli+":") {
		t.Errorf("verdict not first:\n%s", out)
	}

	before, _ := os.ReadFile(d.cli)
	res, err = d.add(t, nil)
	if err != nil || res.AlreadyKnown != "tdns-auth" || res.Wrote || !strings.HasSuffix(res.Update, "config update tdns-auth --repin") {
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
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "add access-file: under apiserver:") {
		t.Errorf("no access file: %v, want the daemon's advice", err)
	}
	if _, err := os.Stat(d.certPath); err == nil || d.commands() != "list" {
		t.Errorf("no access file: asked %q, client pair made: %v", d.commands(), err == nil)
	}
	d.unchanged(t, string(before))

	d.mu.Lock()
	d.noAccessFile, d.refuseAdd = false, "\"tester\" is already there with another pin"
	d.mu.Unlock()
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), d.refuseAdd) || !strings.Contains(err.Error(), "nothing was written") {
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
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), "Nothing was written") || !strings.Contains(err.Error(), "reuses it") {
		t.Fatalf("err = %v", err)
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
	want := ApiDetails{Name: "tdns-auth", AuthMethod: "none", ConfigFile: d.cfg}
	if got := mustEntries(t, d.cli); len(got) != 1 || !reflect.DeepEqual(got[0], want) || res.Running {
		t.Errorf("entries = %+v, running %v; want [%+v]", got, res.Running, want)
	}
	var sb strings.Builder
	printAddResult(&sb, res, false, d.cli)
	if hint := ncliFor(d.cli) + " config update tdns-auth --cert"; res.Update != hint || !strings.Contains(sb.String(), "not running") || strings.Contains(sb.String(), "Try it") {
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

// An entry for the daemon is left alone, and the daemon not asked: a key
// entry, or one with no address, is switched with --cert; a certificate
// entry is re-pinned with --repin; one without config-file: needs it named.
func TestAddLeavesAnExistingEntryAlone(t *testing.T) {
	d := newAddDaemon(t, true)
	for entry, flag := range map[string]string{
		"baseurl: @U@\n     apikey: k\n     authmethod: X-API-Key\n     config-file: @D@":                            "--cert",
		"authmethod: none\n     config-file: @D@":                                                                    "--cert",
		"baseurl: @U@\n     authmethod: certificate\n     tlsauth: pin\n     pins: [ \"p\" ]\n     config-file: @D@": "--repin",
		"baseurl: @U@\n     apikey: k\n     authmethod: X-API-Key":                                                   "--cert --daemon-config " + d.cfg,
		"baseurl: unix://@S@\n     authmethod: none":                                                                 "--cert --daemon-config " + d.cfg,
	} {
		body := "client:\n   cert: " + d.certPath + "\napiservers:\n   - name: tdns-auth\n     " +
			strings.NewReplacer("@U@", d.url, "@D@", d.cfg, "@S@", d.sock).Replace(entry) + "\n"
		writeFile(t, d.cli, body)
		res, err := d.add(t, nil)
		if err != nil || res.AlreadyKnown != "tdns-auth" || !strings.HasSuffix(res.Update, "config update tdns-auth "+flag) {
			t.Errorf("%s: %+v, %v; want %s named", flag, res, err, flag)
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
	body := "client:\n   cert: " + d.certPath + "\napiservers:\n   - name: tdns-auth\n     authmethod: none\n     config-file: " + d.cfg + "\n"
	d.onAdd = func() { writeFile(t, d.cli, body) }
	res, err := d.add(t, nil)
	if err != nil || res.AlreadyKnown != "tdns-auth" || res.Wrote {
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
	for _, running := range []bool{false, true} {
		d := newAddDaemon(t, running)
		raw, _ := os.ReadFile(d.cfg)
		writeFile(t, d.cfg, string(raw)+"   usetls: false\n")
		before, _ := os.ReadFile(d.cli)
		if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "usetls is false") || d.commands() != "" {
			t.Errorf("usetls false, running %v: %v, asked %q", running, err, d.commands())
		}
		d.unchanged(t, string(before))
	}
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
	d.onAdd = func() { writeFile(t, d.cli, body) }
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "changed while config add") {
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
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "(socket: none)") {
		t.Errorf("socket: none: %v", err)
	}
	// A path the daemon refuses is no socket either, and the refusal says
	// why, not "socket: none".
	writeFile(t, d.cfg, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "k", "   socket: run/d.sock\n"))
	if _, err := d.add(t, nil); err == nil || !strings.Contains(err.Error(), "serves no local admin socket") || strings.Contains(err.Error(), "socket: none") {
		t.Errorf("a relative socket path: %v", err)
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
