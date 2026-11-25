package tdns

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const adminOnly = "/api/v1/command stop needs admin, which is available only on the daemon's local admin socket"

// A refusal by the access check has a plain-text body. The client must hand
// back the daemon's words as an error, not a body the caller then fails to
// decode as JSON ("invalid character '/' looking for beginning of value").
// A handler's own non-2xx reply with a JSON body still goes back as before.
func TestPlainTextRefusalIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/refused":
			http.Error(w, adminOnly, http.StatusForbidden)
		case "/json-error":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(CommandResponse{Error: true, ErrorMsg: "bad"})
		default:
			json.NewEncoder(w).Encode(CommandResponse{Status: "ok"})
		}
	}))
	defer srv.Close()
	api := &ApiClient{BaseUrl: srv.URL, AuthMethod: "none", Client: srv.Client()}

	status, _, err := api.Post("/refused", []byte("{}"))
	if err == nil || status != http.StatusForbidden {
		t.Fatalf("refusal: status %d, err %v; want 403 and an error", status, err)
	}
	if !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), adminOnly) {
		t.Errorf("refusal error = %q, want the status and the daemon's message", err)
	}

	status, buf, err := api.Post("/json-error", []byte("{}"))
	if err != nil || status != http.StatusBadRequest || !json.Valid(buf) {
		t.Errorf("JSON error reply: status %d, err %v, body %q; want 400, no error, the JSON body", status, err, buf)
	}

	if _, _, err := api.Post("/ok", []byte("{}")); err != nil {
		t.Errorf("ok reply: err %v", err)
	}
}

// `daemon stop` against a daemon that refuses (stop needs admin) must report
// failure, so the CLI exits non-zero and restart does not go on to start.
// A daemon that is not running makes stop a no-op, not a failure.
func TestStopDaemonReportsARefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, adminOnly, http.StatusForbidden)
	}))
	refusing := &ApiClient{BaseUrl: srv.URL, AuthMethod: "none", Client: srv.Client()}
	if err := refusing.StopDaemon(); err == nil {
		t.Error("StopDaemon on a refusal returned nil")
	}

	stopping := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(CommandResponse{Status: "stopping"})
	}))
	defer stopping.Close()
	ok := &ApiClient{BaseUrl: stopping.URL, AuthMethod: "none", Client: stopping.Client()}
	if err := ok.StopDaemon(); err != nil {
		t.Errorf("StopDaemon on an acknowledged stop: %v", err)
	}

	gone := srv.URL
	srv.Close()
	notRunning := &ApiClient{BaseUrl: gone, AuthMethod: "none", Client: &http.Client{}}
	if err := notRunning.StopDaemon(); err != nil {
		t.Errorf("StopDaemon with no daemon running: %v (want nil: stop is a no-op)", err)
	}

	// The local socket of a daemon that is not running: no socket file.
	// (StartDaemon asks the same daemonNotRunning before it starts one, and
	// while it waits for the new one to answer; see TestDaemonNotRunning.)
	noSocket := NewClient("local", "unix://"+filepath.Join(shortTempDir(t), "absent.sock"), "", "none", "")
	if err := noSocket.StopDaemon(); err != nil {
		t.Errorf("StopDaemon with no socket file: %v (want nil: stop is a no-op)", err)
	}
}

// What start, stop and restart treat as "no daemon there": a refused
// connection, or no socket file. A socket that is not ours to open is
// something else, and so is no error at all.
func TestDaemonNotRunning(t *testing.T) {
	dir := shortTempDir(t)
	status := func(baseurl string) error {
		_, _, err := NewClient("local", baseurl, "", "none", "").UpdateDaemon(CommandPost{Command: "status"}, false)
		return err
	}

	if err := status("unix://" + filepath.Join(dir, "absent.sock")); !daemonNotRunning(err) {
		t.Errorf("no socket file: %v, want not running", err)
	}

	gone := httptest.NewServer(http.NotFoundHandler())
	url := gone.URL
	gone.Close()
	notRunning := &ApiClient{BaseUrl: url, AuthMethod: "none", Client: &http.Client{}}
	if _, _, err := notRunning.UpdateDaemon(CommandPost{Command: "status"}, false); !daemonNotRunning(err) {
		t.Errorf("refused TCP: %v, want not running", err)
	}

	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked.sock")
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: locked, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		os.Chmod(locked, 0)
		if err := status("unix://" + locked); err == nil || daemonNotRunning(err) {
			t.Errorf("a socket we may not open: %v, want an error that is not \"not running\"", err)
		}
	}

	if daemonNotRunning(nil) {
		t.Error("no error counted as not running")
	}
}

// Post, Get, Put and Delete try each of api.Addresses in turn, as RequestNG
// does: an address that does not answer is skipped, and the first reply is
// the answer, a refusal included (the next address is not asked). With no
// Addresses the request goes to BaseUrl as it is.
func TestPostTriesEachAddress(t *testing.T) {
	var hits atomic.Int32
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/api/refused" {
			http.Error(w, adminOnly, http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(CommandResponse{Status: "ok", Msg: r.Method + " " + r.URL.Path})
	}))
	defer live.Close()
	liveAddr := strings.TrimPrefix(live.URL, "http://")
	gone := httptest.NewServer(http.NotFoundHandler())
	dead := strings.TrimPrefix(gone.URL, "http://")
	gone.Close()

	api := &ApiClient{BaseUrl: "http://" + dead + "/api", Addresses: []string{dead, liveAddr}, AuthMethod: "none", Client: &http.Client{}}
	for _, tc := range []struct {
		method string
		call   func() (int, []byte, error)
	}{
		{"POST", func() (int, []byte, error) { return api.Post("/catalog", []byte("{}")) }},
		{"GET", func() (int, []byte, error) { return api.Get("/catalog") }},
		{"PUT", func() (int, []byte, error) { return api.Put("/catalog", []byte("{}")) }},
		{"DELETE", func() (int, []byte, error) { return api.Delete("/catalog") }},
	} {
		status, buf, err := tc.call()
		var cr CommandResponse
		if err != nil || status != http.StatusOK || json.Unmarshal(buf, &cr) != nil || cr.Msg != tc.method+" /api/catalog" {
			t.Errorf("%s with a dead first address: status %d, err %v, body %q; want the live address's answer", tc.method, status, err, buf)
		}
	}

	// A refusal is an answer: the address after it is not asked.
	hits.Store(0)
	refusing := &ApiClient{BaseUrl: live.URL + "/api", Addresses: []string{liveAddr, liveAddr}, AuthMethod: "none", Client: &http.Client{}}
	status, _, err := refusing.Post("/refused", []byte("{}"))
	var ref *ApiRefusal
	if status != http.StatusForbidden || !errors.As(err, &ref) || hits.Load() != 1 {
		t.Errorf("a refusal: status %d, err %v, %d request(s); want one 403 refusal", status, err, hits.Load())
	}

	// No address answers: the error says so, and which were tried.
	allDead := &ApiClient{BaseUrl: "http://" + dead + "/api", Addresses: []string{dead, dead}, AuthMethod: "none", Client: &http.Client{}}
	if _, _, err := allDead.Post("/catalog", []byte("{}")); err == nil || !daemonNotRunning(err) || !strings.Contains(err.Error(), "tried "+dead+", "+dead) {
		t.Errorf("every address dead: %v, want a refused connection naming both", err)
	}

	// No Addresses: BaseUrl.
	plain := &ApiClient{BaseUrl: live.URL + "/api", AuthMethod: "none", Client: &http.Client{}}
	if status, _, err := plain.Post("/catalog", []byte("{}")); err != nil || status != http.StatusOK {
		t.Errorf("no Addresses: status %d, err %v", status, err)
	}
}
