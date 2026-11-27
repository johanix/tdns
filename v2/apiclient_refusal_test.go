package tdns

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	api := &ApiClient{BaseUrl: srv.URL, Client: srv.Client()}

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
	refusing := &ApiClient{BaseUrl: srv.URL, Client: srv.Client()}
	if err := refusing.StopDaemon(); err == nil {
		t.Error("StopDaemon on a refusal returned nil")
	}

	stopping := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(CommandResponse{Status: "stopping"})
	}))
	defer stopping.Close()
	ok := &ApiClient{BaseUrl: stopping.URL, Client: stopping.Client()}
	if err := ok.StopDaemon(); err != nil {
		t.Errorf("StopDaemon on an acknowledged stop: %v", err)
	}

	gone := srv.URL
	srv.Close()
	notRunning := &ApiClient{BaseUrl: gone, Client: &http.Client{}}
	if err := notRunning.StopDaemon(); err != nil {
		t.Errorf("StopDaemon with no daemon running: %v (want nil: stop is a no-op)", err)
	}

	// The local socket of a daemon that is not running: no socket file.
	// (StartDaemon asks the same daemonNotRunning before it starts one, and
	// while it waits for the new one to answer; see TestDaemonNotRunning.)
	noSocket := NewClientWithOptions("local", "unix://"+filepath.Join(shortTempDir(t), "absent.sock"), ClientOptions{})
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
		_, _, err := NewClientWithOptions("local", baseurl, ClientOptions{}).UpdateDaemon(CommandPost{Command: "status"}, false)
		return err
	}

	if err := status("unix://" + filepath.Join(dir, "absent.sock")); !daemonNotRunning(err) {
		t.Errorf("no socket file: %v, want not running", err)
	}

	gone := httptest.NewServer(http.NotFoundHandler())
	url := gone.URL
	gone.Close()
	notRunning := &ApiClient{BaseUrl: url, Client: &http.Client{}}
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
