package tdns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
}
