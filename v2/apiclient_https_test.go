package tdns

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The TCP client sends nothing that is not https: not to an http:// base
// URL, and not where a pinned https daemon redirects it to http.
func TestTCPClientIsHTTPSOnly(t *testing.T) {
	var plainHit atomic.Bool
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHit.Store(true)
	}))
	defer plain.Close()
	pinned := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/api/v1/ping", http.StatusFound)
	}))
	defer pinned.Close()
	pin := SPKISHA256(pinned.Certificate())

	for name, base := range map[string]string{
		"http base URL":    plain.URL + "/api/v1",
		"redirect to http": pinned.URL + "/api/v1",
	} {
		c := NewClientWithOptions("t", base, ClientOptions{Pins: []string{pin}})
		resp, err := c.Client.Get(base + "/ping")
		if err == nil {
			resp.Body.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "https only") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if plainHit.Load() {
		t.Error("a request went out in plaintext")
	}
}
