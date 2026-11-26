package tdns

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// A ping on the local admin socket has no remote address; the reply says the
// socket instead of an empty client.
func TestPingClientOnAdminSocket(t *testing.T) {
	for _, tc := range []struct{ remote, want string }{
		{"", "admin socket"},
		{"@", "admin socket"},
		{"192.0.2.1:54321", "192.0.2.1:54321"},
	} {
		r := httptest.NewRequest("POST", "/api/v1/ping", strings.NewReader(`{"Pings":0}`))
		r.RemoteAddr = tc.remote
		w := httptest.NewRecorder()
		APIping(nil)(w, r)
		var pr PingResponse
		if err := json.Unmarshal(w.Body.Bytes(), &pr); err != nil {
			t.Fatal(err)
		}
		if pr.Client != tc.want {
			t.Errorf("remote %q: client %q, want %q", tc.remote, pr.Client, tc.want)
		}
	}
}
