package cli

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// The running server's API key no longer comes back in the status reply. The
// drift check uses the key the status request was sent with instead: the
// reply came back, so the server accepted that key.
func TestCorrelateStatusApiKeyUsesTheAcceptedKey(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fileKey  string
		accepted string
		wantWarn bool
	}{
		{name: "file key is the one the server accepts", fileKey: "k1", accepted: "k1"},
		{name: "file key was changed, server still on the old one", fileKey: "k2", accepted: "k1", wantWarn: true},
		{name: "no key sent (another auth method)", fileKey: "k2", accepted: ""},
		{name: "no key in the file", fileKey: "", accepted: "k1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.ApiServer.ApiKey = tdns.SensitiveString(tc.fileKey)
			// What a redacting server sends: a set key reads as "[REDACTED]".
			var resp tdns.ConfigResponse
			resp.ApiServer.ApiKey = "[REDACTED]"
			rep := newCCReport()
			correlateStatus(cfg, resp, tc.accepted, rep, "Running server")
			if got := hasLevel(rep, "Running server", "apikey", ccWARN); got != tc.wantWarn {
				t.Fatalf("warned = %v, want %v; report %+v", got, tc.wantWarn, rep.byGroup["Running server"])
			}
		})
	}
}
