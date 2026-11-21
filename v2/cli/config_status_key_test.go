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

			// imr config check makes the same comparison.
			rep = newCCReport()
			correlateImrApiServer(cfg, resp, tc.accepted, rep)
			if got := hasLevel(rep, "Running-config drift", "apikey", ccWARN); got != tc.wantWarn {
				t.Fatalf("imr: warned = %v, want %v; report %+v", got, tc.wantWarn, rep.byGroup["Running-config drift"])
			}
		})
	}
}

// acceptedApiKey must name the key the status request was sent with, and
// GetApiClient picks that client through the role mapping ("auth" ->
// "tdns-auth"). An entry that happens to be named "auth" must not stand in
// for it, and an instance (registered under its own name) gets its own key.
func TestAcceptedApiKeyFollowsTheRoleMapping(t *testing.T) {
	withCleanRoleRegistry(t)
	RegisterRole("auth", "tdns-auth")
	RegisterRole("sectdns", "sectdns")

	saved := apiConfig
	apiConfig = &CliConf{ApiServers: []ApiDetails{
		{Name: "auth", AuthMethod: "X-API-Key", ApiKey: "the-entry-named-auth"},
		{Name: "tdns-auth", AuthMethod: "X-API-Key", ApiKey: "the-client-key"},
		{Name: "sectdns", Role: "auth", AuthMethod: "X-API-Key", ApiKey: "the-instance-key"},
		{Name: "unmapped", AuthMethod: "X-API-Key", ApiKey: "the-raw-name"},
	}}
	t.Cleanup(func() { apiConfig = saved })

	for role, want := range map[string]string{
		"auth":     "the-client-key",
		"sectdns":  "the-instance-key",
		"unmapped": "the-raw-name",
	} {
		if got := acceptedApiKey(role); got != want {
			t.Errorf("acceptedApiKey(%q) = %q, want %q", role, got, want)
		}
	}
}
