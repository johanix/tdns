package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

func testPin(name string) string {
	sum := sha256.Sum256([]byte(name))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// config check warns about apiserver.app-clients: a name the access file
// has no client for, the API key still accepted (it bypasses every
// application limit), and app-clients without an access file.
func TestConfigCheckWarnsAboutAppClients(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, access string // access "" is no access file
		apps         []string
		warn         []string // checks that warn
	}{
		{"none set", "clients:\n  - {name: anna, pin: " + testPin("anna") + ", role: read-write}\n", nil, nil},
		{"enrolled, key off", "keyauth: false\nclients:\n  - {name: anna, pin: " + testPin("anna") + ", role: read-write}\n", []string{"anna"}, nil},
		{"key on", "clients:\n  - {name: anna, pin: " + testPin("anna") + ", role: read-write}\n", []string{"anna"}, []string{"keyauth"}},
		{"not enrolled", "keyauth: false\nclients:\n  - {name: anna, pin: " + testPin("anna") + ", role: read-write}\n", []string{"anna", "ghost"}, []string{"app-clients"}},
		{"no access file", "", []string{"anna"}, []string{"app-clients"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.ApiServer.AppClients = tc.apps
			if tc.access != "" {
				p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".yaml")
				if err := os.WriteFile(p, []byte(tc.access), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg.ApiServer.AccessFile = p
			}
			rep := newCCReport()
			checkApiAccessFile(cfg, rep)
			var warned []string
			for _, r := range rep.byGroup["API access file"] {
				if r.level == ccWARN {
					warned = append(warned, r.check)
					if r.check == "app-clients" && tc.access != "" && !strings.Contains(r.msg, `"ghost"`) {
						t.Errorf("the warning does not name the client: %q", r.msg)
					}
				}
			}
			if strings.Join(warned, " ") != strings.Join(tc.warn, " ") {
				t.Errorf("warnings %v, want %v; report %+v", warned, tc.warn, rep.byGroup["API access file"])
			}
		})
	}
}

// config status -v marks the application clients, and lists a name of
// app-clients that the access file does not have.
func TestConfigStatusShowsAppClients(t *testing.T) {
	out := captureStdout(t, func() {
		printAccessStatus(&tdns.ApiAccessStatus{File: "/etc/tdns/access.yaml", AppClients: []string{"provisioner", "ghost"},
			Clients: []tdns.ApiAccessStatusClient{{Name: "provisioner", Role: "read-write"}, {Name: "ops", Role: "read-write"}}})
	})
	for _, want := range []string{
		"   provisioner (read-write, application client)\n",
		"   ops (read-write)\n",
		"   ghost (in app-clients; not in the access file)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q lacks %q", out, want)
		}
	}
	for _, l := range strings.Split(out, "\n") {
		if len(l) > 72 {
			t.Errorf("line over 72 columns: %q", l)
		}
	}
}

// A plain-text 403 reaches the shared CLI error path once: the senders hand
// back the verdict and the daemon's words, wrapped, with the daemon's
// name for "Error from %q", instead of logging it and wrapping it again. A
// catalog handler's JSON error is the daemon's message, not the raw body.
func TestARefusalPrintsOnceAndReadably(t *testing.T) {
	const refusal = "zone bump: not available to application clients"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/catalog":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(tdns.CatalogResponse{Error: true,
				ErrorMsg: "zone other.example.: not a zone of API owner cert:provisioner"})
		default:
			http.Error(w, refusal, http.StatusForbidden)
		}
	}))
	defer srv.Close()
	api := &tdns.ApiClient{Name: "tdns-auth", BaseUrl: srv.URL, AuthMethod: "none", Client: srv.Client()}

	cr, err := SendZoneCommand(api, tdns.ZonePost{Command: "bump", Zone: "own.example."})
	if err == nil {
		t.Fatal("no error for a 403")
	}
	printed := "Error from \"" + cr.AppName + "\": " + err.Error()
	want := "Error from \"tdns-auth\": refused (HTTP 403):\n  " + refusal
	if printed != want {
		t.Errorf("printed\n%s\nwant\n%s", printed, want)
	}
	for _, l := range strings.Split(printed, "\n") {
		if len(l) > 72 {
			t.Errorf("line over 72 columns: %q", l)
		}
	}
	if _, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{Command: "status", Zone: "own.example."}); err == nil ||
		!strings.HasPrefix(err.Error(), "refused (HTTP 403):\n  ") {
		t.Errorf("parentsync: %v", err)
	}

	resp, err := SendCatalogCommand(api, tdns.CatalogPost{Command: "zone-list", CatalogZone: "other.example."})
	if err == nil || err.Error() != "zone other.example.: not a zone of API owner cert:provisioner" || resp == nil {
		t.Errorf("catalog: %v, want the daemon's message", err)
	}
}
