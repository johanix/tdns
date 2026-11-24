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

// A plain-text 403 reaches the shared printer once: the senders hand back
// the refusal, which prints as one verdict naming the daemon and the
// daemon's words, wrapped, instead of being logged and wrapped again. A
// handler's JSON error (a zone of another client, the catalog's non-2xx
// reply) prints the daemon's message the same way, not the raw body.
func TestARefusalPrintsOnceAndReadably(t *testing.T) {
	const refusal = "zone bump: not available to application clients"
	const notOwn = "zone other.example.: not a zone of API owner cert:provisioner"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var post struct{ Command string }
		_ = json.NewDecoder(r.Body).Decode(&post)
		switch {
		case r.URL.Path == "/catalog":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(tdns.CatalogResponse{Error: true, ErrorMsg: notOwn})
		case r.URL.Path == "/zone" && post.Command == "freeze":
			json.NewEncoder(w).Encode(tdns.ZoneResponse{AppName: "tdns-auth", Error: true, ErrorMsg: notOwn})
		default:
			http.Error(w, refusal, http.StatusForbidden)
		}
	}))
	defer srv.Close()
	api := &tdns.ApiClient{Name: "tdns-auth", BaseUrl: srv.URL, AuthMethod: "none", Client: srv.Client()}

	check := func(what string, err error, want string) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: no error", what)
			return
		}
		printed := captureStdout(t, func() { printDaemonError(api.Name, err) })
		if printed != want {
			t.Errorf("%s: printed\n%s\nwant\n%s", what, printed, want)
		}
		for _, l := range strings.Split(printed, "\n") {
			if len(l) > 72 {
				t.Errorf("%s: line over 72 columns: %q", what, l)
			}
		}
	}
	refused := "Refused by tdns-auth (HTTP 403):\n  " + refusal + "\n"
	errorFrom := "Error from tdns-auth:\n  " + notOwn + "\n"

	_, err := SendZoneCommand(api, tdns.ZonePost{Command: "bump", Zone: "own.example."})
	check("zone bump", err, refused)
	_, err = SendZoneCommand(api, tdns.ZonePost{Command: "freeze", Zone: "other.example."})
	check("zone freeze", err, errorFrom)
	_, err = SendParentSyncCommand(api, tdns.ZoneParentSyncPost{Command: "status", Zone: "own.example."})
	check("parentsync", err, refused)
	resp, err := SendCatalogCommand(api, tdns.CatalogPost{Command: "zone-list", CatalogZone: "other.example."})
	check("catalog", err, errorFrom)
	if resp == nil {
		t.Error("catalog: no response")
	}
	// What a caller that prints err.Error() itself reads is unchanged.
	if err == nil || err.Error() != notOwn {
		t.Errorf("catalog: %v, want the daemon's message", err)
	}
}
