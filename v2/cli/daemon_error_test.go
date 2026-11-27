package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// A daemon's error prints the same from every command: the verdict, which
// names the daemon, on a line of its own, then the daemon's words indented
// two spaces and wrapped within 72 characters, a hint line kept as its own,
// indented line.
func TestDaemonErrorText(t *testing.T) {
	refused, _ := refusalError(&tdns.ApiRefusal{Status: http.StatusForbidden,
		Msg: "config reload: not available to application clients"})
	for _, tc := range []struct {
		name, daemon string
		err          error
		want         []string
	}{
		{"JSON error with a hint", "tdns-auth",
			&daemonError{msg: "zone z.app2.example.: API owner is api, not cert:app1\n  an operator can hand it over with zone setowner"},
			[]string{
				"Error from tdns-auth:",
				"  zone z.app2.example.: API owner is api, not cert:app1",
				"    an operator can hand it over with zone setowner",
			}},
		// As SendConfigCommand returns it: wrapped, and through refusalError.
		{"plain-text 403", "tdns-auth", fmt.Errorf("error from api post: %w", refused),
			[]string{
				"Refused by tdns-auth (HTTP 403):",
				"  config reload: not available to application clients",
			}},
		{"long zone name", "tdns-auth",
			&daemonError{msg: "zone provisioned-by-app-two.customer-zones.app2.example.: not a zone of API owner cert:app1"},
			[]string{
				"Error from tdns-auth:",
				"  zone provisioned-by-app-two.customer-zones.app2.example.: not a zone",
				"  of API owner cert:app1",
			}},
		{"other HTTP status", "tdns-auth", &tdns.ApiRefusal{Status: http.StatusInternalServerError, Msg: "zone list: database is locked"},
			[]string{
				"Error from tdns-auth (HTTP 500):",
				"  zone list: database is locked",
			}},
		{"HTTP status, no body", "tdns-auth", &tdns.ApiRefusal{Status: http.StatusBadRequest},
			[]string{
				"Error from tdns-auth (HTTP 400):",
				"  Bad Request",
			}},
		{"no reply", "tdns-auth", errors.New("error from api post: dial tcp 192.0.2.1:8989: connect: connection refused"),
			[]string{
				"Error talking to tdns-auth:",
				"  error from api post: dial tcp 192.0.2.1:8989: connect: connection",
				"  refused",
			}},
		{"no client name", "", &daemonError{msg: "zone z.example.: not a zone of API owner cert:app1"},
			[]string{
				"Error from the daemon:",
				"  zone z.example.: not a zone of API owner cert:app1",
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Split(daemonErrorText(tc.daemon, tc.err), "\n")
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
			for _, l := range got {
				if len(l) > 72 {
					t.Errorf("line over 72 characters (%d): %q", len(l), l)
				}
			}
		})
	}

	// The senders' errors keep the text they always had, for a caller
	// that prints err.Error() itself.
	if got := refused.Error(); got != "refused (HTTP 403):\n  config reload: not available to application clients" {
		t.Errorf("refusalError text: %q", got)
	}
	if got := (&daemonError{lead: "error from the daemon: ", msg: "no such zone"}).Error(); got != "error from the daemon: no such zone" {
		t.Errorf("daemonError text: %q", got)
	}
}

// refusedPathEnv names the command a child of this test binary runs against a
// daemon that refuses everything (refusedPathEnv+"_URL"), os.Exit and all.
const refusedPathEnv = "TDNS_CLI_TEST_REFUSED_PATH"

// A refused command prints the refusal through the shared printer, once and
// on stdout, not as a log line, and exits 1: config (finding 2), debug
// (finding 3), and daemon status, which goes through RequestNG's own exit.
func TestRefusedCommandsPrintThroughThePrinter(t *testing.T) {
	if path := os.Getenv(refusedPathEnv); path != "" {
		runRefusedPath(path, os.Getenv(refusedPathEnv+"_URL"))
		return
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var post struct{ Command string }
		_ = json.NewDecoder(r.Body).Decode(&post)
		route := strings.TrimPrefix(r.URL.Path, "/api/v1/")
		http.Error(w, route+" "+post.Command+": not available to application clients", http.StatusForbidden)
	}))
	defer srv.Close()

	for _, path := range []string{"config reload", "config reload-zones", "config status", "debug show-ta", "command status"} {
		t.Run(path, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRefusedCommandsPrintThroughThePrinter$")
			cmd.Env = append(os.Environ(), refusedPathEnv+"="+path, refusedPathEnv+"_URL="+srv.URL)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("exit: %v, want status 1; stdout %q, stderr %q", err, stdout.String(), stderr.String())
			}
			want := "Refused by auth (HTTP 403):\n  " + path + ": not available to application clients\n"
			if stdout.String() != want {
				t.Errorf("stdout\n%s\nwant\n%s", stdout.String(), want)
			}
			if strings.Contains(stderr.String(), "not available") {
				t.Errorf("the refusal was also logged: %q", stderr.String())
			}
		})
	}
}

// runRefusedPath runs one command the way tdns-cli runs it, against url.
func runRefusedPath(path, url string) {
	tdns.Globals.ApiClients = map[string]*tdns.ApiClient{
		"auth": tdns.NewClientWithOptions("auth", url+"/api/v1", tdns.ClientOptions{}),
	}
	switch path {
	case "config reload":
		runConfigCmd("auth", "reload", false, false)
	case "config reload-zones":
		runConfigCmd("auth", "reload-zones", false, false)
	case "config status":
		runConfigCmd("auth", "status", true, false)
	case "debug show-ta":
		c := NewDebugCmd("auth")
		c.SetArgs([]string{"show-ta"})
		_ = c.Execute()
	case "command status":
		c := NewDaemonCmd("auth")
		c.SetArgs([]string{"status"})
		_ = c.Execute()
	}
	os.Exit(3) // not reached: a refused command exits 1
}
