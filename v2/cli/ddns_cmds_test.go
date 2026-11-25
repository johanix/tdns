/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

const exportFragment = "; Delegation data for parent zone parent.example.\n" +
	"; --- alpha.parent.example. ---\n" +
	"alpha.parent.example.\t3600\tIN\tNS\tns.alpha.parent.example.\n"

// fakeExportDaemon answers /delegation "export" with the data in the reply,
// as the daemon does. It records each request's outfile, which a client must
// not send (the daemon refuses one), and answers anyway, so that a test
// finds out what the client did with the data.
func fakeExportDaemon(t *testing.T) *[]string {
	t.Helper()
	var outfiles []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var dp tdns.DelegationPost
		json.NewDecoder(r.Body).Decode(&dp)
		outfiles = append(outfiles, dp.Outfile)
		reply := map[string]any{"Zone": dp.Zone, "Export": exportFragment}
		if dp.Command != "export" {
			reply = map[string]any{"Error": true, "ErrorMsg": "not export: " + dp.Command}
		}
		json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(srv.Close)

	saved, had := tdns.Globals.ApiClients["tdns-auth"]
	if tdns.Globals.ApiClients == nil {
		tdns.Globals.ApiClients = map[string]*tdns.ApiClient{}
	}
	tdns.Globals.ApiClients["tdns-auth"] = &tdns.ApiClient{
		Name: "tdns-auth", Client: srv.Client(), BaseUrl: srv.URL + "/api/v1", AuthMethod: "none",
	}
	savedZone := tdns.Globals.Zonename
	tdns.Globals.Zonename = "parent.example."
	t.Cleanup(func() {
		tdns.Globals.Zonename = savedZone
		if had {
			tdns.Globals.ApiClients["tdns-auth"] = saved
		} else {
			delete(tdns.Globals.ApiClients, "tdns-auth")
		}
	})
	return &outfiles
}

func runExportCmd(t *testing.T, args ...string) string {
	t.Helper()
	del := NewDelCmd("auth")
	var out bytes.Buffer
	del.SetOut(&out)
	del.SetErr(&out)
	del.SetArgs(append([]string{"export"}, args...))
	if err := del.Execute(); err != nil {
		t.Fatalf("del export %v: %v", args, err)
	}
	return out.String()
}

// --outfile names a file on the CLI's host. The CLI writes it, with the
// caller's own permissions, and does not pass the path to the daemon.
func TestDelExportWritesTheFileLocally(t *testing.T) {
	sent := fakeExportDaemon(t)
	dir := t.TempDir()
	outfile := filepath.Join(dir, "parent.example.deleg")

	out := runExportCmd(t, "--outfile", outfile)

	for _, o := range *sent {
		if o != "" {
			t.Errorf("the CLI sent outfile %q to the daemon", o)
		}
	}
	got, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatalf("no local file: %v (output %q)", err, out)
	}
	if string(got) != exportFragment {
		t.Errorf("file holds %q, want %q", got, exportFragment)
	}
	fi, err := os.Stat(outfile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&^0o644 != 0 || perm&0o600 != 0o600 {
		t.Errorf("file mode %v, want 0644 less the umask", perm)
	}
	// Verdict first; the path on a line of its own when the line is long.
	if !strings.HasPrefix(out, "parent.example.: delegation data written to") || !strings.Contains(out, outfile) {
		t.Errorf("output %q, want the zone, then where the data went", out)
	}
	// Only the file: the temp file was renamed over it.
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("%d entries in the output directory, want only the file", len(ents))
	}
}

// Without --outfile the data goes to stdout, unchanged, and no file is
// written anywhere.
func TestDelExportWithoutOutfilePrintsTheData(t *testing.T) {
	fakeExportDaemon(t)
	cwd := t.TempDir()
	t.Chdir(cwd)

	out := runExportCmd(t)

	if out != exportFragment {
		t.Errorf("stdout %q, want the data %q", out, exportFragment)
	}
	if ents, _ := os.ReadDir(cwd); len(ents) != 0 {
		t.Errorf("%d files written to the working directory", len(ents))
	}
}

// del export reports a missing zone itself, on stderr, never through
// PrepArgs, which prints on stdout where the export's data goes.
func TestDelExportZone(t *testing.T) {
	if _, err := delExportZone(""); err == nil {
		t.Fatal("no zone: want an error, got none")
	}
	got, err := delExportZone("parent.example")
	if err != nil {
		t.Fatalf("parent.example: %v", err)
	}
	if got != "parent.example." {
		t.Fatalf("parent.example: got %q, want %q", got, "parent.example.")
	}
}
