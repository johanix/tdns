/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

// recordingDaemon is a test API server that answers every request with an
// empty JSON object and records the "command" of each request it was sent.
type recordingDaemon struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newRecordingDaemon(t *testing.T) *recordingDaemon {
	t.Helper()
	d := &recordingDaemon{}
	d.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command string `json:"command"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		d.mu.Lock()
		d.seen = append(d.seen, r.URL.Path+" "+req.Command)
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(d.Close)
	return d
}

// take returns what the daemon was sent since the last call, and forgets it.
func (d *recordingDaemon) take() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.seen
	d.seen = nil
	return s
}

// The tests above check which client a command RESOLVES. This one runs the
// commands. A Run callback that passed a literal role ("agent") where it
// should pass the tree's would reach the canonical daemon from every tree,
// and neither the structural checks nor TestNoHardcodedAuthRoleRemains (which
// looks for GetApiClient("agent")) would see it: RunZoneList("agent", args)
// is not that call. So: one test server per daemon, run each command through
// both trees, and require that each request reaches its own tree's daemon
// and nothing reaches the other.
func TestAgentInstanceCommandsRunAgainstTheirOwnDaemon(t *testing.T) {
	withCleanRoleRegistry(t)
	RegisterRole("agent", "agent")
	RegisterRole("sectagent", "sectagent")

	canonD, instD := newRecordingDaemon(t), newRecordingDaemon(t)
	savedClients := tdns.Globals.ApiClients
	tdns.Globals.ApiClients = map[string]*tdns.ApiClient{
		"agent":     tdns.NewClientWithOptions("agent", canonD.URL+"/api/v1", tdns.ClientOptions{Pins: []string{tdns.SPKISHA256(canonD.Certificate())}}),
		"sectagent": tdns.NewClientWithOptions("sectagent", instD.URL+"/api/v1", tdns.ClientOptions{Pins: []string{tdns.SPKISHA256(instD.Certificate())}}),
	}
	t.Cleanup(func() { tdns.Globals.ApiClients = savedClients })

	root := &cobra.Command{Use: "tdns-ncli"}
	canon := TagRole(&cobra.Command{Use: "agent"}, "agent")
	canon.AddCommand(NewAgentZoneCmd("agent"))
	root.AddCommand(canon, NewAgentTree("sectagent", "sectagent"))

	for _, c := range []struct {
		args []string
		want string // what the daemon must be sent: path and command
	}{
		{[]string{"zone", "list"}, "/api/v1/zone list-zones"},
		{[]string{"zone", "list-dynamic"}, "/api/v1/zone list-dynamic"},
	} {
		for _, tree := range []struct {
			name        string
			own, other  *recordingDaemon
			otherDaemon string
		}{
			{"sectagent", instD, canonD, "the canonical tdns-agent"},
			{"agent", canonD, instD, "sectagent"},
		} {
			args := append([]string{tree.name}, c.args...)
			root.SetArgs(args)
			captureStdout(t, func() {
				if err := root.Execute(); err != nil {
					t.Errorf("%v: %v", args, err)
				}
			})
			if got := tree.own.take(); !slices.Equal(got, []string{c.want}) {
				t.Errorf("%v: its own daemon was sent %q, want [%q]", args, got, c.want)
			}
			if got := tree.other.take(); len(got) != 0 {
				t.Errorf("%v reached %s: %q", args, tree.otherDaemon, got)
			}
		}
	}
}

// `zone update create` signs with keys from a local database. The CLI
// config's db.file is the canonical daemon's; a named instance must use the
// database it reports, and fall back to db.file only with a warning.
func TestUpdateKeyDBPrefersTheInstancesOwn(t *testing.T) {
	asked := false
	report := func(f string) func() string {
		return func() string { asked = true; return f }
	}
	for _, c := range []struct {
		name              string
		shared            string
		instance          bool
		reported          string
		want              string
		warns, mustNotAsk bool
	}{
		{"canonical, db.file set: db.file, server not asked", "/cli/agent.db", false, "/srv/agent.db", "/cli/agent.db", false, true},
		{"canonical, no db.file: the server's", "", false, "/srv/agent.db", "/srv/agent.db", false, false},
		{"instance, db.file set: the instance's own", "/cli/agent.db", true, "/srv/agent2.db", "/srv/agent2.db", false, false},
		{"instance reports none: db.file, with a warning", "/cli/agent.db", true, "", "/cli/agent.db", true, false},
		{"instance, nothing anywhere: empty", "", true, "", "", false, false},
	} {
		asked = false
		got, note := updateKeyDB("agent2", c.shared, c.instance, report(c.reported))
		if got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if warned := strings.HasPrefix(note, "Warning"); warned != c.warns {
			t.Errorf("%s: note %q, want a warning: %v", c.name, note, c.warns)
		}
		if c.mustNotAsk && asked {
			t.Errorf("%s: asked the server", c.name)
		}
	}
}

// Only an apiservers entry with a role:, wired under its own name, is an
// instance. A canonical entry, and a role whose entry is missing, are not.
func TestIsInstanceRole(t *testing.T) {
	withCleanRoleRegistry(t)
	RegisterRole("agent", "agent")
	RegisterRole("agent2", "agent2")

	saved := apiConfig
	apiConfig = &CliConf{ApiServers: []ApiDetails{
		{Name: "agent"},
		{Name: "agent2", Role: "agent"},
	}}
	t.Cleanup(func() { apiConfig = saved })

	for role, want := range map[string]bool{"agent": false, "agent2": true, "nosuch": false} {
		if got := isInstanceRole(role); got != want {
			t.Errorf("isInstanceRole(%q) = %v, want %v", role, got, want)
		}
	}
}
