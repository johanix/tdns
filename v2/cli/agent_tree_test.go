package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

// find walks a command path ("zone dsync status") below root.
func find(t *testing.T, root *cobra.Command, path string) *cobra.Command {
	t.Helper()
	c := root
	for _, word := range strings.Fields(path) {
		c = findChild(c, word)
		if c == nil {
			t.Fatalf("no %q below %s", path, root.Name())
		}
	}
	return c
}

// An agent tree is built once per instance and each is its own tree: the
// factories behind it must be callable repeatedly, with the target carried by
// the tree and not by anything shared.
func TestNewAgentTreeIsIndependentPerRole(t *testing.T) {
	a := NewAgentTree("agent", "agent")
	b := NewAgentTree("sectagent", "sectagent")

	if a == b || a.Name() != "agent" || b.Name() != "sectagent" {
		t.Fatalf("trees are not independent: %q / %q", a.Name(), b.Name())
	}
	if len(a.Commands()) == 0 || len(a.Commands()) != len(b.Commands()) {
		t.Fatalf("trees differ in size: %d vs %d", len(a.Commands()), len(b.Commands()))
	}
	if got := RoleForCmd(find(t, b, "zone dsync status")); got != "sectagent" {
		t.Errorf("sectagent's zone dsync status targets %q", got)
	}
	if got := RoleForCmd(find(t, a, "zone dsync status")); got != "agent" {
		t.Errorf("agent's zone dsync status targets %q", got)
	}
}

// The reason NewAgentZoneCmd exists. Before it, every command in the agent's
// zone group asked for GetApiClient("agent") whatever tree it sat in, so a
// second agent's `zone dsync publish` would have run against the first.
// Resolve each of the seven commands that used to hardcode it, through a
// second instance, and require that they reach the second instance's client.
func TestAgentInstanceZoneCommandsReachTheirOwnClient(t *testing.T) {
	withCleanRoleRegistry(t)
	RegisterRole("sectagent", "sectagent")

	savedClients := tdns.Globals.ApiClients
	tdns.Globals.ApiClients = map[string]*tdns.ApiClient{
		"tdns-agent": tdns.NewClient("tdns-agent", "https://127.0.0.1:8987/api/v1", "k1", "X-API-Key", "insecure"),
		"sectagent":  tdns.NewClient("sectagent", "https://127.0.0.1:8988/api/v1", "k2", "X-API-Key", "insecure"),
	}
	t.Cleanup(func() { tdns.Globals.ApiClients = savedClients })

	inst := NewAgentTree("sectagent", "sectagent")
	canon := TagRole(&cobra.Command{Use: "agent"}, "agent")
	canon.AddCommand(NewAgentZoneCmd("agent"))

	for _, path := range []string{
		"zone dsync status",
		"zone dsync bootstrap-sig0-key",
		"zone dsync roll-sig0-key",
		"zone dsync publish",
		"zone dsync unpublish",
		"zone list",
		"zone update create",
	} {
		c := find(t, inst, path)
		api, err := GetApiClientForCmd(c, false)
		if err != nil || api.Name != "sectagent" {
			t.Errorf("%s via sectagent reached %v (%v), want the sectagent client", path, api, err)
		}
		if !strings.HasPrefix(path, "zone dsync") && !strings.HasPrefix(path, "zone list") {
			continue
		}
		cc := find(t, canon, path)
		if api, err := GetApiClientForCmd(cc, false); err != nil || api.Name != "tdns-agent" {
			t.Errorf("%s via agent reached %v (%v), want tdns-agent", path, api, err)
		}
	}
}

// Which commands exist is decided when the tree is built, before the CLI
// config is loaded, so an agent instance cannot discover it is an agent from
// that config. `config transport-signal` is auth-only: it must be absent from
// an agent instance and present on an auth one. (The check keyed on the role
// NAME, which for an instance is "sectagent", and so added it.)
func TestAgentInstanceConfigHasNoTransportSignal(t *testing.T) {
	agentInst := find(t, NewAgentTree("sectagent", "sectagent"), "config")
	if findChild(agentInst, "transport-signal") != nil {
		t.Error("an agent instance offers config transport-signal")
	}
	if findChild(NewConfigCmd("agent"), "transport-signal") != nil {
		t.Error("the canonical agent offers config transport-signal")
	}
	authInst := find(t, NewAuthTree("sectdns", "sectdns"), "config")
	if findChild(authInst, "transport-signal") == nil {
		t.Error("an auth instance lost config transport-signal")
	}
	if findChild(NewConfigCmd("auth"), "transport-signal") == nil {
		t.Error("the canonical auth lost config transport-signal")
	}
}

func TestAgentInstanceIsWired(t *testing.T) {
	withCleanRoleRegistry(t)
	root := &cobra.Command{Use: "tdns-ncli"}
	w := WireInstanceTrees(root, []ApiDetails{
		{Name: "tdns-agent", BaseURL: "https://127.0.0.1:8987/api/v1"},
		{Name: "sectagent", Role: "agent", BaseURL: "https://127.0.0.1:8988/api/v1"},
	})
	if len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	if findChild(root, "sectagent") == nil {
		t.Fatal("sectagent was not wired")
	}
	if got := GetClientKeyFromParent("sectagent"); got != "sectagent" {
		t.Errorf("sectagent maps to %q", got)
	}
}
