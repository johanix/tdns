/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package cli

import (
	"testing"
)

// The agent's zone tree has the dynamic-zone verbs, as commands of its own:
// not the auth tree's, and not sharing its flag variables.
func TestAgentZoneDynamicCmds(t *testing.T) {
	auth := NewZoneCmd("auth")
	for _, name := range []string{"add", "delete", "modify", "list-dynamic"} {
		a := findSub(t, AgentZoneCmd, name)
		if u := findSub(t, auth, name); a == u {
			t.Errorf("%s: the agent and auth trees share one command", name)
		}
		if want := "agent zone " + name; a.CommandPath() != want {
			t.Errorf("%s: command path %q, want %q", name, a.CommandPath(), want)
		}
	}

	add := findSub(t, AgentZoneCmd, "add")
	for _, f := range []string{"zone", "primaries", "options", "template", "type"} {
		if add.Flags().Lookup(f) == nil {
			t.Errorf("agent zone add: no --%s flag", f)
		}
	}
	if err := add.ParseFlags([]string{"--primaries", "192.0.2.1:53", "--options", "parentsync-proxy"}); err != nil {
		t.Fatalf("agent zone add: %v", err)
	}
	if v, _ := add.Flags().GetStringSlice("options"); len(v) != 1 || v[0] != "parentsync-proxy" {
		t.Errorf("agent zone add --options: %q", v)
	}
	if v, _ := findSub(t, auth, "add").Flags().GetStringSlice("options"); len(v) != 0 {
		t.Errorf("auth zone add --options is %q after parsing the agent's: the two share flag variables", v)
	}
}
