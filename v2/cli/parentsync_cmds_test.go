/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// lookupCmd walks a command path from root, e.g. lookupCmd(AgentCmd, "zone",
// "parentsync", "status"). Returns nil at the first missing step -- unlike the
// findCmd in showcmds_cmds_test.go, which fails the test, because several of
// these assertions are about a command NOT being there.
func lookupCmd(root *cobra.Command, path ...string) *cobra.Command {
	cur := root
	for _, name := range path {
		var next *cobra.Command
		for _, c := range cur.Commands() {
			if c.Name() == name {
				next = c
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

func childNames(c *cobra.Command) map[string]*cobra.Command {
	out := map[string]*cobra.Command{}
	if c == nil {
		return out
	}
	for _, k := range c.Commands() {
		out[k.Name()] = k
	}
	return out
}

// The daemon serves /zone/parentsync for an agent as well as an auth server,
// and the handler gates on the zone's parentsync option rather than on the app
// type -- so every verb worked on an agent already and there was no way to
// reach it (#539).
func TestAgentZoneParentSyncHasTheSameVerbsAsAuth(t *testing.T) {
	agent := lookupCmd(AgentCmd, "zone", "parentsync")
	if agent == nil {
		t.Fatal("tdns-cli agent zone parentsync does not exist")
	}
	auth := lookupCmd(AuthCmd, "zone", "parentsync")
	if auth == nil {
		t.Fatal("tdns-cli auth zone parentsync does not exist")
	}

	agentKids := childNames(agent)
	authKids := childNames(auth)

	for _, verb := range []string{"status", "bootstrap", "roll-key", "inquire", "delta", "sync"} {
		if _, ok := agentKids[verb]; !ok {
			t.Errorf("agent zone parentsync has no %q", verb)
		}
		if _, ok := authKids[verb]; !ok {
			t.Errorf("auth zone parentsync has no %q", verb)
		}
	}

	// Nothing visible under auth that is missing under agent. Guards against a
	// verb being added to the shared constructor and the two drifting apart
	// again, which is how the duplicate subtree came about.
	for name, c := range authKids {
		if c.Hidden {
			continue
		}
		if _, ok := agentKids[name]; !ok {
			t.Errorf("auth zone parentsync has %q and agent does not", name)
		}
	}
}

// election is the one verb that is genuinely agent-side: it posts to the agent
// management API, not to /zone/parentsync, so an auth server has nothing to
// answer it with.
func TestParentSyncElectionIsAgentOnly(t *testing.T) {
	if lookupCmd(AgentCmd, "zone", "parentsync", "election") == nil {
		t.Error("agent zone parentsync election is missing")
	}
	if c := lookupCmd(AuthCmd, "zone", "parentsync", "election"); c != nil {
		t.Error("auth zone parentsync election exists; election has no auth-side endpoint")
	}
}

// The retired subtree hung off "agent" directly. Kept as a hidden alias so
// anything already invoking it keeps working, including the "inquire update"
// spelling, which the canonical tree writes as plain "inquire".
func TestAgentParentSyncLegacyPathStillResolves(t *testing.T) {
	legacy := lookupCmd(AgentCmd, "parentsync")
	if legacy == nil {
		t.Fatal("the top-level agent parentsync path no longer resolves")
	}
	if !legacy.Hidden {
		t.Error("the legacy path must not be advertised alongside the canonical one")
	}
	for _, verb := range []string{"status", "bootstrap", "roll-key", "inquire", "delta", "sync", "election"} {
		if lookupCmd(legacy, verb) == nil {
			t.Errorf("agent parentsync %s no longer resolves", verb)
		}
	}
	upd := lookupCmd(legacy, "inquire", "update")
	if upd == nil {
		t.Fatal("agent parentsync inquire update no longer resolves")
	}
	if !upd.Hidden {
		t.Error("the inquire update spelling is a compatibility alias and must stay hidden")
	}
}

// Each attachment gets its own command objects: cobra records the parent on
// the command, so one shared instance could not hang off three parents.
func TestParentSyncSubtreesAreDistinctInstances(t *testing.T) {
	agentZone := lookupCmd(AgentCmd, "zone", "parentsync")
	legacy := lookupCmd(AgentCmd, "parentsync")
	auth := lookupCmd(AuthCmd, "zone", "parentsync")
	if agentZone == legacy || agentZone == auth || legacy == auth {
		t.Fatal("two attachment points share one command object")
	}
	for _, c := range []*cobra.Command{agentZone, legacy, auth} {
		if c.Parent() == nil {
			t.Error("a parentsync subtree is not attached to anything")
		}
	}
}

// The numeric scheme override existed only on the retired agent "sync"; it is
// carried over rather than dropped.
func TestParentSyncSyncKeepsTheSchemeFlag(t *testing.T) {
	for _, root := range []struct {
		name string
		cmd  *cobra.Command
	}{
		{"agent", lookupCmd(AgentCmd, "zone", "parentsync", "sync")},
		{"auth", lookupCmd(AuthCmd, "zone", "parentsync", "sync")},
	} {
		if root.cmd == nil {
			t.Errorf("%s: parentsync sync is missing", root.name)
			continue
		}
		f := root.cmd.Flags().Lookup("scheme")
		if f == nil {
			t.Errorf("%s: parentsync sync has no --scheme flag", root.name)
			continue
		}
		if f.Shorthand != "S" {
			t.Errorf("%s: --scheme shorthand = %q, want S", root.name, f.Shorthand)
		}
	}
}
