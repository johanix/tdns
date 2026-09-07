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

// "election" posted parentsync-election to the agent management API, which
// only tdns-mp's mpagent implements -- the string appears nowhere else in this
// repository, and mpcli builds its own AgentCmd rather than this one. A
// command tdns's own daemon cannot answer does not belong on tdns's CLI.
func TestParentSyncHasNoElectionVerb(t *testing.T) {
	for _, root := range []struct {
		name string
		cmd  *cobra.Command
	}{
		{"agent zone parentsync", lookupCmd(AgentCmd, "zone", "parentsync")},
		{"agent parentsync", lookupCmd(AgentCmd, "parentsync")},
		{"auth zone parentsync", lookupCmd(AuthCmd, "zone", "parentsync")},
	} {
		if root.cmd == nil {
			t.Fatalf("%s does not exist", root.name)
		}
		if lookupCmd(root.cmd, "election") != nil {
			t.Errorf("%s election is back; its handler lives in tdns-mp", root.name)
		}
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
	for _, verb := range []string{"status", "bootstrap", "roll-key", "inquire", "delta", "sync"} {
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
	subtrees := map[string]*cobra.Command{
		"agent zone parentsync": lookupCmd(AgentCmd, "zone", "parentsync"),
		"agent parentsync":      lookupCmd(AgentCmd, "parentsync"),
		"auth zone parentsync":  lookupCmd(AuthCmd, "zone", "parentsync"),
	}
	// Before any comparison: two missing subtrees are both nil, which would
	// read as "these share one object" and send the reader after the wrong
	// problem -- and the Parent() loop below would panic on the nil.
	for name, c := range subtrees {
		if c == nil {
			t.Fatalf("%s does not exist", name)
		}
	}
	seen := map[*cobra.Command]string{}
	for name, c := range subtrees {
		if other, dup := seen[c]; dup {
			t.Fatalf("%s and %s are the same command object", name, other)
		}
		seen[c] = name
		if c.Parent() == nil {
			t.Errorf("%s is not attached to anything", name)
		}
	}
}

// The retired agent "sync" carried a numeric --scheme override. It is not
// carried over: APIdelegation decodes DelegationPost but builds its
// DelegationSyncRequest without reading dp.Scheme, so the flag set a field
// nothing on the sync path ever looked at.
func TestParentSyncSyncHasNoSchemeFlag(t *testing.T) {
	for _, root := range []struct {
		name string
		cmd  *cobra.Command
	}{
		{"agent", lookupCmd(AgentCmd, "zone", "parentsync", "sync")},
		{"auth", lookupCmd(AuthCmd, "zone", "parentsync", "sync")},
	} {
		if root.cmd == nil {
			t.Fatalf("%s: parentsync sync is missing", root.name)
		}
		if f := root.cmd.Flags().Lookup("scheme"); f != nil {
			t.Errorf("%s: --scheme is back; nothing on the sync path reads it", root.name)
		}
	}
}
