package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	cli "github.com/johanix/tdns/v2/cli"
)

// deliberatelyAbsent are the canonical-tree subtrees an instance does not get,
// and why. Both are wire-protocol tools with no management-API client, so
// there is no instance for them to be scoped to (see cli.NewAuthTree).
var deliberatelyAbsent = map[string]string{
	"notify": "sends NOTIFY to an address; not an API client",
	"report": "builds a report about a zone; not an API client",
}

// paths returns every command path below root, with the root's own name
// stripped, so two trees rooted at different words compare directly.
func paths(root *cobra.Command) map[string]bool {
	out := map[string]bool{}
	var walk func(c *cobra.Command, prefix string)
	walk = func(c *cobra.Command, prefix string) {
		for _, sub := range c.Commands() {
			p := strings.TrimSpace(prefix + " " + sub.Name())
			out[p] = true
			walk(sub, p)
		}
	}
	walk(root, "")
	return out
}

// An instance tree must offer exactly the canonical auth tree minus the
// deliberately-absent subtrees.
//
// This exists because the alternative is a COUNT. "194 of 201 subcommands" was
// true the day it was measured and pins nothing: a command added only to
// cmdv2/{cli,ncli}/shared_cmds.go -- which is where most of the auth tree is
// actually wired -- lands on the canonical tree and silently misses every
// instance, with no compile error and no failing test. An operator then finds
// that `tdns-ncli auth X` works and `tdns-ncli sectdns X` does not exist.
//
// Lives here rather than in v2/cli because the canonical AuthCmd is only
// FULLY wired once this binary's init()s have run.
func TestInstanceTreeMatchesCanonicalAuthTree(t *testing.T) {
	assertTreeParity(t, "auth", "cli.NewAuthTree",
		paths(cli.AuthCmd), paths(cli.NewAuthTree("sectdns", "sectdns")), deliberatelyAbsent)
}

// The same property for an agent instance. Nothing is deliberately absent from
// it: every subtree of the canonical agent tree talks to the agent's API.
func TestInstanceTreeMatchesCanonicalAgentTree(t *testing.T) {
	assertTreeParity(t, "agent", "cli.NewAgentTree",
		paths(cli.AgentCmd), paths(cli.NewAgentTree("sectagent", "sectagent")), nil)
}

func assertTreeParity(t *testing.T, label, factory string, canonical, instance map[string]bool, absent map[string]string) {
	t.Helper()
	if len(canonical) == 0 || len(instance) == 0 {
		t.Fatalf("empty tree: canonical=%d instance=%d", len(canonical), len(instance))
	}

	// In the canonical tree but not in an instance: allowed only if it is one
	// of the deliberately-absent subtrees (or lives under one).
	var unexpectedlyMissing []string
	for p := range canonical {
		if instance[p] {
			continue
		}
		top := strings.SplitN(p, " ", 2)[0]
		if _, ok := absent[top]; ok {
			continue
		}
		unexpectedlyMissing = append(unexpectedlyMissing, p)
	}
	if len(unexpectedlyMissing) > 0 {
		sort.Strings(unexpectedlyMissing)
		t.Errorf("%d command(s) on the canonical %s tree are missing from an instance tree:\n  %s\n\n"+
			"A command wired only into shared_cmds.go reaches `%s` but no instance. Add it to "+
			"%s, or -- if it genuinely has no management-API target -- to "+
			"the deliberately-absent list here with the reason.",
			len(unexpectedlyMissing), label, strings.Join(unexpectedlyMissing, "\n  "), label, factory)
	}

	// In an instance but not canonical: always wrong.
	var extra []string
	for p := range instance {
		if !canonical[p] {
			extra = append(extra, p)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		t.Errorf("%d command(s) exist on an instance tree but not on the canonical %s tree:\n  %s",
			len(extra), label, strings.Join(extra, "\n  "))
	}

	// And the exclusions must still be real, not stale entries masking a gap.
	for name := range absent {
		if !canonical[name] {
			t.Errorf("%q is listed as deliberately absent but is not on the canonical tree either; "+
				"drop the entry", name)
		}
		if instance[name] {
			t.Errorf("%q is listed as deliberately absent but IS on the instance tree; "+
				"either it gained an API target (drop the entry) or %s changed", name, factory)
		}
	}

	t.Logf("%s: canonical %d, instance %d, deliberately absent %d subtrees",
		label, len(canonical), len(instance), len(absent))
}
