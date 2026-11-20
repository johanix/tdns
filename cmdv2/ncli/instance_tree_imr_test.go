package main

import (
	"sort"
	"strings"
	"testing"

	cli "github.com/johanix/tdns/v2/cli"
)

// imrDeliberatelyAbsent are the command paths of the canonical imr tree that an
// imr instance does not get, and why. Unlike the auth tree's two excluded
// top-level words, these include a path two words deep (stats large-ksk), so
// entries match a command or anything below it.
//
// All of them have no management-API target: they read or change the state of
// the process they run in, which for tdns-ncli is not the resolver, or they do
// nothing at all. See cli.NewImrTree.
var imrDeliberatelyAbsent = map[string]string{
	"show":            "reads the state of the process it runs in (for tdns-imr --cli)",
	"set":             "changes the state of the process it runs in (for tdns-imr --cli)",
	"zone":            "placeholders that print a line and do nothing",
	"dsync-query":     "starts its own resolver in the CLI process; no daemon involved",
	"stats large-ksk": "in-process metrics",
}

func underAbsent(p string, absent map[string]string) bool {
	for k := range absent {
		if p == k || strings.HasPrefix(p, k+" ") {
			return true
		}
	}
	return false
}

// The imr instance tree must offer exactly the canonical imr tree minus the
// deliberately-absent commands: the property TestInstanceTreeMatchesCanonical-
// AuthTree gives auth, for the same reason. A command wired only into a
// binary's shared_cmds.go, or added to the canonical tree later, would
// otherwise silently miss every instance.
func TestInstanceTreeMatchesCanonicalImrTree(t *testing.T) {
	canonical := paths(cli.ImrCmd)
	instance := paths(cli.NewImrTree("sectimr", "sectimr"))

	if len(canonical) == 0 || len(instance) == 0 {
		t.Fatalf("empty tree: canonical=%d instance=%d", len(canonical), len(instance))
	}

	var missing []string
	for p := range canonical {
		if !instance[p] && !underAbsent(p, imrDeliberatelyAbsent) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d command(s) on the canonical imr tree are missing from an instance tree:\n  %s\n\n"+
			"Add each to cli.NewImrTree if it talks to the daemon's API, or to imrDeliberatelyAbsent here "+
			"with the reason if it only describes the CLI's own process.",
			len(missing), strings.Join(missing, "\n  "))
	}

	var extra []string
	for p := range instance {
		if !canonical[p] {
			extra = append(extra, p)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		t.Errorf("%d command(s) exist on an instance tree but not on the canonical imr tree:\n  %s",
			len(extra), strings.Join(extra, "\n  "))
	}

	// And the exclusions must still be real: on the canonical tree, off the
	// instance, not stale entries masking a gap.
	for p := range imrDeliberatelyAbsent {
		if !canonical[p] {
			t.Errorf("%q is listed as deliberately absent but is not on the canonical tree either; drop the entry", p)
		}
		if instance[p] {
			t.Errorf("%q is listed as deliberately absent but IS on the instance tree", p)
		}
	}

	t.Logf("imr: canonical %d, instance %d, deliberately absent %d entries",
		len(canonical), len(instance), len(imrDeliberatelyAbsent))
}
