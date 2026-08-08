/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// testTree builds a miniature stand-in for the tdns-cli tree, deep enough to
// exercise the depth-based Hidden rule:
//
//	tdns-cli (0) -> auth (1) -> catalog (2) -> group (3) -> add
//	                                        -> create
//	             -> version            (leaf, no subcommands)
func testTree() *cobra.Command {
	run := func(cmd *cobra.Command, args []string) {}

	add := &cobra.Command{Use: "add", Short: "add a group", Run: run}
	group := &cobra.Command{Use: "group", Short: "group ops"}
	group.AddCommand(add)

	create := &cobra.Command{Use: "create", Short: "create a catalog", Run: run}
	catalog := &cobra.Command{Use: "catalog", Short: "catalog ops"}
	catalog.AddCommand(create, group)

	auth := &cobra.Command{Use: "auth", Short: "auth ops"}
	auth.AddCommand(catalog)

	root := &cobra.Command{Use: "tdns-cli"}
	root.AddCommand(auth, &cobra.Command{Use: "version", Short: "version", Run: run})
	return root
}

// findCmd walks down a path of command names, e.g. "auth", "catalog".
func findCmd(t *testing.T, root *cobra.Command, path ...string) *cobra.Command {
	t.Helper()
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
			t.Fatalf("command %q not found under %q", name, cur.CommandPath())
		}
		cur = next
	}
	return cur
}

// countShowCmds returns the total number of show-cmds commands in the tree.
func countShowCmds(cmd *cobra.Command) int {
	n := 0
	for _, c := range cmd.Commands() {
		if c.Name() == ShowCmdsName {
			n++
			continue
		}
		n += countShowCmds(c)
	}
	return n
}

// TestAttachShowCmdsIsIdempotent guards the exported entry point: it is meant
// to be reusable by other binaries (mpcli, tdns-debug), and cobra's AddCommand
// does not deduplicate, so a second call must not give every parent a second
// show-cmds child.
func TestAttachShowCmdsIsIdempotent(t *testing.T) {
	root := testTree()

	AttachShowCmds(root)
	first := countShowCmds(root)
	// root, auth, catalog, group -- "version" is a leaf and gets none.
	if first != 4 {
		t.Fatalf("after one attach: got %d show-cmds, want 4", first)
	}

	AttachShowCmds(root)
	if second := countShowCmds(root); second != first {
		t.Errorf("attach is not idempotent: %d show-cmds after second call, want %d",
			second, first)
	}
}

// TestAttachShowCmdsHiddenBelowAppLevel pins Johan's placement rule: visible at
// the root and under each application prefix, hidden further down so that the
// deeper help screens stay clean.
func TestAttachShowCmdsHiddenBelowAppLevel(t *testing.T) {
	root := testTree()
	AttachShowCmds(root)

	for _, tc := range []struct {
		path       []string
		wantHidden bool
	}{
		{path: nil, wantHidden: false},                        // tdns-cli
		{path: []string{"auth"}, wantHidden: false},           // app prefix
		{path: []string{"auth", "catalog"}, wantHidden: true}, // below
		{path: []string{"auth", "catalog", "group"}, wantHidden: true},
	} {
		parent := findCmd(t, root, tc.path...)
		sc := findCmd(t, parent, ShowCmdsName)
		if sc.Hidden != tc.wantHidden {
			t.Errorf("%s: Hidden = %v, want %v", sc.CommandPath(), sc.Hidden, tc.wantHidden)
		}
	}
}

// TestAttachShowCmdsSkipsLeaves: a command with no subcommands has nothing to
// list, so it must not grow a show-cmds.
func TestAttachShowCmdsSkipsLeaves(t *testing.T) {
	root := testTree()
	AttachShowCmds(root)

	version := findCmd(t, root, "version")
	for _, c := range version.Commands() {
		if c.Name() == ShowCmdsName {
			t.Errorf("leaf command %q was given a show-cmds", version.CommandPath())
		}
	}
}

// TestCollectShowCmdsListing covers the listing itself: full invocation paths,
// name-sorted, with show-cmds and cobra's own scaffolding left out.
func TestCollectShowCmdsListing(t *testing.T) {
	root := testTree()
	AttachShowCmds(root)

	auth := findCmd(t, root, "auth")
	var got []string
	for _, e := range collectShowCmds(auth, 1, 0, false) {
		got = append(got, e.path)
	}

	want := []string{
		"tdns-cli auth catalog",
		"tdns-cli auth catalog create",
		"tdns-cli auth catalog group",
		"tdns-cli auth catalog group add",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("listing mismatch:\n got: %v\nwant: %v", got, want)
	}
}

// TestCollectShowCmdsDepth: --depth N stops N levels below the subtree root.
func TestCollectShowCmdsDepth(t *testing.T) {
	root := testTree()
	AttachShowCmds(root)
	auth := findCmd(t, root, "auth")

	for _, tc := range []struct {
		depth int
		want  int
	}{
		{depth: 1, want: 1}, // catalog
		{depth: 2, want: 3}, // + create, group
		{depth: 3, want: 4}, // + group add
		{depth: 0, want: 4}, // no limit
	} {
		if got := len(collectShowCmds(auth, 1, tc.depth, false)); got != tc.want {
			t.Errorf("depth %d: got %d entries, want %d", tc.depth, got, tc.want)
		}
	}
}

// TestCollectShowCmdsHiddenAndAll: hidden commands are omitted by default and
// revealed by --all -- but show-cmds itself stays out either way, since it
// exists on every parent and would drown out the tree.
func TestCollectShowCmdsHiddenAndAll(t *testing.T) {
	root := testTree()
	auth := findCmd(t, root, "auth")
	auth.AddCommand(&cobra.Command{
		Use:    "secret",
		Hidden: true,
		Run:    func(cmd *cobra.Command, args []string) {},
	})
	AttachShowCmds(root)

	contains := func(entries []showCmdsEntry, path string) bool {
		for _, e := range entries {
			if e.path == path {
				return true
			}
		}
		return false
	}

	def := collectShowCmds(auth, 1, 0, false)
	if contains(def, "tdns-cli auth secret") {
		t.Error("hidden command listed without --all")
	}

	all := collectShowCmds(auth, 1, 0, true)
	if !contains(all, "tdns-cli auth secret") {
		t.Error("hidden command not listed with --all")
	}
	if contains(all, "tdns-cli auth "+ShowCmdsName) {
		t.Error("show-cmds listed itself with --all")
	}
}

// TestShowCmdsRejectsNegativeDepth: 0 is the documented "no limit" sentinel, so
// a negative value must be an error rather than a silent full dump.
func TestShowCmdsRejectsNegativeDepth(t *testing.T) {
	root := testTree()
	AttachShowCmds(root)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)

	root.SetArgs([]string{"auth", ShowCmdsName, "--depth", "-1"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--depth -1 was accepted, want an error")
	}
	if !strings.Contains(err.Error(), "--depth") {
		t.Errorf("error does not mention the offending flag: %v", err)
	}
}
