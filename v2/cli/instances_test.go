package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The property the whole feature rests on: the auth tree's factories can be
// called a second time with a different role, producing an independent tree.
// If this ever stops holding -- a factory acquires a sync.Once, a package-level
// registration, a singleton -- multi-instance addressing breaks, and it breaks
// by silently sharing state rather than by failing to compile.
func TestNewAuthTreeIsIndependentPerRole(t *testing.T) {
	a := NewAuthTree("auth", "auth")
	b := NewAuthTree("sectdns", "sectdns")

	if a == b {
		t.Fatal("same pointer returned for two roles")
	}
	if a.Name() != "auth" || b.Name() != "sectdns" {
		t.Fatalf("wrong command words: %q / %q", a.Name(), b.Name())
	}
	if len(a.Commands()) == 0 {
		t.Fatal("auth tree has no subcommands")
	}
	if len(a.Commands()) != len(b.Commands()) {
		t.Fatalf("trees differ in size: %d vs %d", len(a.Commands()), len(b.Commands()))
	}
	// Same command set, different targets: that is the whole point.
	for i, ca := range a.Commands() {
		if cb := b.Commands()[i]; ca.Name() != cb.Name() {
			t.Fatalf("subcommand %d differs: %q vs %q", i, ca.Name(), cb.Name())
		}
	}
	if got := RoleForCmd(a); got != "auth" {
		t.Errorf("auth tree targets %q, want \"auth\"", got)
	}
	if got := RoleForCmd(b); got != "sectdns" {
		t.Errorf("sectdns tree targets %q, want \"sectdns\"", got)
	}
}

// A deep subcommand inherits its tree's target. This is what lets a Run
// closure resolve the right daemon without the role having been threaded
// through every constructor between it and the root.
func TestRoleIsInheritedByDepth(t *testing.T) {
	tree := NewAuthTree("sectdns", "sectdns")

	var deepest *cobra.Command
	var walk func(c *cobra.Command, depth int)
	maxDepth := 0
	walk = func(c *cobra.Command, depth int) {
		if depth > maxDepth {
			maxDepth, deepest = depth, c
		}
		for _, sub := range c.Commands() {
			walk(sub, depth+1)
		}
	}
	walk(tree, 0)

	if maxDepth < 3 {
		t.Fatalf("expected a tree at least 3 deep, got %d", maxDepth)
	}
	if got := RoleForCmd(deepest); got != "sectdns" {
		t.Errorf("%s (depth %d) targets %q, want \"sectdns\"",
			deepest.CommandPath(), maxDepth, got)
	}
}

// An untagged tree must be reported as a wiring bug, NOT silently defaulted to
// "auth". A default is precisely the silent wrong-target failure this
// mechanism exists to prevent: it would send a command meant for one daemon to
// another with no diagnostic at all.
func TestUntaggedTreeIsAnErrorNotADefault(t *testing.T) {
	orphan := &cobra.Command{Use: "orphan"}
	if got := RoleForCmd(orphan); got != "" {
		t.Fatalf("untagged command reported role %q, want \"\"", got)
	}
	if _, err := GetApiClientForCmd(orphan, false); err == nil {
		t.Fatal("GetApiClientForCmd on an untagged tree returned no error")
	}
}

// A subtree may override its parent's target -- the walk is upward and stops
// at the first tag, so the nearest one wins.
func TestNearestTagWins(t *testing.T) {
	root := TagRole(&cobra.Command{Use: "root"}, "auth")
	mid := TagRole(&cobra.Command{Use: "mid"}, "sectdns")
	leaf := &cobra.Command{Use: "leaf"}
	mid.AddCommand(leaf)
	root.AddCommand(mid)

	if got := RoleForCmd(leaf); got != "sectdns" {
		t.Errorf("leaf targets %q, want the nearer tag \"sectdns\"", got)
	}
}

// Every way an apiservers entry can be wrong must cost that entry its
// subcommand and nothing else. In particular a name that shadows a built-in
// role must be refused: honouring it would retarget the canonical tree.
func TestWireInstanceTreesRefusesBadEntries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry ApiDetails
		want  string
	}{
		{"shadows a built-in role", ApiDetails{Name: "auth", Role: "auth"}, "collides with a built-in role"},
		{"shadows an existing command", ApiDetails{Name: "version", Role: "auth"}, "collides with the existing"},
		{"unknown role", ApiDetails{Name: "x", Role: "combiner"}, "has no command tree"},
		{"no name", ApiDetails{Name: "", Role: "auth"}, "no name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := &cobra.Command{Use: "tdns-ncli"}
			root.AddCommand(&cobra.Command{Use: "version"})
			before := len(root.Commands())

			warnings := WireInstanceTrees(root, []ApiDetails{tc.entry})

			if len(warnings) != 1 {
				t.Fatalf("got %d warnings, want 1: %v", len(warnings), warnings)
			}
			if !strings.Contains(warnings[0], tc.want) {
				t.Errorf("warning %q does not mention %q", warnings[0], tc.want)
			}
			if len(root.Commands()) != before {
				t.Errorf("a refused entry still added a command")
			}
		})
	}
}

// An entry with no role: is a canonical target, reached through its built-in
// tree. It must not produce a second tree, and must not warn.
func TestWireInstanceTreesIgnoresCanonicalEntries(t *testing.T) {
	root := &cobra.Command{Use: "tdns-ncli"}
	warnings := WireInstanceTrees(root, []ApiDetails{
		{Name: "tdns-auth", BaseURL: "https://127.0.0.1:8989/api/v1"},
	})
	if len(warnings) != 0 {
		t.Errorf("canonical entry warned: %v", warnings)
	}
	if len(root.Commands()) != 0 {
		t.Errorf("canonical entry added a command tree")
	}
}

func TestWireInstanceTreesWiresAGoodEntry(t *testing.T) {
	root := &cobra.Command{Use: "tdns-ncli"}
	warnings := WireInstanceTrees(root, []ApiDetails{
		{Name: "sectdns", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1"},
	})
	if len(warnings) != 0 {
		t.Fatalf("good entry warned: %v", warnings)
	}
	sub := findChild(root, "sectdns")
	if sub == nil {
		t.Fatal("no sectdns command was added")
	}
	if got := RoleForCmd(sub); got != "sectdns" {
		t.Errorf("wired tree targets %q, want \"sectdns\"", got)
	}
	// The command word IS the clientKey: one name for the operator to know.
	if got := GetClientKeyFromParent("sectdns"); got != "sectdns" {
		t.Errorf("role %q maps to clientKey %q, want \"sectdns\"", "sectdns", got)
	}
}

// The config path has to be recovered without cobra's flag parsing, because
// this runs before Find(). Both spellings, and a sane fallback.
func TestConfigPathFromArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--config", "/tmp/a.yaml", "auth", "zone", "list"}, "/tmp/a.yaml"},
		{[]string{"--config=/tmp/b.yaml", "auth"}, "/tmp/b.yaml"},
		{[]string{"auth", "zone", "list"}, "/etc/tdns/tdns-cli.yaml"},
		{[]string{"--config"}, "/etc/tdns/tdns-cli.yaml"}, // dangling: fall back, don't panic
		{nil, "/etc/tdns/tdns-cli.yaml"},
	} {
		if got := ConfigPathFromArgs(tc.args); got != tc.want {
			t.Errorf("ConfigPathFromArgs(%v) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

// Reading the instance list must never be fatal: commands that need no config
// at all have to keep working, and at read time we do not yet know which
// command was typed.
func TestEarlyApiServersIsBestEffort(t *testing.T) {
	if got := EarlyApiServers("/nonexistent/nope.yaml"); got != nil {
		t.Errorf("missing config returned %v, want nil", got)
	}

	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.yaml")
	if err := os.WriteFile(junk, []byte("this: [is: not: valid: yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := EarlyApiServers(junk); got != nil {
		t.Errorf("malformed config returned %v, want nil", got)
	}

	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, []byte(`
apiservers:
   - name: tdns-auth
     baseurl: https://127.0.0.1:8989/api/v1
     apikey: k
     authmethod: X-API-Key
   - name: sectdns
     role: auth
     baseurl: https://127.0.0.1:8990/api/v1
     apikey: k
     authmethod: X-API-Key
     config-file: /etc/tdns/sec-tdns-auth.yaml
`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := EarlyApiServers(good)
	if len(got) != 2 {
		t.Fatalf("read %d entries, want 2: %+v", len(got), got)
	}
	if got[1].Role != "auth" {
		t.Errorf("role decoded as %q, want \"auth\" (mapstructure tag missing?)", got[1].Role)
	}
	if got[1].ConfigFile != "/etc/tdns/sec-tdns-auth.yaml" {
		t.Errorf("config-file decoded as %q", got[1].ConfigFile)
	}
}

// The guide tells operators which instance names are reserved. That list is
// only true if every one of them is actually refused -- and three of them
// (help, completion, show-cmds) are added to the tree AFTER instance wiring
// runs, so they were silently accepted until the wiring forced them in first.
//
// Names the caller is responsible for materialising before wiring (cobra's
// lazily added help/completion) are tested here the way a caller must set them
// up; show-cmds is reserved by name inside WireInstanceTrees because it has to
// be attached after wiring in order to see the instance trees.
func TestReservedNamesAreAllRefused(t *testing.T) {
	reserved := []string{
		"auth", "agent", "imr", "scanner", // built-in roles
		"cert", "util", "version", // built-in top-level commands
		"help", "completion", // cobra's lazily added commands
		ShowCmdsName, // attached after wiring; reserved by name
	}

	for _, name := range reserved {
		t.Run(name, func(t *testing.T) {
			root := &cobra.Command{Use: "tdns-ncli"}
			// The tree a real binary presents at wiring time.
			for _, c := range []*cobra.Command{AuthCmd, AgentCmd, ImrCmd, ScannerCmd} {
				root.AddCommand(&cobra.Command{Use: c.Name()})
			}
			for _, n := range []string{"cert", "util", "version"} {
				root.AddCommand(&cobra.Command{Use: n})
			}
			// As cmdv2/ncli/root.go does, before wiring.
			root.InitDefaultHelpCmd()
			root.InitDefaultCompletionCmd()

			before := len(root.Commands())
			warnings := WireInstanceTrees(root, []ApiDetails{{Name: name, Role: "auth"}})

			if len(warnings) != 1 {
				t.Fatalf("%q was accepted (warnings: %v) -- it would shadow or fight "+
					"an existing command, and guide/multi-instance-cli.md promises "+
					"it is refused", name, warnings)
			}
			if len(root.Commands()) != before {
				t.Errorf("%q was refused but still added a command", name)
			}
		})
	}
}

// An apiservers entry living only in cli.localconfig must still become a
// command word. The early loader read the main config but not the local one,
// so such an entry was invisible at routing time: cobra had already failed
// with `unknown command "..."` by the time the full load found it.
// (CodeRabbit, PR #544.)
func TestEarlyApiServersMergesLocalConfig(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "local.yaml")
	main := filepath.Join(dir, "main.yaml")

	if err := os.WriteFile(local, []byte(`
apiservers:
   - name: localonly
     role: auth
     baseurl: https://127.0.0.1:8992/api/v1
     apikey: k
     authmethod: X-API-Key
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte("cli:\n   localconfig: "+local+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	entries := EarlyApiServers(main)
	found := false
	for _, e := range entries {
		if e.Name == "localonly" && e.Role == "auth" {
			found = true
		}
	}
	if !found {
		t.Fatalf("instance defined only in cli.localconfig was not seen: %+v", entries)
	}

	// A named-but-absent local config is normal -- that is what makes it local
	// -- and must not discard the entries the main config already gave us.
	main2 := filepath.Join(dir, "main2.yaml")
	if err := os.WriteFile(main2, []byte(`
cli:
   localconfig: `+filepath.Join(dir, "does-not-exist.yaml")+`
apiservers:
   - name: tdns-auth
     baseurl: https://127.0.0.1:8989/api/v1
     apikey: k
     authmethod: X-API-Key
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := EarlyApiServers(main2); len(got) != 1 {
		t.Errorf("a missing local config lost the main config's entries: %+v", got)
	}
}
