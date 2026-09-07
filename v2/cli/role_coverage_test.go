package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"

	"github.com/spf13/cobra"
)

// EVERY command in an instance tree must resolve to that instance.
//
// This is the regression test for the whole class of defect phase 2 fixed,
// rather than one test per converted call site. A command that ends up in the
// tree without inheriting its target -- because a subtree was built by a
// factory that forgot to tag, or was accidentally re-parented -- is exactly
// the silent wrong-target failure, and it is invisible in a unit test of that
// one command. Walking the tree catches it wherever it appears.
func TestEveryCommandInAnInstanceTreeInheritsTheTarget(t *testing.T) {
	const role = "sectdns"
	tree := NewAuthTree(role, role)

	var checked int
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		checked++
		if got := RoleForCmd(c); got != role {
			t.Errorf("%s resolves to %q, want %q", c.CommandPath(), got, role)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(tree)

	// A tree that shrank to nothing would pass the loop above vacuously.
	if checked < 100 {
		t.Fatalf("only walked %d commands; the auth tree should be far larger", checked)
	}
	t.Logf("%d commands, all targeting %q", checked, role)
}

// The canonical tree keeps targeting "auth". The instance work must not have
// retargeted it -- which is what attaching a shared command var to a second
// parent would have done.
func TestCanonicalAuthTreeStillTargetsAuth(t *testing.T) {
	for _, c := range []*cobra.Command{AuthCmd, CatalogCmd, DdnsCmd, DelCmd} {
		if got := RoleForCmd(c); got != "auth" {
			t.Errorf("%s targets %q, want \"auth\"", c.Name(), got)
		}
	}
}

// The two subtrees deliberately left off an instance tree are wire-protocol
// tools with no management-API client. If either ever grows a GetApiClient
// call it becomes instance-scoped and belongs in NewAuthTree -- so this fails
// to make that a decision rather than a silent inconsistency.
func TestExcludedSubtreesStillHaveNoApiClient(t *testing.T) {
	for _, f := range []string{"report_cmds.go", "notify_cmds.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if strings.Contains(string(src), "GetApiClient") {
			t.Errorf("%s now calls GetApiClient: it is instance-scoped after all, "+
				"so add it to NewAuthTree (and drop it from that function's "+
				"DELIBERATELY ABSENT note)", f)
		}
	}
}

// Source-level guard against reintroducing the defect phase 2 removed.
//
// A hardcoded role compiles, passes every test of the command it sits in, and
// is wrong only once a second instance exists -- so nothing but a check like
// this will catch the next one. Written as a test rather than a Makefile grep
// because it must run wherever the package's tests run.
//
// Parses rather than greps. A grep matches this file's own explanatory
// comments and any string that happens to contain the call, and a guard that
// cries wolf is a guard that gets deleted.
func TestNoHardcodedAuthRoleRemains(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || fn.Name != "GetApiClient" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			// Roles that have a per-instance tree factory. "agent", "scanner"
			// and "imr" are deliberately absent: those daemons have no
			// instance factory yet, so a literal there is still correct by
			// construction. Add them here when they get one.
			if lit.Value != `"auth"` {
				return true
			}
			pos := fset.Position(call.Pos())
			t.Errorf(`%s:%d hardcodes the "auth" role.

Use GetApiClientForCmd(cmd, ...) instead. A Run closure already has its
*cobra.Command, and the target is read off the tree -- so a command reached
through a second instance drives that instance rather than silently driving
the canonical one.`, f, pos.Line)
			return true
		})
	}
}

// An extra instance's `config check` must read that instance's config file,
// not the canonical daemon's. Checking the wrong file and reporting on the
// wrong server is the same class of failure as a hardcoded role, one level up
// -- and it is the check that makes keeping both configs in /etc/tdns work.
func TestConfigCheckResolvesPerInstancePaths(t *testing.T) {
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })

	apiConfig = &CliConf{ApiServers: []ApiDetails{
		{Name: "tdns-auth", BaseURL: "https://127.0.0.1:8989/api/v1"},
		{Name: "sectdns", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1",
			ConfigFile: "/etc/tdns/sec-tdns-auth.yaml"},
		{Name: "thirdauth", Role: "auth", BaseURL: "https://127.0.0.1:8991/api/v1"},
	}}

	if got := defaultCfgFileForRole("sectdns"); got != "/etc/tdns/sec-tdns-auth.yaml" {
		t.Errorf("sectdns config file = %q, want the instance's own", got)
	}
	// No config-file: on the entry -- fall back to the flavour's compiled-in
	// default rather than inventing a path.
	if got := defaultCfgFileForRole("thirdauth"); got != tdns.DefaultAuthCfgFile {
		t.Errorf("thirdauth config file = %q, want %q", got, tdns.DefaultAuthCfgFile)
	}
	// Built-in roles are untouched.
	if got := defaultCfgFileForRole("auth"); got != tdns.DefaultAuthCfgFile {
		t.Errorf("auth config file = %q, want %q", got, tdns.DefaultAuthCfgFile)
	}
	if got := defaultCfgFileForRole("agent"); got != tdns.DefaultAgentCfgFile {
		t.Errorf("agent config file = %q, want %q", got, tdns.DefaultAgentCfgFile)
	}

	// An auth instance IS a tdns-auth: same endpoints, same config sections.
	if !roleHasConfigPaths("sectdns") {
		t.Error("sectdns: /config/paths discovery disabled; it is a tdns-auth and serves it")
	}
	if got := appTypeForRole("sectdns"); got != tdns.AppTypeAuth {
		t.Errorf("sectdns app type = %v, want AppTypeAuth", got)
	}
	if roleHasConfigPaths("agent") {
		t.Error("agent must not attempt /config/paths discovery")
	}
}
