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

// config-file: must work the same way on a canonical entry and an instance
// entry. It did not: an instance's entry is named after the role ("sectdns"),
// so a raw-name lookup found it, while a built-in role ("auth") resolves
// through RegisterRole to an entry named "tdns-auth" and the raw lookup missed.
// The key silently did nothing on every canonical entry. (CodeRabbit, PR #544.)
func TestConfigFileHonouredOnCanonicalAndInstanceEntries(t *testing.T) {
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })

	apiConfig = &CliConf{ApiServers: []ApiDetails{
		{Name: "tdns-auth", ConfigFile: "/etc/tdns/custom-auth.yaml"},
		{Name: "tdns-agent", ConfigFile: "/etc/tdns/custom-agent.yaml"},
		{Name: "sectdns", Role: "auth", ConfigFile: "/etc/tdns/custom-sectdns.yaml"},
	}}

	for _, tc := range []struct{ role, want string }{
		{"auth", "/etc/tdns/custom-auth.yaml"},       // via RegisterRole -> "tdns-auth"
		{"agent", "/etc/tdns/custom-agent.yaml"},     // ditto
		{"sectdns", "/etc/tdns/custom-sectdns.yaml"}, // raw name
	} {
		if got := defaultCfgFileForRole(tc.role); got != tc.want {
			t.Errorf("defaultCfgFileForRole(%q) = %q, want %q", tc.role, got, tc.want)
		}
	}

	// With no config-file: anywhere, both fall back to the compiled-in default
	// for the flavour -- the instance must not inherit the canonical entry's.
	apiConfig = &CliConf{ApiServers: []ApiDetails{
		{Name: "tdns-auth"},
		{Name: "sectdns", Role: "auth"},
	}}
	for _, role := range []string{"auth", "sectdns"} {
		if got := defaultCfgFileForRole(role); got != tdns.DefaultAuthCfgFile {
			t.Errorf("defaultCfgFileForRole(%q) = %q, want the compiled-in %q",
				role, got, tdns.DefaultAuthCfgFile)
		}
	}
}

// `config check --help` must not name a config path the CLI would never open.
// It used to interpolate the role into "/etc/tdns/tdns-<role>.yaml", which for
// an instance named sectdns advertised /etc/tdns/tdns-sectdns.yaml while the
// command actually read the instance's own config-file:. The resolved path is
// not knowable at construction time (apiConfig is populated later), so the
// help describes the resolution instead of asserting a path.
// (CodeRabbit, PR #544.)
func TestConfigCheckHelpNamesNoBogusPath(t *testing.T) {
	for _, role := range []string{"sectdns", "otherauth"} {
		label, desc := describeConfigTarget(role)
		bogus := "/etc/tdns/tdns-" + role + ".yaml"
		if strings.Contains(desc, bogus) || strings.Contains(label, bogus) {
			t.Errorf("help for instance %q names %q, a path the CLI never opens", role, bogus)
		}
		if !strings.Contains(desc, "config-file:") {
			t.Errorf("help for instance %q should point at its config-file: entry, got %q", role, desc)
		}
	}
	// A built-in role's compiled-in default IS knowable, and naming it is the
	// useful thing to do.
	for _, tc := range []struct{ role, want string }{
		{"auth", tdns.DefaultAuthCfgFile},
		{"agent", tdns.DefaultAgentCfgFile},
		{"imr", tdns.DefaultImrCfgFile},
	} {
		label, desc := describeConfigTarget(tc.role)
		if !strings.Contains(desc, tc.want) {
			t.Errorf("help for built-in %q should name %q, got %q", tc.role, tc.want, desc)
		}
		if label != "tdns-"+tc.role {
			t.Errorf("built-in %q labelled %q, want %q", tc.role, label, "tdns-"+tc.role)
		}
	}
}

// An instance whose flavour is "agent" must be treated as an agent by every
// behaviour branch in config check, not just by the ones that happen to ask
// nicely. Its command role is its own NAME ("secagent"), so a raw
// `role == "agent"` classifies it as a non-agent — skipping checkAgentSpecifics
// and the primary-zone refusal, and running signing checks that cannot apply.
// (CodeRabbit, PR #544 round 2.)
//
// Note no agent instance can be WIRED yet — knownInstanceRoles only carries
// "auth" — so this is latent rather than live. It is pinned now because the
// day "agent" is added there, six silent misclassifications would arrive with
// it.
func TestAgentFlavouredInstanceIsClassifiedAsAnAgent(t *testing.T) {
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })

	apiConfig = &CliConf{ApiServers: []ApiDetails{
		{Name: "tdns-agent", ConfigFile: "/etc/tdns/tdns-agent.yaml"},
		{Name: "secagent", Role: "agent", ConfigFile: "/etc/tdns/sec-tdns-agent.yaml"},
		{Name: "sectdns", Role: "auth"},
	}}

	if got := effectiveRole("secagent"); got != "agent" {
		t.Errorf("effectiveRole(secagent) = %q, want \"agent\" — every agent-only "+
			"branch in config check keys on this", got)
	}
	if got := appTypeForRole("secagent"); got != tdns.AppTypeAgent {
		t.Errorf("appTypeForRole(secagent) = %v, want AppTypeAgent (wrong sections validated)", got)
	}
	// /config/paths is auth-only; an agent instance must not be probed for it,
	// or a 404 reads as "the daemon is down".
	if roleHasConfigPaths("secagent") {
		t.Error("secagent: /config/paths discovery enabled, but only tdns-auth serves it")
	}
	if got := defaultCfgFileForRole("secagent"); got != "/etc/tdns/sec-tdns-agent.yaml" {
		t.Errorf("defaultCfgFileForRole(secagent) = %q, want the instance's own file", got)
	}
	// And an auth instance is still an auth instance.
	if got := effectiveRole("sectdns"); got != "auth" {
		t.Errorf("effectiveRole(sectdns) = %q, want \"auth\"", got)
	}
	// Canonical roles unchanged.
	for _, r := range []string{"auth", "agent", "imr"} {
		if got := effectiveRole(r); got != r {
			t.Errorf("effectiveRole(%q) = %q, want it unchanged", r, got)
		}
	}
}

// Guard against reintroducing a raw role comparison in config check. Same
// reasoning as TestNoHardcodedAuthRoleRemains: it compiles, it passes every
// test of the branch it sits in, and it is wrong only for an instance.
func TestNoRawAgentRoleComparisonInConfigCheck(t *testing.T) {
	const f = "config_check_cmds.go"
	src, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, f, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
			return true
		}
		lhs, ok := bin.X.(*ast.Ident)
		if !ok || lhs.Name != "role" {
			return true
		}
		lit, ok := bin.Y.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		t.Errorf(`%s:%d compares the raw role against %s.

Use effectiveRole(role) for behaviour branches: an extra instance's role is its
own name, so a raw comparison misclassifies it. Keep the raw role only where it
identifies the API target.`, f, fset.Position(bin.Pos()).Line, lit.Value)
		return true
	})
}
