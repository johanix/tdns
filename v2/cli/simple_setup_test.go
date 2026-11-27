package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

// ncliTree is the command tree a tdns-ncli run presents, enough of it to
// parse the commands a refusal prints: the root's --config, the CLI config
// commands, the client commands, and each daemon's tree.
func ncliTree() *cobra.Command {
	root := &cobra.Command{Use: "tdns-ncli"}
	root.PersistentFlags().String("config", "", "")
	root.AddCommand(NewCliConfigCmd(), NewClientTopCmd(),
		NewAuthTree("auth", "auth"), NewAgentTree("agent", "agent"), NewImrTree("imr", "imr"),
		NewAuthTree("auth2", "auth2"))
	return root
}

// checkPrintedCommand parses line, a command a refusal printed for the
// operator to run, against a fresh tdns-ncli tree: the command must exist,
// take every flag given, and accept its arguments. A line broken between
// flags is joined first.
func checkPrintedCommand(t *testing.T, line string) {
	t.Helper()
	root := ncliTree()
	line = strings.TrimSpace(unwrapCommands(line))
	words, err := splitCommandLine(line)
	if err != nil || len(words) == 0 || words[0] != "tdns-ncli" {
		t.Errorf("%q: not a tdns-ncli command line (%v)", line, err)
		return
	}
	cmd, rest, err := root.Find(words[1:])
	if err != nil || cmd == root {
		t.Errorf("%q: no such command (%v)", line, err)
		return
	}
	if err := cmd.ParseFlags(rest); err != nil {
		t.Errorf("%q: %v", line, err)
		return
	}
	if cmd.Args != nil {
		if err := cmd.Args(cmd, cmd.Flags().Args()); err != nil {
			t.Errorf("%q: %v", line, err)
		}
	}
}

// commandsIn are the lines of a refusal that are commands for the operator:
// indented, starting with tdns-ncli, joined where broken.
func commandsIn(s string) []string {
	var out []string
	for _, l := range strings.Split(unwrapCommands(s), "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "tdns-ncli ") {
			// A table row: name and state, then the command.
			if i := strings.Index(t, "tdns-ncli "); i > 0 {
				t = t[i:]
			}
			out = append(out, t)
		} else if i := strings.Index(l, "  tdns-ncli "); i >= 0 {
			out = append(out, strings.TrimSpace(l[i:]))
		}
	}
	return out
}

// Every command the main refusals of the config and client commands print
// is one that runs: it exists, with those flags (design 2026-11-26, change
// 2). The refusal for a daemon's missing access file printed a reload that
// tdns-imr's tree did not have; this is what would have caught it.
func TestRefusalsPrintCommandsThatExist(t *testing.T) {
	asNcli(t)
	cfg := tdns.DefaultNcliCfgFile
	entries := []ApiDetails{
		{Name: "auth", BaseURL: "https://127.0.0.1:8989/api/v1", Pins: []string{pinOf("a")}, ConfigFile: "/etc/tdns/tdns-auth.yaml"},
		{Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1", ConfigFile: "/etc/tdns/tdns-auth2.yaml"},
		{Name: "tdns-imr", ConfigFile: "/etc/tdns/tdns-imr.yaml"},
		{Name: "agent", BaseURL: "http://127.0.0.1:8987/api/v1"},
	}
	var refusals []string
	refusals = append(refusals, updateUsage(cfg, entries, "lead").Error())
	refusals = append(refusals, updateUsage(cfg, nil, "lead").Error())
	refusals = append(refusals, accessFileMissing("/etc/tdns/tdns-auth-access.yaml", "tdns-auth",
		retryAdd(AddOptions{CliConfig: cfg, DaemonConfig: "/etc/tdns/tdns-auth.yaml"}, "")).Error())
	refusals = append(refusals, accessFileMissing("/etc/tdns/tdns-imr-access.yaml", "tdns-imr",
		retryUpdate(UpdateOptions{CliConfig: cfg, Entry: "imr", Cert: true, DaemonConfig: "/etc/tdns/tdns-imr.yaml"}, "tester")).Error())
	for _, e := range entries {
		_, _, err := buildApiClient(e, CliClientConf{Cert: "/nonexistent/c.crt", Key: "/nonexistent/c.key"}, "", "")
		var r clientRefusal
		if errors.As(err, &r) {
			refusals = append(refusals, "\n   "+r.fix)
		}
		refusals = append(refusals, "\n   "+updateFix(e, "--repin"))
	}
	allEntries = entries
	t.Cleanup(func() { allEntries = nil })
	for _, role := range []string{"imr", "agent"} {
		var r clientRefusal
		if errors.As(missingEntry(role, roleToClientKey[role]), &r) {
			refusals = append(refusals, "\n   "+r.fix)
		}
	}
	var sb strings.Builder
	CheckCliConfig(&sb, ncliTree(), cfg, entries, nil)
	refusals = append(refusals, sb.String())

	n := 0
	for _, r := range refusals {
		for _, c := range commandsIn(r) {
			n++
			checkPrintedCommand(t, c)
		}
	}
	if n < 12 {
		t.Errorf("only %d commands found in the refusals; the test lost its subject", n)
	}
}

// A command stays on one line when it fits in 72 columns, indent included;
// one that does not is broken between flags only, with a trailing
// backslash, so it runs as pasted.
func TestCommandLines(t *testing.T) {
	short := "tdns-ncli imr config reload --daemon-config /etc/tdns/tdns-imr.yaml"
	if got := commandLines(short, 3); got != "   "+short {
		t.Errorf("a command that fits (%d columns with its indent) was broken:\n%s", 3+len(short), got)
	}
	long := "tdns-ncli --config /etc/tdns/some/longer/path/tdns-ncli.yaml config update auth2 --cert --client-name operator-host --daemon-config /etc/tdns/tdns-auth2.yaml"
	got := commandLines(long, 3)
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("a %d-column command was not broken:\n%s", len(long), got)
	}
	for i, l := range lines {
		// The first line is the program and its first flag, which stay
		// together; any other line over 72 is one flag that does not fit.
		if len(l) > 72 && strings.Count(strings.TrimSuffix(l, " \\"), " --") > 1 {
			t.Errorf("line %d over 72 though it could break: %q", i, l)
		}
		if i < len(lines)-1 && !strings.HasSuffix(l, " \\") {
			t.Errorf("line %d does not end in a backslash: %q", i, l)
		}
		if i > 0 && !strings.HasPrefix(strings.TrimSpace(l), "--") {
			t.Errorf("line %d does not start with a flag: %q", i, l)
		}
	}
	if unwrapCommands(got) != "   "+long {
		t.Errorf("joined again it is not the command:\n%s", unwrapCommands(got))
	}
}

// config check fails on an entry with an old name, and prints the rename;
// on plain http and on an https entry without pins, with --cert. An entry
// that can be used passes; leftover key lines are a note.
func TestCheckCliConfig(t *testing.T) {
	asNcli(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tdns-ncli.yaml")
	if err := os.WriteFile(cfg, []byte(`apiservers:
   - name: tdns-auth
     baseurl: https://127.0.0.1:8989/api/v1
     apikey: k
     authmethod: X-API-Key
     config-file: /etc/tdns/tdns-auth.yaml
   - name: imr
     baseurl: https://127.0.0.1:8080/api/v1
     pins: [ "`+pinOf("i")+`" ]
     rootca: insecure
   - name: agent
     baseurl: http://127.0.0.1:8987/api/v1
     config-file: /etc/tdns/tdns-agent.yaml
`), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadApiServers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	n := CheckCliConfig(&sb, ncliTree(), cfg, entries, obsoleteEntryKeysIn(cfg))
	out := sb.String()
	if n != 2 || !strings.HasPrefix(out, "CLI config "+cfg+": 2 problems.\n") {
		t.Fatalf("%d problems:\n%s", n, out)
	}
	cmd := "tdns-ncli --config " + cfg + " config update "
	for _, want := range []string{
		"tdns-auth: the old name of the auth entry",
		"\n   " + cmd + "tdns-auth --rename auth --cert\n",
		"agent: plain http",
		"\n   " + cmd + "agent --cert\n",
		"Note: imr has rootca: lines of the API key era",
	} {
		if !strings.Contains(unwrapCommands(out), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, l := range strings.Split(out, "\n") {
		if len(l) > 72 && !strings.Contains(l, cfg) {
			t.Errorf("line over 72: %q", l)
		}
	}
}

// A role whose entry the CLI config has under its old name: the refusal
// says so and gives the rename; with no entry at all, config add.
func TestMissingEntryRefusal(t *testing.T) {
	asNcli(t)
	allEntries = []ApiDetails{{Name: "tdns-auth", ConfigFile: "/etc/tdns/tdns-auth.yaml"}}
	t.Cleanup(func() { allEntries = nil })
	var r clientRefusal
	if !errors.As(missingEntry("auth", "auth"), &r) || r.fix != "tdns-ncli config update tdns-auth --rename auth" {
		t.Errorf("old name: %+v", r)
	}
	if !errors.As(missingEntry("imr", "imr"), &r) || r.fix != "tdns-ncli config add "+tdns.DefaultImrCfgFile {
		t.Errorf("no entry: %+v", r)
	}
}

// Every /config command a daemon serves for operators has a command of the
// same name under `config` in that daemon's tree (design 2026-11-26, change
// 4). tdns-imr's tree had no reload.
func TestConfigTreesCoverTheServedCommands(t *testing.T) {
	for app, tree := range map[tdns.AppType]*cobra.Command{
		tdns.AppTypeAuth:  NewAuthTree("auth", "auth"),
		tdns.AppTypeAgent: NewAgentTree("agent", "agent"),
		tdns.AppTypeImr:   NewImrTree("imr", "imr"),
	} {
		config, _, err := tree.Find([]string{"config"})
		if err != nil || config == tree {
			t.Errorf("%s: no config subtree", tree.Name())
			continue
		}
		for _, served := range tdns.ConfigOperatorCommands[app] {
			if c, _, err := config.Find([]string{served}); err != nil || c == config {
				t.Errorf("%s config has no %q, which tdns-%s serves", tree.Name(), served, tree.Name())
			}
		}
	}
}
