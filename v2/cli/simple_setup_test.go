package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	if err := printedCommandError(line); err != nil {
		t.Error(err)
	}
}

// printedCommandError is checkPrintedCommand's verdict on line.
func printedCommandError(line string) error {
	root := ncliTree()
	line = strings.TrimSpace(unwrapCommands(line))
	words, err := splitCommandLine(line)
	if err != nil || len(words) == 0 || words[0] != "tdns-ncli" {
		return fmt.Errorf("%q: not a tdns-ncli command line (%v)", line, err)
	}
	cmd, rest, err := root.Find(words[1:])
	// A group (config) is found for "config reload" too, with "reload" left
	// over: only a command that runs is one.
	if err != nil || cmd == root || !cmd.Runnable() {
		return fmt.Errorf("%q: no such command (%v)", line, err)
	}
	if err := cmd.ParseFlags(rest); err != nil {
		return fmt.Errorf("%q: %v", line, err)
	}
	if cmd.Args != nil {
		if err := cmd.Args(cmd, cmd.Flags().Args()); err != nil {
			return fmt.Errorf("%q: %v", line, err)
		}
	}
	return nil
}

// TestPrintedCommandCheckRefuses is the checker's negative control: a
// command that does not exist must not pass, a group with a word left over
// among them.
func TestPrintedCommandCheckRefuses(t *testing.T) {
	for _, line := range []string{
		"tdns-ncli config reload",
		"tdns-ncli config",
		"tdns-ncli nosuch",
		"tdns-ncli config update auth --nosuchflag",
	} {
		if printedCommandError(line) == nil {
			t.Errorf("%q passed", line)
		}
	}
	if err := printedCommandError("tdns-ncli config update auth --rename auth2"); err != nil {
		t.Errorf("a real command was refused: %v", err)
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

// The touch line of a missing-file refusal quotes the path, so that it runs
// as pasted (a path with a space in it).
func TestAccessFileMissingQuotesThePath(t *testing.T) {
	const path = "/etc/my tdns/tdns-auth-access.yaml"
	msg := accessFileMissing(path, "tdns-auth", "tdns-ncli config add /etc/tdns/tdns-auth.yaml").Error()
	if !strings.Contains(msg, "\n   touch '"+path+"'\nthen run this again:\n") {
		t.Errorf("refusal:\n%s\nwant the path quoted in the touch line", msg)
	}
}

// A command that needs the CLI config, which is not there, says how to
// create it for the daemon the command is for: imr ping names tdns-imr's
// config, not tdns-auth's.
func TestMissingCliConfigNamesTheCommandsDaemon(t *testing.T) {
	asNcli(t)
	root := ncliTree()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"imr", "ping"}, tdns.DefaultImrCfgFile},
		{[]string{"agent", "zone", "list"}, tdns.DefaultAgentCfgFile},
		{[]string{"auth", "ping"}, tdns.DefaultAuthCfgFile},
		{[]string{"client", "init"}, tdns.DefaultAuthCfgFile},
	} {
		cmd, _, err := root.Find(tc.args)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		got := MissingCliConfig(cmd, tdns.DefaultNcliCfgFile)
		want := "no CLI config " + tdns.DefaultNcliCfgFile + ". Create it with:\n   tdns-ncli config add " + tc.want
		if got != want {
			t.Errorf("%v:\n%s\nwant\n%s", tc.args, got, want)
		}
	}
}

// A dry run's refusal gives a retry that is a dry run too, for config add
// and config update both.
func TestRetriesKeepDryRun(t *testing.T) {
	asNcli(t)
	add := retryAdd(AddOptions{DaemonConfig: "/etc/tdns/tdns-auth2.yaml", DryRun: true}, "")
	up := retryUpdate(UpdateOptions{Entry: "auth2", Cert: true, DryRun: true}, "")
	for _, c := range []string{add, up} {
		if !strings.Contains(c+" ", " --dry-run ") {
			t.Errorf("%q: no --dry-run", c)
		}
		checkPrintedCommand(t, c)
	}
	if c := retryAdd(AddOptions{DaemonConfig: "/etc/tdns/tdns-auth2.yaml"}, ""); strings.Contains(c, "--dry-run") {
		t.Errorf("%q: --dry-run without a dry run", c)
	}
}

// A role's own entry without config-file: (as config update --rename
// writes it, with role:) starts on the role's default config; an instance
// without one is refused.
func TestRoleEntryStartsWithoutConfigFile(t *testing.T) {
	cmd := &cobra.Command{Use: "start"}
	if _, err := daemonStartFlags(cmd, &ApiDetails{Name: "auth", Role: "auth"}); err != nil {
		t.Errorf("auth refused: %v", err)
	}
	if _, err := daemonStartFlags(cmd, &ApiDetails{Name: "auth2", Role: "auth"}); err == nil {
		t.Error("auth2 without config-file: was not refused")
	}
}

// --rename refuses a command word, as wiring would, but takes the role's
// own name.
func TestRenameRefusesACommandWord(t *testing.T) {
	root := ncliTree()
	taken := func(n string) bool { return findChild(root, n) != nil }
	e := ApiDetails{Name: "auth2", Role: "auth"}
	err := checkRename(UpdateOptions{Rename: "config", CommandWordTaken: taken}, []ApiDetails{e}, e)
	if err == nil || !strings.Contains(err.Error(), "a command of the CLI") {
		t.Errorf("--rename config: %v", err)
	}
	old := ApiDetails{Name: "tdns-auth"}
	if err := checkRename(UpdateOptions{Rename: "auth", CommandWordTaken: taken}, []ApiDetails{old}, old); err != nil {
		t.Errorf("--rename auth: %v", err)
	}
}

// An entry with an old name and an explicit role is renamed after its
// role, which checkRename takes.
func TestRenamedToFollowsAnExplicitRole(t *testing.T) {
	if n := renamedTo(ApiDetails{Name: "tdns-auth"}); n != "auth" {
		t.Errorf("tdns-auth: %q", n)
	}
	e := ApiDetails{Name: "tdns-auth", Role: "agent"}
	if n := renamedTo(e); n != "agent" {
		t.Errorf("tdns-auth, role agent: %q", n)
	}
	if err := checkRename(UpdateOptions{Rename: renamedTo(e)}, []ApiDetails{e}, e); err != nil {
		t.Errorf("the rename it gives is refused: %v", err)
	}
}

// config check reports a baseurl the client refuses, not just http://.
func TestCheckCliConfigRefusesOtherSchemes(t *testing.T) {
	asNcli(t)
	cfg := filepath.Join(t.TempDir(), "tdns-ncli.yaml")
	if err := os.WriteFile(cfg, []byte("apiservers:\n   - name: auth\n     role: auth\n     baseurl: ftp://localhost/api/v1\n     config-file: /etc/tdns/tdns-auth.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadApiServers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	if n := CheckCliConfig(&sb, ncliTree(), cfg, entries, nil); n != 1 || !strings.Contains(sb.String(), "neither https:// nor unix://") {
		t.Errorf("%d problems:\n%s", n, sb.String())
	}
}

// commandLines breaks only between shell words: a " --" inside a quoted
// path stays in it.
func TestCommandLinesKeepsQuotedWords(t *testing.T) {
	path := "/srv/a --b/" + strings.Repeat("x", 60) + "/tdns-auth.yaml"
	cmd := "tdns-ncli config update auth --daemon-config " + shellQuote(path) + " --cert"
	if parts := splitAtFlags(cmd); len(parts) != 3 {
		t.Errorf("split into %d: %q", len(parts), parts)
	}
	out := commandLines(cmd, 3)
	if !strings.Contains(out, shellQuote(path)) {
		t.Errorf("the quoted path was broken:\n%s", out)
	}
}

// daemon start, stop and restart need no API client: an entry without one
// (no baseurl, its daemon not running yet) gets its daemon's local admin
// socket. Not for an entry whose TCP address its daemon config does not
// list: that may be another host's daemon.
func TestLifecycleFallsBackToTheSocket(t *testing.T) {
	dir := shortSockDir(t)
	cfg := filepath.Join(dir, "tdns-auth2.yaml")
	sock := filepath.Join(dir, "a2.sock")
	writeFile(t, cfg, daemonYAML("TDNS-AUTH", "127.0.0.1:8995", "   socket: "+sock+"\n"))
	noClient := errors.New("no client")

	c, err := lifecycleSocketClient("auth", &ApiDetails{Name: "auth2", Role: "auth", ConfigFile: cfg}, noClient)
	if err != nil || c == nil || c.BaseUrl != "http://localhost/api/v1" {
		t.Fatalf("socket entry: %v, %+v", err, c)
	}
	same := &ApiDetails{Name: "auth2", Role: "auth", ConfigFile: cfg, BaseURL: "https://127.0.0.1:8995/api/v1"}
	if c, err := lifecycleSocketClient("auth", same, noClient); err != nil || c == nil {
		t.Errorf("entry with its daemon's address: %v", err)
	}
	other := &ApiDetails{Name: "auth2", Role: "auth", ConfigFile: cfg, BaseURL: "https://192.0.2.1:8995/api/v1"}
	if _, err := lifecycleSocketClient("auth", other, noClient); err != noClient {
		t.Errorf("entry with another address: %v", err)
	}
}

// An entry kept off this host's socket by its address says so, with the
// fix that takes the daemon's own address and pins.
func TestTCPRefusalNamesTheAddress(t *testing.T) {
	asNcli(t)
	dir := shortSockDir(t)
	cfg := filepath.Join(dir, "tdns-auth.yaml")
	writeFile(t, cfg, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "   socket: "+filepath.Join(dir, "a.sock")+"\n"))

	_, _, err := buildApiClient(ApiDetails{Name: "auth", Role: "auth", ConfigFile: cfg, BaseURL: "https://127.0.0.1:8075/api/v1"}, CliClientConf{}, "", "")
	var r clientRefusal
	if !errors.As(err, &r) || !strings.Contains(r.why, "127.0.0.1:8075 is not one") || r.fix != "tdns-ncli config update auth --repin" {
		t.Errorf("refusal = %+v (%v)", r, err)
	}
	// Another host's address: that config may not be the daemon's there,
	// so the refusal is the ordinary one.
	_, _, err = buildApiClient(ApiDetails{Name: "auth", Role: "auth", ConfigFile: cfg, BaseURL: "https://192.0.2.1:8989/api/v1"}, CliClientConf{}, "", "")
	if !errors.As(err, &r) || strings.Contains(r.why, "is not one") {
		t.Errorf("another host: %+v (%v)", r, err)
	}
	_, _, err = buildApiClient(ApiDetails{Name: "auth", Role: "auth", ConfigFile: cfg, BaseURL: "https://127.0.0.1:8989/api/v1"}, CliClientConf{}, "", "")
	if !errors.As(err, &r) || strings.Contains(r.why, "is not one") {
		t.Errorf("its own address: %+v (%v)", r, err)
	}
	// What ping says when the entry's address refuses the connection.
	hp, addrs := addressNotListed(ApiDetails{Name: "imr", ConfigFile: cfg, BaseURL: "https://127.0.0.1:8075/api/v1"})
	if hp != "127.0.0.1:8075" || len(addrs) != 1 || addrs[0] != "127.0.0.1:8989" {
		t.Errorf("addressNotListed = %q, %q", hp, addrs)
	}
	if hp, _ := addressNotListed(ApiDetails{Name: "auth", ConfigFile: cfg, BaseURL: "https://127.0.0.1:8989/api/v1"}); hp != "" {
		t.Errorf("its own address reported as not listed: %q", hp)
	}
}

// An entry whose address is on this host but not one its daemon config
// lists (a stale address) reaches the daemon over its local admin socket,
// with a warning that gives the fix. One on another host does not.
func TestStaleLocalAddressUsesTheSocket(t *testing.T) {
	asNcli(t)
	saved := ForceTCP
	t.Cleanup(func() { ForceTCP = saved })
	ForceTCP = false
	dir := shortSockDir(t)
	cfg, sock := filepath.Join(dir, "tdns-imr.yaml"), filepath.Join(dir, "i.sock")
	writeFile(t, cfg, daemonYAML("", "127.0.0.1:8084", "   socket: "+sock+"\n"))
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(tdns.ConfigResponse{ConfigFile: cfg})
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	got, note := usableDaemonSocket(ApiDetails{Name: "imr", Role: "imr", ConfigFile: cfg, BaseURL: "https://127.0.0.1:8075/api/v1"})
	if got != sock || !strings.Contains(note, "127.0.0.1:8075 is not one") || !strings.Contains(note, "tdns-ncli config update imr --repin") {
		t.Errorf("stale local address: %q, note %q", got, note)
	}
	if got, note := usableDaemonSocket(ApiDetails{Name: "imr", Role: "imr", ConfigFile: cfg, BaseURL: "https://127.0.0.1:8084/api/v1"}); got != sock || note != "" {
		t.Errorf("its own address: %q, note %q", got, note)
	}
	if got, _ := usableDaemonSocket(ApiDetails{Name: "imr", Role: "imr", ConfigFile: cfg, BaseURL: "https://192.0.2.1:8084/api/v1"}); got != "" {
		t.Errorf("another host's address used this host's socket %q", got)
	}
}

func TestOnThisHost(t *testing.T) {
	for hp, want := range map[string]bool{
		"127.0.0.1:8075": true, "[::1]:8075": true, "localhost:8075": true,
		"192.0.2.1:8075": false, "example.net:8075": false, "nonsense": false,
	} {
		if got := onThisHost(hp); got != want {
			t.Errorf("onThisHost(%q) = %v", hp, got)
		}
	}
}

// shortSockDir is a temporary directory with a short path: a socket path
// has a limit.
func shortSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ncli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// An entry is named after its daemon's file, whichever order the daemons are
// added in: tdns-auth.yaml is auth even when tdns-auth2.yaml came first (or
// its own add was refused).
func TestEntryNamedAfterItsFile(t *testing.T) {
	withCleanRoleRegistry(t)
	RegisterRole("auth", "auth")
	RegisterRole("imr", "imr")
	for _, c := range []struct {
		role, file string
		existing   []ApiDetails
		want       string
		canonical  bool
	}{
		{"auth", "/etc/tdns/tdns-auth2.yaml", nil, "auth2", false},
		{"auth", "/etc/tdns/tdns-auth.yaml", []ApiDetails{{Name: "auth2", Role: "auth"}}, "auth", true},
		{"auth", "/etc/tdns/tdns-auth3.yaml", []ApiDetails{{Name: "auth2", Role: "auth"}}, "auth3", false},
		{"auth", "/etc/tdns-enc/tdns-auth.yaml", []ApiDetails{{Name: "auth", Role: "auth"}}, "auth2", false},
		{"imr", "/etc/tdns/tdns-imr.yaml", nil, "imr", true},
		{"imr", "/etc/tdns/tdns-imr2.yaml", nil, "imr2", false},
	} {
		var e ApiDetails
		var res AddResult
		if err := chooseEntryName(&e, &res, c.role, c.existing, AddOptions{DaemonConfig: c.file}); err != nil || e.Name != c.want || e.Role != c.role || res.Canonical != c.canonical {
			t.Errorf("%s after %v: %q (role %q, canonical %v), %v", c.file, c.existing, e.Name, e.Role, res.Canonical, err)
		}
	}
}
