package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

func (d *addDaemon) update(t *testing.T, mod func(*UpdateOptions)) (*UpdateResult, error) {
	t.Helper()
	o := UpdateOptions{CliConfig: d.cli, Entry: "auth", ClientName: "tester"}
	if mod != nil {
		mod(&o)
	}
	res, err := UpdateEntry(o)
	d.checkHook(t)
	return res, err
}

// cliText is d's CLI config: the client: block, then body, with @U@ the
// daemon's URL, @D@ its config and @P@ its pin. writeCli writes it.
func (d *addDaemon) cliText(body string) string {
	return "client:\n   cert: " + d.certPath + "\n   key: " + strings.TrimSuffix(d.certPath, ".crt") + ".key\n" +
		strings.NewReplacer("@U@", d.url, "@D@", d.cfg, "@P@", d.srvPin).Replace(body)
}

func (d *addDaemon) writeCli(t *testing.T, body string) string {
	t.Helper()
	s := d.cliText(body)
	writeFile(t, d.cli, s)
	return s
}

func withCert(o *UpdateOptions)  { o.Cert = true }
func withRepin(o *UpdateOptions) { o.Repin = true }

const keyEntries = `# The daemons.
apiservers:
   - name:        auth   # the first
     baseurl:     @U@
     apikey:      k
     authmethod:  X-API-Key   # the key, for now
     rootca:      insecure
     # kept as it is
     config-file: @D@

   - name:        other
     role:        auth
     baseurl:     https://127.0.0.1:1/api/v1
     apikey:      x
     authmethod:  X-API-Key
     tlsauth:     pin
     pins:        [ "p" ]
# after the list
`

// --cert on an entry of the API key era: the pin enrolled and checked over
// TCP, then the entry rewritten in place, its apikey:, authmethod: and
// rootca: lines gone, the daemon's pins set. Every other line, comments
// included, and the other entry stay as they were. Run again it enrols and
// writes the same; --repin finds the pins current.
func TestUpdateCertSwitchesAKeyEntry(t *testing.T) {
	d := newAddDaemon(t, true)
	d.writeCli(t, keyEntries)
	res, err := d.update(t, withCert)
	if err != nil || !res.Wrote {
		t.Fatalf("%+v, %v", res, err)
	}
	want := d.cliText(strings.Replace(keyEntries, `     apikey:      k
     authmethod:  X-API-Key   # the key, for now
     rootca:      insecure
     # kept as it is
     config-file: @D@
`, `     # kept as it is
     config-file: @D@
     pins:        [ "@P@" ]
`, 1))
	if got, _ := os.ReadFile(d.cli); string(got) != want {
		t.Errorf("the CLI config is\n%s\nwant\n%s", got, want)
	}
	pin, _, err := ensureClientCert(d.certPath, strings.TrimSuffix(d.certPath, ".crt")+".key", "x")
	if clients, _ := d.state(); err != nil || clients["tester"] != pin || d.commands() != "list add" {
		t.Errorf("the daemon was asked %q, enrolled %v (pin %s, %v)", d.commands(), clients, pin, err)
	}
	var sb strings.Builder
	printUpdateResult(&sb, res, UpdateOptions{Cert: true, CliConfig: d.cli})
	out := sb.String()
	if !strings.HasPrefix(out, `"auth" now uses your client certificate, in `+d.cli+":") ||
		!strings.Contains(out, "TCP check: ok (TLS, read-write, certificate tester)") || !strings.Contains(out, "Try it:") {
		t.Errorf("printed:\n%s", out)
	}

	if res, err := d.update(t, withCert); err != nil || !res.Wrote {
		t.Errorf("--cert again: %+v, %v; want it enrolled again (already there) and written", res, err)
	}
	d.unchanged(t, want)
	res, err = d.update(t, withRepin)
	if err != nil || !res.Current || res.Wrote || d.commands() != "list add list add list" {
		t.Errorf("--repin: %+v, %v, asked %q", res, err, d.commands())
	}
	d.unchanged(t, want)
}

// --rename gives an entry its new name where its name: stands, and needs no
// daemon. An old name (tdns-auth) becomes the role's; with --cert it is
// renamed and switched in one go.
func TestUpdateRename(t *testing.T) {
	d := newAddDaemon(t, true)
	old := strings.Replace(keyEntries, "- name:        auth   # the first", "- name:        tdns"+"-auth   # the first", 1)
	d.writeCli(t, old)
	res, err := d.update(t, func(o *UpdateOptions) { o.Entry, o.Rename = "tdns-auth", "auth" })
	if err != nil || !res.Wrote || d.commands() != "" {
		t.Fatalf("rename: %+v, %v, asked %q", res, err, d.commands())
	}
	got := mustEntries(t, d.cli)
	if len(got) != 2 || got[0].Name != "auth" || got[0].Role != "auth" || got[1].Name != "other" {
		t.Errorf("entries after the rename: %+v", got)
	}
	raw, _ := os.ReadFile(d.cli)
	if !strings.Contains(string(raw), "- name:        auth   # the first\n") || strings.Contains(string(raw), "apikey:      k") {
		t.Errorf("the CLI config after the rename:\n%s", raw)
	}
	var sb strings.Builder
	printUpdateResult(&sb, res, UpdateOptions{Rename: "auth", CliConfig: d.cli})
	if !strings.HasPrefix(sb.String(), `Renamed "tdns-auth" to "auth" in `) {
		t.Errorf("printed:\n%s", sb.String())
	}

	d.writeCli(t, old)
	if res, err := d.update(t, func(o *UpdateOptions) { o.Entry, o.Rename, o.Cert = "tdns-auth", "auth", true }); err != nil || !res.Wrote {
		t.Fatalf("rename with --cert: %+v, %v", res, err)
	}
	if got := mustEntries(t, d.cli); got[0].Name != "auth" || !reflect.DeepEqual(got[0].Pins, []string{d.srvPin}) {
		t.Errorf("after rename with --cert: %+v", got[0])
	}

	// Refused, nothing written: a name in use, an old name, another role's
	// name, a name that is no command word.
	body := d.writeCli(t, old)
	for _, tc := range []struct{ entry, name, want string }{
		{"tdns-auth", "other", "an entry has that name already"},
		{"other", "tdns-imr", "an old name"},
		{"other", "imr", "the imr entry's name"},
		{"other", "Not A Name", "not usable"},
	} {
		if _, err := d.update(t, func(o *UpdateOptions) { o.Entry, o.Rename = tc.entry, tc.name }); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("rename %s to %q: %v, want %q", tc.entry, tc.name, err, tc.want)
		}
	}
	d.unchanged(t, body)
}

// A stopped daemon's add gives the config-file:-only entry; --cert is
// refused until the daemon runs, and then gives the entry its address,
// the certificate and the pins: what config add gives a running daemon.
func TestUpdateCertCompletesAConfigFileOnlyEntry(t *testing.T) {
	d := newAddDaemon(t, false)
	if _, err := d.add(t, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(d.cli)
	if _, err := d.update(t, withCert); err == nil || !strings.Contains(err.Error(), "is not running") || !strings.Contains(err.Error(), "nothing was written") {
		t.Errorf("stopped: %v", err)
	}
	d.unchanged(t, string(before))

	d.start(t)
	if _, err := d.update(t, withCert); err != nil {
		t.Fatal(err)
	}
	want := ApiDetails{Name: "auth", Role: "auth", BaseURL: d.url, Pins: []string{d.srvPin}, ConfigFile: d.cfg}
	if got := mustEntries(t, d.cli); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("entries = %+v\nwant      [%+v]", got, want)
	}
	// The new lines are added at the end; the ones before stay.
	if after, _ := os.ReadFile(d.cli); !strings.HasPrefix(string(after), string(before)) {
		t.Errorf("lines before the new ones changed:\n%s", after)
	}
}

// An entry without config-file: needs --daemon-config, and the daemon is
// not asked without it. Given, the line is written. One that disagrees
// with the entry's config-file: is refused.
func TestUpdateNeedsTheDaemonConfig(t *testing.T) {
	d := newAddDaemon(t, true)
	body := d.writeCli(t, "apiservers:\n   - name: auth\n     baseurl: @U@\n     apikey: k\n     authmethod: X-API-Key\n")
	if _, err := d.update(t, withCert); err == nil || !strings.Contains(unwrapCommands(err.Error()), "config update auth --cert --client-name tester --daemon-config "+tdns.DefaultAuthCfgFile) || d.commands() != "" {
		t.Errorf("no config-file: %v, asked %q", err, d.commands())
	}
	d.unchanged(t, body)

	if _, err := d.update(t, func(o *UpdateOptions) { o.Cert, o.DaemonConfig = true, d.cfg }); err != nil {
		t.Fatal(err)
	}
	got := mustEntries(t, d.cli)
	if raw, _ := os.ReadFile(d.cli); len(got) != 1 || got[0].ConfigFile != d.cfg || len(got[0].Pins) != 1 || strings.Contains(string(raw), "apikey") {
		t.Errorf("entries = %+v\n%s", got, raw)
	}
	after, _ := os.ReadFile(d.cli)
	if _, err := d.update(t, func(o *UpdateOptions) { o.Repin, o.DaemonConfig = true, d.cfg+".other" }); err == nil || !strings.Contains(err.Error(), "(--daemon-config)") {
		t.Errorf("another --daemon-config: %v", err)
	}
	d.unchanged(t, string(after))
}

// --cert: a client pair changed while the pin was enrolled is not the one
// enrolled, and nothing is written.
func TestUpdateCertClientPairChanged(t *testing.T) {
	d := newAddDaemon(t, true)
	d.writeCli(t, keyEntries)
	changed := strings.Replace(d.cliText(keyEntries), d.certPath, d.certPath+".new", 1)
	d.onAdd = func() error { return os.WriteFile(d.cli, []byte(changed), 0o600) }
	if _, err := d.update(t, withCert); err == nil || !strings.Contains(err.Error(), "changed while config update") || !strings.Contains(err.Error(), "enrolled as tester") || !strings.Contains(unwrapCommands(err.Error()), "\n   "+ncliFor(d.cli)+" config update auth --cert --client-name tester\nor run that with another --client-name") {
		t.Errorf("client pair changed: %v", err)
	}
	d.unchanged(t, changed)
}

// --cert stops before anything is written: no access file (the touch line
// and the command to run again, and no client pair made), a refused
// enrolment, a failed TCP request (the pin stays enrolled).
func TestUpdateCertStopsWhenTheDaemonRefuses(t *testing.T) {
	d := newAddDaemon(t, true)
	body := d.writeCli(t, keyEntries)
	d.noAccessFile = true
	if _, err := d.update(t, withCert); err == nil || !strings.Contains(err.Error(), "touch /etc/tdns/tdns-auth-access.yaml") ||
		!strings.Contains(unwrapCommands(err.Error()), "then run this again:\n   "+ncliFor(d.cli)+" config update auth --cert --client-name tester") {
		t.Errorf("no access file: %v", err)
	}
	if _, err := os.Stat(d.certPath); err == nil || d.commands() != "list" {
		t.Errorf("no access file: asked %q, client pair made: %v", d.commands(), err == nil)
	}
	d.unchanged(t, body)

	d.mu.Lock()
	d.noAccessFile, d.refuseAdd = false, `"tester" is already there with another pin`
	d.mu.Unlock()
	if _, err := d.update(t, withCert); err == nil || !strings.Contains(err.Error(), d.refuseAdd) {
		t.Errorf("refused add: %v", err)
	}
	d.unchanged(t, body)

	d.mu.Lock()
	d.refuseAdd, d.refusePing = "", true
	d.mu.Unlock()
	if _, err := d.update(t, withCert); err == nil || !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(unwrapCommands(err.Error()), "reuses it:\n   "+ncliFor(d.cli)+" config update auth --cert --client-name tester") {
		t.Errorf("TCP check fails: %v", err)
	}
	d.unchanged(t, body)
}

// --repin replaces the pins (a block list, its lines going with it) after
// one request over TCP with the new ones and the client certificate. The
// same pins again: nothing written. A failed request: nothing written.
func TestUpdateRepin(t *testing.T) {
	d := newAddDaemon(t, true)
	d.mu.Lock()
	d.clients["tester"] = "" // enrolled below, with the pair config update uses
	d.mu.Unlock()
	pin, _, err := ensureClientCert(d.certPath, strings.TrimSuffix(d.certPath, ".crt")+".key", "tester")
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.clients["tester"] = pin
	d.mu.Unlock()
	old := `apiservers:
   - name: auth
     baseurl: @U@
     pins:              # the old certificate, and the one before
        - "b2xk"
        - "b2xkZXI="
     config-file: @D@
`
	d.writeCli(t, old)
	res, err := d.update(t, withRepin)
	if err != nil || !res.Wrote || d.commands() != "list" {
		t.Fatalf("%+v, %v, asked %q", res, err, d.commands())
	}
	want := d.cliText(strings.Replace(old, "     pins:              # the old certificate, and the one before\n        - \"b2xk\"\n        - \"b2xkZXI=\"\n",
		"     pins: [ \"@P@\" ]              # the old certificate, and the one before\n", 1))
	if got, _ := os.ReadFile(d.cli); string(got) != want {
		t.Errorf("the CLI config is\n%s\nwant\n%s", got, want)
	}
	if !strings.Contains(strings.Join(res.Steps, "\n"), "TCP check: ok (TLS, read-write, certificate tester)") {
		t.Errorf("steps = %q", res.Steps)
	}

	res, err = d.update(t, withRepin)
	var sb strings.Builder
	printUpdateResult(&sb, res, UpdateOptions{Repin: true})
	if err != nil || !res.Current || !strings.HasPrefix(sb.String(), `The pins of "auth" are already current; nothing written.`) {
		t.Errorf("again: %+v, %v\n%s", res, err, sb.String())
	}
	d.unchanged(t, want)

	// Current pins but no config-file:: --daemon-config writes the line.
	noCfg := "apiservers:\n   - name: auth\n     baseurl: @U@\n     pins: [ \"@P@\" ]\n"
	d.writeCli(t, noCfg)
	res, err = d.update(t, func(o *UpdateOptions) { o.Repin, o.DaemonConfig = true, d.cfg })
	if err != nil || !res.Wrote || res.Current || res.Entry.ConfigFile != d.cfg {
		t.Errorf("current pins, no config-file: %+v, %v", res, err)
	}
	if got := mustEntries(t, d.cli); len(got) != 1 || got[0].ConfigFile != d.cfg {
		t.Errorf("current pins, no config-file: entries %+v", got)
	}

	body := d.writeCli(t, old)
	d.refusePing = true
	if _, err := d.update(t, withRepin); err == nil || !strings.Contains(err.Error(), "with the daemon's\npins failed") {
		t.Errorf("TCP check fails: %v", err)
	}
	d.unchanged(t, body)
}

// Refused, nothing asked or written: no such entry, both flags, none, or
// not one entry. Each such refusal lists the entries with the command for
// each, as one line when it fits. A dry run asks what the daemon serves,
// shows the entry as it would be, and enrols, makes and writes nothing.
func TestUpdateRefusalsAndDryRun(t *testing.T) {
	d := newAddDaemon(t, true)
	body := d.writeCli(t, keyEntries)
	for _, tc := range []struct {
		want string
		mod  func(*UpdateOptions)
	}{
		{`no entry named "nope"`, func(o *UpdateOptions) { o.Cert, o.Entry = true, "nope" }},
		{"takes --cert or --repin, not both", func(o *UpdateOptions) { o.Cert, o.Repin = true, true }},
		{"needs an entry and --cert, --repin or\n--rename.", nil},
		{"needs an entry and --cert, --repin or\n--rename.", func(o *UpdateOptions) { o.Cert, o.Args = true, []string{} }},
	} {
		_, err := d.update(t, tc.mod)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.want, err)
			continue
		}
		msg := unwrapCommands(err.Error())
		for _, want := range []string{"Your entries in " + d.cli + ":", ncliFor(d.cli) + " config update auth --cert", ncliFor(d.cli) + " config update other --repin"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: the refusal lacks %q:\n%s", tc.want, want, err)
			}
		}
	}
	d.unchanged(t, body)
	body2 := d.writeCli(t, strings.Replace(keyEntries, "https://127", "http://127", 1))
	if _, err := d.update(t, func(o *UpdateOptions) { o.Repin, o.Entry = true, "other" }); err == nil || !strings.Contains(err.Error(), "no https address") {
		t.Errorf("--repin, http: %v", err)
	}
	d.unchanged(t, body2)
	d.writeCli(t, keyEntries)
	if d.commands() != "" {
		t.Errorf("the daemon was asked %q", d.commands())
	}

	res, err := d.update(t, func(o *UpdateOptions) { o.Cert, o.DryRun = true, true })
	if err != nil || res.Wrote || len(res.Steps) != 3 || len(res.Entry.Pins) != 1 {
		t.Fatalf("dry run: %+v, %v", res, err)
	}
	if _, err := os.Stat(d.certPath); err == nil || d.commands() != "list" {
		t.Errorf("dry run: asked %q, client pair made: %v", d.commands(), err == nil)
	}
	d.unchanged(t, body)
	var sb strings.Builder
	printUpdateResult(&sb, res, UpdateOptions{Cert: true, DryRun: true})
	if out := sb.String(); !strings.HasPrefix(out, `Would change "auth" in `) || !strings.Contains(out, "First it would:\n - make your client certificate") {
		t.Errorf("dry run printed:\n%s", out)
	}
}

// The listing in a refusal: one aligned line per entry when every line fits
// in 72 columns, the command for each; an old name gets --rename.
func TestUpdateUsageListsTheEntries(t *testing.T) {
	asNcli(t)
	err := updateUsage(tdns.DefaultNcliCfgFile, []ApiDetails{
		{Name: "auth", BaseURL: "https://127.0.0.1:8989/api/v1", Pins: []string{pinOf("a")}, ConfigFile: "/etc/tdns/tdns-auth.yaml"},
		{Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1", ConfigFile: "/etc/tdns/tdns-auth2.yaml"},
		{Name: "tdns-imr", ConfigFile: "/etc/tdns/tdns-imr.yaml"},
	}, "config update needs an entry and --cert, --repin or\n--rename.")
	want := `config update needs an entry and --cert, --repin or
--rename.
Your entries in /etc/tdns/tdns-ncli.yaml:
   auth      pinned    tdns-ncli config update auth --repin
   auth2     no pins   tdns-ncli config update auth2 --cert
   tdns-imr  old name  tdns-ncli config update tdns-imr --rename imr`
	if err == nil || err.Error() != want {
		t.Errorf("refusal:\n%v\nwant\n%s", err, want)
	}
	for _, l := range strings.Split(err.Error(), "\n") {
		if len("Error: "+l) > 72 && !strings.HasPrefix(l, "   ") {
			t.Errorf("line over 72: %q", l)
		}
		if strings.HasPrefix(l, "   ") && len(l) > 72 {
			t.Errorf("entry line over 72: %q", l)
		}
	}
}

// A tdns-cli run (#1205): the stale-pin fix names tdns-ncli with --config
// <the file this run read>, not tdns-ncli's own config, and that command,
// run as printed, re-pins the entry in the tdns-cli config.
func TestPinRefusalWorksForATdnsCliConfig(t *testing.T) {
	d := newAddDaemon(t, true)
	// As tdns-cli has it: its own sections, a key entry, a stale pin.
	cfg := filepath.Join(filepath.Dir(d.cli), "tdns-cli.yaml")
	// The client pair the CLI config names, enrolled with the daemon.
	pin, _, err := ensureClientCert(d.certPath, strings.TrimSuffix(d.certPath, ".crt")+".key", "tester")
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.clients["tester"] = pin
	d.mu.Unlock()
	writeFile(t, cfg, strings.NewReplacer("@U@", d.url, "@D@", d.cfg, "@C@", d.certPath, "@K@", strings.TrimSuffix(d.certPath, ".crt")+".key").Replace(`algorithms:
   costsfile: /etc/tdns/algorithm-costs.yaml
client:
   cert: @C@
   key: @K@
apiservers:
   - name:              auth
     baseurl:           @U@
     pins:              [ "b2xk" ]
     config-file:       @D@
`))
	savedCfg, savedDef := apiConfig, DefaultCliConfigFile
	t.Cleanup(func() { apiConfig, DefaultCliConfigFile = savedCfg, savedDef })
	DefaultCliConfigFile = tdns.DefaultCliCfgFile // as tdns-cli runs

	e := mustEntries(t, cfg)[0]
	apiConfig = nil // the file not known: tdns-cli's default
	if fix := updateFix(e, "--repin"); fix != "tdns-ncli --config "+tdns.DefaultCliCfgFile+" config update auth --repin" {
		t.Errorf("no file known: fix = %q", fix)
	}
	apiConfig = &CliConf{File: cfg} // as tdns-cli's root sets it
	fix := updateFix(e, "--repin")
	if want := "tdns-ncli --config " + cfg + " config update auth --repin"; fix != want {
		t.Fatalf("fix = %q, want %q", fix, want)
	}

	// Run as printed: tdns-ncli's root flag --config, then config update.
	words := strings.Fields(fix) // cfg is one shell word (a temp dir)
	root := &cobra.Command{Use: words[0]}
	root.PersistentFlags().String("config", "", "")
	config := &cobra.Command{Use: "config"}
	config.AddCommand(newConfigUpdateCmd())
	root.AddCommand(config)
	root.SetArgs(words[1:])
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := mustEntries(t, cfg); len(got) != 1 || !reflect.DeepEqual(got[0].Pins, []string{d.srvPin}) {
		t.Errorf("after the fix: %+v, want the daemon's pin", got)
	}
	if raw, _ := os.ReadFile(cfg); !strings.HasPrefix(string(raw), "algorithms:\n   costsfile: /etc/tdns/algorithm-costs.yaml\nclient:\n") {
		t.Errorf("tdns-cli's own section changed:\n%s", raw)
	}
}
