package cli

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func (d *addDaemon) update(t *testing.T, mod func(*UpdateOptions)) (*UpdateResult, error) {
	t.Helper()
	o := UpdateOptions{CliConfig: d.cli, Entry: "tdns-auth", ClientName: "tester"}
	if mod != nil {
		mod(&o)
	}
	return UpdateEntry(o)
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
   - name:        tdns-auth   # the first
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

// --cert on a key entry: the pin enrolled and checked over TCP, then the
// entry rewritten in place, its key and rootca: gone, the daemon's pins
// set. Every other line, comments included, and the other entry stay as
// they were. Run again it is refused; --repin finds the pins current.
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
`, `     authmethod:  certificate   # the key, for now
     # kept as it is
     config-file: @D@
     tlsauth:     pin
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
	if !strings.HasPrefix(out, `Switched "tdns-auth" to your client certificate in `+d.cli+":") ||
		!strings.Contains(out, "TCP check: ok (TLS, read-write, certificate tester)") || !strings.Contains(out, "Try it:") {
		t.Errorf("printed:\n%s", out)
	}

	if _, err := d.update(t, withCert); err == nil || !strings.Contains(err.Error(), "already uses a certificate; --repin") {
		t.Errorf("--cert again: %v", err)
	}
	res, err = d.update(t, withRepin)
	if err != nil || !res.Current || res.Wrote || d.commands() != "list add list" {
		t.Errorf("--repin: %+v, %v, asked %q", res, err, d.commands())
	}
	d.unchanged(t, want)
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
	want := ApiDetails{Name: "tdns-auth", BaseURL: d.url, AuthMethod: "certificate",
		TLSAuth: "pin", Pins: []string{d.srvPin}, ConfigFile: d.cfg}
	if got := mustEntries(t, d.cli); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("entries = %+v\nwant      [%+v]", got, want)
	}
	// authmethod: changed where it stands; the rest added at the end.
	if after, _ := os.ReadFile(d.cli); !strings.HasPrefix(string(after), strings.Replace(string(before), "none\n", "certificate\n", 1)) {
		t.Errorf("lines before the new ones changed:\n%s", after)
	}
}

// An entry without config-file: needs --daemon-config, and the daemon is
// not asked without it. Given, the line is written. One that disagrees
// with the entry's config-file: is refused.
func TestUpdateNeedsTheDaemonConfig(t *testing.T) {
	d := newAddDaemon(t, true)
	body := d.writeCli(t, "apiservers:\n   - name: tdns-auth\n     baseurl: @U@\n     apikey: k\n     authmethod: X-API-Key\n")
	if _, err := d.update(t, withCert); err == nil || !strings.Contains(err.Error(), "--daemon-config <file>") || d.commands() != "" {
		t.Errorf("no config-file: %v, asked %q", err, d.commands())
	}
	d.unchanged(t, body)

	if _, err := d.update(t, func(o *UpdateOptions) { o.Cert, o.DaemonConfig = true, d.cfg }); err != nil {
		t.Fatal(err)
	}
	got := mustEntries(t, d.cli)
	if len(got) != 1 || got[0].ConfigFile != d.cfg || got[0].ApiKey != "" || got[0].AuthMethod != "certificate" {
		t.Errorf("entries = %+v", got)
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
	d.onAdd = func() { writeFile(t, d.cli, changed) }
	if _, err := d.update(t, withCert); err == nil || !strings.Contains(err.Error(), "changed while config update") || !strings.Contains(err.Error(), "stays enrolled") {
		t.Errorf("client pair changed: %v", err)
	}
	d.unchanged(t, changed)
}

// --cert stops before anything is written: no access file (the daemon's
// advice, and no client pair made), a refused enrolment, a failed TCP
// request (the pin stays enrolled).
func TestUpdateCertStopsWhenTheDaemonRefuses(t *testing.T) {
	d := newAddDaemon(t, true)
	body := d.writeCli(t, keyEntries)
	d.noAccessFile = true
	if _, err := d.update(t, withCert); err == nil || !strings.Contains(err.Error(), "add access-file: under apiserver:") {
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
	if _, err := d.update(t, withCert); err == nil || !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), "run config update again") {
		t.Errorf("TCP check fails: %v", err)
	}
	d.unchanged(t, body)
}

// --repin replaces the pins (a block list, its lines going with it) after
// one request over TCP with the new ones, as the entry authenticates (here
// the key). The same pins again: nothing written. A failed request:
// nothing written.
func TestUpdateRepin(t *testing.T) {
	d := newAddDaemon(t, true)
	old := `apiservers:
   - name: tdns-auth
     baseurl: @U@
     apikey: k
     authmethod: X-API-Key
     tlsauth: pin
     pins:              # the old key, and the one before
        - "b2xk"
        - "b2xkZXI="
     config-file: @D@
`
	d.writeCli(t, old)
	res, err := d.update(t, withRepin)
	if err != nil || !res.Wrote || d.commands() != "list" {
		t.Fatalf("%+v, %v, asked %q", res, err, d.commands())
	}
	want := d.cliText(strings.Replace(old, "     pins:              # the old key, and the one before\n        - \"b2xk\"\n        - \"b2xkZXI=\"\n",
		"     pins: [ \"@P@\" ]              # the old key, and the one before\n", 1))
	if got, _ := os.ReadFile(d.cli); string(got) != want {
		t.Errorf("the CLI config is\n%s\nwant\n%s", got, want)
	}
	if !strings.Contains(strings.Join(res.Steps, "\n"), "TCP check: ok (TLS, read-write)") {
		t.Errorf("steps = %q", res.Steps)
	}

	res, err = d.update(t, withRepin)
	var sb strings.Builder
	printUpdateResult(&sb, res, UpdateOptions{Repin: true})
	if err != nil || !res.Current || !strings.HasPrefix(sb.String(), `The pins of "tdns-auth" are already current; nothing written.`) {
		t.Errorf("again: %+v, %v\n%s", res, err, sb.String())
	}
	d.unchanged(t, want)

	body := d.writeCli(t, old)
	d.refusePing = true
	if _, err := d.update(t, withRepin); err == nil || !strings.Contains(err.Error(), "with the daemon's\npins failed") {
		t.Errorf("TCP check fails: %v", err)
	}
	d.unchanged(t, body)
}

// Refused, nothing asked or written: no such entry, both flags or none.
// A dry run asks what the daemon serves, shows the entry as it would be,
// and enrols, makes and writes nothing.
func TestUpdateRefusalsAndDryRun(t *testing.T) {
	d := newAddDaemon(t, true)
	body := d.writeCli(t, keyEntries)
	for _, tc := range []struct {
		want string
		mod  func(*UpdateOptions)
	}{
		{`no entry named "nope"`, func(o *UpdateOptions) { o.Cert, o.Entry = true, "nope" }},
		{"give one of --cert", func(o *UpdateOptions) { o.Cert, o.Repin = true, true }},
		{"give one of --cert", nil},
	} {
		if _, err := d.update(t, tc.mod); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.want, err)
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
	if err != nil || res.Wrote || len(res.Steps) != 3 || res.Entry.AuthMethod != "certificate" || res.Entry.ApiKey != "" {
		t.Fatalf("dry run: %+v, %v", res, err)
	}
	if _, err := os.Stat(d.certPath); err == nil || d.commands() != "list" {
		t.Errorf("dry run: asked %q, client pair made: %v", d.commands(), err == nil)
	}
	d.unchanged(t, body)
	var sb strings.Builder
	printUpdateResult(&sb, res, UpdateOptions{Cert: true, DryRun: true})
	if out := sb.String(); !strings.HasPrefix(out, `Would change "tdns-auth" in `) || !strings.Contains(out, "First it would:\n - make your client certificate") {
		t.Errorf("dry run printed:\n%s", out)
	}
}
