package cli

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	tdns "github.com/johanix/tdns/v2"
)

func TestApiBaseURL(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want string
		err  bool
	}{
		{"127.0.0.1:8989", "https://127.0.0.1:8989/api/v1", false},
		{"0.0.0.0:8990", "https://127.0.0.1:8990/api/v1", false}, // wildcard: where it listens, not where we connect
		{":8990", "https://127.0.0.1:8990/api/v1", false},
		{"[::]:8990", "https://[::1]:8990/api/v1", false},
		{"[2001:db8::1]:8989", "https://[2001:db8::1]:8989/api/v1", false},
		{"ns1.example.net:8989", "https://ns1.example.net:8989/api/v1", false},
		{"[fe80::1%eth0]:8990", "https://[fe80::1%25eth0]:8990/api/v1", false}, // a zone's % escaped, so the URL parses
		{"127.0.0.1", "", true}, // no port
		{"", "", true},
	} {
		got, err := apiBaseURL(tc.addr)
		if (err != nil) != tc.err {
			t.Errorf("apiBaseURL(%q): err=%v, want error=%v", tc.addr, err, tc.err)
			continue
		}
		if got != tc.want {
			t.Errorf("apiBaseURL(%q) = %q, want %q", tc.addr, got, tc.want)
		}
		if got != "" {
			if _, err := url.Parse(got); err != nil {
				t.Errorf("apiBaseURL(%q) = %q does not parse: %v", tc.addr, got, err)
			}
		}
	}
}

func TestDeriveInstanceName(t *testing.T) {
	for path, want := range map[string]string{
		"/etc/tdns/tdns-auth2.yaml":        "auth2",
		"/etc/tdns/tdns-auth.yaml":         "auth",
		"/etc/tdns/sec-tdns-auth.yaml":     "sec-tdns-auth",
		"/etc/tdns/TDNS-Auth_Two.yml":      "auth-two",
		"/etc/tdns/tdns-2nd-auth.yaml":     "", // must start with a letter
		"/etc/tdns/tdns-.yaml":             "",
		"/etc/tdns/tdns-auth.example.yaml": "auth-example",
	} {
		if got := deriveInstanceName(path); got != want {
			t.Errorf("deriveInstanceName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestFreeName(t *testing.T) {
	taken := map[string]bool{"auth": true, "auth2": true, "auth3": true}
	f := func(n string) bool { return taken[n] }
	for base, want := range map[string]string{
		"auth":  "auth4", // auth, auth2, auth3 all used
		"auth2": "auth4", // stripped to the stem, not auth22
		"other": "other",
	} {
		if got := freeName(base, f); got != want {
			t.Errorf("freeName(%q) = %q, want %q", base, got, want)
		}
	}
}

// TestDerivedNameIsValidated: a derived name that is taken gets a digit
// appended, which can push it past 32 characters. It is refused like an
// invalid --name, not written.
func TestDerivedNameIsValidated(t *testing.T) {
	long := strings.Repeat("a", 32) // valid, and the most a name may be
	existing := []ApiDetails{{Name: "auth"}, {Name: long, Role: "auth"}}
	var entry ApiDetails
	var res AddResult
	err := chooseEntryName(&entry, &res, "auth", existing, AddOptions{DaemonConfig: "/etc/tdns/tdns-" + long + ".yaml"})
	if err == nil || !strings.Contains(err.Error(), "--name") {
		t.Fatalf("err = %v, entry = %+v; want a refusal pointing at --name", err, entry)
	}
	if entry.Name != "" {
		t.Errorf("entry.Name = %q, want it left empty", entry.Name)
	}
}

func TestDetectDaemonRole(t *testing.T) {
	for _, tc := range []struct {
		name       string
		service    string
		hasService bool
		hasImr     bool
		path       string
		want       string
		wantWarn   bool
		wantErrIn  string
	}{
		{name: "auth by service.name", service: "TDNS-AUTH", hasService: true, path: "/etc/tdns/x.yaml", want: "auth"},
		{name: "auth with a digit", service: "TDNS-AUTH2", hasService: true, path: "/etc/tdns/x.yaml", want: "auth"},
		{name: "agent by service.name", service: "TDNS-AGENT", hasService: true, hasImr: true, path: "/etc/tdns/x.yaml", want: "agent"},
		{name: "imr: no service block", hasImr: true, path: "/etc/tdns/x.yaml", want: "imr"},
		{name: "auth: imrengine alone does not make it imr", service: "TDNS-AUTH", hasService: true, hasImr: true, path: "/etc/tdns/x.yaml", want: "auth"},
		{name: "falls back to the file name", path: "/etc/tdns/tdns-auth2.yaml", want: "auth"},
		{name: "service.name wins over the file name", service: "TDNS-AGENT", hasService: true, path: "/etc/tdns/tdns-auth.yaml", want: "agent", wantWarn: true},
		{name: "undecidable", path: "/etc/tdns/foo.yaml", wantErrIn: "use --role"},
		{name: "mp daemon refused", service: "TDNS-MPAGENT", hasService: true, path: "/etc/tdns/tdns-mpagent.yaml", wantErrIn: "tdns-mp"},
		// A hyphen splits "mp" off as a word of its own, which used to leave
		// "agent" to be read as a tdns agent.
		{name: "hyphenated mp service.name refused", service: "TDNS-MP-AGENT", hasService: true, path: "/etc/tdns/x.yaml", wantErrIn: "tdns-mp"},
		{name: "hyphenated mp file name refused", path: "/etc/tdns/tdns-mp-agent.yaml", wantErrIn: "tdns-mp"},
		// The file name only decides when service.name does not: a tdns-auth
		// whose file happens to carry "mp" is a tdns-auth, with a warning.
		{name: "service.name wins over an mp file name", service: "TDNS-AUTH", hasService: true, path: "/etc/tdns/west-mp-auth.yaml", want: "auth", wantWarn: true},
		{name: "an mp service.name is refused whatever the file", service: "TDNS-MPSIGNER", hasService: true, path: "/etc/tdns/tdns-auth.yaml", wantErrIn: "tdns-mp"},
		// A deciding name with two roles in it is no evidence for either.
		{name: "file name with two roles", service: "WEST", hasService: true, path: "/etc/tdns/west-agent-auth.yaml", wantErrIn: "more than one daemon type"},
		{name: "service.name with two roles", service: "AGENT-AUTH", hasService: true, path: "/etc/tdns/x.yaml", wantErrIn: "more than one daemon type"},
		{name: "the same role twice is one role", path: "/etc/tdns/auth-auth2.yaml", want: "auth"},
		{name: "service.name decides over a two-role file name", service: "TDNS-AUTH", hasService: true, path: "/etc/tdns/west-agent-auth.yaml", want: "auth", wantWarn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, warn, err := detectDaemonRole(tc.service, tc.hasService, tc.hasImr, tc.path)
			if tc.wantErrIn != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrIn) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErrIn)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("role = %q, want %q", got, tc.want)
			}
			if (warn != "") != tc.wantWarn {
				t.Errorf("warning = %q, wantWarn = %v", warn, tc.wantWarn)
			}
		})
	}
}

// ------------------------------------------------------------------ splice

const sampleCli = `# CLI config
apiservers:
   - name:              auth
     baseurl:           https://127.0.0.1:8989/api/v1
     apikey:            key-one
     authmethod:        X-API-Key

   - name:              agent
     baseurl:           https://127.0.0.1:8987/api/v1
     apikey:            key-two
     authmethod:        X-API-Key
     # config-file:     /etc/tdns/tdns-agent.yaml

# Keys follow.
keys:
   tsig: []
`

func newEntry() ApiDetails {
	return ApiDetails{
		Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1",
		Pins: []string{"cGluLXRocmVlLXBpbi10aHJlZS1waW4tdGhyZWUtcGk="}, ConfigFile: "/etc/tdns/tdns-auth2.yaml",
	}
}

// parseApiservers reads apiservers: with a plain YAML parse, independent of
// the viper path the CLI uses, so the splice is checked against two readers.
func parseApiservers(t *testing.T, s string) []ApiDetails {
	t.Helper()
	var doc struct {
		ApiServers []ApiDetails `yaml:"apiservers"`
	}
	if err := yaml.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatalf("result is not valid YAML: %v\n%s", err, s)
	}
	return doc.ApiServers
}

func TestSpliceMatchesTheNeighbours(t *testing.T) {
	out, block, err := spliceApiserver([]byte(sampleCli), newEntry())
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	// Every original line is still there, in order; the splice only inserted.
	orig := strings.Split(sampleCli, "\n")
	res := strings.Split(got, "\n")
	j := 0
	for _, l := range res {
		if j < len(orig) && l == orig[j] {
			j++
		}
	}
	if j != len(orig) {
		t.Errorf("an original line was changed or lost (matched %d of %d):\n%s", j, len(orig), got)
	}

	// The trailing comment and the next section still follow the list.
	if !strings.Contains(got, "\n# Keys follow.\nkeys:\n") {
		t.Errorf("the text after the list moved:\n%s", got)
	}
	// In the neighbours' style: same indent, aligned values, blank-line separated.
	for _, want := range []string{
		"\n\n   - name:              auth2\n",
		"\n     role:              auth\n",
		"\n     baseurl:           https://127.0.0.1:8990/api/v1\n",
		"\n     config-file:       /etc/tdns/tdns-auth2.yaml\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(block, "\n\n") || strings.HasPrefix(block, "\n") {
		t.Errorf("block should be the bare entry: %q", block)
	}

	entries := parseApiservers(t, got)
	if len(entries) != 3 {
		t.Fatalf("parsed %d entries, want 3: %+v", len(entries), entries)
	}
	if !reflect.DeepEqual(entries[2], newEntry()) {
		t.Errorf("third entry = %+v, want %+v", entries[2], newEntry())
	}
}

func TestSpliceDashAtColumnZero(t *testing.T) {
	src := "apiservers:\n- name: a\n  baseurl: https://127.0.0.1:1/api/v1\n  apikey: k\n  authmethod: X-API-Key\nother: 1\n"
	out, _, err := spliceApiserver([]byte(src), newEntry())
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "\n- name: auth2\n  role: auth\n") {
		t.Errorf("did not follow the column-0, single-space style:\n%s", got)
	}
	if !strings.HasSuffix(got, "other: 1\n") {
		t.Errorf("the next key moved:\n%s", got)
	}
	if n := len(parseApiservers(t, got)); n != 2 {
		t.Errorf("parsed %d entries, want 2", n)
	}
}

// A list whose items put "-" on a line of its own, mapping below, at a
// two-space indentation: the new item must sit at the same indentation, or
// the file no longer loads.
func TestSpliceBareDashItems(t *testing.T) {
	src := "apiservers:\n  -\n    name: a\n    baseurl: https://127.0.0.1:1/api/v1\n    apikey: k\n    authmethod: X-API-Key\nother: 1\n"
	out, _, err := spliceApiserver([]byte(src), newEntry())
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "\n  - name:") {
		t.Errorf("the new item is not at the list's two-space indentation:\n%s", got)
	}
	if n := len(parseApiservers(t, got)); n != 2 {
		t.Errorf("parsed %d entries, want 2:\n%s", n, got)
	}

	// The bare dash may carry a comment.
	src = "apiservers:\n  - # the first one\n    name: a\n    baseurl: https://127.0.0.1:1/api/v1\n    apikey: k\n    authmethod: X-API-Key\n"
	if out, _, err = spliceApiserver([]byte(src), newEntry()); err != nil {
		t.Fatal(err)
	}
	if got = string(out); !strings.Contains(got, "\n  - name:") || len(parseApiservers(t, got)) != 2 {
		t.Errorf("a commented bare dash:\n%s", got)
	}
}

func TestSpliceWithoutApiserversKey(t *testing.T) {
	for name, src := range map[string]string{
		"empty file":          "",
		"other keys only":     "cli:\n   localconfig: /x\n",
		"no trailing newline": "cli:\n   localconfig: /x",
	} {
		t.Run(name, func(t *testing.T) {
			out, _, err := spliceApiserver([]byte(src), newEntry())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(out), src) {
				t.Errorf("existing text was changed:\n%s", out)
			}
			if e := parseApiservers(t, string(out)); len(e) != 1 || !reflect.DeepEqual(e[0], newEntry()) {
				t.Errorf("parsed %+v", e)
			}
		})
	}
}

func TestSpliceRefusesFlowStyle(t *testing.T) {
	for _, src := range []string{
		"apiservers: []\n",
		"apiservers: [ {name: a} ]\n",
	} {
		if _, _, err := spliceApiserver([]byte(src), newEntry()); err != errFlowApiservers {
			t.Errorf("%q: err = %v, want errFlowApiservers", src, err)
		}
	}
}

func TestYamlScalar(t *testing.T) {
	for in, want := range map[string]string{
		"winter-is-coming":              "winter-is-coming",
		"https://127.0.0.1:8989/api/v1": "https://127.0.0.1:8989/api/v1",
		"/etc/tdns/tdns-auth2.yaml":     "/etc/tdns/tdns-auth2.yaml",
		"has space":                     "'has space'",
		"hash#tag":                      "'hash#tag'",
		"it's":                          "'it''s'",
		"*star":                         "'*star'",
		"trailing:":                     "'trailing:'",
		"true":                          "'true'",
		"":                              "''",
		"001234":                        "'001234'", // plain, an octal integer
		"1e3":                           "'1e3'",    // a float
		".inf":                          "'.inf'",
		"/etc/tdns/a\nb.yaml":           `"/etc/tdns/a\nb.yaml"`, // a line break folds in single quotes
		"tab\there":                     `"tab\there"`,
		"c1\u0080control":               `"c1\u0080control"`, // the reader refuses a C1 control unescaped
		"line\u2028sep":                 `"line\u2028sep"`,
	} {
		if got := yamlScalar(in); got != want {
			t.Errorf("yamlScalar(%q) = %s, want %s", in, got, want)
		}
		// And whatever it produced reads back as the same string.
		var back struct{ V string }
		if err := yaml.Unmarshal([]byte("v: "+yamlScalar(in)+"\n"), &back); err != nil || back.V != in {
			t.Errorf("yamlScalar(%q) does not round-trip: %q, %v", in, back.V, err)
		}
	}
}

// A name or path YAML would read as something other than a string -- a
// number, mostly -- must come back through the CLI's own reader exactly as
// written, or the add would undo itself.
func TestNumericLookingValuesReadBackAsWritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tdns-ncli.yaml")
	for _, v := range []string{"001234", "0x1F", "0o17", "1e3", "12", "1.50", "1_000", ".inf", "~", "null"} {
		e := newEntry()
		e.ConfigFile = v
		writeFile(t, p, "apiservers:\n"+renderEntry(e, itemLayout{indent: 3, gap: 1, valueCol: defValueCol}))
		got, err := ReadApiServers(p)
		if err != nil || len(got) != 1 || got[0].ConfigFile != v {
			t.Errorf("config-file %q read back as %+v, %v", v, got, err)
		}
	}
}

// A cli.localconfig that is there but cannot be checked stops the CLI's own
// load, so `config list` and `config add` must not quietly read the main list
// instead. One that is simply absent is still fine.
func TestReadApiServersReportsAnUnreadableLocalConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root enters every directory")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(locked, "local.yaml"), "x: 1\n")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o700) })

	list := "apiservers:\n" + renderEntry(newEntry(), itemLayout{indent: 3, gap: 1, valueCol: defValueCol})
	cfg := filepath.Join(dir, "tdns-ncli.yaml")
	writeFile(t, cfg, "cli:\n   localconfig: "+filepath.Join(locked, "local.yaml")+"\n"+list)
	got, err := ReadApiServers(cfg)
	if err == nil || !strings.Contains(err.Error(), "cli.localconfig") {
		t.Errorf("err = %v, want the cli.localconfig error", err)
	}
	if len(got) != 1 {
		t.Errorf("the main list was dropped with the error: %+v", got)
	}

	writeFile(t, cfg, "cli:\n   localconfig: "+filepath.Join(dir, "absent.yaml")+"\n"+list)
	if got, err := ReadApiServers(cfg); err != nil || len(got) != 1 {
		t.Errorf("absent local config: %+v, %v", got, err)
	}
}

// The CLI reads its config with viper's AutomaticEnv, so a setting can come
// from the environment; ReadApiServers must see the same list.
func TestReadApiServersTakesSettingsFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	e := newEntry()
	e.Name = "from-env"
	local := filepath.Join(dir, "local.yaml")
	writeFile(t, local, "apiservers:\n"+renderEntry(e, itemLayout{indent: 3, gap: 1, valueCol: defValueCol}))
	cfg := filepath.Join(dir, "tdns-ncli.yaml")
	writeFile(t, cfg, "apiservers:\n"+renderEntry(newEntry(), itemLayout{indent: 3, gap: 1, valueCol: defValueCol}))
	t.Setenv("CLI.LOCALCONFIG", local)
	got, err := ReadApiServers(cfg)
	if err != nil || len(got) != 1 || got[0].Name != "from-env" {
		t.Errorf("got %+v, %v; want the list from the local config the environment names", got, err)
	}
}

// ------------------------------------------------------------- daemon config

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// daemonYAML is a daemon config with an apiserver: block.
func daemonYAML(service, addr, key string, extra string) string {
	s := ""
	if service != "" {
		s += "service:\n   name: " + service + "\n"
	}
	_ = key // daemons have no API key; kept so call sites read as before
	return s + "apiserver:\n   addresses: [ " + addr + " ]\n" + extra
}

func TestReadDaemonApi(t *testing.T) {
	dir := t.TempDir()

	p := filepath.Join(dir, "tdns-auth2.yaml")
	writeFile(t, p, daemonYAML("TDNS-AUTH", "127.0.0.1:8990", "k2", ""))
	got, err := ReadDaemonApi(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != "auth" || got.ConfigFile != p || got.AccessFile != filepath.Join(dir, "tdns-auth2-access.yaml") {
		t.Errorf("got %+v", got)
	}

	// An imrengine: block and no service: is tdns-imr; access-file: moves
	// the access file.
	p2 := filepath.Join(dir, "tdns-imr.yaml")
	writeFile(t, p2, "imrengine:\n   x: 1\n"+daemonYAML("", "127.0.0.1:8080", "ik", "   access-file: /srv/imr-access.yaml\n"))
	got, err = ReadDaemonApi(p2, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != "imr" || got.AccessFile != "/srv/imr-access.yaml" {
		t.Errorf("imr: %+v", got)
	}

	// --role overrides detection.
	if got, err = ReadDaemonApi(p, "agent"); err != nil || got.Role != "agent" {
		t.Errorf("override: %+v, %v", got, err)
	}

	// An apiserver: block in an included file is found.
	inc := filepath.Join(dir, "api.yaml")
	writeFile(t, inc, "apiserver:\n   addresses: [ 127.0.0.1:9000 ]\n   apikey: ik3\n")
	p3 := filepath.Join(dir, "tdns-auth3.yaml")
	writeFile(t, p3, "service:\n   name: TDNS-AUTH\ninclude:\n   - api.yaml\n")
	if got, err = ReadDaemonApi(p3, ""); err != nil || got.Addresses[0] != "127.0.0.1:9000" {
		t.Errorf("include: %+v, %v", got, err)
	}

	// However deep the include: chain, as in the daemon: main -> site -> api.
	writeFile(t, filepath.Join(dir, "deep-api.yaml"), "apiserver:\n   addresses: [ 127.0.0.1:9002 ]\n   apikey: ik6\n")
	writeFile(t, filepath.Join(dir, "site.yaml"), "include:\n   - deep-api.yaml\n")
	p6 := filepath.Join(dir, "tdns-auth6.yaml")
	writeFile(t, p6, "service:\n   name: TDNS-AUTH\ninclude:\n   - site.yaml\n")
	if got, err = ReadDaemonApi(p6, ""); err != nil || len(got.Addresses) == 0 || got.Addresses[0] != "127.0.0.1:9002" || len(got.Warnings) != 0 {
		t.Errorf("nested include: %+v, %v", got, err)
	}

	// An include that fails to load is named in the error when the key it
	// would have supplied is missing: the addresses are only in the include.
	// (A missing include is skipped as an optional overlay; a present but
	// broken one is what fails.)
	broken := filepath.Join(dir, "api-broken.yaml")
	writeFile(t, broken, "apiserver:\n   addresses: [ 127.0.0.1:9001\n")
	p5 := filepath.Join(dir, "tdns-auth5.yaml")
	writeFile(t, p5, "service:\n   name: TDNS-AUTH\ninclude:\n   - api-broken.yaml\n")
	_, err = ReadDaemonApi(p5, "")
	if err == nil || !strings.Contains(err.Error(), "apiserver.addresses") || !strings.Contains(err.Error(), "include:") {
		t.Errorf("failed include: err = %v, want it to name both the missing addresses and the include failure", err)
	}

	// Missing pieces are errors that say which.
	p4 := filepath.Join(dir, "tdns-auth4.yaml")
	writeFile(t, p4, "service:\n   name: TDNS-AUTH\n")
	if _, err = ReadDaemonApi(p4, ""); err == nil || !strings.Contains(err.Error(), "apiserver.addresses") {
		t.Errorf("no addresses: err = %v", err)
	}
	// No API key is needed: an address is enough.
	writeFile(t, p4, "service:\n   name: TDNS-AUTH\napiserver:\n   addresses: [ 127.0.0.1:1 ]\n")
	if _, err = ReadDaemonApi(p4, ""); err != nil {
		t.Errorf("no apikey: err = %v, want none", err)
	}
}

// --------------------------------------------------------------- config add

type addEnv struct {
	dir, cli string
}

// newAddEnv is a CLI config to add to, and daemons that are not running:
// each has its default local admin socket, with nothing on it.
func newAddEnv(t *testing.T) *addEnv {
	t.Helper()
	withCleanRoleRegistry(t)
	sockDir, err := os.MkdirTemp("/tmp", "ncli") // short: a socket path has a limit
	if err != nil {
		t.Fatal(err)
	}
	saved := tdns.DefaultApiSocketDir
	t.Cleanup(func() { tdns.DefaultApiSocketDir = saved; os.RemoveAll(sockDir) })
	tdns.DefaultApiSocketDir = sockDir
	dir := t.TempDir()
	return &addEnv{dir: dir, cli: filepath.Join(dir, "tdns-ncli.yaml")}
}

func (e *addEnv) daemon(t *testing.T, file, service, addr string) string {
	t.Helper()
	p := filepath.Join(e.dir, file)
	writeFile(t, p, daemonYAML(service, addr, "key-"+file, ""))
	return p
}

func (e *addEnv) add(t *testing.T, daemon string, mod func(*AddOptions)) (*AddResult, error) {
	t.Helper()
	o := AddOptions{CliConfig: e.cli, DaemonConfig: daemon}
	if mod != nil {
		mod(&o)
	}
	return AddDaemonConfig(o)
}

func (e *addEnv) entries(t *testing.T) []ApiDetails {
	t.Helper()
	got, err := ReadApiServers(e.cli)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// The scenario this command exists for: two tdns-auth configs on one host, the
// CLI config built from them.
func TestAddTwoAuthDaemons(t *testing.T) {
	env := newAddEnv(t)
	first := env.daemon(t, "tdns-auth.yaml", "TDNS-AUTH", "127.0.0.1:8989")
	second := env.daemon(t, "tdns-auth2.yaml", "TDNS-AUTH", "127.0.0.1:8990")

	// The CLI config does not exist yet: the first add creates it, 0600, as
	// the canonical tdns-auth.
	res, err := env.add(t, first, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || !res.Canonical || res.Entry.Name != "auth" || res.Entry.Role != "auth" {
		t.Errorf("first add: %+v", res)
	}
	if fi, err := os.Stat(env.cli); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("created file mode: %v, %v", fi, err)
	}

	// The second becomes an instance, named after its file, role: auth.
	res, err = env.add(t, second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Canonical || res.Entry.Name != "auth2" || res.Entry.Role != "auth" || !res.Wrote {
		t.Errorf("second add: %+v", res)
	}
	got := env.entries(t)
	if len(got) != 2 {
		t.Fatalf("%d entries: %+v", len(got), got)
	}
	// Not running: config-file: only, and the command that completes it.
	want := ApiDetails{Name: "auth2", Role: "auth", ConfigFile: second}
	if !reflect.DeepEqual(got[1], want) {
		t.Errorf("entry = %+v\nwant    %+v", got[1], want)
	}
	if got[0].ConfigFile != first {
		t.Errorf("canonical entry lost its config-file: %+v", got[0])
	}
	if want := "config update auth2 --cert"; !strings.HasSuffix(res.Update, want) {
		t.Errorf("update = %q, want %q", res.Update, want)
	}

	// Adding either again changes nothing.
	before, _ := os.ReadFile(env.cli)
	for _, d := range []string{first, second} {
		res, err = env.add(t, d, nil)
		if err != nil || res.AlreadyKnown == "" || res.Wrote || !strings.HasSuffix(res.Update, " --cert") {
			t.Errorf("re-add %s: %+v, %v", d, res, err)
		}
	}
	if after, _ := os.ReadFile(env.cli); string(after) != string(before) {
		t.Errorf("re-adding changed the file:\n%s", after)
	}

	// The result is exactly what the wiring accepts: one instance, no warnings.
	root := &cobra.Command{Use: "tdns-ncli"}
	if w := WireInstanceTrees(root, env.entries(t)); len(w) != 0 {
		t.Errorf("wiring warned: %v", w)
	}
	if findChild(root, "auth2") == nil {
		t.Error("auth2 was not wired")
	}
}

func TestAddPreservesTheRestOfTheFile(t *testing.T) {
	env := newAddEnv(t)
	writeFile(t, env.cli, sampleCli)
	d := env.daemon(t, "tdns-auth2.yaml", "TDNS-AUTH", "127.0.0.1:8990")
	// tdns-auth exists in sampleCli, so this is an instance.
	if _, err := env.add(t, d, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(env.cli)
	orig := strings.Split(sampleCli, "\n")
	res := strings.Split(string(after), "\n")
	j := 0
	for _, l := range res {
		if j < len(orig) && l == orig[j] {
			j++
		}
	}
	if j != len(orig) {
		t.Errorf("an original line changed:\n%s", after)
	}
	if got := env.entries(t); len(got) != 3 || got[2].Name != "auth2" {
		t.Errorf("entries: %+v", got)
	}
}

func TestAddNaming(t *testing.T) {
	env := newAddEnv(t)
	first := env.daemon(t, "tdns-auth.yaml", "TDNS-AUTH", "127.0.0.1:8989")
	if _, err := env.add(t, first, nil); err != nil {
		t.Fatal(err)
	}

	// A file named like the canonical one, elsewhere: "auth" is a role word, so
	// the derived name is taken and the next free one is used.
	sub := filepath.Join(env.dir, "other")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(sub, "tdns-auth.yaml")
	writeFile(t, p, daemonYAML("TDNS-AUTH", "127.0.0.1:8991", "k", ""))
	res, err := env.add(t, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry.Name != "auth2" {
		t.Errorf("name = %q, want auth2", res.Entry.Name)
	}

	// --name: refused when it collides with anything.
	for name, why := range map[string]string{
		"auth":      "a role",
		"tdns-auth": "the canonical entry",
		"auth2":     "an entry just added",
		"config":    "a command",
		"show-cmds": "reserved",
		"Bad Name":  "not a valid word",
		"9lives":    "must start with a letter",
	} {
		q := filepath.Join(env.dir, "q.yaml")
		writeFile(t, q, daemonYAML("TDNS-AUTH", "127.0.0.1:8999", "k", ""))
		_, err := env.add(t, q, func(o *AddOptions) {
			o.Name = name
			o.CommandWordTaken = func(n string) bool { return n == "config" }
		})
		if err == nil {
			t.Errorf("--name %q (%s) was accepted", name, why)
		}
	}
	if n := len(env.entries(t)); n != 2 {
		t.Errorf("a refused add changed the config: %d entries", n)
	}

	// --name that is fine.
	q := filepath.Join(env.dir, "q.yaml")
	res, err = env.add(t, q, func(o *AddOptions) { o.Name = "sectdns" })
	if err != nil || res.Entry.Name != "sectdns" || res.Entry.Role != "auth" {
		t.Errorf("--name sectdns: %+v, %v", res, err)
	}
}

func TestAddRefusesClashes(t *testing.T) {
	env := newAddEnv(t)
	first := env.daemon(t, "tdns-auth.yaml", "TDNS-AUTH", "127.0.0.1:8989")
	writeFile(t, env.cli, "apiservers:\n   - name: auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: k\n     authmethod: X-API-Key\n     config-file: "+first+"\n")

	// A different daemon config naming the same API address.
	clash := env.daemon(t, "tdns-auth9.yaml", "TDNS-AUTH", "127.0.0.1:8989")
	if _, err := env.add(t, clash, nil); err == nil || !strings.Contains(err.Error(), "already uses the API address") {
		t.Errorf("address clash: err = %v", err)
	}

	// The same file, but its API address has since moved.
	writeFile(t, first, daemonYAML("TDNS-AUTH", "127.0.0.1:7777", "k", ""))
	if _, err := env.add(t, first, nil); err == nil || !strings.Contains(err.Error(), "different API address") {
		t.Errorf("moved address: err = %v", err)
	}

	// A second agent: there is no instance tree for it yet.
	a1 := env.daemon(t, "tdns-agent.yaml", "TDNS-AGENT", "127.0.0.1:8987")
	if _, err := env.add(t, a1, nil); err != nil {
		t.Fatal(err)
	}
	a2 := env.daemon(t, "tdns-agent2.yaml", "TDNS-AGENT", "127.0.0.1:8986")
	_, err := env.add(t, a2, nil)
	if _, has := knownInstanceRoles["agent"]; !has {
		if err == nil || !strings.Contains(err.Error(), "no command tree") {
			t.Errorf("second agent: err = %v", err)
		}
	}

	// A bad --role, and a daemon that cannot be told.
	if _, err := env.add(t, first, func(o *AddOptions) { o.Role = "combiner" }); err == nil {
		t.Error("--role combiner was accepted")
	}
	foo := env.daemon(t, "foo.yaml", "", "127.0.0.1:1")
	if _, err := env.add(t, foo, nil); err == nil || !strings.Contains(err.Error(), "--role") {
		t.Errorf("undecidable daemon: err = %v", err)
	}
}

func TestAddDryRunChangesNothing(t *testing.T) {
	env := newAddEnv(t)
	writeFile(t, env.cli, sampleCli)
	d := env.daemon(t, "tdns-auth2.yaml", "TDNS-AUTH", "127.0.0.1:8990")
	res, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true })
	if err != nil || res.Wrote {
		t.Fatalf("%+v, %v", res, err)
	}
	if b, _ := os.ReadFile(env.cli); string(b) != sampleCli {
		t.Error("dry run changed the file")
	}
	// What it prints: the entry, no key, and what completes it.
	var sb strings.Builder
	printAddResult(&sb, res, true, env.cli)
	out := sb.String()
	if !strings.HasPrefix(out, "Would add \"auth2\"") || strings.Contains(out, "apikey") || !strings.Contains(unwrapCommands(out), "config update auth2 --cert") ||
		!strings.Contains(out, "\n   touch "+filepath.Join(env.dir, "tdns-auth2-access.yaml")+"\n") {
		t.Errorf("printed:\n%s", out)
	}
}

// apiservers: defined in cli.localconfig REPLACES the main file's list, so an
// entry added to the main file is invisible to the CLI. The add must notice
// before it writes, and say how to do it right.
func TestAddRefusesWhenAnOverlayHidesTheEntry(t *testing.T) {
	env := newAddEnv(t)
	local := filepath.Join(env.dir, "local.yaml")
	writeFile(t, local, "apiservers:\n   - name: auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: k\n     authmethod: X-API-Key\n")
	mainCfg := "cli:\n   localconfig: " + local + "\napiservers:\n   - name: imr\n     baseurl: http://127.0.0.1:8080/api/v1\n     apikey: k\n     authmethod: X-API-Key\n"
	writeFile(t, env.cli, mainCfg)
	d := env.daemon(t, "tdns-auth2.yaml", "TDNS-AUTH", "127.0.0.1:8990")

	// --dry-run sees it coming: it loads the config with the edit in place,
	// without writing it.
	_, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true })
	if err == nil || !strings.Contains(err.Error(), "would not load") || !strings.Contains(err.Error(), "Nothing was written") {
		t.Fatalf("dry run: err = %v", err)
	}
	if b, _ := os.ReadFile(env.cli); string(b) != mainCfg {
		t.Errorf("the dry run changed the main file:\n%s", b)
	}
	// And accepts the file that holds the winning list.
	if res, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true; o.TargetFile = local }); err != nil || res.Wrote {
		t.Fatalf("dry run with --file: %+v, %v", res, err)
	}
	if b, _ := os.ReadFile(local); strings.Contains(string(b), "auth2") {
		t.Error("the dry run wrote the local file")
	}

	// --file naming a symlink to the local config: the add writes through the
	// link, so the preview must read the edit through it too.
	link := filepath.Join(env.dir, "local-link.yaml")
	if err := os.Symlink(local, link); err == nil {
		if res, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true; o.TargetFile = link }); err != nil || res.Wrote {
			t.Errorf("dry run with --file a symlink to the local config: %+v, %v", res, err)
		}
		// And the other way round: cli.localconfig names the link, --file the
		// file itself.
		viaLink := strings.Replace(mainCfg, "localconfig: "+local, "localconfig: "+link, 1)
		writeFile(t, env.cli, viaLink)
		if res, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true; o.TargetFile = local }); err != nil || res.Wrote {
			t.Errorf("dry run with cli.localconfig a symlink to --file: %+v, %v", res, err)
		}
		writeFile(t, env.cli, mainCfg)
	}

	// --file a hard link to the local config: the add's rename replaces the
	// link, cli.localconfig still reads the old file, and the add is undone.
	// The preview must say the same, not read the edit through both names.
	hard := filepath.Join(env.dir, "local-hard.yaml")
	if err := os.Link(local, hard); err == nil {
		if _, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true; o.TargetFile = hard }); err == nil || !strings.Contains(err.Error(), "would not load") {
			t.Errorf("dry run with --file a hard link to the local config: err = %v, want the preview to fail as the add does", err)
		}
		// The add is refused before it writes: an undo after the rename could
		// not join the two names again.
		if _, err := env.add(t, d, func(o *AddOptions) { o.TargetFile = hard }); err == nil || !strings.Contains(err.Error(), "Nothing was written") {
			t.Errorf("add with --file a hard link to the local config: err = %v, want it refused before writing", err)
		}
		if a, b := statOf(t, local), statOf(t, hard); !os.SameFile(a, b) {
			t.Error("the refused add detached --file from the local config")
		}
		os.Remove(hard)
	}

	_, err = env.add(t, d, nil)
	if err == nil || !strings.Contains(err.Error(), "--file") || !strings.Contains(err.Error(), "Nothing was written") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(env.cli); string(b) != mainCfg {
		t.Errorf("the refused add changed the main file:\n%s", b)
	}

	// Naming the file that holds the winning list works.
	res, err := env.add(t, d, func(o *AddOptions) { o.TargetFile = local })
	if err != nil {
		t.Fatal(err)
	}
	if res.File != local || len(env.entries(t)) != 2 {
		t.Errorf("%+v, entries %+v", res, env.entries(t))
	}
}

func TestAddFollowsASymlink(t *testing.T) {
	env := newAddEnv(t)
	real := filepath.Join(env.dir, "real.yaml")
	writeFile(t, real, sampleCli)
	if err := os.Symlink(real, env.cli); err != nil {
		t.Skip("no symlinks here")
	}
	d := env.daemon(t, "tdns-auth2.yaml", "TDNS-AUTH", "127.0.0.1:8990")
	if _, err := env.add(t, d, nil); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(env.cli); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a regular file")
	}
	if b, _ := os.ReadFile(real); !strings.Contains(string(b), "auth2") {
		t.Error("the file behind the link was not updated")
	}
}

// A link to a file not made yet reads as "no config", and writing it by
// renaming over it would replace the link. Refused, dry run included.
func TestAddRefusesADanglingSymlink(t *testing.T) {
	env := newAddEnv(t)
	if err := os.Symlink(filepath.Join(env.dir, "not-yet.yaml"), env.cli); err != nil {
		t.Skip("no symlinks here")
	}
	d := env.daemon(t, "tdns-auth.yaml", "TDNS-AUTH", "127.0.0.1:8989")
	for _, dry := range []bool{true, false} {
		_, err := env.add(t, d, func(o *AddOptions) { o.DryRun = dry })
		if err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("dry run %v: err = %v", dry, err)
		}
	}
	if fi, err := os.Lstat(env.cli); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced")
	}
}

func TestAddFlowStyleTellsYouWhatToAdd(t *testing.T) {
	env := newAddEnv(t)
	writeFile(t, env.cli, "apiservers: []\n")
	d := env.daemon(t, "tdns-auth2.yaml", "TDNS-AUTH", "127.0.0.1:8990")
	_, err := env.add(t, d, nil)
	if err == nil || !strings.Contains(err.Error(), "by hand") || !strings.Contains(err.Error(), "- name:") {
		t.Fatalf("err = %v", err)
	}
}

// ---------------------------------------------------- instance-name hardening

// An instance named like another entry's API client is refused: both would
// be one client in tdns.Globals.ApiClients, the later silently winning. The
// client of a downstream role may have another name than the role (a
// package registers it), and a role-less entry is a client of its own.
func TestInstanceNameMayNotShareAnApiClient(t *testing.T) {
	for name, tc := range map[string]struct {
		register [2]string
		entries  []ApiDetails
		want     string
	}{
		"a downstream role's client name": {register: [2]string{"signer", "tdns-mpsigner"},
			entries: []ApiDetails{{Name: "tdns-mpsigner", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1"}},
			want:    "API-client name"},
		"an entry for a daemon with no tree": {
			entries: []ApiDetails{
				{Name: "tdns-reporter", BaseURL: "https://127.0.0.1:8991/api/v1"},
				{Name: "tdns-reporter", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1"},
			},
			want: "API-client name"},
		"a built-in role's name": {
			entries: []ApiDetails{{Name: "imr", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1"}},
			want:    "collides with a built-in role"},
		"a role entry twice": {
			entries: []ApiDetails{
				{Name: "auth", BaseURL: "https://127.0.0.1:8989/api/v1"},
				{Name: "auth", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1"},
			},
			want: "an earlier apiservers entry has the same name"},
	} {
		t.Run(name, func(t *testing.T) {
			withCleanRoleRegistry(t)
			if tc.register[0] != "" {
				RegisterRole(tc.register[0], tc.register[1])
			}
			root := &cobra.Command{Use: "tdns-ncli"}
			w := WireInstanceTrees(root, tc.entries)
			if len(w) != 1 || !strings.Contains(w[0], tc.want) {
				t.Fatalf("warnings = %v, want one with %q", w, tc.want)
			}
			if len(root.Commands()) != 0 {
				t.Error("the colliding instance was wired anyway")
			}
		})
	}
}

// Refusing the colliding instance its tree is not enough: InitApiClients must
// not build its client either, or the client replaces the canonical one and
// `tdns-ncli auth ...` reaches the instance's daemon.
func TestCollidingInstanceGetsNoClient(t *testing.T) {
	withCleanRoleRegistry(t)
	savedClients, savedApi, savedConf := tdns.Globals.ApiClients, tdns.Globals.Api, apiConfig
	t.Cleanup(func() { tdns.Globals.ApiClients, tdns.Globals.Api, apiConfig = savedClients, savedApi, savedConf })
	tdns.Globals.ApiClients = map[string]*tdns.ApiClient{}

	p := []string{pinOf("d")}
	c := &CliConf{Client: testClientPair(t), ApiServers: []ApiDetails{
		{Name: "auth", BaseURL: "https://127.0.0.1:8989/api/v1", Pins: p, ConfigFile: "/etc/tdns/tdns-auth.yaml"},
		{Name: "auth", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1", Pins: p, ConfigFile: "/etc/tdns/other.yaml"},
		{Name: "imr", Role: "auth", BaseURL: "https://127.0.0.1:8991/api/v1", Pins: p},
		{Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8992/api/v1", Pins: p},
		{Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8993/api/v1", Pins: p},
		// The wiring refuses the first auth3 (no tree for its role) and wires
		// the second: the client must be the second's.
		{Name: "auth3", Role: "nosuch", BaseURL: "https://127.0.0.1:8994/api/v1", Pins: p},
		{Name: "auth3", Role: "auth", BaseURL: "https://127.0.0.1:8995/api/v1", Pins: p},
		// Refused for its name (a command).
		{Name: "config", Role: "auth", BaseURL: "https://127.0.0.1:8996/api/v1", Pins: p},
	}}
	root := &cobra.Command{Use: "tdns-ncli"}
	root.AddCommand(&cobra.Command{Use: "config"})
	WireInstanceTrees(root, c.ApiServers)
	if err := InitApiClients(c); err != nil {
		t.Fatal(err)
	}
	if ac, ok := tdns.Globals.ApiClients["config"]; ok {
		t.Errorf("an entry the wiring refused got a client: %+v", ac)
	}
	if ac := tdns.Globals.ApiClients["auth"]; ac == nil || ac.BaseUrl != "https://127.0.0.1:8989/api/v1" {
		t.Errorf("auth client (the first auth wins): %+v", ac)
	}
	if ac, ok := tdns.Globals.ApiClients["imr"]; ok {
		t.Errorf("an auth instance named imr got the imr client: %+v", ac)
	}
	if ac := tdns.Globals.ApiClients["auth2"]; ac == nil || ac.BaseUrl != "https://127.0.0.1:8992/api/v1" {
		t.Errorf("auth2 client (the first auth2 wins, as in the wiring): %+v", ac)
	}
	if ac := tdns.Globals.ApiClients["auth3"]; ac == nil || ac.BaseUrl != "https://127.0.0.1:8995/api/v1" {
		t.Errorf("auth3 client (the entry the wiring accepts, not the refused one before it): %+v", ac)
	}
	if d := getApiDetailsByClientKey("auth"); d == nil || d.ConfigFile != "/etc/tdns/tdns-auth.yaml" {
		t.Errorf("config lookup for auth: %+v", d)
	}
}

// ----------------------------------------------------------------- config list

func TestBuildListRows(t *testing.T) {
	withCleanRoleRegistry(t)
	root := &cobra.Command{Use: "tdns-ncli"}
	root.AddCommand(&cobra.Command{Use: "version"}, NewCliConfigCmd())
	entries := []ApiDetails{
		{Name: "auth", BaseURL: "https://127.0.0.1:8989/api/v1"},
		{Name: "tdns-reporter", BaseURL: "https://127.0.0.1:8991/api/v1"},
		{Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1", ConfigFile: "/etc/tdns/tdns-auth2.yaml"},
		{Name: "config", Role: "auth", BaseURL: "https://127.0.0.1:8992/api/v1"},
		{Name: "odd", Role: "combiner", BaseURL: "https://127.0.0.1:8993/api/v1"},
	}
	// Wire first, as the binary does, so the root already carries the instance
	// tree: the list must not mistake that tree for a collision with itself.
	WireInstanceTrees(root, entries)
	if findChild(root, "auth2") == nil {
		t.Fatal("setup: auth2 not wired")
	}

	rows := BuildListRows(root, entries)
	if len(rows) != len(entries) {
		t.Fatalf("%d rows", len(rows))
	}
	byName := map[string]ListRow{}
	for _, r := range rows {
		byName[r.Name] = r
	}

	if r := byName["auth"]; r.Command != "auth" || r.Status != "ok" || !strings.HasSuffix(r.ConfigFile, "(default)") || !strings.Contains(r.ConfigFile, tdns.DefaultAuthCfgFile) {
		t.Errorf("canonical: %+v", r)
	}
	if r := byName["tdns-reporter"]; r.Command != "-" || !strings.Contains(r.Status, "no command tree") {
		t.Errorf("no-tree: %+v", r)
	}
	if r := byName["auth2"]; r.Command != "auth2" || r.Status != "ok" || r.Kind != "instance of auth" || r.ConfigFile != "/etc/tdns/tdns-auth2.yaml" {
		t.Errorf("instance: %+v", r)
	}
	if r := byName["config"]; r.Command != "-" || !strings.HasPrefix(r.Status, "ignored:") || !strings.Contains(r.Status, "existing") {
		t.Errorf("collision with the config command: %+v", r)
	}
	if r := byName["odd"]; !strings.HasPrefix(r.Status, "ignored:") || !strings.Contains(r.Status, "no command tree") {
		t.Errorf("unknown role: %+v", r)
	}
	// What the list says is what the wiring did.
	for _, r := range rows {
		wired := findChild(root, r.Name) != nil && r.Kind != "built-in auth"
		if r.Kind == "instance of auth" && (r.Status == "ok") != wired && r.Name != "config" {
			t.Errorf("%s: list says %q but wired=%v", r.Name, r.Status, wired)
		}
	}
}

func TestCheckEntriesPingsEachAPI(t *testing.T) {
	// The handler hands over what it saw on a channel: the HTTP answer is no
	// synchronisation edge between the handler's goroutine and this one.
	gotCert := make(chan bool, 8)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ping" {
			http.NotFound(w, r)
			return
		}
		gotCert <- r.TLS != nil && len(r.TLS.PeerCertificates) == 1
		json.NewEncoder(w).Encode(tdns.PingResponse{
			Msg: "pong", Version: "v-test", BootTime: time.Now().Add(-90 * time.Minute), Pings: 1, Pongs: 1,
		})
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	pin := tdns.SPKISHA256(srv.Certificate())

	entries := []ApiDetails{
		{Name: "up", BaseURL: srv.URL + "/api/v1", Pins: []string{pin}},
		{Name: "down", BaseURL: "https://127.0.0.1:1/api/v1", Pins: []string{pin}},
		{Name: "wrongpin", BaseURL: srv.URL + "/api/v1", Pins: []string{pinOf("other")}},
		{Name: "nopins", BaseURL: srv.URL + "/api/v1"},
		{Name: "plain", BaseURL: "http://127.0.0.1:1/api/v1"},
	}
	res := CheckEntries(entries, testClientPair(t), 5*time.Second)

	if !strings.HasPrefix(res[0], "ok") || !strings.Contains(res[0], "v-test") || !strings.Contains(res[0], "up 1h30m") {
		t.Errorf("up: %q", res[0])
	}
	select {
	case ok := <-gotCert:
		if !ok {
			t.Error("the server saw no client certificate")
		}
	case <-time.After(5 * time.Second):
		t.Error("the server saw no ping")
	}
	if !strings.HasPrefix(res[1], "FAIL") {
		t.Errorf("down: %q", res[1])
	}
	if !strings.HasPrefix(res[2], "FAIL") || !strings.Contains(res[2], "--repin") {
		t.Errorf("wrongpin: %q, want FAIL naming --repin", res[2])
	}
	if !strings.HasPrefix(res[3], "FAIL") || !strings.Contains(res[3], "--cert") {
		t.Errorf("nopins: %q, want FAIL naming --cert", res[3])
	}
	if !strings.HasPrefix(res[4], "FAIL") || !strings.Contains(res[4], "TLS only") {
		t.Errorf("plain: %q, want FAIL: TLS only", res[4])
	}
}

func TestConfigAddHint(t *testing.T) {
	saved := DefaultCliConfigFile
	t.Cleanup(func() { DefaultCliConfigFile = saved })
	DefaultCliConfigFile = "/etc/tdns/tdns-ncli.yaml"
	for cfg, want := range map[string]string{
		"":                         "tdns-ncli config add",
		"/etc/tdns/tdns-ncli.yaml": "tdns-ncli config add",
		"/tmp/lab.yaml":            "tdns-ncli --config /tmp/lab.yaml config add",
		"/tmp/my lab.yaml":         "tdns-ncli --config '/tmp/my lab.yaml' config add",
		"/tmp/lab;backup.yaml":     "tdns-ncli --config '/tmp/lab;backup.yaml' config add",
		"/tmp/a&b|c.yaml":          "tdns-ncli --config '/tmp/a&b|c.yaml' config add",
		"~/lab.yaml":               "tdns-ncli --config '~/lab.yaml' config add",
		"/tmp/it's.yaml":           `tdns-ncli --config '/tmp/it'\''s.yaml' config add`,
	} {
		if got := ConfigAddHint(cfg); got != want {
			t.Errorf("ConfigAddHint(%q) = %q, want %q", cfg, got, want)
		}
	}
}

func TestIsCliConfigCmd(t *testing.T) {
	root := &cobra.Command{Use: "tdns-ncli"}
	cfg := NewCliConfigCmd()
	root.AddCommand(cfg)
	other := &cobra.Command{Use: "config"}
	root.AddCommand(&cobra.Command{Use: "auth"})
	findChild(root, "auth").AddCommand(other)

	if !IsCliConfigCmd(cfg) || !IsCliConfigCmd(findChild(cfg, "add")) || !IsCliConfigCmd(findChild(cfg, "list")) {
		t.Error("the config subtree is not recognised")
	}
	if IsCliConfigCmd(other) || IsCliConfigCmd(root) {
		t.Error("`auth config` (a daemon's config check) was taken for the CLI-config command")
	}
}

func statOf(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// An entry with the old name (tdns-auth) holds the auth entry until it is
// renamed: an add that would become the auth entry says to rename it, with
// the command, and an add under a name of its own is not blocked by it.
func TestOldNameEntryHoldsTheRoleEntry(t *testing.T) {
	asNcli(t)
	existing := []ApiDetails{{Name: "tdns-auth", BaseURL: "https://127.0.0.1:8989/api/v1"}}
	var entry ApiDetails
	var res AddResult
	err := chooseEntryName(&entry, &res, "auth", existing, AddOptions{DaemonConfig: "/etc/tdns/tdns-auth.yaml"})
	if err == nil || !strings.Contains(err.Error(), "\n   tdns-ncli config update tdns-auth --rename auth") {
		t.Fatalf("err = %v, entry = %+v; want the rename named", err, entry)
	}
	entry, res = ApiDetails{}, AddResult{}
	if err := chooseEntryName(&entry, &res, "auth", existing, AddOptions{DaemonConfig: "/etc/tdns/x.yaml", Name: "auth3"}); err != nil || entry.Name != "auth3" {
		t.Errorf("an add under its own name: %+v, %v", entry, err)
	}
}

// The same daemon config reached through a symlink is the same daemon:
// "already known", not two daemons on one address.
func TestSameDaemonThroughASymlinkIsAlreadyKnown(t *testing.T) {
	env := newAddEnv(t)
	d := env.daemon(t, "tdns-auth.yaml", "TDNS-AUTH", "127.0.0.1:8989")
	if _, err := env.add(t, d, nil); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "tdns-auth.yaml")
	if err := os.Symlink(d, link); err != nil {
		t.Skip("no symlinks here")
	}
	res, err := env.add(t, link, nil)
	if err != nil || res.AlreadyKnown != "auth" || res.Wrote {
		t.Fatalf("re-add through a symlink: %+v, %v; want it already known", res, err)
	}
}

// Advice printed after an add, or for an empty list, reads the CLI config the
// command read: with --config when that is not the default.
func TestPrintedAdviceKeepsTheCliConfig(t *testing.T) {
	saved := DefaultCliConfigFile
	t.Cleanup(func() { DefaultCliConfigFile = saved })
	DefaultCliConfigFile = "/etc/tdns/tdns-ncli.yaml"
	cfg := "/tmp/lab config.yaml"

	var sb strings.Builder
	res := &AddResult{Entry: ApiDetails{Name: "auth2", Role: "auth"}, File: "/tmp/local.yaml", Running: true}
	printAddResult(&sb, res, false, cfg)
	if want := "Try it:  tdns-ncli --config '/tmp/lab config.yaml' auth2 ping"; !strings.Contains(sb.String(), want) {
		t.Errorf("missing %q in:\n%s", want, sb.String())
	}
	sb.Reset()
	printListRows(&sb, nil, false, cfg)
	if want := "tdns-ncli --config '/tmp/lab config.yaml' config add <daemon-config.yaml>"; !strings.Contains(sb.String(), want) {
		t.Errorf("missing %q in:\n%s", want, sb.String())
	}
	sb.Reset()
	printAddResult(&sb, res, false, DefaultCliConfigFile)
	if want := "Try it:  tdns-ncli auth2 ping"; !strings.Contains(sb.String(), want) {
		t.Errorf("missing %q in:\n%s", want, sb.String())
	}
}

// A binary that wires no instance trees (tdns-cli) builds clients for its
// canonical entries only: nothing in it reaches an instance.
func TestNoWiringNoInstanceClients(t *testing.T) {
	withCleanRoleRegistry(t)
	savedClients, savedApi, savedConf := tdns.Globals.ApiClients, tdns.Globals.Api, apiConfig
	t.Cleanup(func() { tdns.Globals.ApiClients, tdns.Globals.Api, apiConfig = savedClients, savedApi, savedConf })
	tdns.Globals.ApiClients = map[string]*tdns.ApiClient{}

	c := &CliConf{Client: testClientPair(t), ApiServers: []ApiDetails{
		{Name: "auth", BaseURL: "https://127.0.0.1:8989/api/v1", Pins: []string{pinOf("a")}},
		{Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1", Pins: []string{pinOf("b")}},
	}}
	if err := InitApiClients(c); err != nil {
		t.Fatal(err)
	}
	if tdns.Globals.ApiClients["auth"] == nil {
		t.Error("no client for the auth entry")
	}
	if ac, ok := tdns.Globals.ApiClients["auth2"]; ok {
		t.Errorf("an instance nothing wired got a client: %+v", ac)
	}
}
