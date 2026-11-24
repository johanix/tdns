package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	tdns "github.com/johanix/tdns/v2"
)

func TestApiBaseURL(t *testing.T) {
	for _, tc := range []struct {
		addr   string
		useTLS bool
		want   string
		err    bool
	}{
		{"127.0.0.1:8989", true, "https://127.0.0.1:8989/api/v1", false},
		{"127.0.0.1:8989", false, "http://127.0.0.1:8989/api/v1", false},
		{"0.0.0.0:8990", true, "https://127.0.0.1:8990/api/v1", false}, // wildcard: where it listens, not where we connect
		{":8990", true, "https://127.0.0.1:8990/api/v1", false},
		{"[::]:8990", true, "https://[::1]:8990/api/v1", false},
		{"[2001:db8::1]:8989", true, "https://[2001:db8::1]:8989/api/v1", false},
		{"ns1.example.net:8989", true, "https://ns1.example.net:8989/api/v1", false},
		{"[fe80::1%eth0]:8990", true, "https://[fe80::1%25eth0]:8990/api/v1", false}, // a zone's % escaped, so the URL parses
		{"127.0.0.1", true, "", true},                                                // no port
		{"", true, "", true},
	} {
		got, err := apiBaseURL(tc.addr, tc.useTLS)
		if (err != nil) != tc.err {
			t.Errorf("apiBaseURL(%q): err=%v, want error=%v", tc.addr, err, tc.err)
			continue
		}
		if got != tc.want {
			t.Errorf("apiBaseURL(%q, %v) = %q, want %q", tc.addr, tc.useTLS, got, tc.want)
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
	existing := []ApiDetails{{Name: "tdns-auth"}, {Name: long, Role: "auth"}}
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
   - name:              tdns-auth
     baseurl:           https://127.0.0.1:8989/api/v1
     apikey:            key-one
     authmethod:        X-API-Key

   - name:              tdns-agent
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
		ApiKey: "key-three", AuthMethod: "X-API-Key", ConfigFile: "/etc/tdns/tdns-auth2.yaml",
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

// An API key YAML would read as something other than a string -- a number,
// mostly -- must come back through the CLI's own reader exactly as written,
// or the add would undo itself.
func TestNumericLookingKeysReadBackAsWritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tdns-ncli.yaml")
	for _, key := range []string{"001234", "0x1F", "0o17", "1e3", "12", "1.50", "1_000", ".inf", "~", "null"} {
		e := newEntry()
		e.ApiKey = key
		writeFile(t, p, "apiservers:\n"+renderEntry(e, itemLayout{indent: 3, gap: 1, valueCol: defValueCol}))
		got, err := ReadApiServers(p)
		if err != nil || len(got) != 1 || got[0].ApiKey != key {
			t.Errorf("key %q read back as %+v, %v", key, got, err)
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

// daemonYAML is a daemon config with an apiserver: block. It presents
// testDaemonCert, so config add can pin it, unless extra names a certfile:
// or keyfile: of its own.
func daemonYAML(service, addr, key string, extra string) string {
	if !strings.Contains(extra, "certfile:") && !strings.Contains(extra, "keyfile:") {
		extra = "   certfile: " + testDaemonCert + "\n" + extra
	}
	return daemonYAMLDefaultCert(service, addr, key, extra)
}

// daemonYAMLDefaultCert is daemonYAML without a certfile: the daemon then
// serves its default API pair (tdns.ApiCertPaths), written at its first
// start.
func daemonYAMLDefaultCert(service, addr, key string, extra string) string {
	s := ""
	if service != "" {
		s += "service:\n   name: " + service + "\n"
	}
	return s + "apiserver:\n   addresses: [ " + addr + " ]\n   apikey: " + key + "\n" + extra
}

func TestReadDaemonApi(t *testing.T) {
	dir := t.TempDir()

	p := filepath.Join(dir, "tdns-auth2.yaml")
	writeFile(t, p, daemonYAML("TDNS-AUTH", "127.0.0.1:8990", "k2", ""))
	got, err := ReadDaemonApi(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != "auth" || got.ApiKey != "k2" || !got.UseTLS || got.ConfigFile != p {
		t.Errorf("got %+v", got)
	}

	// usetls false is honoured; absent means true, as in the daemon.
	p2 := filepath.Join(dir, "tdns-imr.yaml")
	writeFile(t, p2, "imrengine:\n   x: 1\n"+daemonYAML("", "127.0.0.1:8080", "ik", "   usetls: false\n"))
	got, err = ReadDaemonApi(p2, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != "imr" || got.UseTLS {
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
	writeFile(t, p4, "service:\n   name: TDNS-AUTH\napiserver:\n   addresses: [ 127.0.0.1:1 ]\n")
	if _, err = ReadDaemonApi(p4, ""); err == nil || !strings.Contains(err.Error(), "apikey") {
		t.Errorf("no apikey: err = %v", err)
	}
}

// --------------------------------------------------------------- config add

// addEnv is a directory for daemon configs and a CLI config, with the
// operator's client pair and the daemons' default admin sockets in places of
// the test's own: config add sets the certificate up, and must touch neither
// the real home directory nor /var/run.
type addEnv struct {
	dir, cli  string
	cert, key string // the operator's pair (made by the first add)
	sockDir   string // tdns.DefaultApiSocketDir: no socket in it exists
}

func newAddEnv(t *testing.T) *addEnv {
	t.Helper()
	withCleanRoleRegistry(t)
	dir := t.TempDir()
	e := &addEnv{dir: dir, cli: filepath.Join(dir, "tdns-ncli.yaml")}
	e.cert, e.key = filepath.Join(dir, "certs", "client.crt"), filepath.Join(dir, "certs", "client.key")
	// Short: a socket path has a length limit.
	sockDir, err := os.MkdirTemp("/tmp", "ncli")
	if err != nil {
		t.Fatal(err)
	}
	e.sockDir = sockDir
	savedPaths, savedDir := defaultClientCertPaths, tdns.DefaultApiSocketDir
	t.Cleanup(func() {
		defaultClientCertPaths, tdns.DefaultApiSocketDir = savedPaths, savedDir
		os.RemoveAll(sockDir)
	})
	defaultClientCertPaths = func() (string, string) { return e.cert, e.key }
	tdns.DefaultApiSocketDir = sockDir
	return e
}

// pin is the operator's pin, the pair made if need be.
func (e *addEnv) pin(t *testing.T) string {
	t.Helper()
	pin, _, err := ensureClientCert(e.cert, e.key, "tester")
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

// accessFile is the access file config add suggests for daemon config d.
func accessFileOf(d string) string { return suggestedAccessFile(d) }

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

	// The CLI config does not exist yet: the first add creates it, 0600 (it
	// holds API keys), as the canonical tdns-auth.
	res, err := env.add(t, first, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || !res.Canonical || res.Entry.Name != "tdns-auth" || res.Entry.Role != "" {
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
	// By certificate, no key: each daemon's access file lists the pin.
	want := ApiDetails{
		Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1",
		AuthMethod: "certificate", ConfigFile: second,
		TLSAuth: "pin", Pins: []string{testDaemonPin},
	}
	if !reflect.DeepEqual(got[1], want) {
		t.Errorf("entry = %+v\nwant    %+v", got[1], want)
	}
	if got[0].ConfigFile != first {
		t.Errorf("canonical entry lost its config-file: %+v", got[0])
	}
	for _, d := range []string{first, second} {
		info, err := ReadDaemonApi(d, "")
		if err != nil {
			t.Fatalf("%s does not read back: %v", d, err)
		}
		if info.AccessFile != accessFileOf(d) {
			t.Errorf("%s: access-file %q, want %s", d, info.AccessFile, accessFileOf(d))
		}
		af, err := tdns.LoadAccessFile(accessFileOf(d))
		if err != nil || len(af.Clients) != 1 || af.Clients[0].Pin != env.pin(t) || af.Clients[0].Role != "read-write" {
			t.Errorf("%s: access file %+v (%v), want the pin, read-write", d, af, err)
		}
	}

	// Adding either again changes nothing.
	before, _ := os.ReadFile(env.cli)
	for _, d := range []string{first, second} {
		res, err = env.add(t, d, nil)
		if err != nil || res.AlreadyKnown == "" || res.Wrote {
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
	if _, err := env.add(t, first, nil); err != nil {
		t.Fatal(err)
	}

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
	// Nor anything on the daemon's side, nor the operator's pair.
	if b, _ := os.ReadFile(d); string(b) != daemonYAML("TDNS-AUTH", "127.0.0.1:8990", "key-tdns-auth2.yaml", "") {
		t.Errorf("dry run changed the daemon config:\n%s", b)
	}
	for _, p := range []string{accessFileOf(d), env.cert, env.key} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("dry run created %s", p)
		}
	}
	// What it would print carries no key, and says what it would do.
	out := printed(res, true, env.cli)
	if strings.Contains(out, "key-tdns-auth2.yaml") || strings.Contains(out, "apikey") {
		t.Errorf("the API key was printed:\n%s", out)
	}
	for _, want := range []string{"authmethod:", "certificate", "Would create your client certificate", "Would create " + accessFileOf(d), "Would add under apiserver:", "access-file: " + accessFileOf(d)} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out)
		}
	}
	// A masked key, where an entry has one.
	var sb strings.Builder
	printAddResult(&sb, &AddResult{Entry: ApiDetails{Name: "x", Role: "auth", ApiKey: "sekret", AuthMethod: "X-API-Key"}}, true, env.cli)
	if strings.Contains(sb.String(), "sekret") || !strings.Contains(sb.String(), "********") {
		t.Errorf("expected a masked key:\n%s", sb.String())
	}
}

// apiservers: defined in cli.localconfig REPLACES the main file's list, so an
// entry added to the main file is invisible to the CLI. The add must notice,
// undo itself, and say how to do it right.
func TestAddUndoesWhenAnOverlayHidesTheEntry(t *testing.T) {
	env := newAddEnv(t)
	local := filepath.Join(env.dir, "local.yaml")
	writeFile(t, local, "apiservers:\n   - name: tdns-auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: k\n     authmethod: X-API-Key\n")
	mainCfg := "cli:\n   localconfig: " + local + "\napiservers:\n   - name: tdns-imr\n     baseurl: http://127.0.0.1:8080/api/v1\n     apikey: k\n     authmethod: X-API-Key\n"
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

// The same daemon, changed since it was added: a rotated key, or usetls
// turned off on the same port. "Already known" would leave a dead entry.
func TestAddSaysWhenTheDaemonChanged(t *testing.T) {
	env := newAddEnv(t)
	d := env.daemon(t, "tdns-auth.yaml", "TDNS-AUTH", "127.0.0.1:8989")
	// An entry that uses the key (a certificate entry sends none, so a new
	// key on the daemon is nothing to it).
	writeFile(t, env.cli, "apiservers:\n   - name: tdns-auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: key-tdns-auth.yaml\n     authmethod: X-API-Key\n     config-file: "+d+"\n")
	before, _ := os.ReadFile(env.cli)

	writeFile(t, d, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "rotated-key", ""))
	_, err := env.add(t, d, nil)
	if err == nil || !strings.Contains(err.Error(), "apikey") || !strings.Contains(err.Error(), "by hand") {
		t.Errorf("rotated key: err = %v", err)
	}
	if err != nil && (strings.Contains(err.Error(), "rotated-key") || strings.Contains(err.Error(), "key-tdns-auth.yaml")) {
		t.Errorf("a key is in the error text: %v", err)
	}

	writeFile(t, d, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "key-tdns-auth.yaml", "   usetls: false\n"))
	_, err = env.add(t, d, nil)
	if err == nil || !strings.Contains(err.Error(), "scheme") || strings.Contains(err.Error(), "apikey") {
		t.Errorf("usetls off: err = %v", err)
	}

	if after, _ := os.ReadFile(env.cli); string(after) != string(before) {
		t.Errorf("the refused adds changed the file:\n%s", after)
	}

	// A certificate entry sends no key: the daemon's new key is nothing to it.
	env2 := newAddEnv(t)
	d2 := env2.daemon(t, "tdns-auth.yaml", "TDNS-AUTH", "127.0.0.1:8989")
	if _, err := env2.add(t, d2, nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(d2) // now with its access-file: line
	writeFile(t, d2, strings.Replace(string(cfg), "apikey: key-tdns-auth.yaml", "apikey: rotated-key", 1))
	if res, err := env2.add(t, d2, nil); err != nil || res.AlreadyKnown != "tdns-auth" || res.Wrote {
		t.Errorf("certificate entry, rotated key: %+v, %v; want it already known, unchanged", res, err)
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
	if strings.Contains(err.Error(), "key-tdns-auth2.yaml") {
		t.Errorf("the API key is in the error text: %v", err)
	}
}

// ---------------------------------------------------- instance-name hardening

// The collision the role-name check could not see: an instance named like the
// canonical entry's API CLIENT (tdns-auth), not like its role (auth). Both
// would be one client in tdns.Globals.ApiClients, the later silently winning.
func TestInstanceNameMayNotShareAnApiClient(t *testing.T) {
	for name, entries := range map[string][]ApiDetails{
		"canonical entry present": {
			{Name: "tdns-auth", BaseURL: "https://127.0.0.1:8989/api/v1"},
			{Name: "tdns-auth", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1"},
		},
		"canonical entry absent": {
			{Name: "tdns-imr", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1"},
		},
		"an entry for a daemon with no tree": {
			{Name: "tdns-reporter", BaseURL: "https://127.0.0.1:8991/api/v1"},
			{Name: "tdns-reporter", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			withCleanRoleRegistry(t)
			root := &cobra.Command{Use: "tdns-ncli"}
			w := WireInstanceTrees(root, entries)
			if len(w) != 1 || !strings.Contains(w[0], "API-client name") {
				t.Fatalf("warnings = %v", w)
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

	c := &CliConf{ApiServers: []ApiDetails{
		{Name: "tdns-auth", BaseURL: "https://127.0.0.1:8989/api/v1", ConfigFile: "/etc/tdns/tdns-auth.yaml"},
		{Name: "tdns-auth", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1", ConfigFile: "/etc/tdns/other.yaml"},
		{Name: "tdns-imr", Role: "auth", BaseURL: "https://127.0.0.1:8991/api/v1"},
		{Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8992/api/v1"},
		{Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8993/api/v1"},
		// The wiring refuses the first auth3 (no tree for its role) and wires
		// the second: the client must be the second's.
		{Name: "auth3", Role: "nosuch", BaseURL: "https://127.0.0.1:8994/api/v1"},
		{Name: "auth3", Role: "auth", BaseURL: "https://127.0.0.1:8995/api/v1"},
		// Refused for its name (a command), and its rootca does not exist:
		// a client for it would make tdns.NewClient exit, stopping every
		// command, not just this entry.
		{Name: "config", Role: "auth", BaseURL: "https://127.0.0.1:8996/api/v1", RootCA: "/nonexistent/ca.pem"},
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
	if ac := tdns.Globals.ApiClients["tdns-auth"]; ac == nil || ac.BaseUrl != "https://127.0.0.1:8989/api/v1" {
		t.Errorf("tdns-auth client: %+v", ac)
	}
	if ac, ok := tdns.Globals.ApiClients["tdns-imr"]; ok {
		t.Errorf("an auth instance named tdns-imr got the imr client: %+v", ac)
	}
	if ac := tdns.Globals.ApiClients["auth2"]; ac == nil || ac.BaseUrl != "https://127.0.0.1:8992/api/v1" {
		t.Errorf("auth2 client (the first auth2 wins, as in the wiring): %+v", ac)
	}
	if ac := tdns.Globals.ApiClients["auth3"]; ac == nil || ac.BaseUrl != "https://127.0.0.1:8995/api/v1" {
		t.Errorf("auth3 client (the entry the wiring accepts, not the refused one before it): %+v", ac)
	}
	if d := getApiDetailsByClientKey("tdns-auth"); d == nil || d.ConfigFile != "/etc/tdns/tdns-auth.yaml" {
		t.Errorf("config lookup for tdns-auth: %+v", d)
	}
}

// ----------------------------------------------------------------- config list

func TestBuildListRows(t *testing.T) {
	withCleanRoleRegistry(t)
	root := &cobra.Command{Use: "tdns-ncli"}
	root.AddCommand(&cobra.Command{Use: "version"}, NewCliConfigCmd())
	entries := []ApiDetails{
		{Name: "tdns-auth", BaseURL: "https://127.0.0.1:8989/api/v1"},
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

	if r := byName["tdns-auth"]; r.Command != "auth" || r.Status != "ok" || !strings.HasSuffix(r.ConfigFile, "(default)") || !strings.Contains(r.ConfigFile, tdns.DefaultAuthCfgFile) {
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
	gotKey := make(chan string, 8)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ping" {
			http.NotFound(w, r)
			return
		}
		gotKey <- r.Header.Get("X-API-Key")
		json.NewEncoder(w).Encode(tdns.PingResponse{
			Msg: "pong", Version: "v-test", BootTime: time.Now().Add(-90 * time.Minute), Pings: 1, Pongs: 1,
		})
	}))
	defer srv.Close()

	// A directory passes a stat but is no CA file; tdns.NewClient would end
	// the process on it. So would a file with no certificate in it.
	caDir := t.TempDir()
	notPEM := filepath.Join(caDir, "not.pem")
	writeFile(t, notPEM, "not a certificate\n")

	entries := []ApiDetails{
		{Name: "up", BaseURL: srv.URL + "/api/v1", ApiKey: "sekret", AuthMethod: "X-API-Key"},
		{Name: "down", BaseURL: "https://127.0.0.1:1/api/v1", ApiKey: "k", AuthMethod: "X-API-Key"},
		{Name: "badca", BaseURL: srv.URL + "/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: "/nonexistent/ca.pem"},
		{Name: "tlsa", BaseURL: srv.URL + "/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: "tlsa"},
		{Name: "cadir", BaseURL: srv.URL + "/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: caDir},
		{Name: "notpem", BaseURL: srv.URL + "/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: notPEM},
	}
	res := CheckEntries(entries, CliClientConf{}, 5*time.Second)

	if !strings.HasPrefix(res[0], "ok") || !strings.Contains(res[0], "v-test") || !strings.Contains(res[0], "up 1h30m") {
		t.Errorf("up: %q", res[0])
	}
	select {
	case k := <-gotKey:
		if k != "sekret" {
			t.Errorf("server saw X-API-Key %q", k)
		}
	case <-time.After(5 * time.Second):
		t.Error("the server saw no ping")
	}
	if !strings.HasPrefix(res[1], "FAIL") {
		t.Errorf("down: %q", res[1])
	}
	if !strings.HasPrefix(res[2], "FAIL") || !strings.Contains(res[2], "rootca") {
		t.Errorf("badca: %q", res[2])
	}
	if !strings.HasPrefix(res[3], "not checked") {
		t.Errorf("tlsa: %q", res[3])
	}
	// newApiClientFor reads and parses the CA file, so a directory or a file
	// with no certificate in it fails this entry, not the process.
	if !strings.HasPrefix(res[4], "FAIL") || !strings.Contains(res[4], "rootca") {
		t.Errorf("cadir: %q", res[4])
	}
	if !strings.HasPrefix(res[5], "FAIL") || !strings.Contains(res[5], "no PEM certificate") {
		t.Errorf("notpem: %q", res[5])
	}

	// The warning every other command would give for an entry (here: an
	// unverified daemon) is in the check's result too, after the verdict, so
	// the leading ok or FAIL that sets the exit status stays first.
	saved := RequireServerVerification
	t.Cleanup(func() { RequireServerVerification = saved })
	RequireServerVerification = true
	warned := CheckEntries([]ApiDetails{
		{Name: "insecure", BaseURL: srv.URL + "/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: "insecure"},
		{Name: "insecuredown", BaseURL: "https://127.0.0.1:1/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: "insecure"},
	}, CliClientConf{}, 5*time.Second)
	if !strings.HasPrefix(warned[0], "ok") || !strings.Contains(warned[0], "warning:") || !strings.Contains(warned[0], "not verified") {
		t.Errorf("insecure entry that answers: %q, want ok with the warning", warned[0])
	}
	if !strings.HasPrefix(warned[1], "FAIL") || !strings.Contains(warned[1], "warning:") {
		t.Errorf("insecure entry that does not answer: %q, want FAIL with the warning", warned[1])
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

// config add writes the daemon's TCP entry with config-file:, whoever runs it
// and whether or not the daemon has a local admin socket: tdns-ncli finds the
// socket through config-file: when it runs (usableDaemonSocket), so the CLI
// config never holds its path. A daemon with only the socket gets an entry
// with config-file: alone, which root adds.
func TestAddWritesTheTCPEntryWithConfigFile(t *testing.T) {
	setRoot := func(t *testing.T, root bool) {
		saved := runningAsRoot
		t.Cleanup(func() { runningAsRoot = saved })
		runningAsRoot = func() bool { return root }
	}
	// The socket is the test's own, and nothing listens on it.
	sockOf := func(env *addEnv) string { return filepath.Join(env.sockDir, "tdns-auth.sock") }
	withSocket := func(env *addEnv, t *testing.T, file, addr string) string {
		p := filepath.Join(env.dir, file)
		writeFile(t, p, daemonYAML("TDNS-AUTH", addr, "key-"+file, "   socket: "+sockOf(env)+"\n"))
		return p
	}

	for _, root := range []bool{true, false} {
		t.Run(fmt.Sprintf("root=%v gets the TCP entry", root), func(t *testing.T) {
			setRoot(t, root)
			env := newAddEnv(t)
			d := withSocket(env, t, "tdns-auth.yaml", "127.0.0.1:8989")
			res, err := env.add(t, d, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := ApiDetails{Name: "tdns-auth", BaseURL: "https://127.0.0.1:8989/api/v1",
				AuthMethod: "certificate", ConfigFile: d,
				TLSAuth: "pin", Pins: []string{testDaemonPin}}
			if got := env.entries(t); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
				t.Errorf("entries = %+v\nwant      [%+v]", got, want)
			}
			if raw, _ := os.ReadFile(env.cli); strings.Contains(string(raw), sockOf(env)) {
				t.Errorf("the CLI config repeats the socket's path:\n%s", raw)
			}
			if !strings.Contains(strings.Join(res.Notes, " "), sockOf(env)) {
				t.Errorf("notes = %q, want one saying root reaches the daemon over %s", res.Notes, sockOf(env))
			}
		})
	}

	t.Run("a TCP entry needs the key", func(t *testing.T) {
		for _, root := range []bool{true, false} {
			setRoot(t, root)
			env := newAddEnv(t)
			p := filepath.Join(env.dir, "tdns-auth.yaml")
			writeFile(t, p, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "", "   socket: "+sockOf(env)+"\n"))
			if _, err := env.add(t, p, nil); err == nil || !strings.Contains(err.Error(), "apiserver.apikey is not set, which the daemon requires") || strings.Contains(err.Error(), "no key to send") {
				t.Errorf("root=%v: err = %v, want one naming apiserver.apikey", root, err)
			}
		}
	})

	t.Run("a socket-only daemon: root adds config-file: alone", func(t *testing.T) {
		setRoot(t, true)
		env := newAddEnv(t)
		p := filepath.Join(env.dir, "tdns-auth.yaml")
		writeFile(t, p, "service:\n   name: TDNS-AUTH\napiserver:\n   apikey: k\n   socket: "+sockOf(env)+"\n")
		res, err := env.add(t, p, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := ApiDetails{Name: "tdns-auth", AuthMethod: "none", ConfigFile: p}
		if got := env.entries(t); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
			t.Errorf("entries = %+v\nwant      [%+v]", got, want)
		}
		raw, _ := os.ReadFile(env.cli)
		if s := string(raw); strings.Contains(s, "baseurl") || strings.Contains(s, "apikey") {
			t.Errorf("a socket-only entry has no baseurl or apikey line:\n%s", raw)
		}
		// No TCP: no certificate, and nothing done on the daemon's side.
		if _, err := os.Stat(accessFileOf(p)); res.Cert != nil || err == nil {
			t.Errorf("socket-only daemon: cert %+v, access file there: %v", res.Cert, err == nil)
		}
		if res, err := env.add(t, p, nil); err != nil || res.AlreadyKnown != "tdns-auth" || res.Wrote {
			t.Errorf("re-add: %+v, %v; want it already known", res, err)
		}

		setRoot(t, false)
		env2 := newAddEnv(t)
		if _, err := env2.add(t, p, nil); err == nil || !strings.Contains(err.Error(), "only root") {
			t.Errorf("not root: err = %v, want one saying only root can use the socket", err)
		}
	})

	t.Run("a socket entry written before is the same daemon", func(t *testing.T) {
		setRoot(t, true)
		env := newAddEnv(t)
		d := withSocket(env, t, "tdns-auth.yaml", "127.0.0.1:8989")
		writeFile(t, env.cli, "apiservers:\n   - name: tdns-auth\n     baseurl: unix://"+sockOf(env)+"\n     authmethod: none\n     config-file: "+d+"\n")
		res, err := env.add(t, d, nil)
		if err != nil || res.AlreadyKnown != "tdns-auth" || res.Wrote {
			t.Errorf("%+v, %v; want it already known", res, err)
		}
	})

	t.Run("a rotated key: the key entry is stale", func(t *testing.T) {
		setRoot(t, true)
		env := newAddEnv(t)
		d := withSocket(env, t, "tdns-auth.yaml", "127.0.0.1:8989")
		writeFile(t, env.cli, "apiservers:\n   - name: tdns-auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: key-tdns-auth.yaml\n     authmethod: X-API-Key\n     config-file: "+d+"\n")
		writeFile(t, d, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "rotated-key", "   socket: "+sockOf(env)+"\n"))
		if _, err := env.add(t, d, nil); err == nil || !strings.Contains(err.Error(), "apikey") || strings.Contains(err.Error(), "scheme") {
			t.Errorf("err = %v, want the apikey named, and only it", err)
		}
	})

	t.Run("a relative socket path is not used", func(t *testing.T) {
		setRoot(t, true)
		env := newAddEnv(t)
		p := filepath.Join(env.dir, "tdns-auth.yaml")
		writeFile(t, p, daemonYAML("TDNS-AUTH", "127.0.0.1:8989", "the-key", "   socket: run/tdns-auth.sock\n"))
		// No socket the daemon serves, so no access file: a new entry, which
		// would need one for the certificate, is refused, and says why.
		_, err := env.add(t, p, nil)
		var r addRefusal
		if !errors.As(err, &r) || !strings.Contains(err.Error(), "local admin socket") || !strings.Contains(err.Error(), "not an absolute path") {
			t.Errorf("err = %v, want a refusal naming the socket, and why there is none", err)
		}
		if _, serr := os.Stat(env.cli); serr == nil {
			t.Error("the refused add wrote the CLI config")
		}

		// With no TCP address there is nothing to add.
		writeFile(t, p, "service:\n   name: TDNS-AUTH\napiserver:\n   socket: run/tdns-auth.sock\n")
		env2 := newAddEnv(t)
		if _, err := env2.add(t, p, nil); err == nil || !strings.Contains(err.Error(), "neither apiserver.addresses nor apiserver.socket") {
			t.Errorf("err = %v, want one saying there is no management API to address", err)
		}
	})
}

func statOf(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// A row named tdns-auth that carries a role: is an instance using a reserved
// name, which the CLI ignores. It is not the canonical entry: an add that
// would become the canonical tdns-auth says so instead of filing the daemon
// as an extra instance (which left `tdns-ncli auth` with no client), and an
// add under a name of its own is not blocked by it.
func TestRoleCarryingCanonicalNameIsNotTheCanonicalEntry(t *testing.T) {
	existing := []ApiDetails{{Name: "tdns-auth", Role: "auth", BaseURL: "https://127.0.0.1:8989/api/v1"}}
	var entry ApiDetails
	var res AddResult
	err := chooseEntryName(&entry, &res, "auth", existing, AddOptions{DaemonConfig: "/etc/tdns/tdns-auth.yaml"})
	if err == nil || !strings.Contains(err.Error(), "role: auth") {
		t.Fatalf("err = %v, entry = %+v; want the ignored tdns-auth row named", err, entry)
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
	if err != nil || res.AlreadyKnown != "tdns-auth" || res.Wrote {
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
	res := &AddResult{Entry: ApiDetails{Name: "auth2", Role: "auth"}, File: "/tmp/local.yaml"}
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

	c := &CliConf{ApiServers: []ApiDetails{
		{Name: "tdns-auth", BaseURL: "https://127.0.0.1:8989/api/v1"},
		{Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1", RootCA: "/nonexistent/ca.pem"},
	}}
	if err := InitApiClients(c); err != nil {
		t.Fatal(err)
	}
	if tdns.Globals.ApiClients["tdns-auth"] == nil {
		t.Error("no client for the canonical entry")
	}
	if ac, ok := tdns.Globals.ApiClients["auth2"]; ok {
		t.Errorf("an instance nothing wired got a client: %+v", ac)
	}
}

// ------------------------------------------- config add and the certificate

// certDaemonCfg is a tdns-auth config as an operator writes it: comments, an
// aligned apiserver: block, the access-file: line still commented out, and
// another section after it. @CERT@, @SOCK@ and @EXTRA@ (more apiserver:
// lines) are filled in by certDaemon.
const certDaemonCfg = `# a tdns-auth, as an operator writes it
service:
   name: TDNS-AUTH

apiserver:
   addresses:  [ 127.0.0.1:8989 ]
   apikey:     the-key
   certfile:   @CERT@
   socket:     @SOCK@@EXTRA@
   # access-file: comes later

db:
   file: /var/tmp/tdns-auth.db
`

// certDaemon writes certDaemonCfg to dir/tdns-auth.yaml, with a certificate
// for the daemon to serve and a socket in env.sockDir (nothing listens there
// unless a test serves it). It returns the config's path and the daemon's
// pin.
func (e *addEnv) certDaemon(t *testing.T, dir, extra string) (string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler()) // only for a certificate
	srv.Close()
	certFile := filepath.Join(e.dir, "api.crt")
	writeFile(t, certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	d := filepath.Join(dir, "tdns-auth.yaml")
	cfg := strings.NewReplacer("@CERT@", certFile, "@SOCK@", e.socket(), "@EXTRA@", extra).Replace(certDaemonCfg)
	writeFile(t, d, cfg)
	return d, tdns.SPKISHA256(srv.Certificate())
}

func (e *addEnv) socket() string { return filepath.Join(e.sockDir, "auth.sock") }

// withAccessLine is daemon config d as certDaemonCfg wrote it with
// "access-file: af" added after the commented-out line, as config add adds it
// (quoted, as a path with a comma in it is).
func withAccessLine(cfg, af string) string {
	return strings.Replace(cfg, "   # access-file: comes later\n", "   # access-file: comes later\n   access-file: "+yamlScalar(af)+"\n", 1)
}

func readBytes(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// printed is what config add prints for r, its whitespace flattened: the
// wrapping depends on the lengths of the test's paths. The layout itself is
// TestAddOutputLayout's.
func printed(r *AddResult, dryRun bool, cfg string) string {
	var sb strings.Builder
	printAddResult(&sb, r, dryRun, cfg)
	return flat(sb.String())
}

// flat is s with every run of white space one space.
func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

// A new entry authenticates by certificate. The daemon config names no access
// file, so config add creates one with the operator's pin (read-write), adds
// access-file: to the daemon config (nothing else in it changes), and, the
// daemon not running, says its next start reads them. The operator had no
// pair: it is made, and its pin printed. Run again, nothing changes.
func TestAddEnrollsTheCertificate(t *testing.T) {
	env := newAddEnv(t)
	d, daemonPin := env.certDaemon(t, env.dir, "")
	// A daemon config others may read: the access file is the daemon's
	// policy all the same, 0600.
	if err := os.Chmod(d, 0o644); err != nil {
		t.Fatal(err)
	}
	orig := readBytes(t, d)
	af := accessFileOf(d)

	res, err := env.add(t, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	pin := env.pin(t) // made by the add
	want := ApiDetails{Name: "tdns-auth", BaseURL: "https://127.0.0.1:8989/api/v1", AuthMethod: "certificate",
		TLSAuth: "pin", Pins: []string{daemonPin}, ConfigFile: d}
	if got := env.entries(t); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("entries = %+v\nwant      [%+v]", got, want)
	}
	if raw := readBytes(t, env.cli); strings.Contains(raw, "apikey") || strings.Contains(raw, "the-key") {
		t.Errorf("a certificate entry has no apikey: line:\n%s", raw)
	}
	if got := readBytes(t, d); got != withAccessLine(orig, af) {
		t.Errorf("daemon config =\n%s\nwant\n%s", got, withAccessLine(orig, af))
	}
	if fi := statOf(t, af); fi.Mode().Perm() != 0o600 {
		t.Errorf("the new access file has mode %v, want 0600", fi.Mode().Perm())
	}
	if fi := statOf(t, d); fi.Mode().Perm() != 0o644 {
		t.Errorf("the daemon config has mode %v, want its 0644 kept", fi.Mode().Perm())
	}
	acc, err := tdns.LoadAccessFile(af)
	if err != nil || !acc.KeyAuthOn() || len(acc.Clients) != 1 || acc.Clients[0].Pin != pin ||
		acc.Clients[0].Role != "read-write" || acc.Clients[0].Name != clientNameOf(env.cert) {
		t.Errorf("access file %+v (%v), want the pin as %s, read-write", acc, err, clientNameOf(env.cert))
	}
	// The entry builds: the pair it names is there.
	if _, _, err := newApiClientFor(env.entries(t)[0], ReadCliClientConf(env.cli)); err != nil {
		t.Errorf("the entry does not build: %v", err)
	}

	out := printed(res, false, env.cli)
	for _, w := range []string{
		`Created ` + env.cli + ` with "tdns-auth"`,
		"Created your client certificate " + env.cert, pin,
		"Created " + af, "access-file: " + af,
		"read-write there, no longer admin", "TLS 1.3", "local admin socket's alone",
		"not running", "next start",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	if strings.Index(out, "Created "+env.cli) != 0 {
		t.Errorf("the verdict is not first:\n%s", out)
	}

	cliBefore, accBefore, cfgBefore := readBytes(t, env.cli), readBytes(t, af), readBytes(t, d)
	res, err = env.add(t, d, nil)
	if err != nil || res.AlreadyKnown != "tdns-auth" || res.Wrote || res.Cert.state != certWorks {
		t.Errorf("second add: %+v, %v; want it already known, nothing to do", res, err)
	}
	if readBytes(t, env.cli) != cliBefore || readBytes(t, af) != accBefore || readBytes(t, d) != cfgBefore {
		t.Error("the second add changed a file")
	}
	if out := printed(res, false, env.cli); !strings.Contains(out, "nothing changed") || strings.Contains(out, "Created your client") {
		t.Errorf("second add printed:\n%s", out)
	}
}

// A daemon config that names its access file: the pin is added to it, the
// other clients and keyauth as they were, the old file kept as .prev, and the
// daemon config not touched.
func TestAddEnrollsInTheAccessFileThere(t *testing.T) {
	env := newAddEnv(t)
	pin := env.pin(t)
	af := filepath.Join(env.dir, "access.yaml")
	d, _ := env.certDaemon(t, env.dir, "\n   access-file: "+af)
	old := "keyauth: true\nclients:\n   - name: anna\n     pin: " + pinOf("anna") + "\n     role: read-only\n"
	writeFile(t, af, old)
	cfg := readBytes(t, d)

	res, err := env.add(t, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry.AuthMethod != "certificate" || res.Cert.nameIt || res.Cert.createFile {
		t.Errorf("result %+v, cert %+v", res, res.Cert)
	}
	acc, err := tdns.LoadAccessFile(af)
	if err != nil || len(acc.Clients) != 2 || acc.Clients[0].Name != "anna" || acc.Clients[0].Role != "read-only" ||
		acc.Clients[1].Name != "tester" || acc.Clients[1].Pin != pin || acc.Clients[1].Role != "read-write" {
		t.Errorf("access file %+v (%v), want anna as she was, then tester", acc, err)
	}
	if prev := readBytes(t, af+".prev"); prev != old {
		t.Errorf(".prev = %q, want the file before", prev)
	}
	if readBytes(t, d) != cfg {
		t.Error("the daemon config changed, though it named its access file")
	}
	if out := printed(res, false, env.cli); !strings.Contains(out, "Enrolled your certificate in "+af) || strings.Contains(out, "no longer admin") {
		t.Errorf("printed:\n%s", out)
	}
}

// The pin is listed already, under another name: not added again, the file
// not rewritten, and the entry uses the certificate.
func TestAddFindsThePinListed(t *testing.T) {
	env := newAddEnv(t)
	pin := env.pin(t)
	af := filepath.Join(env.dir, "access.yaml")
	d, _ := env.certDaemon(t, env.dir, "\n   access-file: "+af)
	old := "keyauth: true\nclients:\n   - name: laptop\n     pin: " + pin + "\n     role: read-only\n"
	writeFile(t, af, old)

	res, err := env.add(t, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry.AuthMethod != "certificate" || res.Cert.state != certWorks || res.Cert.listedAs != "laptop" {
		t.Errorf("result %+v, cert %+v", res, res.Cert)
	}
	if readBytes(t, af) != old {
		t.Errorf("the access file was rewritten:\n%s", readBytes(t, af))
	}
	if _, err := os.Stat(af + ".prev"); err == nil {
		t.Error("a .prev was written, though nothing changed")
	}
	// It is listed read-only, and config add does not change that: it says
	// so, plainly.
	if out := printed(res, false, env.cli); !strings.Contains(out, "lists your certificate as laptop, read-only: write commands will be refused") ||
		!strings.Contains(out, "tdns-ncli auth client set-role laptop read-write") {
		t.Errorf("printed:\n%s", out)
	}
	// Read-write: the role named, nothing more.
	writeFile(t, af, strings.Replace(old, "read-only", "read-write", 1))
	if res, err = env.add(t, d, nil); err != nil {
		t.Fatal(err)
	}
	if out := printed(res, false, env.cli); !strings.Contains(out, "lists your certificate as laptop (read-write).") {
		t.Errorf("read-write, printed:\n%s", out)
	}
}

// The pin is listed, disabled: config add does not enable it. A new entry is
// refused, saying how to enable it; a key entry keeps the key and says so.
func TestAddReportsADisabledPin(t *testing.T) {
	env := newAddEnv(t)
	pin := env.pin(t)
	af := filepath.Join(env.dir, "access.yaml")
	d, _ := env.certDaemon(t, env.dir, "\n   access-file: "+af)
	old := "keyauth: true\nclients:\n   - name: laptop\n     pin: " + pin + "\n     role: read-write\n     disabled: true\n"
	writeFile(t, af, old)

	_, err := env.add(t, d, nil)
	var r addRefusal
	if !errors.As(err, &r) || !strings.Contains(err.Error(), "disabled") || !strings.Contains(strings.Join(r.fix, "\n"), "tdns-ncli auth client enable laptop") {
		t.Errorf("new entry: err = %v, want a refusal with client enable", err)
	}
	if _, err := os.Stat(env.cli); err == nil {
		t.Error("the refused add wrote the CLI config")
	}

	key := "apiservers:\n   - name: tdns-auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: the-key\n     authmethod: X-API-Key\n     config-file: " + d + "\n"
	writeFile(t, env.cli, key)
	res, err := env.add(t, d, nil)
	if err != nil || !res.KeyKept || res.Switched {
		t.Fatalf("key entry: %+v, %v; want the key kept", res, err)
	}
	if got := env.entries(t); got[0].AuthMethod != "X-API-Key" || got[0].ApiKey != "the-key" {
		t.Errorf("entry %+v, want it on the key", got[0])
	}
	out := printed(res, false, env.cli)
	if !strings.Contains(out, "keeps the API key") || !strings.Contains(out, "disabled") || !strings.Contains(out, "client enable laptop") {
		t.Errorf("printed:\n%s", out)
	}
	if readBytes(t, af) != old {
		t.Error("the access file changed")
	}
}

// An entry that uses the key is switched to the certificate once the daemon
// accepts it: authmethod: certificate where the line stands (its comment
// kept), its apikey: line gone, every other line as it was.
func TestAddSwitchesAKeyEntry(t *testing.T) {
	env := newAddEnv(t)
	d, daemonPin := env.certDaemon(t, env.dir, "")
	head := "# CLI config\napiservers:\n   # the auth server\n   - name:          tdns-auth\n     baseurl:       https://127.0.0.1:8989/api/v1\n"
	tail := "     tlsauth:       pin\n     pins:          [ \"" + daemonPin + "\" ]\n     config-file:   " + d + "\n\n# end\n"
	writeFile(t, env.cli, head+"     apikey:        the-key\n     authmethod:    X-API-Key     # the key, for now\n"+tail)

	res, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true })
	if err != nil || !res.Switched || res.Wrote {
		t.Fatalf("dry run: %+v, %v", res, err)
	}
	if _, err := os.Stat(accessFileOf(d)); err == nil {
		t.Error("the dry run created the access file")
	}

	res, err = env.add(t, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Switched || res.Pinned || !res.Wrote || res.KeyKept {
		t.Errorf("result = %+v", res)
	}
	want := head + "     authmethod:    certificate     # the key, for now\n" + tail
	if got := readBytes(t, env.cli); got != want {
		t.Errorf("file =\n%s\nwant\n%s", got, want)
	}
	if got := env.entries(t); got[0].AuthMethod != "certificate" || got[0].ApiKey != "" {
		t.Errorf("entry = %+v", got[0])
	}
	if acc, err := tdns.LoadAccessFile(accessFileOf(d)); err != nil || len(acc.Clients) != 1 || acc.Clients[0].Pin != env.pin(t) {
		t.Errorf("access file %+v (%v)", acc, err)
	}
	if out := printed(res, false, env.cli); !strings.Contains(out, "switched it to your client certificate") {
		t.Errorf("printed:\n%s", out)
	}
}

// readOnlyDaemonDir is a directory for daemon configs that the test cannot
// write in: config add cannot make the daemon's side, as for anyone but root
// on a daemon host.
func readOnlyDaemonDir(t *testing.T, env *addEnv) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := filepath.Join(env.dir, "daemon")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) }) // before TempDir's cleanup removes it
	return dir
}

// When config add cannot write the daemon's side, an entry whose key works at
// both ends keeps it, and the result says what the certificate still needs:
// the exact client add line, and the access-file: line. A new entry is
// refused with that fix. A key the access file turns off does not work: the
// key entry is refused too.
func TestAddKeepsTheKeyWhenItCannotWriteTheDaemonSide(t *testing.T) {
	env := newAddEnv(t)
	pin := env.pin(t)
	dir := readOnlyDaemonDir(t, env)
	d, daemonPin := env.certDaemon(t, dir, "")
	os.Chmod(dir, 0o555)
	cfg := readBytes(t, d)

	// New: refused, with the fix, and nothing written.
	_, err := env.add(t, d, nil)
	var r addRefusal
	if !errors.As(err, &r) {
		t.Fatalf("new entry: err = %v, want a refusal", err)
	}
	fix := strings.Join(r.fix, "\n")
	for _, w := range []string{"tdns-ncli auth client add tester --pin " + pin + " --role read-write", "access-file: " + accessFileOf(d)} {
		if !strings.Contains(fix, w) {
			t.Errorf("fix lacks %q:\n%s", w, fix)
		}
	}
	if _, err := os.Stat(env.cli); err == nil {
		t.Error("the refused add wrote the CLI config")
	}
	var sb strings.Builder
	printRefusal(&sb, r)
	if out := sb.String(); !strings.HasPrefix(out, "Error: not adding "+d) || !strings.Contains(out, "\n  Fix: ") {
		t.Errorf("refusal printed:\n%s", out)
	}

	// Known, on the key: kept, and the fix printed.
	key := "apiservers:\n   - name: tdns-auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: the-key\n     authmethod: X-API-Key\n     tlsauth: pin\n     pins: [ \"" + daemonPin + "\" ]\n     config-file: " + d + "\n"
	writeFile(t, env.cli, key)
	res, err := env.add(t, d, nil)
	if err != nil || !res.KeyKept || res.Switched || res.Wrote {
		t.Fatalf("key entry: %+v, %v; want the key kept, nothing written", res, err)
	}
	if readBytes(t, env.cli) != key || readBytes(t, d) != cfg {
		t.Error("a file changed")
	}
	if _, err := os.Stat(accessFileOf(d)); err == nil {
		t.Error("an access file was created")
	}
	out := printed(res, false, env.cli)
	for _, w := range []string{"keeps the API key", "tdns-ncli auth client add tester --pin " + pin + " --role read-write", "access-file: " + accessFileOf(d)} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "the-key") {
		t.Errorf("the key was printed:\n%s", out)
	}

	// The access file turns the key off: neither works, so it is refused.
	os.Chmod(dir, 0o755)
	af := filepath.Join(dir, "access.yaml")
	writeFile(t, af, "keyauth: false\nclients: []\n")
	writeFile(t, d, withAccessLine(cfg, af))
	os.Chmod(dir, 0o555)
	if _, err := env.add(t, d, nil); !errors.As(err, &r) || !strings.Contains(err.Error(), "keyauth: false") {
		t.Errorf("keyauth off: err = %v, want a refusal naming it", err)
	}
	if readBytes(t, env.cli) != key {
		t.Error("the refused add changed the CLI config")
	}
}

// usetls: false with TCP addresses: the daemon refuses an access file then,
// and a certificate needs TLS anyway. No access file is created, the daemon
// config is not touched; a new entry is refused, a key entry keeps its key,
// and both say TLS is what is missing.
func TestAddWithoutTLSCreatesNoAccessFile(t *testing.T) {
	env := newAddEnv(t)
	d, _ := env.certDaemon(t, env.dir, "\n   usetls:     false")
	cfg := readBytes(t, d)

	_, err := env.add(t, d, nil)
	var r addRefusal
	if !errors.As(err, &r) || !strings.Contains(err.Error(), "usetls") {
		t.Errorf("new entry: err = %v, want a refusal naming usetls", err)
	}
	key := "apiservers:\n   - name: tdns-auth\n     baseurl: http://127.0.0.1:8989/api/v1\n     apikey: the-key\n     authmethod: X-API-Key\n     config-file: " + d + "\n"
	writeFile(t, env.cli, key)
	res, err := env.add(t, d, nil)
	if err != nil || !res.KeyKept || res.Switched || res.Wrote {
		t.Fatalf("http key entry: %+v, %v; want the key kept", res, err)
	}
	if out := printed(res, false, env.cli); !strings.Contains(out, "keeps the API key") || !strings.Contains(out, "usetls") {
		t.Errorf("printed:\n%s", out)
	}
	if _, err := os.Stat(accessFileOf(d)); err == nil {
		t.Error("an access file was created for a daemon without TLS")
	}
	if readBytes(t, d) != cfg || readBytes(t, env.cli) != key {
		t.Error("a file changed")
	}
	if _, err := os.Stat(env.cert); err == nil {
		t.Error("a client pair was made for a daemon that cannot use it")
	}
}

// fakeSocketDaemon answers /config on a daemon's local admin socket: it says
// it runs cfg (or runs, when set), and a reload loads the access file into the
// policy status reports (without its clients, when forget is set).
type fakeSocketDaemon struct {
	mu          sync.Mutex
	cfg, access string
	runs        string
	forget      bool
	policy      *tdns.ApiAccessStatus
	reloads     int
}

func serveFakeDaemon(t *testing.T, sock, cfg, access string) *fakeSocketDaemon {
	t.Helper()
	f := &fakeSocketDaemon{cfg: cfg, access: access}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var cp tdns.ConfigPost
		json.NewDecoder(r.Body).Decode(&cp)
		f.mu.Lock()
		defer f.mu.Unlock()
		resp := tdns.ConfigResponse{ConfigFile: f.cfg}
		if f.runs != "" {
			resp.ConfigFile = f.runs
		}
		switch cp.Command {
		case "reload":
			f.reloads++
			resp.Msg = "Config reloaded."
			if _, err := os.Stat(f.access); errors.Is(err, os.ErrNotExist) {
				f.policy = nil // no access file: the key is admin again
			} else if af, err := tdns.LoadAccessFile(f.access); err == nil {
				st := &tdns.ApiAccessStatus{File: f.access, KeyAuth: af.KeyAuthOn(), Clients: []tdns.ApiAccessStatusClient{}}
				for _, c := range af.Clients {
					if !f.forget {
						st.Clients = append(st.Clients, tdns.ApiAccessStatusClient{Name: c.Name, Pin: c.Pin, Role: c.Role, Disabled: c.Disabled})
					}
				}
				f.policy = st
				resp.Msg += fmt.Sprintf(" Access file reloaded: %d client(s), keyauth on.", len(st.Clients))
			}
		case "status":
			resp.Access = f.policy
		}
		json.NewEncoder(w).Encode(resp)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return f
}

func (f *fakeSocketDaemon) reloadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reloads
}

// A running daemon is reloaded over its local socket, and the policy it then
// runs is checked for the pin. A reload that does not put the pin in force
// fails the add, and every file is put back as it was. Another daemon on the
// socket is not this one's: nothing is written.
func TestAddReloadsARunningDaemon(t *testing.T) {
	t.Run("reloaded, the pin in force", func(t *testing.T) {
		env := newAddEnv(t)
		d, _ := env.certDaemon(t, env.dir, "")
		f := serveFakeDaemon(t, env.socket(), d, accessFileOf(d))
		res, err := env.add(t, d, nil)
		if err != nil {
			t.Fatal(err)
		}
		if n := f.reloadCount(); n != 1 || !res.Cert.running {
			t.Errorf("%d reloads, running %v; want one reload", n, res.Cert.running)
		}
		if out := printed(res, false, env.cli); !strings.Contains(out, "Reloaded: Config reloaded. Access file reloaded: 1 client(s)") {
			t.Errorf("printed:\n%s", out)
		}
	})

	t.Run("the reload leaves the pin out: put back", func(t *testing.T) {
		env := newAddEnv(t)
		d, _ := env.certDaemon(t, env.dir, "")
		cfg := readBytes(t, d)
		f := serveFakeDaemon(t, env.socket(), d, accessFileOf(d))
		f.forget = true
		_, err := env.add(t, d, nil)
		var r addRefusal
		if !errors.As(err, &r) || !strings.Contains(err.Error(), "does not have your certificate") || !strings.Contains(err.Error(), "as they were") {
			t.Errorf("err = %v, want a refusal saying the files are put back", err)
		}
		if readBytes(t, d) != cfg {
			t.Errorf("the daemon config was not put back:\n%s", readBytes(t, d))
		}
		if _, err := os.Stat(accessFileOf(d)); err == nil {
			t.Error("the new access file was not removed")
		}
		if _, err := os.Stat(env.cli); err == nil {
			t.Error("the CLI config was written")
		}
	})

	t.Run("another daemon on the socket: nothing written", func(t *testing.T) {
		env := newAddEnv(t)
		d, _ := env.certDaemon(t, env.dir, "")
		cfg := readBytes(t, d)
		f := serveFakeDaemon(t, env.socket(), d, accessFileOf(d))
		f.runs = "/etc/tdns/other.yaml"
		_, err := env.add(t, d, nil)
		if err == nil || !strings.Contains(err.Error(), "runs /etc/tdns/other.yaml") {
			t.Errorf("err = %v, want a refusal naming the other config", err)
		}
		if readBytes(t, d) != cfg || f.reloadCount() != 0 {
			t.Error("the daemon config changed, or a reload was sent")
		}
		if _, err := os.Stat(accessFileOf(d)); err == nil {
			t.Error("an access file was created")
		}
	})
}

// The access-file: line goes at the end of the daemon config's apiserver:
// block, at its keys' column, aligned like its first key; the rest of the
// file stays byte for byte. What config add cannot edit with confidence it
// refuses.
func TestAddAccessFileLine(t *testing.T) {
	const af = "/etc/tdns/tdns-auth-access.yaml"
	for _, tc := range []struct{ name, src, want string }{
		{
			name: "aligned, after a trailing comment",
			src:  "apiserver:\n   addresses:  [ 127.0.0.1:8989 ]\n   apikey:     k\n   # access-file: " + af + "\n\nkeys:\n   tsig: []\n",
			want: "apiserver:\n   addresses:  [ 127.0.0.1:8989 ]\n   apikey:     k\n   # access-file: " + af + "\n   access-file: " + af + "\n\nkeys:\n   tsig: []\n",
		},
		{
			name: "wider alignment",
			src:  "# x\napiserver:\n  addresses:      [ 127.0.0.1:8989 ]\n  apikey:         k\n",
			want: "# x\napiserver:\n  addresses:      [ 127.0.0.1:8989 ]\n  apikey:         k\n  access-file:    " + af + "\n",
		},
		{
			name: "tabs after the colons: one space",
			src:  "apiserver:\n   addresses:     \t[ 127.0.0.1:8987 ]\n   apikey:\tk\nserver:\n   id: x\n",
			want: "apiserver:\n   addresses:     \t[ 127.0.0.1:8987 ]\n   apikey:\tk\n   access-file: " + af + "\nserver:\n   id: x\n",
		},
		{
			name: "a list value last",
			src:  "apiserver:\n   apikey: k\n   addresses:\n      - 127.0.0.1:8989\n      - '[::1]:8989'\ndb:\n   file: x\n",
			want: "apiserver:\n   apikey: k\n   addresses:\n      - 127.0.0.1:8989\n      - '[::1]:8989'\n   access-file: " + af + "\ndb:\n   file: x\n",
		},
		{
			name: "CRLF",
			src:  "apiserver:\r\n   apikey: k\r\n",
			want: "apiserver:\r\n   apikey: k\r\n   access-file: " + af + "\r\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := addAccessFileLine([]byte(tc.src), af)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
	for name, src := range map[string]string{
		"in an include":   "include:\n   - api.yaml\nservice:\n   name: TDNS-AUTH\n",
		"flow style":      "apiserver: { apikey: k }\n",
		"there already":   "apiserver:\n   apikey: k\n   access-file: \"\"\n",
		"tabs":            "apiserver:\n\tapikey: k\n",
		"two blocks":      "apiserver:\n   apikey: k\napiserver:\n   apikey: l\n",
		"an empty block":  "apiserver:\nservice:\n   name: x\n",
		"not YAML at all": "apiserver:\n   apikey: [ k\n",
	} {
		if out, err := addAccessFileLine([]byte(src), af); err == nil {
			t.Errorf("%s: edited, want a refusal:\n%s", name, out)
		}
	}
}

// Switching an entry to the certificate rewrites authmethod: where it stands
// and takes out apikey: (with any lines of its value); an entry with no
// authmethod: line gets one at its end.
func TestEditEntryTextToCert(t *testing.T) {
	up := ApiDetails{Name: "tdns-auth", AuthMethod: "certificate"}
	src := "apiservers:\n   - name: tdns-auth\n     apikey: >\n        folded-key\n     authmethod: \"X-API-Key\"  # note\n     config-file: /etc/tdns/tdns-auth.yaml\n"
	want := "apiservers:\n   - name: tdns-auth\n     authmethod: certificate  # note\n     config-file: /etc/tdns/tdns-auth.yaml\n"
	if got, err := editEntryText([]byte(src), "tdns-auth", up, entryEdit{toCert: true}); err != nil || string(got) != want {
		t.Errorf("got %q (%v)\nwant %q", got, err, want)
	}
	src = "apiservers:\n   - name:       tdns-auth\n     apikey:     k\n     baseurl:    https://127.0.0.1:8989/api/v1\n"
	want = "apiservers:\n   - name:       tdns-auth\n     baseurl:    https://127.0.0.1:8989/api/v1\n     authmethod: certificate\n"
	if got, err := editEntryText([]byte(src), "tdns-auth", up, entryEdit{toCert: true}); err != nil || string(got) != want {
		t.Errorf("no authmethod line: got %q (%v)\nwant %q", got, err, want)
	}
	if _, err := editEntryText([]byte("apiservers:\n   - authmethod: X-API-Key\n     name: tdns-auth\n"), "tdns-auth", up, entryEdit{toCert: true}); err == nil {
		t.Error("authmethod: on the item's first line was edited")
	}
}

// The daemon config is edited the way the access file is: its old bytes kept
// as .prev, the new file renamed over it with the old one's mode and group
// (the owner too, which a test that is not root cannot vary). A reload that
// fails puts the old bytes back the same way and leaves the .prev.
func TestAddKeepsTheDaemonConfigsPrevModeAndGroup(t *testing.T) {
	// A group of the test's user other than the one a new file gets, if it
	// has one: the one change of owner an unprivileged process may make.
	altGroup := func(t *testing.T, dir string) int {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		_, dirGid, ok := fileOwner(fi)
		if !ok {
			return -1
		}
		groups, _ := os.Getgroups()
		for _, g := range groups {
			if g != dirGid && g != os.Getegid() {
				return g
			}
		}
		return -1
	}
	setup := func(t *testing.T) (*addEnv, string, string, int) {
		env := newAddEnv(t)
		d, _ := env.certDaemon(t, env.dir, "")
		if err := os.Chmod(d, 0o640); err != nil {
			t.Fatal(err)
		}
		gid := -1
		if g := altGroup(t, env.dir); g >= 0 && os.Chown(d, -1, g) == nil {
			gid = g
		}
		return env, d, readBytes(t, d), gid
	}
	check := func(t *testing.T, d string, gid int, uid int) {
		t.Helper()
		fi := statOf(t, d)
		if fi.Mode().Perm() != 0o640 {
			t.Errorf("%s has mode %v, want the old 0640", d, fi.Mode().Perm())
		}
		if u, g, ok := fileOwner(fi); ok {
			if u != uid {
				t.Errorf("%s has owner %d, want %d", d, u, uid)
			}
			if gid >= 0 && g != gid {
				t.Errorf("%s has group %d, want the old %d", d, g, gid)
			}
		}
	}

	t.Run("edited: .prev, mode and group", func(t *testing.T) {
		env, d, orig, gid := setup(t)
		uid, _, _ := fileOwner(statOf(t, d))
		if _, err := env.add(t, d, nil); err != nil {
			t.Fatal(err)
		}
		if got := readBytes(t, d); got != withAccessLine(orig, accessFileOf(d)) {
			t.Errorf("daemon config =\n%s", got)
		}
		if prev := readBytes(t, d+".prev"); prev != orig {
			t.Errorf(".prev =\n%s\nwant the old bytes\n%s", prev, orig)
		}
		check(t, d, gid, uid)
		if gid < 0 {
			t.Log("no second group to give the daemon config: its group not varied")
		}
	})

	t.Run("a failed reload: restored, .prev left", func(t *testing.T) {
		env, d, orig, gid := setup(t)
		uid, _, _ := fileOwner(statOf(t, d))
		f := serveFakeDaemon(t, env.socket(), d, accessFileOf(d))
		f.forget = true // the reload does not put the pin in force
		if _, err := env.add(t, d, nil); err == nil || !strings.Contains(err.Error(), "as they were") {
			t.Fatalf("err = %v, want the add refused, the files put back", err)
		}
		if got := readBytes(t, d); got != orig {
			t.Errorf("daemon config not restored:\n%s", got)
		}
		if prev := readBytes(t, d+".prev"); prev != orig {
			t.Errorf(".prev =\n%s\nwant the old bytes", prev)
		}
		check(t, d, gid, uid)
	})
}

// What config add prints keeps to textWidth (a command line or the entry's
// pins: line, with a pin in it, aside): a note's continuation lines are indented two spaces, the socket's
// path on a line of its own; the daemon's reload reply a sentence to a line;
// an entry that keeps the key says so once, in the verdict; a refusal is
// wrapped too. Paths as short as /etc/tdns ones, so the widths are real.
func TestAddOutputLayout(t *testing.T) {
	short := func(t *testing.T) *addEnv {
		env := newAddEnv(t)
		dir, err := os.MkdirTemp("/tmp", "n")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		env.dir, env.cli = dir, filepath.Join(dir, "tdns-ncli.yaml")
		env.cert, env.key = filepath.Join(dir, "certs", "client.crt"), filepath.Join(dir, "certs", "client.key")
		return env
	}
	lines := func(t *testing.T, out string) []string {
		t.Helper()
		ls := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		for _, l := range ls {
			if body := strings.TrimLeft(l, " "); len(l) > textWidth && !strings.HasPrefix(body, "tdns-ncli ") && !strings.HasPrefix(body, "pins:") {
				t.Errorf("a line of %d characters: %q", len(l), l)
			}
		}
		return ls
	}
	follows := func(t *testing.T, ls []string, want ...string) {
		t.Helper()
		for i := range ls {
			if ls[i] == want[0] {
				for j := 1; j < len(want); j++ {
					if i+j >= len(ls) || ls[i+j] != want[j] {
						t.Errorf("after %q, want %q, got\n%s", want[0], want[j], strings.Join(ls, "\n"))
						return
					}
				}
				return
			}
		}
		t.Errorf("no line %q in\n%s", want[0], strings.Join(ls, "\n"))
	}

	t.Run("a new entry, reloaded", func(t *testing.T) {
		env := short(t)
		d, _ := env.certDaemon(t, env.dir, "")
		serveFakeDaemon(t, env.socket(), d, accessFileOf(d))
		res, err := env.add(t, d, nil)
		if err != nil {
			t.Fatal(err)
		}
		var sb strings.Builder
		printAddResult(&sb, res, false, env.cli)
		ls := lines(t, sb.String())
		follows(t, ls,
			"Note: as root, tdns-ncli uses this daemon's local admin socket",
			"  "+env.socket()+" (admin, no key);",
			"  tdns-ncli --tcp uses the TCP address")
		follows(t, ls,
			"Note: there was no tdns-auth entry yet, so this is the canonical one",
			"  (tdns-ncli auth ...); --name adds an extra instance instead")
		follows(t, ls,
			"Reloaded: Config reloaded.",
			"  Access file reloaded: 1 client(s), keyauth on.")
	})

	t.Run("the key kept, said once; a refusal", func(t *testing.T) {
		env := short(t)
		pin := env.pin(t)
		dir := readOnlyDaemonDir(t, env)
		d, dpin := env.certDaemon(t, dir, "")
		os.Chmod(dir, 0o555)

		_, err := env.add(t, d, nil)
		var r addRefusal
		if !errors.As(err, &r) {
			t.Fatalf("new entry: err = %v, want a refusal", err)
		}
		var sb strings.Builder
		printRefusal(&sb, r)
		ls := lines(t, sb.String())
		if !strings.HasPrefix(ls[0], "Error: not adding "+d+": ") {
			t.Errorf("refusal begins %q", ls[0])
		}
		follows(t, ls, "  Fix: on the daemon's host, as root:",
			"          tdns-ncli auth client add tester --pin "+pin+" --role read-write")

		writeFile(t, env.cli, "apiservers:\n   - name: tdns-auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: the-key\n     authmethod: X-API-Key\n     tlsauth: pin\n     pins: [ \""+dpin+"\" ]\n     config-file: "+d+"\n")
		res, err := env.add(t, d, nil)
		if err != nil || !res.KeyKept {
			t.Fatalf("%+v, %v", res, err)
		}
		sb.Reset()
		printAddResult(&sb, res, false, env.cli)
		out := sb.String()
		ls = lines(t, out)
		if n := strings.Count(flat(out), "keeps the API key"); n != 1 {
			t.Errorf("says it keeps the key %d times:\n%s", n, out)
		}
		if !strings.HasPrefix(ls[0], `Already known as "tdns-auth"; it keeps the API key: your`) {
			t.Errorf("verdict %q", ls[0])
		}
		follows(t, ls, "To use the certificate instead, on the daemon's host, as root:",
			"   tdns-ncli auth client add tester --pin "+pin+" --role read-write",
			"and add under apiserver: in "+d+":",
			"   access-file: "+accessFileOf(d),
			"and reload the daemon; then run config add again.")
	})
}

// ------------------------------------------- review round (CodeRabbit, 11-23)

// keyEntry is a hand-written key entry for daemon config d, pinned.
func keyEntry(d, dpin string) string {
	return "apiservers:\n   - name: tdns-auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: the-key\n     authmethod: X-API-Key\n     tlsauth: pin\n     pins: [ \"" + dpin + "\" ]\n     config-file: " + d + "\n"
}

// A known entry keeps the key only if the daemon takes it, and that is found
// out whatever becomes of the certificate: with a client pair that cannot be
// used, and when the entry cannot be rewritten for the certificate. When it
// cannot be found out (the access file unreadable, the daemon not answering)
// the entry keeps the key, and the result says so. An access file the daemon
// config does not name says nothing about the key.
func TestAddKeyFallbackNeedsAKeyTheDaemonTakes(t *testing.T) {
	t.Run("keyauth off, the pair unusable: refused", func(t *testing.T) {
		env := newAddEnv(t)
		af := filepath.Join(env.dir, "access.yaml")
		writeFile(t, af, "keyauth: false\nclients: []\n")
		d, dpin := env.certDaemon(t, env.dir, "\n   access-file: "+af)
		os.MkdirAll(filepath.Dir(env.key), 0o700)
		writeFile(t, env.key, "a key without its certificate\n")
		writeFile(t, env.cli, keyEntry(d, dpin))
		_, err := env.add(t, d, nil)
		var r addRefusal
		if !errors.As(err, &r) || !strings.Contains(err.Error(), "keyauth: false") || !strings.Contains(err.Error(), "without its certificate") {
			t.Errorf("err = %v, want a refusal naming keyauth and the pair", err)
		}
		if readBytes(t, env.cli) != keyEntry(d, dpin) {
			t.Error("the CLI config changed")
		}
	})

	t.Run("the access file unreadable, the daemon not answering: kept, said", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads anything")
		}
		env := newAddEnv(t)
		env.pin(t)
		af := filepath.Join(env.dir, "access.yaml")
		writeFile(t, af, "keyauth: true\nclients: []\n")
		os.Chmod(af, 0)
		d, dpin := env.certDaemon(t, env.dir, "\n   access-file: "+af)
		writeFile(t, env.cli, keyEntry(d, dpin))
		res, err := env.add(t, d, nil)
		if err != nil || !res.KeyKept || !strings.Contains(strings.Join(res.Notes, " "), "could not be told") {
			t.Errorf("%+v, %v; want the key kept, with a note that its acceptance could not be told", res, err)
		}
	})

	t.Run("the entry cannot be rewritten, keyauth off: refused", func(t *testing.T) {
		env := newAddEnv(t)
		env.pin(t)
		af := filepath.Join(env.dir, "access.yaml")
		writeFile(t, af, "keyauth: false\nclients: []\n")
		d, dpin := env.certDaemon(t, env.dir, "\n   access-file: "+af)
		first := "apiservers:\n   - authmethod: X-API-Key\n     name: tdns-auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: the-key\n     tlsauth: pin\n     pins: [ \"" + dpin + "\" ]\n     config-file: " + d + "\n"
		writeFile(t, env.cli, first)
		_, err := env.add(t, d, nil)
		var r addRefusal
		if !errors.As(err, &r) || !strings.Contains(err.Error(), "keyauth: false") {
			t.Errorf("err = %v, want a refusal", err)
		}
		if readBytes(t, env.cli) != first || readBytes(t, af) != "keyauth: false\nclients: []\n" {
			t.Error("a file changed")
		}
	})

	t.Run("a file the daemon config does not name: the key works", func(t *testing.T) {
		env := newAddEnv(t)
		env.pin(t)
		dir := readOnlyDaemonDir(t, env)
		d, dpin := env.certDaemon(t, dir, "")
		writeFile(t, accessFileOf(d), "keyauth: false\nclients: []\n")
		os.Chmod(dir, 0o555)
		writeFile(t, env.cli, keyEntry(d, dpin))
		if res, err := env.add(t, d, nil); err != nil || !res.KeyKept {
			t.Errorf("%+v, %v; want the key kept", res, err)
		}
	})
}

// The pin in the access file is not enough when the running daemon does not
// have it (a `client add --no-reload`): config add reloads it, checks, and
// only then switches the entry. Nothing is written to the access file.
func TestAddReloadsAPendingPolicy(t *testing.T) {
	env := newAddEnv(t)
	pin := env.pin(t)
	af := filepath.Join(env.dir, "access.yaml")
	acc := "keyauth: true\nclients:\n   - name: laptop\n     pin: " + pin + "\n     role: read-write\n"
	writeFile(t, af, acc)
	d, dpin := env.certDaemon(t, env.dir, "\n   access-file: "+af)
	f := serveFakeDaemon(t, env.socket(), d, af) // runs no policy yet
	writeFile(t, env.cli, keyEntry(d, dpin))
	res, err := env.add(t, d, nil)
	if err != nil || !res.Switched || res.Cert.state != certCanEnable {
		t.Fatalf("%+v, %v; want it switched after a reload", res, err)
	}
	if n := f.reloadCount(); n != 1 {
		t.Errorf("%d reloads, want 1", n)
	}
	if readBytes(t, af) != acc {
		t.Error("the access file was rewritten")
	}
	// Run again: the daemon now has the pin, so nothing more.
	if res, err = env.add(t, d, nil); err != nil || res.Cert.state != certWorks || f.reloadCount() != 1 {
		t.Errorf("again: %+v, %v, %d reloads", res, err, f.reloadCount())
	}
}

// Between config add's read of the daemon config and its write, the config
// may come to name another access file: the enrollment is not made in the
// old one.
func TestAddRechecksTheAccessFileBinding(t *testing.T) {
	env := newAddEnv(t)
	env.pin(t)
	d, _ := env.certDaemon(t, env.dir, "")
	info, err := ReadDaemonApi(d, "")
	if err != nil {
		t.Fatal(err)
	}
	c := planCert(AddOptions{CliConfig: env.cli}, info, "auth")
	if c.state != certCanEnable || !c.nameIt {
		t.Fatalf("plan %+v", c)
	}
	other := filepath.Join(env.dir, "other-access.yaml")
	moved := withAccessLine(readBytes(t, d), other)
	writeFile(t, d, moved)
	if err := c.apply(nil); err == nil || !strings.Contains(err.Error(), "now names") {
		t.Errorf("err = %v, want a refusal saying the binding changed", err)
	}
	if _, err := os.Stat(accessFileOf(d)); err == nil {
		t.Error("the planned access file was written")
	}
	if readBytes(t, d) != moved {
		t.Error("the daemon config was changed")
	}
}

// A daemon that starts after config add found none, but before the files
// are written, read the old ones: it is reloaded and checked like one that
// was running.
func TestAddReloadsADaemonThatStartedMeanwhile(t *testing.T) {
	env := newAddEnv(t)
	env.pin(t)
	d, _ := env.certDaemon(t, env.dir, "")
	info, _ := ReadDaemonApi(d, "")
	c := planCert(AddOptions{CliConfig: env.cli}, info, "auth")
	if c.state != certCanEnable || c.running {
		t.Fatalf("plan %+v", c)
	}
	f := serveFakeDaemon(t, env.socket(), d, accessFileOf(d))
	if err := c.apply(nil); err != nil {
		t.Fatal(err)
	}
	if !c.running || f.reloadCount() != 1 || c.reloaded == "" {
		t.Errorf("running %v, %d reloads, reply %q; want it reloaded", c.running, f.reloadCount(), c.reloaded)
	}
}

// A reload that does not put the pin in force is undone in the daemon too:
// the files put back, and the daemon reloaded again so it runs them.
func TestAddRollbackReloadsTheDaemon(t *testing.T) {
	env := newAddEnv(t)
	d, _ := env.certDaemon(t, env.dir, "")
	f := serveFakeDaemon(t, env.socket(), d, accessFileOf(d))
	f.forget = true
	_, err := env.add(t, d, nil)
	if err == nil || !strings.Contains(err.Error(), "the files are as they were, and the daemon runs them again") {
		t.Errorf("err = %v, want the files and the daemon put back", err)
	}
	if n := f.reloadCount(); n != 2 {
		t.Errorf("%d reloads, want 2 (the edit, and its undo)", n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy != nil {
		t.Errorf("the daemon still runs a policy: %+v", f.policy)
	}
}

// When the CLI config cannot be written after the daemon's side was set up,
// the daemon's side is put back too: no access policy for an entry that does
// not exist.
func TestAddRollsBackWhenTheCliConfigCannotBeWritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	env := newAddEnv(t)
	env.pin(t)
	d, _ := env.certDaemon(t, env.dir, "")
	orig := readBytes(t, d)
	cliDir := filepath.Join(env.dir, "cli")
	os.Mkdir(cliDir, 0o755)
	env.cli = filepath.Join(cliDir, "tdns-ncli.yaml")
	// The lock file is there, so the add gets as far as its write.
	unlock, err := lockCliConfig(context.Background(), env.cli)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	os.Chmod(cliDir, 0o555)
	t.Cleanup(func() { os.Chmod(cliDir, 0o755) })

	_, err = env.add(t, d, nil)
	if err == nil || !strings.Contains(err.Error(), "On the daemon's side, the files are as they were") {
		t.Errorf("err = %v, want the daemon's side put back", err)
	}
	if readBytes(t, d) != orig {
		t.Error("the daemon config was not put back")
	}
	if _, err := os.Stat(accessFileOf(d)); err == nil {
		t.Error("the access file was not removed")
	}
}

// clientCommandsFor makes the `client` commands of role auth edit daemon
// config d, as on the daemon's host: the role's entry names d. Its address
// is port 1, where nothing listens, so an edit's check of the running daemon
// finds none.
func clientCommandsFor(t *testing.T, d string) {
	t.Helper()
	RegisterRole("auth", "tdns-auth")
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })
	apiConfig = &CliConf{ApiServers: []ApiDetails{{Name: "tdns-auth", BaseURL: "https://127.0.0.1:1/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", ConfigFile: d}}}
	if err := InitApiClients(apiConfig); err != nil {
		t.Fatal(err)
	}
}

// appliedCert is a config add whose apply enrolled the pin in an access file
// that was there (anna in it) and named it in the daemon config: both files
// written, a rollback still to come.
type appliedCert struct {
	c          *CertSetup
	d, af      string
	cfg, acc   string // the daemon config and the access file before apply
	accApplied string // the access file as apply wrote it
}

func applyForRollback(t *testing.T) appliedCert {
	t.Helper()
	env := newAddEnv(t)
	env.pin(t)
	d, _ := env.certDaemon(t, env.dir, "")
	a := appliedCert{d: d, af: accessFileOf(d), cfg: readBytes(t, d),
		acc: "keyauth: true\nclients:\n   - name: anna\n     pin: " + pinOf("anna") + "\n     role: read-only\n"}
	writeFile(t, a.af, a.acc)
	info, err := ReadDaemonApi(d, "")
	if err != nil {
		t.Fatal(err)
	}
	a.c = planCert(AddOptions{CliConfig: env.cli}, info, "auth")
	if a.c.state != certCanEnable || !a.c.nameIt || !a.c.addPin {
		t.Fatalf("plan %+v", a.c)
	}
	if err := a.c.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(a.c.undo) != 2 || readBytes(t, d) == a.cfg {
		t.Fatalf("apply did not write both files: %+v", a.c.undo)
	}
	a.accApplied = readBytes(t, a.af)
	clientCommandsFor(t, d)
	return a
}

// rollback compares each file with what apply wrote and puts it back as one
// step, under the locks apply takes: the access file's, which the `client`
// edits take, and the daemon config's. An edit that comes between the
// compare and the restore waits for the lock, and is then made on the file
// put back: neither change is lost. A file changed before the compare is
// left as it is. Apply's own rollback runs under the locks apply holds,
// without taking them again (which would wait for itself).
func TestRollbackHoldsTheFileLocks(t *testing.T) {
	t.Run("an edit between compare and restore waits, and is kept", func(t *testing.T) {
		a := applyForRollback(t)
		var restored []string
		var done chan struct{}
		var editErr error
		testHookRollbackRestore = func(path string) {
			restored = append(restored, path)
			switch path {
			case a.d:
				// Another add, which would write access-file: here,
				// waits for the daemon config's lock.
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				if unlock, err := lockCliConfig(ctx, a.d); err == nil {
					unlock()
					t.Error("the daemon config's lock is free between rollback's compare and its restore")
				}
			case a.af:
				done = make(chan struct{})
				go func() {
					defer close(done)
					editErr = editAccessFile(context.Background(), "auth", accessEditOpts{NoReload: true}, true, func(af *tdns.AccessFile) (string, error) {
						af.Clients = append(af.Clients, tdns.AccessClient{Name: "late", Pin: pinOf("late"), Role: "read-only"})
						return "added late", nil
					})
				}()
				select {
				case <-done:
					t.Errorf("the client edit did not wait for rollback's lock (err %v)", editErr)
				case <-time.After(300 * time.Millisecond):
				}
				if got := readBytes(t, a.af); got != a.accApplied {
					t.Errorf("the access file changed between rollback's compare and its restore:\n%s", got)
				}
			}
		}
		t.Cleanup(func() { testHookRollbackRestore = nil })
		msg := a.c.rollback(context.Background())
		testHookRollbackRestore = nil
		if !reflect.DeepEqual(restored, []string{a.d, a.af}) {
			t.Fatalf("rollback put back %v, want %s, then %s", restored, a.d, a.af)
		}
		<-done
		if editErr != nil {
			t.Fatalf("the client edit, once rollback let go: %v", editErr)
		}
		if msg != "the files are as they were" {
			t.Errorf("rollback says %q", msg)
		}
		if readBytes(t, a.d) != a.cfg {
			t.Errorf("the daemon config was not put back:\n%s", readBytes(t, a.d))
		}
		// The edit was made on the file put back: its .prev is that file,
		// and the result is anna and late, without the pin apply enrolled.
		if prev := readBytes(t, a.af+".prev"); prev != a.acc {
			t.Errorf("the edit read %q, want the file put back", prev)
		}
		acc, err := tdns.LoadAccessFile(a.af)
		if err != nil || len(acc.Clients) != 2 || acc.Clients[0].Name != "anna" || acc.Clients[1].Name != "late" {
			t.Errorf("access file %+v (%v), want anna, then late", acc, err)
		}
	})

	t.Run("a file changed before the compare is left as it is", func(t *testing.T) {
		a := applyForRollback(t)
		if err := editAccessFile(context.Background(), "auth", accessEditOpts{NoReload: true}, false, func(af *tdns.AccessFile) (string, error) {
			af.Clients = append(af.Clients, tdns.AccessClient{Name: "early", Pin: pinOf("early"), Role: "read-only"})
			return "added early", nil
		}); err != nil {
			t.Fatal(err)
		}
		edited := readBytes(t, a.af)
		var restored []string
		testHookRollbackRestore = func(path string) { restored = append(restored, path) }
		t.Cleanup(func() { testHookRollbackRestore = nil })
		msg := a.c.rollback(context.Background())
		testHookRollbackRestore = nil
		if !reflect.DeepEqual(restored, []string{a.d}) {
			t.Errorf("rollback went on to put back %v, want only %s", restored, a.d)
		}
		if readBytes(t, a.af) != edited {
			t.Errorf("rollback overwrote the access file changed since apply:\n%s", readBytes(t, a.af))
		}
		if !strings.Contains(msg, "except "+a.af+", changed since config add wrote it, and left as it is") {
			t.Errorf("rollback says %q", msg)
		}
		if readBytes(t, a.d) != a.cfg {
			t.Error("the daemon config was not put back")
		}
	})

	t.Run("apply's own rollback: under the locks it holds, taken once", func(t *testing.T) {
		env := newAddEnv(t)
		env.pin(t)
		d, _ := env.certDaemon(t, env.dir, "")
		cfg := readBytes(t, d)
		f := serveFakeDaemon(t, env.socket(), d, accessFileOf(d))
		f.mu.Lock()
		f.forget = true // the reload leaves the pin out: apply fails after both writes
		f.mu.Unlock()
		info, err := ReadDaemonApi(d, "")
		if err != nil {
			t.Fatal(err)
		}
		c := planCert(AddOptions{CliConfig: env.cli}, info, "auth")
		if c.state != certCanEnable || !c.nameIt {
			t.Fatalf("plan %+v", c)
		}
		var held []string
		testHookRollbackRestore = func(path string) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if unlock, err := lockCliConfig(ctx, path); err == nil {
				unlock()
				return
			}
			held = append(held, path)
		}
		t.Cleanup(func() { testHookRollbackRestore = nil })
		done := make(chan error, 1)
		go func() { done <- c.apply(context.Background()) }()
		select {
		case err = <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("apply hangs: its rollback waits for the locks apply holds")
		}
		if err == nil || !strings.Contains(err.Error(), "does not have your certificate") || !strings.Contains(err.Error(), "the files are as they were") {
			t.Errorf("err = %v, want the failure and the files put back", err)
		}
		if want := []string{d, accessFileOf(d)}; !reflect.DeepEqual(held, want) {
			t.Errorf("files put back with their lock held: %v, want %v", held, want)
		}
		if readBytes(t, d) != cfg {
			t.Error("the daemon config was not put back")
		}
		if _, err := os.Stat(accessFileOf(d)); err == nil {
			t.Error("the new access file was not removed")
		}
	})
}

// A socket that answers for another daemon config is not this daemon, told
// apart from a socket config add may not open (asked over TCP then): neither
// that daemon nor the access file is taken, though the file lists your pin.
// A key entry keeps its key, saying the daemon could not be told, and is not
// switched to the certificate; a new entry is refused. Nothing is written,
// and nothing reloaded.
func TestAddSocketRunningAnotherConfig(t *testing.T) {
	type world struct {
		env         *addEnv
		d, dpin, af string
		cfg, acc    string
		f           *fakeSocketDaemon
	}
	setup := func(t *testing.T) world {
		env := newAddEnv(t)
		w := world{env: env, af: filepath.Join(env.dir, "access.yaml")}
		w.acc = "keyauth: true\nclients:\n   - name: laptop\n     pin: " + env.pin(t) + "\n     role: read-write\n"
		writeFile(t, w.af, w.acc)
		w.d, w.dpin = env.certDaemon(t, env.dir, "\n   access-file: "+w.af)
		w.cfg = readBytes(t, w.d)
		w.f = serveFakeDaemon(t, env.socket(), w.d, w.af)
		w.f.mu.Lock()
		w.f.runs = "/etc/tdns/other.yaml"
		w.f.mu.Unlock()
		return w
	}
	unchanged := func(t *testing.T, w world) {
		t.Helper()
		if readBytes(t, w.af) != w.acc || readBytes(t, w.d) != w.cfg {
			t.Error("the access file or the daemon config changed")
		}
		if n := w.f.reloadCount(); n != 0 {
			t.Errorf("%d reloads sent to the other daemon", n)
		}
	}

	t.Run("a key entry: kept, not switched", func(t *testing.T) {
		w := setup(t)
		writeFile(t, w.env.cli, keyEntry(w.d, w.dpin))
		res, err := w.env.add(t, w.d, nil)
		if err != nil || !res.KeyKept || res.Switched || res.Cert == nil || res.Cert.state != certCannot || res.Cert.listedAs != "" {
			t.Fatalf("%+v, %v; want the key kept, the certificate not taken", res, err)
		}
		if readBytes(t, w.env.cli) != keyEntry(w.d, w.dpin) {
			t.Errorf("the CLI config changed:\n%s", readBytes(t, w.env.cli))
		}
		if notes := strings.Join(res.Notes, " "); !strings.Contains(notes, "could not be told") || !strings.Contains(notes, "runs /etc/tdns/other.yaml") {
			t.Errorf("notes %q, want the key's acceptance not told, for the other config", notes)
		}
		if out := printed(res, false, w.env.cli); !strings.Contains(out, "keeps the API key") || !strings.Contains(out, "runs /etc/tdns/other.yaml") || strings.Contains(out, "lists your certificate") {
			t.Errorf("printed:\n%s", out)
		}
		unchanged(t, w)
	})

	t.Run("a new entry: refused", func(t *testing.T) {
		w := setup(t)
		_, err := w.env.add(t, w.d, nil)
		var r addRefusal
		if !errors.As(err, &r) || !strings.Contains(err.Error(), "runs /etc/tdns/other.yaml") || strings.Contains(err.Error(), "lists your certificate") {
			t.Errorf("err = %v, want a refusal naming the other config", err)
		}
		if _, err := os.Stat(w.env.cli); err == nil {
			t.Error("the refused add wrote the CLI config")
		}
		unchanged(t, w)
	})

	// The fix is about the daemon that answers, naming both configs, not
	// the enrolment (there is no name or pin to give it, and enrolling does
	// not help while another daemon answers): the dry run and the add alike.
	fixFor := func(w world) []string {
		return []string{
			"stop the daemon that runs /etc/tdns/other.yaml,",
			"or give /etc/tdns/other.yaml and " + w.d,
			"their own admin socket and API addresses",
			"(apiserver.socket, apiserver.addresses);",
			"then run config add again.",
		}
	}
	noEnrol := func(t *testing.T, out string) {
		t.Helper()
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "client add ''") || strings.Contains(l, "<your pin>") || strings.Contains(l, "client add") {
				t.Errorf("printed the enrolment: %q", l)
			}
		}
	}
	for _, dry := range []bool{true, false} {
		t.Run(fmt.Sprintf("a key entry, dry run %v: the fix", dry), func(t *testing.T) {
			w := setup(t)
			writeFile(t, w.env.cli, keyEntry(w.d, w.dpin))
			res, err := w.env.add(t, w.d, func(o *AddOptions) { o.DryRun = dry })
			if err != nil || res.Cert == nil {
				t.Fatalf("%+v, %v", res, err)
			}
			want := fixFor(w)
			if got := res.Cert.fixLines(); !reflect.DeepEqual(got, want) {
				t.Errorf("fix:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			var sb strings.Builder
			printAddResult(&sb, res, dry, w.env.cli)
			out := sb.String()
			if !strings.Contains(flat(out), "To use the certificate instead, "+flat(strings.Join(want, " "))) {
				t.Errorf("printed:\n%s", out)
			}
			noEnrol(t, out)
			unchanged(t, w)
		})
		t.Run(fmt.Sprintf("a new entry, dry run %v: the fix", dry), func(t *testing.T) {
			w := setup(t)
			_, err := w.env.add(t, w.d, func(o *AddOptions) { o.DryRun = dry })
			var r addRefusal
			if !errors.As(err, &r) {
				t.Fatalf("err = %v, want a refusal", err)
			}
			if want := fixFor(w); !reflect.DeepEqual(r.fix, want) {
				t.Errorf("fix:\n%s\nwant:\n%s", strings.Join(r.fix, "\n"), strings.Join(want, "\n"))
			}
			var sb strings.Builder
			printRefusal(&sb, r)
			noEnrol(t, sb.String())
			unchanged(t, w)
		})
	}
}

// A daemon on the socket that is not told to be this one for another reason
// gets a fix about that too; and a dry run before your pair exists names no
// pin it does not have.
func TestCertFixLinesUnidentifiedAndNoPin(t *testing.T) {
	tg := &accessTarget{DaemonConfig: "/etc/tdns/tdns-auth.yaml", File: "/etc/tdns/tdns-auth-access.yaml", Socket: "/var/run/tdns-auth.sock", Configured: true}
	for _, tc := range []struct {
		name string
		c    *CertSetup
		want []string
	}{
		{
			name: "it does not say which config it runs",
			c:    &CertSetup{word: "auth", state: certCannot, t: tg, unidentified: true, other: &otherConfigError{want: tg.DaemonConfig}},
			want: []string{
				"stop the daemon that answers on /var/run/tdns-auth.sock if it does",
				"not run /etc/tdns/tdns-auth.yaml, or give the two configs their own",
				"admin socket and API addresses; if it does, upgrade it so it",
				"says which config it runs; then run config add again.",
			},
		},
		{
			name: "it cannot be asked",
			c:    &CertSetup{word: "auth", state: certCannot, t: tg, unidentified: true},
			want: []string{
				"fix what stops the daemon on /var/run/tdns-auth.sock saying",
				"which config it runs (the error says what);",
				"then run config add again.",
			},
		},
		{
			name: "a dry run before your pair exists",
			c:    &CertSetup{word: "auth", name: "ops-laptop", state: certCannot, t: tg, pairNew: true},
			want: []string{
				"your client certificate does not exist yet, so it has no pin",
				"to enrol; config add makes it when run without --dry-run,",
				"and then says how to enrol it.",
			},
		},
	} {
		if got := tc.c.fixLines(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s; fix:\n%s\nwant:\n%s", tc.name, strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
		}
	}
}

// When the daemon's socket cannot be used, a request through the role's entry
// names the daemon config it is for, so a daemon that runs another refuses it
// before acting on it.
func TestConfigToDaemonFallbackNamesTheConfig(t *testing.T) {
	got := make(chan string, 4)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get(tdns.ExpectConfigFileHeader)
		json.NewEncoder(w).Encode(tdns.ConfigResponse{})
	}))
	defer srv.Close()
	e := newAccessEnv(t, true, srv.URL+"/api/v1")
	apiConfig.ApiServers[0].TLSAuth = "pin"
	apiConfig.ApiServers[0].Pins = []string{tdns.SPKISHA256(srv.Certificate())}
	if err := InitApiClients(apiConfig); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "ncli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	absent := filepath.Join(dir, "absent.sock")
	if _, err := configToDaemon("auth", absent, e.daemonCfg, tdns.ConfigPost{Command: "reload"}); err != nil {
		t.Fatal(err)
	}
	if h := <-got; h != e.daemonCfg {
		t.Errorf("the request named %q, want %s", h, e.daemonCfg)
	}
	// The role's client itself is unchanged.
	api, _ := GetApiClient("auth", false)
	if _, err := SendConfigCommand(api, tdns.ConfigPost{Command: "status"}); err != nil {
		t.Fatal(err)
	}
	if h := <-got; h != "" {
		t.Errorf("the role's own client now names %q", h)
	}
}

// A dry run writes nothing, not even a probe: it predicts the access file's
// edit in a directory it could not write, and says that is found out when
// config add runs. Its prediction of a new pair matches what the add does: a
// key without its certificate is refused, as ensureClientCert refuses it.
func TestAddDryRunProbesNothing(t *testing.T) {
	env := newAddEnv(t)
	pin := env.pin(t)
	certBefore, keyBefore := readBytes(t, env.cert), readBytes(t, env.key)
	dir := readOnlyDaemonDir(t, env)
	d, _ := env.certDaemon(t, dir, "")
	os.Chmod(dir, 0o555)
	res, err := env.add(t, d, func(o *AddOptions) { o.DryRun = true })
	if err != nil || res.Cert.state != certCanEnable {
		t.Fatalf("%+v, %v; want the edit predicted", res, err)
	}
	// The pair that is there is read, not made again (not through
	// ensureClientCert, which makes one if the certificate went meanwhile).
	if res.Cert.pin != pin || res.Cert.pairNew || readBytes(t, env.cert) != certBefore || readBytes(t, env.key) != keyBefore {
		t.Errorf("the dry run did not read your pair as it is: pin %q (want %q), new %v", res.Cert.pin, pin, res.Cert.pairNew)
	}
	if out := printed(res, true, env.cli); !strings.Contains(out, "found out when it runs") {
		t.Errorf("printed:\n%s", out)
	}

	env2 := newAddEnv(t)
	d2, _ := env2.certDaemon(t, env2.dir, "")
	os.MkdirAll(filepath.Dir(env2.key), 0o700)
	writeFile(t, env2.key, "a key without its certificate\n")
	if _, err := env2.add(t, d2, func(o *AddOptions) { o.DryRun = true }); err == nil || !strings.Contains(err.Error(), clientKeyWithoutCertError(env2.cert, env2.key).Error()) {
		t.Errorf("dry run, an orphan key: err = %v, want the refusal the add gives", err)
	}
	if _, err := os.Stat(env2.cert); err == nil {
		t.Error("the dry run made a certificate")
	}
}

// The advice is a command that runs as printed: a client name with a space
// is quoted; and a pin already listed is not enrolled again.
func TestCertFixLines(t *testing.T) {
	tg := &accessTarget{DaemonConfig: "/etc/tdns/tdns-auth.yaml", File: "/etc/tdns/tdns-auth-access.yaml"}
	c := &CertSetup{word: "auth", listedAs: "Ops Laptop", state: certDisabled, t: tg}
	if fix := strings.Join(c.fixLines(), "\n"); !strings.Contains(fix, "client enable 'Ops Laptop'") {
		t.Errorf("fix:\n%s", fix)
	}
	c = &CertSetup{word: "auth", listedAs: "laptop", pin: pinOf("p"), state: certCannot, t: tg}
	fix := strings.Join(c.fixLines(), "\n")
	if strings.Contains(fix, "client add") || !strings.Contains(fix, "access-file: "+tg.File) {
		t.Errorf("a listed pin, the file not named; fix:\n%s", fix)
	}
	tg.Configured = true
	if fix := strings.Join(c.fixLines(), "\n"); strings.Contains(fix, "client add") || !strings.Contains(fix, "tdns-ncli auth config reload") {
		t.Errorf("a listed pin, the file named; fix:\n%s", fix)
	}
}

// When the operator's own pair cannot be used there is no pin, so the fix is
// not the enrolment (client add --pin): it is to put the pair right, or to
// remove it so config add makes a new one, with the paths named. The dry run
// and the add say the same.
func TestAddOwnPairUnusableFix(t *testing.T) {
	keyOnly := func(cert, key string) []string {
		return []string{
			"put back your certificate " + cert + ",",
			"or remove your key " + key + " so config add makes a new pair;",
			"then run config add again.",
		}
	}
	noMatch := func(cert, key string) []string {
		return []string{
			"make your certificate " + cert + " and your key " + key + " one pair again,",
			"or remove both so config add makes a new pair;",
			"then run config add again.",
		}
	}
	badCert := func(cert, key string) []string {
		return []string{
			"fix your certificate " + cert + " so it can be read,",
			"or remove it and your key " + key + " so config add makes a new pair;",
			"then run config add again.",
		}
	}
	for _, tc := range []struct {
		name    string
		notRoot bool // root reads anything
		setup   func(t *testing.T, env *addEnv)
		want    func(cert, key string) []string
		whyHas  string
	}{
		{
			name: "a key without its certificate",
			setup: func(t *testing.T, env *addEnv) {
				os.MkdirAll(filepath.Dir(env.key), 0o700)
				writeFile(t, env.key, "a key without its certificate\n")
			},
			want: keyOnly, whyHas: "without its certificate",
		},
		{
			name: "a certificate with another pair's key",
			setup: func(t *testing.T, env *addEnv) {
				env.pin(t)
				other := filepath.Join(env.dir, "other")
				if _, _, err := ensureClientCert(filepath.Join(other, "o.crt"), filepath.Join(other, "o.key"), "otto"); err != nil {
					t.Fatal(err)
				}
				writeFile(t, env.key, readBytes(t, filepath.Join(other, "o.key")))
			},
			want: noMatch, whyHas: "not a usable pair",
		},
		{
			name: "a certificate without its key",
			setup: func(t *testing.T, env *addEnv) {
				env.pin(t)
				os.Remove(env.key)
			},
			want: noMatch, whyHas: "not a usable pair",
		},
		{
			name:    "an unreadable certificate",
			notRoot: true,
			setup: func(t *testing.T, env *addEnv) {
				env.pin(t)
				os.Chmod(env.cert, 0)
			},
			want: badCert, whyHas: "permission denied",
		},
	} {
		for _, dry := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, dry run %v", tc.name, dry), func(t *testing.T) {
				if tc.notRoot && os.Geteuid() == 0 {
					t.Skip("root reads anything")
				}
				env := newAddEnv(t)
				d, _ := env.certDaemon(t, env.dir, "")
				tc.setup(t, env)
				res, err := env.add(t, d, func(o *AddOptions) { o.DryRun = dry })
				var r addRefusal
				if !errors.As(err, &r) {
					t.Fatalf("%+v, %v; want a refusal", res, err)
				}
				if want := tc.want(env.cert, env.key); !reflect.DeepEqual(r.fix, want) {
					t.Errorf("fix:\n%s\nwant:\n%s", strings.Join(r.fix, "\n"), strings.Join(want, "\n"))
				}
				if !strings.Contains(r.why, tc.whyHas) {
					t.Errorf("why %q, want it to say %q", r.why, tc.whyHas)
				}
				var sb strings.Builder
				printRefusal(&sb, r)
				if out := sb.String(); strings.Contains(out, "client add") || !strings.Contains(out, "  Fix: ") {
					t.Errorf("printed:\n%s", out)
				}
				if _, err := os.Stat(accessFileOf(d)); err == nil {
					t.Error("an access file was written")
				}
			})
		}
	}
}

// The fix for the operator's pair names it, whatever else the setup says;
// any other pair trouble (the error says what) is not the enrolment either.
func TestCertFixLinesOwnPair(t *testing.T) {
	tg := &accessTarget{DaemonConfig: "/etc/tdns/tdns-auth.yaml", File: "/etc/tdns/tdns-auth-access.yaml"}
	c := &CertSetup{word: "auth", cert: "/root/.config/tdns/client.crt", key: "/root/.config/tdns/client.key", state: certCannot, t: tg, pairProblem: pairOther}
	want := []string{
		"fix what stops config add reading or making your pair,",
		"/root/.config/tdns/client.crt and /root/.config/tdns/client.key (the error says what);",
		"then run config add again.",
	}
	if got := c.fixLines(); !reflect.DeepEqual(got, want) {
		t.Errorf("other pair trouble; fix:\n%s", strings.Join(got, "\n"))
	}
	var sb strings.Builder
	printRefusal(&sb, c.refusal("your client certificate cannot be used (mkdir: permission denied)"))
	wantOut := "Error: your client certificate cannot be used (mkdir: permission\n" +
		"  denied).\n" +
		"  Fix: fix what stops config add reading or making your pair,\n" +
		"       /root/.config/tdns/client.crt and /root/.config/tdns/client.key\n" +
		"       (the error says what); then run config add again.\n"
	if out := sb.String(); out != wantOut {
		t.Errorf("printed:\n%s\nwant:\n%s", out, wantOut)
	}
}

// fakeTCPDaemon is a daemon's TCP API that answers pings: as the access
// file would, a client certificate with the enrolled pin is taken (as
// tester, read-write), the API key when keyTaken, anything else refused
// (403). It asks for client certificates, as the daemon does.
type fakeTCPDaemon struct {
	srv      *httptest.Server
	enrolled string // the pin taken
	keyTaken bool
	certFile string // its certificate, for apiserver.certfile
}

func serveFakeTCPDaemon(t *testing.T, enrolled string, keyTaken bool) *fakeTCPDaemon {
	t.Helper()
	f := &fakeTCPDaemon{enrolled: enrolled, keyTaken: keyTaken}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ping" {
			http.NotFound(w, r)
			return
		}
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if tdns.SPKISHA256(r.TLS.PeerCertificates[0]) == f.enrolled {
				json.NewEncoder(w).Encode(tdns.PingResponse{Msg: "pong", Role: "read-write", Via: "certificate", Identity: "tester"})
				return
			}
			http.Error(w, "unknown client certificate", http.StatusForbidden)
			return
		}
		if r.Header.Get("X-API-Key") == "the-key" && f.keyTaken {
			json.NewEncoder(w).Encode(tdns.PingResponse{Msg: "pong", Role: "read-write", Via: "api key", Identity: "apikey"})
			return
		}
		http.Error(w, "refused", http.StatusForbidden)
	}))
	f.srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.certFile = filepath.Join(t.TempDir(), "api.crt")
	writeFile(t, f.certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})))
	return f
}

// addr is the fake's host:port, for apiserver.addresses.
func (f *fakeTCPDaemon) addr() string { return strings.TrimPrefix(f.srv.URL, "https://") }

// A daemon whose socket a non-root operator cannot open, and whose access
// file it cannot read (0600), is asked over its TCP API, pinned, with the
// client certificate and with the key. An operator whose pin root has enrolled is
// switched to the certificate; a key the daemon takes is kept, and an
// unpinned entry re-pinned; a key it refuses is refused (after the pin is
// written: re-pinning does not wait on the key).
func TestAddAsksTheDaemonOverTCP(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads the access file")
	}
	setup := func(t *testing.T, enrolledSelf, keyTaken bool) (*addEnv, string, *fakeTCPDaemon) {
		env := newAddEnv(t)
		pin := env.pin(t)
		enrolled := pinOf("someone else")
		if enrolledSelf {
			enrolled = pin
		}
		f := serveFakeTCPDaemon(t, enrolled, keyTaken)
		af := filepath.Join(env.dir, "tdns-auth-access.yaml")
		writeFile(t, af, "keyauth: true\nclients: []\n")
		os.Chmod(af, 0)
		// Its local admin socket is there, and not ours to open, as for a
		// non-root operator on the daemon's host.
		ln, err := net.Listen("unix", env.socket())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		os.Chmod(env.socket(), 0)
		d := filepath.Join(env.dir, "tdns-auth.yaml")
		writeFile(t, d, "service:\n   name: TDNS-AUTH\napiserver:\n   addresses: [ "+f.addr()+" ]\n   apikey: the-key\n   certfile: "+f.certFile+"\n   socket: "+env.socket()+"\n   access-file: "+af+"\n")
		return env, d, f
	}
	// An entry with no pin (rootca: insecure), as written before pinning.
	unpinned := func(d, addr string) string {
		return "apiservers:\n   - name: tdns-auth\n     baseurl: https://" + addr + "/api/v1\n     apikey: the-key\n     authmethod: X-API-Key\n     rootca: insecure\n     config-file: " + d + "\n"
	}

	t.Run("enrolled: switched", func(t *testing.T) {
		env, d, f := setup(t, true, true)
		writeFile(t, env.cli, unpinned(d, f.addr()))
		res, err := env.add(t, d, nil)
		if err != nil || !res.Switched || !res.Pinned || !res.Cert.byDaemon {
			t.Fatalf("%+v, %v; want it switched and pinned", res, err)
		}
		got := env.entries(t)[0]
		if got.AuthMethod != "certificate" || got.ApiKey != "" || got.TLSAuth != "pin" {
			t.Errorf("entry %+v", got)
		}
		if out := printed(res, false, env.cli); !strings.Contains(out, "The daemon takes your certificate, as tester (read-write).") {
			t.Errorf("printed:\n%s", out)
		}
		// A new entry too: the loop the rig found (refused, enrolled by root,
		// refused again) is gone.
		env.cli = filepath.Join(env.dir, "new-cli.yaml")
		if res, err := env.add(t, d, nil); err != nil || res.Entry.AuthMethod != "certificate" {
			t.Errorf("new entry: %+v, %v; want a certificate entry", res, err)
		}
	})

	t.Run("not enrolled, the key taken: kept and re-pinned", func(t *testing.T) {
		env, d, f := setup(t, false, true)
		writeFile(t, env.cli, unpinned(d, f.addr()))
		res, err := env.add(t, d, nil)
		if err != nil || !res.KeyKept || !res.Pinned || res.Switched {
			t.Fatalf("%+v, %v; want the key kept and the entry pinned", res, err)
		}
		got := env.entries(t)[0]
		if got.AuthMethod != "X-API-Key" || got.ApiKey != "the-key" || got.TLSAuth != "pin" || len(got.Pins) != 1 || got.RootCA != "" {
			t.Errorf("entry %+v", got)
		}
		// The reason is said once.
		out := printed(res, false, env.cli)
		if n := strings.Count(out, "does not take your certificate"); n != 1 {
			t.Errorf("the reason is said %d times:\n%s", n, out)
		}
	})

	t.Run("not enrolled, the key refused: re-pinned, then refused", func(t *testing.T) {
		env, d, f := setup(t, false, false)
		writeFile(t, env.cli, unpinned(d, f.addr()))
		_, err := env.add(t, d, nil)
		var r addRefusal
		if !errors.As(err, &r) || !strings.Contains(err.Error(), "is re-pinned, but it cannot authenticate") || !strings.Contains(err.Error(), "refuses the key") {
			t.Fatalf("err = %v, want a refusal after the re-pin", err)
		}
		if got := env.entries(t)[0]; got.TLSAuth != "pin" || len(got.Pins) != 1 {
			t.Errorf("entry %+v; want it pinned all the same", got)
		}
	})
}

// --------------------------------------- review round 2 (CodeRabbit, 11-24)

// tcpKeyEntry is a key entry for daemon config d on its TCP address addr,
// pinned to dpin.
func tcpKeyEntry(d, addr, dpin string) string {
	return "apiservers:\n   - name: tdns-auth\n     baseurl: https://" + addr + "/api/v1\n     apikey: the-key\n     authmethod: X-API-Key\n     tlsauth: pin\n     pins: [ \"" + dpin + "\" ]\n     config-file: " + d + "\n"
}

// Nothing on the daemon's local admin socket does not make it a daemon that
// is not running: one started before its config named another socket:
// serves its TCP API all the same, with the policy it loaded, not the one
// on disk. config add asks it over TCP, as when its socket is not ours to
// open; the access file decides only when nothing answers there either. A
// TCP API that neither refuses nor answers leaves the daemon unknown, and
// the file is not taken for its policy.
func TestAddAsksTCPWhenNothingAnswersOnTheSocket(t *testing.T) {
	// The pin is enrolled in the access file on disk; whether the daemon
	// that runs takes it is enrolled (the fake's own policy).
	world := func(t *testing.T, addr, certFile string) (*addEnv, string) {
		env := newAddEnv(t)
		pin := env.pin(t)
		af := filepath.Join(env.dir, "access.yaml")
		writeFile(t, af, "keyauth: true\nclients:\n   - name: tester\n     pin: "+pin+"\n     role: read-write\n")
		d := filepath.Join(env.dir, "tdns-auth.yaml")
		writeFile(t, d, "service:\n   name: TDNS-AUTH\napiserver:\n   addresses: [ "+addr+" ]\n   apikey: the-key\n   certfile: "+certFile+"\n   socket: "+env.socket()+"\n   access-file: "+af+"\n")
		return env, d
	}
	setup := func(t *testing.T, enrolledSelf bool) (*addEnv, string, *fakeTCPDaemon) {
		f := serveFakeTCPDaemon(t, pinOf("someone else"), true)
		env, d := world(t, f.addr(), f.certFile)
		if enrolledSelf {
			f.enrolled = env.pin(t)
		}
		return env, d, f
	}

	t.Run("it runs without the pin: the key kept, a new entry refused", func(t *testing.T) {
		env, d, f := setup(t, false)
		key := tcpKeyEntry(d, f.addr(), tdns.SPKISHA256(f.srv.Certificate()))
		writeFile(t, env.cli, key)
		res, err := env.add(t, d, nil)
		if err != nil || !res.KeyKept || res.Switched || res.Cert.state == certWorks {
			t.Fatalf("%+v, %v; want the key kept, the certificate not taken", res, err)
		}
		if readBytes(t, env.cli) != key {
			t.Errorf("the CLI config changed:\n%s", readBytes(t, env.cli))
		}
		if out := printed(res, false, env.cli); !strings.Contains(out, "does not take it yet") {
			t.Errorf("printed:\n%s", out)
		}
		env.cli = filepath.Join(env.dir, "new-cli.yaml")
		_, err = env.add(t, d, nil)
		var r addRefusal
		if !errors.As(err, &r) || !strings.Contains(err.Error(), "does not take it yet") {
			t.Errorf("new entry: err = %v, want a refusal", err)
		}
		if _, err := os.Stat(env.cli); err == nil {
			t.Error("the refused add wrote the CLI config")
		}
	})

	t.Run("it takes the certificate: switched", func(t *testing.T) {
		env, d, f := setup(t, true)
		writeFile(t, env.cli, tcpKeyEntry(d, f.addr(), tdns.SPKISHA256(f.srv.Certificate())))
		res, err := env.add(t, d, nil)
		if err != nil || !res.Switched || !res.Cert.byDaemon {
			t.Fatalf("%+v, %v; want it switched, as the daemon said", res, err)
		}
	})

	t.Run("TCP neither refuses nor answers: not taken for stopped", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()
		srv := httptest.NewTLSServer(http.NotFoundHandler()) // only for a certificate
		srv.Close()
		certFile := filepath.Join(t.TempDir(), "api.crt")
		writeFile(t, certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
		env, d := world(t, ln.Addr().String(), certFile)
		key := tcpKeyEntry(d, ln.Addr().String(), tdns.SPKISHA256(srv.Certificate()))
		writeFile(t, env.cli, key)
		res, err := env.add(t, d, nil)
		if err != nil || !res.KeyKept || res.Switched || !strings.Contains(strings.Join(res.Notes, " "), "could not be told") {
			t.Fatalf("%+v, %v; want the key kept, its acceptance not told", res, err)
		}
		if readBytes(t, env.cli) != key {
			t.Errorf("the CLI config changed:\n%s", readBytes(t, env.cli))
		}
		env.cli = filepath.Join(env.dir, "new-cli.yaml")
		if _, err := env.add(t, d, nil); err == nil || !strings.Contains(err.Error(), "cannot be asked") {
			t.Errorf("new entry: err = %v, want a refusal: the daemon cannot be asked", err)
		}
	})
}

// When a reload config add sent does not put the pin in force, the rollback
// reloads the daemon with the files put back, and they may turn the key off:
// a keyauth: false in the access file that was not yet in force when config
// add asked. The key entry keeps the key only if the daemon takes it after
// that, which is asked again; here it does not, so it is refused.
func TestAddRechecksTheKeyAfterAFailedReload(t *testing.T) {
	env := newAddEnv(t)
	env.pin(t)
	af := filepath.Join(env.dir, "access.yaml")
	acc := "keyauth: false\nclients: []\n"
	writeFile(t, af, acc)
	d, dpin := env.certDaemon(t, env.dir, "\n   access-file: "+af)
	f := serveFakeDaemon(t, env.socket(), d, af)
	f.mu.Lock()
	// It runs the policy from before the file turned the key off, and its
	// reload leaves the pin out.
	f.policy = &tdns.ApiAccessStatus{File: af, KeyAuth: true, Clients: []tdns.ApiAccessStatusClient{}}
	f.forget = true
	f.mu.Unlock()
	writeFile(t, env.cli, keyEntry(d, dpin))

	_, err := env.add(t, d, nil)
	var r addRefusal
	if !errors.As(err, &r) || !strings.Contains(err.Error(), "cannot authenticate") || !strings.Contains(err.Error(), "keyauth: false") {
		t.Errorf("err = %v, want the key entry refused: the daemon now runs keyauth: false", err)
	}
	if readBytes(t, env.cli) != keyEntry(d, dpin) {
		t.Errorf("the CLI config changed:\n%s", readBytes(t, env.cli))
	}
	if readBytes(t, af) != acc {
		t.Errorf("the access file was not put back:\n%s", readBytes(t, af))
	}
	if n := f.reloadCount(); n != 2 {
		t.Errorf("%d reloads, want 2 (the edit, and its undo)", n)
	}
}

// accessWithAdmin is an access file that lists pin, enabled, beside a
// client the daemon refuses (admin is the local socket's alone): the daemon
// would not load it, so the pin in it does not work.
func accessWithAdmin(pin string) string {
	return "keyauth: true\nclients:\n   - name: tester\n     pin: " + pin + "\n     role: read-write\n" +
		"   - name: root-laptop\n     pin: " + pinOf("root") + "\n     role: admin\n"
}

// A pin listed in an access file the daemon would not load is not taken to
// work: with the daemon not running, a new entry is refused and a key entry
// too (its next start closes the TCP API, so the key does not work either);
// and apply, which finds the pin listed, does not name such a file in the
// daemon config.
func TestAddValidatesTheAccessFileItReliesOn(t *testing.T) {
	t.Run("the daemon not running: refused", func(t *testing.T) {
		env := newAddEnv(t)
		pin := env.pin(t)
		af := filepath.Join(env.dir, "access.yaml")
		writeFile(t, af, accessWithAdmin(pin))
		d, dpin := env.certDaemon(t, env.dir, "\n   access-file: "+af)
		_, err := env.add(t, d, nil)
		var r addRefusal
		if !errors.As(err, &r) || !strings.Contains(err.Error(), "not an access file the daemon would load") || !strings.Contains(err.Error(), `role "admin"`) {
			t.Fatalf("new entry: err = %v, want a refusal naming the file and why", err)
		}
		want := []string{"fix " + af + " so the daemon would load it", "(the error says what), then run config add again."}
		if !reflect.DeepEqual(r.fix, want) {
			t.Errorf("fix:\n%s\nwant:\n%s", strings.Join(r.fix, "\n"), strings.Join(want, "\n"))
		}
		if _, err := os.Stat(env.cli); err == nil {
			t.Error("the refused add wrote the CLI config")
		}
		writeFile(t, env.cli, keyEntry(d, dpin))
		if _, err := env.add(t, d, nil); !errors.As(err, &r) || !strings.Contains(err.Error(), "cannot authenticate") || !strings.Contains(err.Error(), "closes its TCP API") {
			t.Errorf("key entry: err = %v, want it refused", err)
		}
		if readBytes(t, env.cli) != keyEntry(d, dpin) || readBytes(t, af) != accessWithAdmin(pin) {
			t.Error("a file changed")
		}
	})

	t.Run("apply: the file lists the pin, and does not validate", func(t *testing.T) {
		env := newAddEnv(t)
		pin := env.pin(t)
		d, _ := env.certDaemon(t, env.dir, "")
		af := accessFileOf(d)
		writeFile(t, af, "keyauth: true\nclients:\n   - name: tester\n     pin: "+pin+"\n     role: read-write\n")
		cfg := readBytes(t, d)
		info, err := ReadDaemonApi(d, "")
		if err != nil {
			t.Fatal(err)
		}
		c := planCert(AddOptions{CliConfig: env.cli}, info, "auth")
		if c.state != certCanEnable || !c.nameIt || c.addPin {
			t.Fatalf("plan %+v", c)
		}
		writeFile(t, af, accessWithAdmin(pin))
		if err := c.apply(context.Background()); err == nil || !strings.Contains(err.Error(), "not an access file the daemon would load") {
			t.Errorf("err = %v, want apply refused", err)
		}
		if readBytes(t, d) != cfg {
			t.Errorf("the daemon config was changed:\n%s", readBytes(t, d))
		}
	})
}
