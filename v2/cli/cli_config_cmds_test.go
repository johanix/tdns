package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
		{"127.0.0.1", true, "", true}, // no port
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
	if len(entries) != 3 || entries[2] != newEntry() {
		t.Errorf("parsed %d entries, last = %+v", len(entries), entries[len(entries)-1])
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
			if e := parseApiservers(t, string(out)); len(e) != 1 || e[0] != newEntry() {
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

// ------------------------------------------------------------- daemon config

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func daemonYAML(service, addr, key string, extra string) string {
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

type addEnv struct {
	dir, cli string
}

func newAddEnv(t *testing.T) *addEnv {
	t.Helper()
	withCleanRoleRegistry(t)
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
	want := ApiDetails{
		Name: "auth2", Role: "auth", BaseURL: "https://127.0.0.1:8990/api/v1",
		ApiKey: "key-tdns-auth2.yaml", AuthMethod: "X-API-Key", ConfigFile: second,
	}
	if got[1] != want {
		t.Errorf("entry = %+v\nwant    %+v", got[1], want)
	}
	if got[0].ConfigFile != first {
		t.Errorf("canonical entry lost its config-file: %+v", got[0])
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
	// And what it would print does not carry the key.
	var sb strings.Builder
	printAddResult(&sb, res, true)
	if strings.Contains(sb.String(), "key-tdns-auth2.yaml") {
		t.Errorf("the API key was printed:\n%s", sb.String())
	}
	if !strings.Contains(sb.String(), "********") {
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

	_, err := env.add(t, d, nil)
	if err == nil || !strings.Contains(err.Error(), "--file") || !strings.Contains(err.Error(), "undone") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(env.cli); string(b) != mainCfg {
		t.Errorf("the main file was not restored:\n%s", b)
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
	var gotKey string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ping" {
			http.NotFound(w, r)
			return
		}
		gotKey = r.Header.Get("X-API-Key")
		json.NewEncoder(w).Encode(tdns.PingResponse{
			Msg: "pong", Version: "v-test", BootTime: time.Now().Add(-90 * time.Minute), Pings: 1, Pongs: 1,
		})
	}))
	defer srv.Close()

	entries := []ApiDetails{
		{Name: "up", BaseURL: srv.URL + "/api/v1", ApiKey: "sekret", AuthMethod: "X-API-Key"},
		{Name: "down", BaseURL: "https://127.0.0.1:1/api/v1", ApiKey: "k", AuthMethod: "X-API-Key"},
		{Name: "badca", BaseURL: srv.URL + "/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: "/nonexistent/ca.pem"},
		{Name: "tlsa", BaseURL: srv.URL + "/api/v1", ApiKey: "k", AuthMethod: "X-API-Key", RootCA: "tlsa"},
	}
	res := CheckEntries(entries, 5*time.Second)

	if !strings.HasPrefix(res[0], "ok") || !strings.Contains(res[0], "v-test") || !strings.Contains(res[0], "up 1h30m") {
		t.Errorf("up: %q", res[0])
	}
	if gotKey != "sekret" {
		t.Errorf("server saw X-API-Key %q", gotKey)
	}
	if !strings.HasPrefix(res[1], "FAIL") {
		t.Errorf("down: %q", res[1])
	}
	if !strings.HasPrefix(res[2], "FAIL: rootca") {
		t.Errorf("badca: %q", res[2])
	}
	if !strings.HasPrefix(res[3], "not checked") {
		t.Errorf("tlsa: %q", res[3])
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

// A daemon with a local admin socket gets a socket entry when root adds it: no
// key, no TLS, admin. Anyone else, or --tcp, gets the TCP entry.
func TestAddPrefersTheLocalSocketForRoot(t *testing.T) {
	const sock = "/var/run/tdns/tdns-auth.sock"
	setRoot := func(t *testing.T, root bool) {
		saved := runningAsRoot
		t.Cleanup(func() { runningAsRoot = saved })
		runningAsRoot = func() bool { return root }
	}
	withSocket := func(env *addEnv, t *testing.T, file, addr string) string {
		p := filepath.Join(env.dir, file)
		writeFile(t, p, daemonYAML("TDNS-AUTH", addr, "key-"+file, "   socket: "+sock+"\n"))
		return p
	}

	t.Run("root gets the socket", func(t *testing.T) {
		setRoot(t, true)
		env := newAddEnv(t)
		d := withSocket(env, t, "tdns-auth.yaml", "127.0.0.1:8989")
		if _, err := env.add(t, d, nil); err != nil {
			t.Fatal(err)
		}
		want := ApiDetails{Name: "tdns-auth", BaseURL: "unix://" + sock, AuthMethod: "none", ConfigFile: d}
		if got := env.entries(t); len(got) != 1 || got[0] != want {
			t.Errorf("entries = %+v\nwant      [%+v]", got, want)
		}
		raw, _ := os.ReadFile(env.cli)
		if strings.Contains(string(raw), "apikey") {
			t.Errorf("a socket entry should have no apikey line:\n%s", raw)
		}
	})

	t.Run("anyone else gets TCP, with a note", func(t *testing.T) {
		setRoot(t, false)
		env := newAddEnv(t)
		d := withSocket(env, t, "tdns-auth.yaml", "127.0.0.1:8989")
		res, err := env.add(t, d, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Entry.BaseURL != "https://127.0.0.1:8989/api/v1" || res.Entry.ApiKey == "" {
			t.Errorf("entry = %+v, want the TCP one", res.Entry)
		}
		if !strings.Contains(strings.Join(res.Notes, " "), "root-only") {
			t.Errorf("notes = %q, want one saying the socket is root-only", res.Notes)
		}
	})

	t.Run("--tcp as root gets TCP", func(t *testing.T) {
		setRoot(t, true)
		env := newAddEnv(t)
		d := withSocket(env, t, "tdns-auth.yaml", "127.0.0.1:8989")
		res, err := env.add(t, d, func(o *AddOptions) { o.TCP = true })
		if err != nil {
			t.Fatal(err)
		}
		if res.Entry.BaseURL != "https://127.0.0.1:8989/api/v1" || res.Entry.AuthMethod != "X-API-Key" {
			t.Errorf("entry = %+v, want the TCP one", res.Entry)
		}
	})

	t.Run("socket-only daemon needs root", func(t *testing.T) {
		setRoot(t, false)
		env := newAddEnv(t)
		p := filepath.Join(env.dir, "tdns-auth.yaml")
		writeFile(t, p, "service:\n   name: TDNS-AUTH\napiserver:\n   socket: "+sock+"\n")
		if _, err := env.add(t, p, nil); err == nil || !strings.Contains(err.Error(), "only root") {
			t.Errorf("err = %v, want one saying only root can use the socket", err)
		}
	})

	t.Run("an existing TCP entry is the same daemon", func(t *testing.T) {
		setRoot(t, false)
		env := newAddEnv(t)
		d := withSocket(env, t, "tdns-auth.yaml", "127.0.0.1:8989")
		if _, err := env.add(t, d, nil); err != nil { // as non-root: a TCP entry
			t.Fatal(err)
		}
		setRoot(t, true)
		res, err := env.add(t, d, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.AlreadyKnown != "tdns-auth" {
			t.Errorf("AlreadyKnown = %q, want tdns-auth (one daemon, not a second instance)", res.AlreadyKnown)
		}
		if !strings.Contains(strings.Join(res.Notes, " "), "unix://"+sock) {
			t.Errorf("notes = %q, want one saying how to switch to the socket", res.Notes)
		}
		if got := env.entries(t); len(got) != 1 {
			t.Errorf("%d entries, want 1", len(got))
		}
	})
}
