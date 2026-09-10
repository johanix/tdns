/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// dogOptions is the authoritative list of +options dog accepts: every spelling
// ProcessOptions dispatches on, with a sample argument for the ones that take a
// value.
//
// It exists so an option cannot be added without being documented. `+time=`,
// `+tries=`, `+retry=` and `+adflag` were added and appeared in neither `dog -h`
// nor guide/app-dog.md, and the guide separately documented `+OTS`, which dog
// rejects — the option is `+OOTS`. Both failure directions are cheap to catch
// and neither shows up in any other test: the parser tests assert on options
// they already know about.
var dogOptions = []struct {
	arg string // fed to ProcessOptions verbatim
	doc string // must appear in the help text; "" means use arg
}{
	{arg: "+dnssec"}, {arg: "+do"},
	{arg: "+cd"},
	{arg: "+adflag"}, {arg: "+ad"},
	{arg: "+noadflag"}, {arg: "+noad"},
	{arg: "+recurse"}, {arg: "+rec"}, {arg: "+rdflag"},
	{arg: "+norecurse"}, {arg: "+norec"}, {arg: "+nordflag"},
	{arg: "+compact"}, {arg: "+co"},
	{arg: "+deleg"}, {arg: "+de"},
	{arg: "+bufsize=512", doc: "+bufsize="}, {arg: "+bufsiz=512", doc: "+bufsiz="},
	{arg: "+oots"}, {arg: "+oots=opt_in", doc: "+oots="},
	{arg: "+er=agent.example.com", doc: "+er="},
	{arg: "+privacy"}, {arg: "+pr"},
	{arg: "+pr=strict", doc: "+pr"}, {arg: "+privacy=none", doc: "+privacy"},

	{arg: "+tcp"},
	{arg: "+tls"}, {arg: "+dot"},
	{arg: "+https"}, {arg: "+doh"},
	{arg: "+quic"}, {arg: "+doq"},

	{arg: "+time=5", doc: "+time="}, {arg: "+timeout=5", doc: "+timeout="},
	{arg: "+tries=3", doc: "+tries="},
	{arg: "+retry=2", doc: "+retry="},

	{arg: "+cert=/tmp/c.pem", doc: "+cert="}, {arg: "+key=/tmp/k.pem", doc: "+key="},
	{arg: "+cafile=/tmp/ca.pem", doc: "+cafile="},
	{arg: "+pin=AAAA", doc: "+pin="},
	{arg: "+tlsa"},
	{arg: "+showpin"},

	{arg: "+zonemd"}, {arg: "+zmd"},
	{arg: "+ignoreserial"}, {arg: "+ignser"},

	{arg: "+sigchase"}, {arg: "+sigcha"}, {arg: "+sc"},
	{arg: "+algchase"}, {arg: "+algcha"}, {arg: "+ac"},

	{arg: "+short"},
	{arg: "+multi"},
	{arg: "+width=100", doc: "+width="},
	{arg: "+opcode=QUERY", doc: "+opcode="},
}

// Every option in the list is one ProcessOptions actually accepts. Guards the
// direction the guide got wrong: documenting something that does not exist.
func TestDocumentedOptionsAreAccepted(t *testing.T) {
	for _, o := range dogOptions {
		t.Run(o.arg, func(t *testing.T) {
			if _, err := ProcessOptions(map[string]string{}, strings.ToUpper(o.arg), o.arg); err != nil {
				t.Errorf("ProcessOptions(%q) rejected a documented option: %v", o.arg, err)
			}
		})
	}
}

// And every option dog accepts appears in `dog -h`. Guards the other
// direction: adding a flag and leaving it undiscoverable.
func TestAcceptedOptionsAppearInHelp(t *testing.T) {
	help := strings.ToLower(rootCmd.Long)
	if help == "" {
		t.Fatal("rootCmd.Long is empty; the help text is the thing under test")
	}
	for _, o := range dogOptions {
		want := o.doc
		if want == "" {
			want = o.arg
		}
		if !strings.Contains(help, strings.ToLower(want)) {
			t.Errorf("%q is accepted but does not appear in dog -h (looked for %q)", o.arg, want)
		}
	}
}

// The same list against the guide, which is where the long form lives and
// where the four timeout/AD options were also missing.
func TestAcceptedOptionsAppearInTheGuide(t *testing.T) {
	guide, err := readGuideAppDog()
	if err != nil {
		t.Skipf("guide/app-dog.md not readable from here: %v", err)
	}
	lower := strings.ToLower(guide)
	for _, o := range dogOptions {
		want := o.doc
		if want == "" {
			want = o.arg
		}
		if !strings.Contains(lower, strings.ToLower(want)) {
			t.Errorf("%q is accepted but does not appear in guide/app-dog.md (looked for %q)", o.arg, want)
		}
	}
}

// readGuideAppDog finds guide/app-dog.md relative to this package. dog is its
// own Go module inside the tdns tree, so the guide is four levels up.
func readGuideAppDog() (string, error) {
	b, err := os.ReadFile("../../guide/app-dog.md")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// parserSourceFiles are the files that dispatch on a "+option" literal.
// ProcessOptions is most of it; +bufsize is recognised in internal/options.
var parserSourceFiles = []string{"dog.go", "internal/options/options.go"}

// optionLiteral matches a dispatch literal: "+TCP", "+TIME=", "+ER" (the
// handler checks for "=" itself). Uppercase because ProcessOptions dispatches
// on an uppercased argument.
var optionLiteral = regexp.MustCompile(`"(\+[A-Z][A-Z0-9_]*)=?"`)

// bareName strips a trailing "=" and any sample value, so "+time=5", "+TIME="
// and "+time" all reduce to "+time".
func bareName(s string) string {
	if i := strings.Index(s, "="); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// dogOptions has to cover every option the parser dispatches on, or the two
// tests above are only as good as somebody's memory: an option added to
// ProcessOptions and not to the list passes all of them while being
// undocumented, which is exactly how +time= and +adflag shipped in #591.
//
// Scanning the source is the cheap way to make the list authoritative. The
// thorough way is for ProcessOptions to dispatch FROM a shared definition that
// the tests consume, which is a refactor of the parser rather than of its
// documentation; this closes the same hole without touching parsing.
func TestDogOptionsCoversTheParser(t *testing.T) {
	covered := map[string]bool{}
	for _, o := range dogOptions {
		covered[bareName(o.arg)] = true
	}

	seen := 0
	for _, f := range parserSourceFiles {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		for _, m := range optionLiteral.FindAllStringSubmatch(string(src), -1) {
			name := bareName(m[1])
			seen++
			if !covered[name] {
				t.Errorf("%s dispatches on %q, which is not in dogOptions — so nothing checks that it is documented", f, m[1])
			}
		}
	}
	if seen == 0 {
		t.Fatal("scanned no option literals; the regex or the file list has gone stale")
	}
}

// documentedValues are the arguments the help text and the guide spell out for
// the options that take an enumerated value. Each must be accepted.
//
// A separate list because the name-level checks cannot see them: `dog -h` said
// "+oots=opt_in|opt_out" for as long as +oots has existed, and the parser
// rejects opt_out as "presence-only (-03)". Documenting a value that does not
// work is the same defect as documenting an option that does not exist.
func TestDocumentedValuesAreAccepted(t *testing.T) {
	for _, arg := range []string{
		"+oots", "+oots=opt_in", "+oots=1",
		"+pr", "+pr=strict", "+pr=opportunistic", "+pr=none",
		"+privacy", "+privacy=strict", "+privacy=opportunistic", "+privacy=none",
		"+opcode=QUERY", "+opcode=NOTIFY", "+opcode=UPDATE",
		"+opcode=0", "+opcode=4", "+opcode=5",
		"+time=1", "+time=65535", "+tries=1", "+retry=0",
		"+bufsize=512", "+bufsize=4096", "+bufsiz=1232",
	} {
		t.Run(arg, func(t *testing.T) {
			if _, err := ProcessOptions(map[string]string{}, strings.ToUpper(arg), arg); err != nil {
				t.Errorf("ProcessOptions(%q) rejected a documented value: %v", arg, err)
			}
		})
	}
}

// The value the docs used to advertise and the parser never took.
func TestOotsOptOutIsRejected(t *testing.T) {
	if _, err := ProcessOptions(map[string]string{}, "+OOTS=OPT_OUT", "+oots=opt_out"); err == nil {
		t.Error("+oots=opt_out was accepted; if OOTS gained an opt-out value, document it")
	}
	for _, f := range append([]string{"../../guide/app-dog.md"}, "dog.go") {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(string(b)), "opt_in|opt_out") {
			t.Errorf("%s still advertises +oots=opt_in|opt_out", f)
		}
	}
}
