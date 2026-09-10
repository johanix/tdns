/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"os"
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
	{arg: "+recurse"}, {arg: "+rec"},
	{arg: "+norecurse"}, {arg: "+norec"},
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
