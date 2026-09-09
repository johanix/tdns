package main

import (
	"strings"
	"testing"
)

// opt runs one "+..." argument through the parser the way main does, uppercasing
// for the switch while keeping the original for value extraction.
func opt(t *testing.T, args ...string) map[string]string {
	t.Helper()
	m := map[string]string{}
	var err error
	for _, a := range args {
		m, err = ProcessOptions(m, strings.ToUpper(a), a)
		if err != nil {
			t.Fatalf("ProcessOptions(%q): %v", a, err)
		}
	}
	return m
}

func TestTimeFlagAndAlias(t *testing.T) {
	for _, a := range []string{"+time=5", "+timeout=5"} {
		if got := opt(t, a)["timeout"]; got != "5" {
			t.Errorf("%s gave timeout=%q, want 5", a, got)
		}
	}
}

// dig clamps rather than refusing: 0 means "as fast as possible" and 255 is the
// ceiling. A script passing either must not die.
func TestTimeFlagClamps(t *testing.T) {
	if got := opt(t, "+time=0")["timeout"]; got != "1" {
		t.Errorf("+time=0 gave %q, want 1", got)
	}
	if got := opt(t, "+time=999")["timeout"]; got != "255" {
		t.Errorf("+time=999 gave %q, want 255", got)
	}
}

// +tries is the TOTAL number of attempts; +retry is the number after the
// first. They differ by one, and confusing them makes a "single attempt"
// request send two.
func TestTriesAndRetryDifferByOne(t *testing.T) {
	if got := opt(t, "+tries=3")["tries"]; got != "3" {
		t.Errorf("+tries=3 gave %q, want 3", got)
	}
	if got := opt(t, "+retry=3")["tries"]; got != "4" {
		t.Errorf("+retry=3 gave %q, want 4 (retries are after the first)", got)
	}
	// dig still sends one query for +tries=0.
	if got := opt(t, "+tries=0")["tries"]; got != "1" {
		t.Errorf("+tries=0 gave %q, want 1", got)
	}
}

func TestAdFlag(t *testing.T) {
	if got := opt(t, "+adflag")["ad_bit"]; got != "true" {
		t.Errorf("+adflag gave ad_bit=%q, want true", got)
	}
	if got := opt(t, "+noadflag")["ad_bit"]; got != "false" {
		t.Errorf("+noadflag gave ad_bit=%q, want false", got)
	}
	// Last one wins, so a script can override an earlier default.
	if got := opt(t, "+adflag", "+noadflag")["ad_bit"]; got != "false" {
		t.Errorf("+adflag then +noadflag gave %q, want false", got)
	}
}

// A malformed value must be an error, not a silent fallback to the default:
// "+time=5s" quietly meaning 5 seconds on one build and 0 on another is how a
// script hangs in production and nowhere else.
func TestBadValuesAreErrors(t *testing.T) {
	for _, a := range []string{"+time=abc", "+tries=x", "+retry=", "+timeout=1s"} {
		m := map[string]string{}
		if _, err := ProcessOptions(m, strings.ToUpper(a), a); err == nil {
			t.Errorf("ProcessOptions(%q) accepted a malformed value", a)
		}
	}
}

// Both clients dog builds -- the one that queries and the one that retries a
// truncated answer over TCP -- take their timeout from here. A +time= that
// applied to the first but not the second would lapse exactly when a response
// was large enough to need the retry.
//
// This covers the shared source. Proving the fallback path itself calls it
// needs a server that truncates, which this package has no harness for.
func TestTimeoutOptionsIsSharedAndSafe(t *testing.T) {
	if got := timeoutOptions(map[string]string{"timeout": "5"}); len(got) != 1 {
		t.Errorf("timeout=5 gave %d options, want 1", len(got))
	}
	for _, m := range []map[string]string{
		{},                 // not asked for
		{"timeout": ""},    // empty
		{"timeout": "abc"}, // unparsable
		{"timeout": "0"},   // would be an instant timeout
		{"timeout": "-1"},  // ditto
	} {
		if got := timeoutOptions(m); got != nil {
			t.Errorf("timeoutOptions(%v) returned %d options, want none", m, len(got))
		}
	}
}
