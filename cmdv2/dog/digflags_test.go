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

// dig's two ends are not symmetric, and matching it matters more than being
// uniform. Below 1 it raises silently to 1 -- a script passing 0 must not die.
// Above MAXTIMEOUT (0xffff, bin/dig/dighost.h) it refuses, and so do we: a
// timeout silently shortened from the one the caller asked for is the same
// trap as reading "+time=5s" as 5.
func TestTimeFlagFloorAndCeiling(t *testing.T) {
	if got := opt(t, "+time=0")["timeout"]; got != "1" {
		t.Errorf("+time=0 gave %q, want 1", got)
	}
	// Well past the old 255, and accepted, because dig accepts it.
	if got := opt(t, "+time=999")["timeout"]; got != "999" {
		t.Errorf("+time=999 gave %q, want 999", got)
	}
	if got := opt(t, "+time=65535")["timeout"]; got != "65535" {
		t.Errorf("+time=65535 gave %q, want 65535", got)
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
	for _, a := range []string{"+time=abc", "+tries=x", "+retry=", "+timeout=1s", "+time=65536"} {
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

// The +tries= budget the exchange loop actually spends. Absent means one
// attempt: dog sends a single query where dig sends three, and this locks that
// difference in rather than leaving it to be rediscovered.
func TestTriesFrom(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options map[string]string
		want    int
	}{
		{"not asked for", map[string]string{}, 1},
		{"empty", map[string]string{"tries": ""}, 1},
		{"as parsed", map[string]string{"tries": "3"}, 3},
		{"+retry=2 became 3 attempts", opt(t, "+retry=2"), 3},
		{"+tries=2 stayed 2", opt(t, "+tries=2"), 2},
		// States ProcessOptions cannot produce, but a bare map can.
		{"unparsable", map[string]string{"tries": "x"}, 1},
		{"zero", map[string]string{"tries": "0"}, 1},
		{"negative", map[string]string{"tries": "-3"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := triesFrom(tc.options); got != tc.want {
				t.Errorf("triesFrom(%v) = %d, want %d", tc.options, got, tc.want)
			}
		})
	}
}
