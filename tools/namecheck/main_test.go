package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runOn parses a fixture and returns the findings, keyed by check name.
func runOn(t *testing.T, fixture string) ([]finding, map[string]int) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatalf("reading %s: %v", fixture, err)
	}
	r := &reporter{fset: token.NewFileSet(), allow: map[string]bool{}, root: "."}
	f, err := parser.ParseFile(r.fset, fixture, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", fixture, err)
	}
	r.checkKeyFold(f)
	r.checkNameCmp(f)
	r.checkFoldPair(f)

	byCheck := map[string]int{}
	for _, fd := range r.findings {
		byCheck[fd.check]++
	}
	return r.findings, byCheck
}

// Each of the three checks fires on the shape it exists for. The fixture is one
// function per shape, so a count is a meaningful assertion.
func TestChecksFireOnTheShapesTheyName(t *testing.T) {
	findings, byCheck := runOn(t, "bad.go.txt")

	for check, want := range map[string]int{
		"keyfold":  3, // direct key, key via a local, key returned from a helper
		"foldpair": 1, // HasPrefix(fold(x), lit) beside TrimPrefix(x, lit)
		"namecmp":  2, // EqualFold on names, HasSuffix as a bailiwick test
	} {
		if got := byCheck[check]; got != want {
			t.Errorf("%s fired %d times, want %d", check, got, want)
			for _, f := range findings {
				if f.check == check {
					t.Logf("   line %d: %s", f.pos.Line, f.msg)
				}
			}
		}
	}
}

// THE POINT OF THE WHOLE TOOL. The correct forms must be silent, or it is a
// gate nobody can pass and everybody will disable. Includes an algorithm name
// folded with ToUpper -- legitimate, because it is not a domain name -- and a
// block comment, which a parser does not see and a grep would have.
func TestCorrectFormsAreSilent(t *testing.T) {
	findings, _ := runOn(t, "good.go.txt")
	for _, f := range findings {
		t.Errorf("false positive at line %d [%s]: %s", f.pos.Line, f.check, f.msg)
	}
}

// A block comment is invisible. The ad-hoc grep that drove this series was not
// able to say that, and reported two commented-out lines as sites to convert.
func TestBlockCommentsAreInvisible(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "good.go.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "strings.EqualFold(qname, zonename)") {
		t.Fatal("the fixture no longer contains a commented-out EqualFold; " +
			"this test would pass for the wrong reason")
	}
	if findings, _ := runOn(t, "good.go.txt"); len(findings) != 0 {
		t.Errorf("commented-out code was reported: %+v", findings)
	}
}

// An allowlist entry has to say why. A bare "path:line" is refused, so silencing
// a finding cannot be done without leaving a reason behind.
func TestAllowlistDemandsAReason(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "allow.txt")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if _, err := loadAllow(write("v2/foo.go:12: pre-existing, tracked in the scope doc\n")); err != nil {
		t.Errorf("a well-formed entry was refused: %v", err)
	}
	if _, err := loadAllow(write("v2/foo.go:12\n")); err == nil {
		t.Error("an entry with no reason was accepted")
	}
	if _, err := loadAllow(write("v2/foo.go:12: \n")); err == nil {
		t.Error("an entry with an empty reason was accepted")
	}

	// And a listed line really is silenced.
	allow, err := loadAllow(write("bad.go.txt:13: deliberate\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !allow["bad.go.txt:13"] {
		t.Error("a well-formed entry did not land in the allowlist")
	}
}
