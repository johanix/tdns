package main

import (
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A registry.go fixture exercising every idiom parseRegistry must
// resolve: named Caps shorthands, the base+concat package form, inline
// Caps, and the Group constants.
const registryFixture = `package registry

type Group string

const (
	PureGo Group = "purego"
	Liboqs Group = "liboqs"
)

type Caps struct{ ForSIG0, ForDNSSEC, ForKSK, ForZSK bool }

type Alg struct {
	Codepoint uint8
	Name      string
	Caps      Caps
	Package   string
	Group     Group
}

var dnssec = Caps{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: true}
var kskOnly = Caps{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: false}

const base = "github.com/johanix/dnssec-algorithms/"

var Algorithms = []Alg{
	{199, "MLDSA44", dnssec, base + "mldsa44", PureGo},
	{200, "SLHDSA128S", kskOnly, base + "slhdsa128s", PureGo},
	{201, "FALCON512", dnssec, base + "falcon512", Liboqs},
	{214, "CROSSX", Caps{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: false}, base + "crossx", Liboqs},
}
`

func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry")
	if err := os.MkdirAll(reg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reg, "registry.go"), []byte(registryFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestParseRegistry(t *testing.T) {
	algrepo := writeFixture(t)
	algs, err := parseRegistry(filepath.Join(algrepo, "registry", "registry.go"))
	if err != nil {
		t.Fatalf("parseRegistry: %v", err)
	}
	if len(algs) != 4 {
		t.Fatalf("got %d algs, want 4", len(algs))
	}

	byName := map[string]Alg{}
	for _, a := range algs {
		byName[a.Name] = a
	}

	// Named shorthand resolved.
	if got := byName["MLDSA44"]; got.Codepoint != 199 || !got.Caps.ForZSK || got.Package != "github.com/johanix/dnssec-algorithms/mldsa44" || got.Group != "purego" {
		t.Errorf("MLDSA44 parsed wrong: %+v", got)
	}
	// kskOnly shorthand → ForZSK false.
	if byName["SLHDSA128S"].Caps.ForZSK {
		t.Error("SLHDSA128S should have ForZSK=false")
	}
	// Group constant string value.
	if byName["FALCON512"].Group != "liboqs" {
		t.Errorf("FALCON512 group = %q, want liboqs", byName["FALCON512"].Group)
	}
	// Inline Caps literal resolved.
	if crossx := byName["CROSSX"]; !crossx.Caps.ForKSK || crossx.Caps.ForZSK {
		t.Errorf("CROSSX inline caps parsed wrong: %+v", crossx.Caps)
	}
}

func TestGenMetadataIsValidGo(t *testing.T) {
	algrepo := writeFixture(t)
	all, err := parseRegistry(filepath.Join(algrepo, "registry", "registry.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := genMetadata("main", all)
	if _, err := format.Source(src); err != nil {
		t.Fatalf("generated metadata not valid Go: %v\n%s", err, src)
	}
	s := string(src)
	if strings.Count(s, "RegisterMetadata(") != 4 {
		t.Errorf("expected 4 RegisterMetadata lines, got %d", strings.Count(s, "RegisterMetadata("))
	}
	if !strings.Contains(s, "ForKSK: true, ForZSK: false") {
		t.Error("metadata does not encode a KSK-only algorithm")
	}
}

func TestGenRegisteredNoBuildTags(t *testing.T) {
	algrepo := writeFixture(t)
	all, err := parseRegistry(filepath.Join(algrepo, "registry", "registry.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := genRegistered("main", all)
	if _, err := format.Source(src); err != nil {
		t.Fatalf("generated registered_algs not valid Go: %v\n%s", err, src)
	}
	s := string(src)
	if strings.Contains(s, "//go:build") {
		t.Error("registered_algs.go must NOT contain build tags")
	}
	if !strings.Contains(s, "mldsa44.New()") || !strings.Contains(s, "falcon512.New()") {
		t.Error("registered_algs.go missing expected constructor calls")
	}
}

func TestReadListErrors(t *testing.T) {
	algrepo := writeFixture(t)
	all, err := parseRegistry(filepath.Join(algrepo, "registry", "registry.go"))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Alg{}
	for _, a := range all {
		byName[a.Name] = a
	}

	dir := t.TempDir()
	good := filepath.Join(dir, "good.list")
	os.WriteFile(good, []byte("MLDSA44\n# comment\n\nFALCON512\n"), 0o644)
	sel, err := readList(good, byName)
	if err != nil || len(sel) != 2 {
		t.Fatalf("good list: sel=%d err=%v", len(sel), err)
	}

	bad := filepath.Join(dir, "bad.list")
	os.WriteFile(bad, []byte("NOSUCH\n"), 0o644)
	if _, err := readList(bad, byName); err == nil {
		t.Error("expected error for unknown alg")
	}

	dup := filepath.Join(dir, "dup.list")
	os.WriteFile(dup, []byte("MLDSA44\nMLDSA44\n"), 0o644)
	if _, err := readList(dup, byName); err == nil {
		t.Error("expected error for duplicate alg")
	}
}

// TestDetectLibFailure verifies that a library whose -env.sh exits
// non-zero is reported as unavailable (a stub script that fails).
func TestDetectLibFailure(t *testing.T) {
	algrepo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(algrepo, "liboqs"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(algrepo, "liboqs", "liboqs-env.sh")
	os.WriteFile(script, []byte("#!/bin/bash\necho 'not found' >&2\nexit 1\n"), 0o755)

	if _, err := detectLib(algrepo, "liboqs"); err == nil {
		t.Error("detectLib should fail when the env script exits non-zero")
	}
}

// TestDetectLibSuccess verifies parsing of a successful env script's
// exported variables.
func TestDetectLibSuccess(t *testing.T) {
	algrepo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(algrepo, "liboqs"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(algrepo, "liboqs", "liboqs-env.sh")
	os.WriteFile(script, []byte("#!/bin/bash\necho 'export PKG_CONFIG_PATH=\"/x/pc\"'\necho 'export CGO_LDFLAGS=\"-lcrypto\"'\n"), 0o755)

	env, err := detectLib(algrepo, "liboqs")
	if err != nil {
		t.Fatalf("detectLib: %v", err)
	}
	if env.vars["PKG_CONFIG_PATH"] != "/x/pc" || env.vars["CGO_LDFLAGS"] != "-lcrypto" {
		t.Errorf("parsed env wrong: %+v", env.vars)
	}
}
