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

type Facts struct {
	PubKeyBytes, SigBytes, SecKeyBytes, SecurityLevel int
	Maturity, Description                             string
}

var AlgorithmFacts = map[string]Facts{
	"MLDSA44":    {PubKeyBytes: 1312, SigBytes: 2420, SecKeyBytes: 2560, SecurityLevel: 2, Maturity: "final", Description: "ML-DSA-44"},
	"SLHDSA128S": {PubKeyBytes: 32, SigBytes: 7856, SecKeyBytes: 64, SecurityLevel: 1, Maturity: "final"},
	// FALCON512 and CROSSX deliberately have NO facts entry, to test the
	// join leaving them zero-valued.
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

	// Facts joined by name.
	if f := byName["MLDSA44"].Facts; f.PubKeyBytes != 1312 || f.SigBytes != 2420 ||
		f.SecurityLevel != 2 || f.Maturity != "final" || f.Description != "ML-DSA-44" {
		t.Errorf("MLDSA44 facts parsed wrong: %+v", f)
	}
	// An algorithm with a facts entry but omitted optional fields.
	if f := byName["SLHDSA128S"].Facts; f.SigBytes != 7856 || f.Description != "" {
		t.Errorf("SLHDSA128S facts parsed wrong: %+v", f)
	}
	// An algorithm with NO facts entry keeps zero-valued Facts.
	if f := byName["FALCON512"].Facts; f != (Facts{}) {
		t.Errorf("FALCON512 should have zero Facts (no AlgorithmFacts entry), got %+v", f)
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

// TestGenRegisteredEmptySelection covers the metadata-only case (an app
// with an empty algs.list). genRegistered must emit a compilable file
// with no imports — an earlier version always imported the algs package,
// which does not compile when there are no Register calls to use it.
func TestGenRegisteredEmptySelection(t *testing.T) {
	src := genRegistered("main", nil)
	if _, err := format.Source(src); err != nil {
		t.Fatalf("empty-selection registered_algs not valid Go: %v\n%s", err, src)
	}
	s := string(src)
	if strings.Contains(s, "algs \"github.com/johanix/tdns/v2/algorithms\"") {
		t.Error("empty-selection file must not import the algs package (unused → won't compile)")
	}
	if strings.Contains(s, "algs.Register(") {
		t.Error("empty-selection file must contain no Register calls")
	}
}

// TestGenAlgrepoMkRecordsAlgrepo verifies the shared algs-env.mk records
// ALGREPO (so any app Makefile can re-run genalgs).
func TestGenAlgrepoMkRecordsAlgrepo(t *testing.T) {
	const repo = "/abs/path/to/dnssec-algorithms"
	out := string(genAlgrepoMk(repo))
	if !strings.Contains(out, "ALGREPO := "+repo) {
		t.Errorf("shared algs-env.mk missing ALGREPO:\n%s", out)
	}
	if strings.Contains(out, "export ") {
		t.Errorf("shared algs-env.mk must not carry per-app library exports:\n%s", out)
	}
}

// TestGenLibsMkPathListJoin verifies that a path-list variable contributed
// by more than one library is colon-joined (not space-joined, which would
// produce an invalid path), while a flag-list variable stays space-joined.
func TestGenLibsMkPathListJoin(t *testing.T) {
	need := map[string]bool{"sqisign": true, "qruov": true}
	envs := map[string]libEnv{
		"sqisign": {group: "sqisign", vars: map[string]string{"LD_LIBRARY_PATH": "/a/lib", "CGO_LDFLAGS": "-lsqisign"}},
		"qruov":   {group: "qruov", vars: map[string]string{"LD_LIBRARY_PATH": "/b/lib", "CGO_LDFLAGS": "-lqruov"}},
	}
	out := string(genLibsMk(need, envs))

	// Values are ordered by sortedGroups (qruov before sqisign). The point
	// of the test is the SEPARATOR: colon for the path list, space for the
	// flag list.
	if !strings.Contains(out, "export LD_LIBRARY_PATH := /b/lib:/a/lib") {
		t.Errorf("LD_LIBRARY_PATH must be colon-joined:\n%s", out)
	}
	if !strings.Contains(out, "export CGO_LDFLAGS := -lqruov -lsqisign") {
		t.Errorf("CGO_LDFLAGS must stay space-joined:\n%s", out)
	}
}

func TestGenLibsMkEmpty(t *testing.T) {
	out := string(genLibsMk(map[string]bool{}, map[string]libEnv{}))
	if !strings.Contains(out, "no C-backed algorithms") {
		t.Errorf("empty selection should note no library env:\n%s", out)
	}
	if strings.Contains(out, "export ") {
		t.Errorf("empty selection must not export library vars:\n%s", out)
	}
}

// stubEnvScript writes a passing <group>-env.sh under algrepo, at the
// path detectLib expects for that group.
func stubEnvScript(t *testing.T, algrepo, group, rel string) {
	t.Helper()
	dir := filepath.Join(algrepo, filepath.Dir(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(algrepo, rel)
	body := "#!/bin/bash\necho 'export PKG_CONFIG_PATH=\"/x/" + group + "\"'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestRunRelativeAlgrepo is the regression test for the doubled-path bug:
// a relative --algrepo used to be applied twice when running the -env.sh
// detection scripts (once as the subprocess Dir, once in the script path
// resolved from that Dir), so a valid relative path failed with a
// spurious "library not available". run() must absolutize --algrepo so a
// relative path works. The test runs from a scratch cwd with a relative
// path to the fixture repo, selecting a liboqs-backed algorithm.
func TestRunRelativeAlgrepo(t *testing.T) {
	algrepo := writeFixture(t)               // has registry/registry.go
	stubEnvScript(t, algrepo, "liboqs", "liboqs/liboqs-env.sh")

	// A working directory a fixed number of levels below algrepo's parent,
	// so a relative path to algrepo is meaningful. Use algrepo's parent as
	// cwd and "<base>" as the relative algrepo.
	parent := filepath.Dir(algrepo)
	rel := filepath.Base(algrepo)

	// App out dir is a child of a scratch root so shared algs-env.mk lands
	// in the parent (cmdv2 layout: app/ → ../algs-env.mk).
	root := t.TempDir()
	outDir := filepath.Join(root, "app")
	if err := os.Mkdir(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	listPath := filepath.Join(outDir, "algs.list")
	os.WriteFile(listPath, []byte("FALCON512\n"), 0o644) // liboqs-backed

	// Run from `parent` with the relative algrepo.
	restore := chdir(t, parent)
	defer restore()

	if err := run(rel, listPath, outDir, "main"); err != nil {
		t.Fatalf("run with relative --algrepo failed (doubled-path regression?): %v", err)
	}
	// The shared env fragment should record an ABSOLUTE ALGREPO (the whole
	// point of the fix). Match on the fixture's basename rather than the exact
	// path: on macOS t.TempDir() lives under /var, a symlink to
	// /private/var, so filepath.Abs yields the /private form.
	mk, err := os.ReadFile(filepath.Join(root, "algs-env.mk"))
	if err != nil {
		t.Fatalf("reading shared algs-env.mk: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "algs-libs.mk")); err != nil {
		t.Fatalf("per-app algs-libs.mk missing: %v", err)
	}
	line := ""
	for _, l := range strings.Split(string(mk), "\n") {
		if strings.HasPrefix(l, "ALGREPO := ") {
			line = strings.TrimPrefix(l, "ALGREPO := ")
			break
		}
	}
	if line == "" {
		t.Fatalf("no ALGREPO line in algs-env.mk:\n%s", mk)
	}
	if !filepath.IsAbs(line) {
		t.Errorf("ALGREPO %q is not absolute (relative --algrepo was not absolutized)", line)
	}
	if filepath.Base(line) != rel {
		t.Errorf("ALGREPO %q does not resolve to the fixture repo %q", line, rel)
	}
}

// TestRunBadAlgrepo verifies run() rejects an --algrepo that is not a
// dnssec-algorithms checkout, rather than failing later with a confusing
// error.
func TestRunBadAlgrepo(t *testing.T) {
	notARepo := t.TempDir() // no registry/registry.go under it
	root := t.TempDir()
	outDir := filepath.Join(root, "app")
	if err := os.Mkdir(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	listPath := filepath.Join(outDir, "algs.list")
	os.WriteFile(listPath, []byte("MLDSA44\n"), 0o644)

	err := run(notARepo, listPath, outDir, "main")
	if err == nil {
		t.Fatal("run should reject an --algrepo with no registry/registry.go")
	}
	if !strings.Contains(err.Error(), "dnssec-algorithms checkout") {
		t.Errorf("error should explain the bad --algrepo, got: %v", err)
	}
}

// chdir changes to dir and returns a function restoring the original cwd.
func chdir(t *testing.T, dir string) func() {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return func() { os.Chdir(orig) }
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
