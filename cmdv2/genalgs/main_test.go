package main

import (
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johanix/dnssec-algorithms/registry"
)

func mustName(t *testing.T, name string) registry.Alg {
	t.Helper()
	for _, a := range registry.Algorithms {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("registry has no algorithm %q", name)
	return registry.Alg{}
}

// TestGenMetadataIsValidGo ensures the generated metadata file for the
// full registry is syntactically valid, gofmt-clean Go, contains a
// RegisterMetadata line for every algorithm, and encodes role caps.
func TestGenMetadataIsValidGo(t *testing.T) {
	src := genMetadata("main", registry.Algorithms)

	if _, err := format.Source(src); err != nil {
		t.Fatalf("generated metadata is not valid Go: %v\n%s", err, src)
	}
	s := string(src)
	for _, a := range registry.Algorithms {
		if !strings.Contains(s, `RegisterMetadata(`) || !strings.Contains(s, a.Name) {
			t.Errorf("metadata missing entry for %q", a.Name)
		}
	}
	// Spot-check a KSK-only algorithm carries ForZSK: false.
	cross := mustName(t, "CROSSRSDPG128SMALL")
	if !cross.Caps.ForKSK || cross.Caps.ForZSK {
		t.Fatalf("registry sanity: CROSS should be ForKSK && !ForZSK, got %+v", cross.Caps)
	}
	if !strings.Contains(s, "ForKSK: true, ForZSK: false") {
		t.Error("generated metadata does not encode a ForKSK:true/ForZSK:false algorithm")
	}
}

// TestGenImplBuildTags checks that non-purego groups get a build tag and
// purego does not, and that impl files import the adapter packages.
func TestGenImplBuildTags(t *testing.T) {
	liboqs := genImpl("main", registry.Liboqs, []registry.Alg{mustName(t, "FALCON512")})
	if !strings.Contains(string(liboqs), "//go:build liboqs") {
		t.Error("liboqs impl missing build tag")
	}
	if !strings.Contains(string(liboqs), `"github.com/johanix/dnssec-algorithms/falcon512"`) {
		t.Error("liboqs impl missing adapter import")
	}
	if !strings.Contains(string(liboqs), "falcon512.New()") {
		t.Error("liboqs impl missing constructor call")
	}

	purego := genImpl("main", registry.PureGo, []registry.Alg{mustName(t, "MLDSA44")})
	if strings.Contains(string(purego), "//go:build") {
		t.Error("purego impl should have NO build tag")
	}
	if _, err := format.Source(purego); err != nil {
		t.Fatalf("purego impl not valid Go: %v", err)
	}
}

// TestReadListUnknownNameFails ensures a typo'd algorithm name is a hard
// error, not a silent drop.
func TestReadListUnknownNameFails(t *testing.T) {
	byName := map[string]registry.Alg{}
	for _, a := range registry.Algorithms {
		byName[a.Name] = a
	}

	dir := t.TempDir()
	good := filepath.Join(dir, "good.list")
	if err := os.WriteFile(good, []byte("MLDSA44\n# comment\n\nFALCON512\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	algs, err := readList(good, byName)
	if err != nil {
		t.Fatalf("good list: %v", err)
	}
	if len(algs) != 2 {
		t.Fatalf("good list: got %d algs, want 2", len(algs))
	}

	bad := filepath.Join(dir, "bad.list")
	if err := os.WriteFile(bad, []byte("MLDSA44\nNOSUCHALG\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readList(bad, byName); err == nil {
		t.Error("expected error for unknown algorithm name, got nil")
	}

	dup := filepath.Join(dir, "dup.list")
	if err := os.WriteFile(dup, []byte("MLDSA44\nMLDSA44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readList(dup, byName); err == nil {
		t.Error("expected error for duplicate algorithm name, got nil")
	}
}
