// Command genalgs generates a tdns app's algorithm registration files
// from two inputs:
//
//  1. the authoritative registry table, parsed from
//     <algrepo>/registry/registry.go in a dnssec-algorithms checkout, and
//  2. a per-app plain-text "algs.list" (one algorithm NAME per line) that
//     selects which algorithms this app links an implementation for.
//
// Availability is resolved at GENERATE time, not compile time: for each
// selected algorithm whose implementation needs a C library, the
// generator runs that library's <algrepo>/<dir>/*-env.sh detection
// script. If a selected algorithm's library is NOT installed, generation
// FAILS — there are no build tags and no silent skips. Because
// availability is guaranteed before emit, all Register calls collapse
// into a single flat file with no //go:build tags.
//
// Outputs (into --out):
//
//   - metadata_algs.go: RegisterMetadata(...) for EVERY registry
//     algorithm. Pure Go, compiled into every app — the global
//     codepoint<->name<->role table (enables dog +algchase).
//   - registered_algs.go: Register(...) for every SELECTED algorithm,
//     one flat file, no build tags. Register promotes the metadata entry
//     to a real, usable algorithm (see v2/algorithms record()).
//   - algs-env.mk: a Makefile fragment exporting PKG_CONFIG_PATH /
//     CGO_LDFLAGS / LD_LIBRARY_PATH for the libraries the selected
//     algorithms need, for the app Makefile to `include`.
//
// The generated .go files are build artifacts: regenerated per build
// host, not committed.
//
// Usage:
//
//	genalgs --algrepo <dir> --list <algs.list> --out <dir> [--pkg main]
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	algrepo := flag.String("algrepo", "", "root of a dnssec-algorithms checkout (has registry/ and the *-env.sh scripts)")
	listPath := flag.String("list", "algs.list", "per-app algorithm list (one NAME per line)")
	outDir := flag.String("out", ".", "directory to write the generated files into")
	pkgName := flag.String("pkg", "main", "package name for the generated files")
	flag.Parse()

	if *algrepo == "" {
		fmt.Fprintln(os.Stderr, "genalgs: --algrepo is required")
		os.Exit(2)
	}
	if err := run(*algrepo, *listPath, *outDir, *pkgName); err != nil {
		fmt.Fprintf(os.Stderr, "genalgs: %v\n", err)
		os.Exit(1)
	}
}

func run(algrepo, listPath, outDir, pkgName string) error {
	registryFile := filepath.Join(algrepo, "registry", "registry.go")
	all, err := parseRegistry(registryFile)
	if err != nil {
		return fmt.Errorf("parsing registry %s: %w", registryFile, err)
	}
	byName := map[string]Alg{}
	for _, a := range all {
		byName[a.Name] = a
	}

	selected, err := readList(listPath, byName)
	if err != nil {
		return err
	}

	// Resolve library availability for every group the selection needs.
	// A selected algorithm whose library is absent is a hard error.
	needGroups := map[string]bool{}
	for _, a := range selected {
		if a.Group != groupPureGo {
			needGroups[a.Group] = true
		}
	}
	envByGroup := map[string]libEnv{}
	for g := range needGroups {
		env, err := detectLib(algrepo, g)
		if err != nil {
			// Name the algorithms that triggered the requirement.
			var culprits []string
			for _, a := range selected {
				if a.Group == g {
					culprits = append(culprits, a.Name)
				}
			}
			sort.Strings(culprits)
			return fmt.Errorf("%s library required by %s is not available: %w\n"+
				"  install it (see dnssec-algorithms/BUILDING.md) or remove those algorithms from %s",
				g, strings.Join(culprits, ", "), err, listPath)
		}
		envByGroup[g] = env
	}

	if err := writeFormatted(filepath.Join(outDir, "metadata_algs.go"), genMetadata(pkgName, all)); err != nil {
		return err
	}
	if err := writeFormatted(filepath.Join(outDir, "registered_algs.go"), genRegistered(pkgName, selected)); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "algs-env.mk"), genEnvMk(needGroups, envByGroup), 0o644); err != nil {
		return fmt.Errorf("writing algs-env.mk: %w", err)
	}

	groups := sortedGroups(needGroups)
	fmt.Printf("genalgs: %d algorithms in registry, %d selected; libraries: %v\n",
		len(all), len(selected), groups)
	return nil
}

// readList parses the per-app list of algorithm NAMEs. Blank lines and
// #-comments are ignored. Unknown or duplicate names are hard errors.
func readList(path string, byName map[string]Alg) ([]Alg, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	var out []Alg
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		a, ok := byName[s]
		if !ok {
			return nil, fmt.Errorf("%s:%d: unknown algorithm %q (not in the registry)", path, line, s)
		}
		if seen[s] {
			return nil, fmt.Errorf("%s:%d: duplicate algorithm %q", path, line, s)
		}
		seen[s] = true
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return out, nil
}

func sortedGroups(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

const doNotEdit = "// Code generated by genalgs; DO NOT EDIT.\n"

func capsLiteral(c Caps) string {
	return fmt.Sprintf("algs.Capabilities{ForSIG0: %t, ForDNSSEC: %t, ForKSK: %t, ForZSK: %t}",
		c.ForSIG0, c.ForDNSSEC, c.ForKSK, c.ForZSK)
}

func genMetadata(pkgName string, all []Alg) []byte {
	sorted := append([]Alg(nil), all...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Codepoint < sorted[j].Codepoint })

	var b bytes.Buffer
	b.WriteString(doNotEdit)
	b.WriteString("//\n// Metadata for every algorithm in the registry, compiled into every\n")
	b.WriteString("// build regardless of which implementations are linked. The Register\n")
	b.WriteString("// calls in registered_algs.go later promote the selected entries to real,\n")
	b.WriteString("// usable algorithms.\n\n")
	fmt.Fprintf(&b, "package %s\n\n", pkgName)
	b.WriteString("import algs \"github.com/johanix/tdns/v2/algorithms\"\n\n")
	b.WriteString("func init() {\n")
	for _, a := range sorted {
		fmt.Fprintf(&b, "\talgs.RegisterMetadata(%d, %q, %s)\n", a.Codepoint, a.Name, capsLiteral(a.Caps))
	}
	b.WriteString("}\n")
	return b.Bytes()
}

func genRegistered(pkgName string, selected []Alg) []byte {
	sorted := append([]Alg(nil), selected...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Codepoint < sorted[j].Codepoint })

	var b bytes.Buffer
	b.WriteString(doNotEdit)
	b.WriteString("//\n// Register the algorithm implementations this app selected in its\n")
	b.WriteString("// algs.list. No build tags: the generator verified each library was\n")
	b.WriteString("// installed before emitting these calls. Each Register promotes the\n")
	b.WriteString("// algorithm's metadata entry to a real, usable algorithm.\n\n")
	fmt.Fprintf(&b, "package %s\n\n", pkgName)

	b.WriteString("import (\n")
	for _, a := range sorted {
		fmt.Fprintf(&b, "\t%q\n", a.Package)
	}
	b.WriteString("\n\talgs \"github.com/johanix/tdns/v2/algorithms\"\n")
	b.WriteString(")\n\n")

	b.WriteString("func init() {\n")
	for _, a := range sorted {
		pkgIdent := a.Package[strings.LastIndex(a.Package, "/")+1:]
		fmt.Fprintf(&b, "\talgs.Register(%d, %s.New(), %s)\n", a.Codepoint, pkgIdent, capsLiteral(a.Caps))
	}
	b.WriteString("}\n")
	return b.Bytes()
}

func writeFormatted(path string, src []byte) error {
	formatted, err := format.Source(src)
	if err != nil {
		_ = os.WriteFile(path+".broken", src, 0o644)
		return fmt.Errorf("gofmt %s: %w (unformatted source written to %s.broken)", path, err, path)
	}
	if err := os.WriteFile(path, formatted, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
