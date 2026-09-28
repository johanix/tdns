/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// frozenTrees are the top-level directories whose modules are not built or
// tested any more (the v1 tree, music/, obe/; see check-all in the top
// Makefile). They require upstream miekg/dns and are left as they are.
var frozenTrees = map[string]bool{"cmd": true, "tdns": true, "music": true, "obe": true}

// stripGoModComments drops // comments, so a commented-out replace does not
// count and "// indirect" does not hide a requirement.
func stripGoModComments(data []byte) string {
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if i := strings.Index(l, "//"); i >= 0 {
			l = l[:i]
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}

// A replace applies only in the main module, and every binary and every test
// run is built from its own go.mod: v2's replace does nothing for cmdv2/auth.
// So every live module that requires miekg/dns must replace it with the
// johanix fork itself, all at one version -- and its go.sum must not still
// carry another fork version. A module that silently misses a re-pin builds
// fine and runs the old library.
func TestEveryLiveModuleUsesTheDNSFork(t *testing.T) {
	requireRE := regexp.MustCompile(`(?m)^\s*(require\s+)?github\.com/miekg/dns\s+v\S+`)
	replaceRE := regexp.MustCompile(`(?m)^\s*(replace\s+)?github\.com/miekg/dns\s+=>\s+github\.com/johanix/dns\s+(v\S+)\s*$`)

	root := ".."
	var mods []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			if rel, _ := filepath.Rel(root, p); frozenTrees[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			mods = append(mods, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repo: %v", err)
	}
	sort.Strings(mods)

	versions := map[string][]string{}
	users := 0
	for _, m := range mods {
		data, err := os.ReadFile(m)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		text := stripGoModComments(data)
		if !requireRE.MatchString(text) {
			continue
		}
		users++
		match := replaceRE.FindStringSubmatch(text)
		if match == nil {
			t.Errorf("%s requires github.com/miekg/dns but does not replace it with github.com/johanix/dns", m)
			continue
		}
		versions[match[2]] = append(versions[match[2]], m)

		// The go.sum must agree: an entry for any other fork version means
		// the module was not tidied after the re-pin.
		sum, err := os.Open(filepath.Join(filepath.Dir(m), "go.sum"))
		if err != nil {
			t.Errorf("%s: no go.sum beside it: %v", m, err)
			continue
		}
		sc := bufio.NewScanner(sum)
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) >= 2 && f[0] == "github.com/johanix/dns" {
				if v := strings.TrimSuffix(f[1], "/go.mod"); v != match[2] {
					t.Errorf("%s/go.sum still has github.com/johanix/dns %s; the module replaces it with %s",
						filepath.Dir(m), v, match[2])
				}
			}
		}
		sum.Close()
	}
	// v2, its sub-modules and the cmdv2 apps: well over ten. Far fewer means
	// the walk is not looking at the tdns tree.
	if users < 10 {
		t.Fatalf("found only %d live modules requiring github.com/miekg/dns in %d go.mod files; is the walk rooted at the tdns tree?",
			users, len(mods))
	}
	if len(versions) > 1 {
		t.Errorf("live modules pin different fork versions: %v", versions)
	}
}

// johanix/dns v1.1.72-johanix.2 panicked in KeyTag(), and in ToDS() through
// it, on an RSAMD5 DNSKEY whose public key is shorter than 3 bytes: the RSAMD5
// branch sliced modulus[len-3:] behind a len > 1 guard. tdns computes key tags
// of DNSKEYs from other zones, so such a key is attacker-controlled input.
// .3 guards the slice and gives the key tag 0.
func TestKeyTagDoesNotPanicOnAShortRSAMD5Key(t *testing.T) {
	for _, key := range []string{"AAA=", "AA==", "AAAA"} { // 2, 1 and 3 bytes
		rr, err := dns.NewRR("example. 3600 IN DNSKEY 257 3 1 " + key)
		if err != nil {
			t.Fatalf("parsing the DNSKEY with key %q: %v", key, err)
		}
		k := rr.(*dns.DNSKEY)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("key %q: KeyTag or ToDS panicked: %v", key, r)
				}
			}()
			tag := k.KeyTag()
			if ds := k.ToDS(dns.SHA256); ds != nil && ds.KeyTag != tag {
				t.Errorf("key %q: DS key tag %d, DNSKEY key tag %d", key, ds.KeyTag, tag)
			}
		}()
	}
}
