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
	// The RSAMD5 tag is the big-endian uint16 at modulus[len-3:len-1]
	// (RFC 4034 B.1). A key shorter than 3 bytes has no tag and gets 0.
	for _, tc := range []struct {
		key string
		tag uint16
	}{
		{"AA==", 0},          // 1 byte
		{"AAA=", 0},          // 2 bytes: panicked in .2
		{"AAAA", 0},          // 3 zero bytes
		{"AQID", 0x0102},     // 3 bytes 01 02 03
		{"AQIDBA==", 0x0203}, // 4 bytes 01 02 03 04
	} {
		rr, err := dns.NewRR("example. 3600 IN DNSKEY 257 3 1 " + tc.key)
		if err != nil {
			t.Fatalf("parsing the DNSKEY with key %q: %v", tc.key, err)
		}
		k := rr.(*dns.DNSKEY)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("key %q: KeyTag or ToDS panicked: %v", tc.key, r)
				}
			}()
			if got := k.KeyTag(); got != tc.tag {
				t.Errorf("key %q: KeyTag() = %d, want %d", tc.key, got, tc.tag)
			}
			ds := k.ToDS(dns.SHA256)
			if ds == nil {
				t.Errorf("key %q: ToDS returned nil", tc.key)
				return
			}
			if ds.KeyTag != tc.tag {
				t.Errorf("key %q: DS key tag %d, want %d", tc.key, ds.KeyTag, tc.tag)
			}
		}()
	}
}
