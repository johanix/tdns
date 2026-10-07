/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

// Presentation form spells one octet several ways: a as a, \a or \097; 0xff
// as a raw byte or \255; a dot inside a label as \. or \046. The zone parser
// hands names over as the zone file wrote them, and miekg writes names it
// unpacks from the wire its own way. A key that follows the spelling makes one
// name several keys, and a lookup by one spelling misses a name stored under
// another.
var spellingGroups = [][]string{
	{"a.example.", "A.example.", `\a.example.`, `\A.example.`, `\097.example.`, `\065.example.`},
	{"\xff.example.", `\255.example.`},
	{"\x00.example.", `\000.example.`},
	{`a\.b.example.`, `a\046b.example.`, `A\.B.EXAMPLE.`},
	{`a\\b.example.`, `a\092b.example.`},
	{"*.example.", `\*.example.`, `\042.example.`},
	{"_dns.example.", `\_dns.example.`, `\095DNS.example.`},
	{"K.example.", `\226\132\170.example.`},
	{"(p.example.", `\(p.example.`, `\040p.example.`},
	{"a b.example.", `a\ b.example.`, `a\032b.example.`},
}

func TestCanonicalizeNameGivesEverySpellingOneKey(t *testing.T) {
	for _, group := range spellingGroups {
		want := CanonicalizeName(group[0])
		for _, spelling := range group[1:] {
			if got := CanonicalizeName(spelling); got != want {
				t.Errorf("CanonicalizeName(%q) = %q, but CanonicalizeName(%q) = %q: one name, two keys",
					spelling, got, group[0], want)
			}
		}
	}

	// And different names stay different keys, or this passes with a key that
	// throws octets away.
	seen := map[string]string{}
	for _, name := range []string{
		"a.example.", "b.example.", "a.b.example.", `a\.b.example.`, "a.example",
		"\xfe.example.", "\xff.example.", "k.example.", "K.example.",
		`\000.example.`, `\001.example.`, "*.example.", `\\.example.`,
	} {
		key := CanonicalizeName(name)
		if prev, dup := seen[key]; dup {
			t.Errorf("%q and %q are different names with one key %q", prev, name, key)
		}
		seen[key] = name
	}
}

// Canonicalising changes how a name is written and the case of its letters,
// never the octets it stands for.
func TestCanonicalizeNameKeepsTheOctets(t *testing.T) {
	foldedWire := func(name string) []byte {
		t.Helper()
		buf := make([]byte, 256)
		off, err := dns.PackDomainName(name, buf, 0, nil, false)
		if err != nil {
			t.Fatalf("PackDomainName(%q): %v", name, err)
		}
		w := buf[:off]
		for i := 0; i < len(w) && w[i] != 0; i += 1 + int(w[i]) {
			for j := i + 1; j <= i+int(w[i]); j++ {
				if w[j] >= 'A' && w[j] <= 'Z' {
					w[j] += 'a' - 'A'
				}
			}
		}
		return w
	}
	for _, group := range spellingGroups {
		for _, name := range group {
			key := CanonicalizeName(name)
			if !bytes.Equal(foldedWire(key), foldedWire(name)) {
				t.Errorf("CanonicalizeName(%q) = %q, which packs to % x, not % x",
					name, key, foldedWire(key), foldedWire(name))
			}
			if again := CanonicalizeName(key); again != key {
				t.Errorf("CanonicalizeName(%q): %q then %q -- not idempotent", name, key, again)
			}
		}
	}
}

// EqualNames and CanonicalizeName are two halves of one rule, and they have to
// agree about escapes as they already agree about case.
func TestEqualNamesAgreesWithCanonicalizeNameAcrossSpellings(t *testing.T) {
	var names []string
	for _, group := range spellingGroups {
		names = append(names, group...)
	}
	names = append(names, "a.example", "b.example.", "a.b.example.", `\\.example.`)
	for _, a := range names {
		for _, b := range names {
			byKey := CanonicalizeName(a) == CanonicalizeName(b)
			if byCmp := EqualNames(a, b); byCmp != byKey {
				t.Errorf("EqualNames(%q, %q) = %v but key equality = %v", a, b, byCmp, byKey)
			}
		}
	}
}

// Both run on the query path. A canonical name with an escape in it must not
// cost a copy, and neither must comparing two spellings.
func TestNameSpellingDoesNotAllocate(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() {
		_ = CanonicalizeName(`_dns.a\.b.example.`)
	}); n != 0 {
		t.Errorf("CanonicalizeName allocates %v times on an already-canonical name with an escape, want 0", n)
	}
	if n := testing.AllocsPerRun(100, func() {
		_ = EqualNames(`\097\255.example.`, "A\xff.EXAMPLE.")
	}); n != 0 {
		t.Errorf("EqualNames allocates %v times comparing two spellings, want 0", n)
	}
}
