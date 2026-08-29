/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package core

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestCanonicalizeName(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"already canonical", "ns1.example.", "ns1.example."},
		{"upper", "NS1.EXAMPLE.", "ns1.example."},
		{"mixed", "Ns1.ExAmPlE.", "ns1.example."},
		{"first byte upper", "Example.", "example."},
		{"last byte upper", "example.cO", "example.co"},
		{"empty", "", ""},

		// Digits, hyphens and underscores sit next to the letters in ASCII; an
		// off-by-one in the range check would corrupt them.
		{"digits and hyphen", "a-b1.example.", "a-b1.example."},
		{"underscore label", "_DNS.example.", "_dns.example."},
		{"punctuation either side of A-Z", "@[`{.example.", "@[`{.example."},

		// Only US-ASCII A-Z folds. These are what strings.ToLower gets wrong.
		{"kelvin sign untouched", "\u212a.example.", "\u212a.example."},
		{"a-umlaut untouched", "Ä.example.", "Ä.example."},

		// Not relativised, not absolutised.
		{"relative stays relative", "NS1.EXAMPLE", "ns1.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanonicalizeName(tc.in); got != tc.want {
				t.Errorf("CanonicalizeName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// THE REASON THIS EXISTS INSTEAD OF dns.CanonicalName. A domain name is a
// string of octets and not all of them are valid UTF-8. dns.CanonicalName runs
// the name through strings.Map, which decodes it, so a lone 0xff comes back as
// U+FFFD -- three bytes where there was one.
//
// As a map key that is not merely untidy: two names differing only in such an
// octet collide, and neither can be looked up by the bytes it actually has.
func TestCanonicalizeNamePreservesNonUTF8Octets(t *testing.T) {
	raw := "ns\xff1.example."

	got := CanonicalizeName(raw)
	if got != raw {
		t.Errorf("CanonicalizeName(% x) = % x, want the input unchanged",
			[]byte(raw), []byte(got))
	}

	// The behaviour we are avoiding. If miekg ever stops corrupting this, the
	// comparison below stops being evidence and this test should say so rather
	// than keep passing for the wrong reason.
	if lossy := dns.CanonicalName(raw); lossy == raw {
		t.Skip("dns.CanonicalName no longer rewrites non-UTF-8 octets; " +
			"the hazard this function exists to avoid is gone")
	}

	// And distinct octets must stay distinct, which is the property that makes
	// this usable as a key.
	a, b := CanonicalizeName("ns\xfe1.example."), CanonicalizeName("ns\xff1.example.")
	if a == b {
		t.Errorf("0xfe and 0xff canonicalise to the same key %q -- they would collide", a)
	}
	if dns.CanonicalName("ns\xfe1.example.") != dns.CanonicalName("ns\xff1.example.") {
		t.Log("note: dns.CanonicalName no longer collides these; the collision " +
			"argument in the doc comment needs revisiting")
	}
}

// Canonicalising twice must change nothing. A key derived from a key has to be
// the same key, or a value stored under one becomes unreachable via the other.
func TestCanonicalizeNameIsIdempotent(t *testing.T) {
	for _, in := range []string{
		"NS1.Example.COM.", "ns1.example.com.", "", ".", "ns\xff1.EXAMPLE.",
		"Ä.example.", "K.example.", "_DNS.eXaMpLe.",
	} {
		once := CanonicalizeName(in)
		if twice := CanonicalizeName(once); twice != once {
			t.Errorf("CanonicalizeName(%q): %q then %q -- not idempotent", in, once, twice)
		}
	}
}

// An already-canonical name is the overwhelmingly common lookup, and it is on
// the query path. It must not allocate, or every query pays for a copy.
func TestCanonicalizeNameDoesNotAllocateWhenAlreadyCanonical(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() {
		_ = CanonicalizeName("ns1.example.com.")
	}); n != 0 {
		t.Errorf("CanonicalizeName allocates %v times on an already-canonical name, want 0", n)
	}
}

// The two halves of the pair have to agree: names that compare equal must
// canonicalise to the same key, and names that do not, must not. If they ever
// disagree, a lookup and a comparison on the same two names give different
// answers, which is worse than either being wrong on its own.
func TestCanonicalizeNameAgreesWithEqualNames(t *testing.T) {
	alphabet := []string{
		"a", "A", "k", "K", "s", "S", "z", "Z", "0", "9", "-", "_", ".",
		"K", "ſ", "ä", "\xff", "\xfe", "\\065", "[", "`", "{", "@",
	}

	var built []string
	for _, x := range alphabet {
		for _, y := range alphabet {
			built = append(built, x+y+".example.", x+".ex"+y+"ample.")
		}
	}

	checked := 0
	for _, a := range built {
		for _, b := range built {
			byKey := CanonicalizeName(a) == CanonicalizeName(b)
			if byCmp := EqualNames(a, b); byCmp != byKey {
				t.Fatalf("EqualNames(%q, %q) = %v but key equality = %v",
					a, b, byCmp, byKey)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("the agreement test compared nothing")
	}
	t.Logf("EqualNames and CanonicalizeName agreed on %d pairs", checked)
}

// strings.ToLower is the wrong tool and this pins why, so that "simplify it to
// ToLower" is a conversation with a failing test rather than a silent change.
func TestCanonicalizeNameIsNotToLower(t *testing.T) {
	for _, in := range []string{"K.example.", "ſ.example.", "Ä.example."} {
		lowered := strings.ToLower(in)
		if lowered == in {
			continue // this Go version does not fold it; nothing to prove here
		}
		if got := CanonicalizeName(in); got == lowered {
			t.Errorf("CanonicalizeName(%q) = %q, the same as strings.ToLower: "+
				"only US-ASCII A-Z may fold, per RFC 4343", in, got)
		}
	}
}
