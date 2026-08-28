/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package core

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestEqualNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", "ns1.example.", "ns1.example.", true},
		{"upper vs lower", "NS1.EXAMPLE.", "ns1.example.", true},
		{"mixed", "Ns1.ExAmPlE.", "nS1.eXaMpLe.", true},
		{"different name", "ns1.example.", "ns2.example.", false},
		{"different length", "ns1.example.", "ns1.example.org.", false},
		{"empty pair", "", "", true},
		{"one empty", "", "example.", false},

		// Digits and hyphens must not be touched by the folding arithmetic --
		// they sit next to the letters in ASCII and an off-by-one in the range
		// check would corrupt them.
		{"digits", "ns1.example.", "ns1.example.", true},
		{"hyphen", "a-b.example.", "A-B.EXAMPLE.", true},
		{"digit vs letter", "ns1.example.", "nsa.example.", false},

		// The trailing dot is part of the string; nothing here normalises it.
		{"relative vs absolute", "example.com", "example.com.", false},

		// Case-folding must not be applied outside A-Z. These are the pairs
		// strings.EqualFold gets wrong.
		{"kelvin sign is not k", "K.example.", "k.example.", false},
		{"long s is not s", "ſ.example.", "s.example.", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EqualNames(tc.a, tc.b); got != tc.want {
				t.Errorf("EqualNames(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
			// Comparison is symmetric, and a table this size is where an
			// asymmetric bug would hide.
			if got := EqualNames(tc.b, tc.a); got != tc.want {
				t.Errorf("EqualNames(%q, %q) = %v, want %v (asymmetric)", tc.b, tc.a, got, tc.want)
			}
		})
	}
}

// THE POINT OF HAVING THIS FUNCTION AT ALL. If it ever agrees with
// strings.EqualFold on these, it has stopped being a DNS comparison and the
// reason for its existence has gone with it.
func TestEqualNamesIsNotUnicodeFolding(t *testing.T) {
	for _, tc := range []struct{ a, b, why string }{
		{"K.example.", "k.example.", "U+212A KELVIN SIGN"},
		{"ſ.example.", "s.example.", "U+017F LATIN SMALL LETTER LONG S"},
	} {
		if !strings.EqualFold(tc.a, tc.b) {
			t.Skipf("%s no longer folds to ASCII in this Go version; the trap this guards is gone", tc.why)
		}
		if EqualNames(tc.a, tc.b) {
			t.Errorf("EqualNames(%q, %q) = true (%s): only US-ASCII A-Z may fold, per RFC 4343",
				tc.a, tc.b, tc.why)
		}
	}
}

func TestEqualNamesContains(t *testing.T) {
	names := []string{"ns1.example.", "NS2.example.", "ns3.example."}

	for _, want := range []string{"ns1.example.", "NS1.EXAMPLE.", "ns2.example.", "Ns2.Example."} {
		if !EqualNamesContains(names, want) {
			t.Errorf("EqualNamesContains(%q) = false, want true", want)
		}
	}
	for _, absent := range []string{"ns4.example.", "ns1.example.org.", ""} {
		if EqualNamesContains(names, absent) {
			t.Errorf("EqualNamesContains(%q) = true, want false", absent)
		}
	}
	if EqualNamesContains(nil, "ns1.example.") {
		t.Error("an empty list contains nothing")
	}
}

// Allocation-free, which is what makes it usable on every comparison rather
// than only where someone has decided it is worth the cost.
func TestEqualNamesDoesNotAllocate(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() {
		_ = EqualNames("NS1.Example.COM.", "ns1.example.com.")
	}); n != 0 {
		t.Errorf("EqualNames allocates %v times per call, want 0", n)
	}
}

// Differential test against miekg's own canonicalisation. equal() is
// unexported, but dns.CanonicalName is exported and folds by the same
// ASCII-only rule (RFC 4034 §6.2), so the two must agree on every input. If
// they ever diverge, this copy has drifted from the library it was lifted from.
func TestEqualNamesAgreesWithCanonicalName(t *testing.T) {
	// Mixed deliberately: ASCII letters either side of the fold, digits and
	// hyphens adjacent to them in the table, the two Unicode traps, an escape
	// sequence, and the empty label.
	alphabet := []string{
		"a", "A", "z", "Z", "m", "M", "0", "9", "-", "_", ".",
		"K", "ſ", "ä", "\\065", "[", "`", "{", "@",
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
			want := dns.CanonicalName(a) == dns.CanonicalName(b)
			if got := EqualNames(a, b); got != want {
				t.Fatalf("EqualNames(%q, %q) = %v, but CanonicalName equality says %v",
					a, b, got, want)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("the differential test compared nothing")
	}
	t.Logf("agreed with dns.CanonicalName on %d pairs", checked)
}
