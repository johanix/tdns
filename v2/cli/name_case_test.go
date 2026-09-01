/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"strings"
	"testing"
)

// config check keys two different kinds of thing by name: DNS names (zones,
// TSIG key names) and config identifiers (template names, policy names, zone
// types). lc is right for the second -- Unicode folding an identifier is
// harmless and ASCII is all that occurs -- and wrong for the first.
//
// nk is the one key function for DNS names in this file. "One" is the point:
// this stage introduced nk, converted the places that LOOK UP with it, and left
// two of the maps being looked up still built with lc. A name stored under one
// function and read under the other is a miss, and the check would report a
// TSIG key as absent from a keystore that has it.
func TestConfigCheckNameKeyIsOneFunction(t *testing.T) {
	// The ordinary rule: every spelling of one name is one key.
	for _, spelling := range []string{"Example.COM.", "example.com", "  EXAMPLE.com.  "} {
		if got := nk(spelling); got != "example.com." {
			t.Errorf("nk(%q) = %q, want example.com.", spelling, got)
		}
	}
	// zoneKey is nk, not a second implementation that agrees today. The
	// non-ASCII spellings are the point: any two foldings agree on A-Z, so a
	// list of ASCII names would pass with zoneKey still folding by Unicode.
	for _, spelling := range []string{
		"Example.COM.", "example.com", "child.Example.com.",
		"\u212a.example.", "ns\xff1.example.", "\u017f.example.",
	} {
		if zoneKey(spelling) != nk(spelling) {
			t.Errorf("zoneKey(%q) = %q but nk gives %q: two key functions for one file",
				spelling, zoneKey(spelling), nk(spelling))
		}
	}

	// And the rule lc gets wrong. U+212A KELVIN SIGN folds onto "k" under
	// Unicode; two distinct DNS names must not share a bucket.
	kelvin, ascii := "K.example.", "k.example."
	if strings.ToLower(kelvin) != ascii {
		t.Skip("this Go version no longer folds U+212A onto k; the hazard is gone")
	}
	if nk(kelvin) == nk(ascii) {
		t.Errorf("nk collapses %q and %q onto one key %q", kelvin, ascii, nk(ascii))
	}
	if lc(kelvin) != lc(ascii) {
		t.Log("note: lc no longer collapses these either; nk and lc have converged")
	}

	// A name carrying an octet that is not valid UTF-8 keeps it, so two such
	// names stay two keys.
	if nk("ns\xfe1.example.") == nk("ns\xff1.example.") {
		t.Error("nk collapses two names differing by one octet onto one key")
	}
}
