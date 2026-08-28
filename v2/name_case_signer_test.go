/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Canonical ordering, and the keys the signer and keystore index by.
 *
 * RFC 4034 §6.1 orders domain names as OCTET strings with US-ASCII A-Z folded
 * and every other octet left alone. That order is not a detail of presentation:
 * it IS the NSEC chain, and it is the order records are fed to the ZONEMD
 * digest. Fold it by any other rule and the chain is one no validator accepts
 * and the digest is one no other implementation computes.
 */
package tdns

import (
	"bytes"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// TWO DISTINCT NAMES MUST NOT SHARE A POSITION. strings.ToLower folds by
// Unicode, and U+212A KELVIN SIGN folds onto "k" -- so it gave
// "K.example." and "k.example." the SAME sort key. In a chain that is two
// names at one position; in a digest it is a record ordered as though it were
// another record.
func TestCanonicalSortKeyFoldsOnlyASCII(t *testing.T) {
	kelvin, ascii := "K.example.", "k.example."

	if strings.ToLower(kelvin) != ascii {
		t.Skip("this Go version no longer folds U+212A onto k; the hazard is gone")
	}
	if bytes.Equal(canonicalSortKey(kelvin), canonicalSortKey(ascii)) {
		t.Errorf("canonicalSortKey gives %q and %q the same key: two different "+
			"names occupy one position in the chain", kelvin, ascii)
	}
	if canonicalOwnerLess(kelvin, ascii) == canonicalOwnerLess(ascii, kelvin) {
		t.Errorf("canonicalOwnerLess cannot order %q against %q: neither sorts "+
			"before the other, so their relative position depends on the sort",
			kelvin, ascii)
	}

	// ASCII case still folds, which is the rule these implement.
	if !bytes.Equal(canonicalSortKey("WWW.EXAMPLE."), canonicalSortKey("www.example.")) {
		t.Error("canonicalSortKey stopped folding US-ASCII case")
	}
	if canonicalOwnerLess("WWW.EXAMPLE.", "www.example.") ||
		canonicalOwnerLess("www.example.", "WWW.EXAMPLE.") {
		t.Error("canonicalOwnerLess orders one spelling of a name before another")
	}
}

// A name is a string of octets and not all of them are valid UTF-8.
// strings.ToLower rewrites any that are not into U+FFFD, so the key was built
// over three bytes the name does not contain -- and two names differing only in
// such an octet collapsed onto one key.
func TestCanonicalSortKeyPreservesRawOctets(t *testing.T) {
	fe, ff := "ns\xfe1.example.", "ns\xff1.example."

	if bytes.Equal(canonicalSortKey(fe), canonicalSortKey(ff)) {
		t.Error("two names differing by one octet produce the same sort key")
	}
	if !bytes.Contains(canonicalSortKey(ff), []byte{0xff}) {
		t.Errorf("the 0xff octet is not in its own sort key: % x", canonicalSortKey(ff))
	}
	if canonicalOwnerLess(fe, ff) == canonicalOwnerLess(ff, fe) {
		t.Error("canonicalOwnerLess cannot order two names differing by one octet")
	}
}

// The comparator and the bulk key must agree, on exactly the inputs where
// folding is what decides. The existing canonical_sortkey_test.go covers ASCII;
// this is the same property over the two traps.
func TestCanonicalSortKeyAndComparatorAgreeOnFoldingTraps(t *testing.T) {
	names := []string{
		"example.", "k.example.", "K.example.", "K.example.",
		"ns\xfe1.example.", "ns\xff1.example.", "NS1.example.", "ns1.example.",
	}
	for _, a := range names {
		for _, b := range names {
			byKey := bytes.Compare(canonicalSortKey(a), canonicalSortKey(b)) < 0
			if byLess := canonicalOwnerLess(a, b); byLess != byKey {
				t.Errorf("canonicalOwnerLess(%q, %q) = %v but the sort keys say %v",
					a, b, byLess, byKey)
			}
		}
	}
}

// The apex ZONEMD is excluded from its own digest (RFC 8976 §3.3). The
// exclusion is an apex test on the record's owner, and a digest that covers the
// ZONEMD it is supposed to be will never verify anywhere.
func TestZoneDigestExcludesTheApexZonemdInAnyCase(t *testing.T) {
	mk := func(t *testing.T, text string) dns.RR {
		t.Helper()
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatalf("building %q: %v", text, err)
		}
		return rr
	}

	base := []dns.RR{
		mk(t, "example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200"),
		mk(t, "example. 3600 IN NS ns.example."),
		mk(t, "ns.example. 3600 IN A 192.0.2.1"),
	}
	zonemd := "example. 3600 IN ZONEMD 1 1 1 " + strings.Repeat("ab", 48)

	want, err := ZoneDigest("example.", base, 1, 1)
	if err != nil {
		t.Fatalf("ZoneDigest: %v", err)
	}

	// The same zone plus an apex ZONEMD, spelled several ways, must digest to
	// the same value -- because the ZONEMD is excluded however it is written.
	for _, owner := range []string{"example.", "EXAMPLE.", "Example."} {
		withZonemd := append(append([]dns.RR{}, base...),
			mk(t, strings.Replace(zonemd, "example.", owner, 1)))
		got, err := ZoneDigest("example.", withZonemd, 1, 1)
		if err != nil {
			t.Fatalf("ZoneDigest with a %q ZONEMD: %v", owner, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("an apex ZONEMD spelled %q was fed to its own digest: "+
				"the zone would never verify", owner)
		}
	}

	// A ZONEMD at another owner is ordinary data and MUST be digested, or this
	// test would pass with the exclusion applied to everything.
	elsewhere := append(append([]dns.RR{}, base...),
		mk(t, "sub.example. 3600 IN ZONEMD 1 1 1 "+strings.Repeat("ab", 48)))
	if got, err := ZoneDigest("example.", elsewhere, 1, 1); err != nil {
		t.Fatalf("ZoneDigest: %v", err)
	} else if bytes.Equal(got, want) {
		t.Error("a ZONEMD below the apex was excluded; only the apex one is")
	}
}

// The keystore's zone selector is compared as strings, so both sides have to be
// folded by the same function -- and it is a name, so that function is not
// strings.ToLower.
func TestKeystoreZoneSelectorFoldsOnlyASCII(t *testing.T) {
	sel, err := NewKeySelector([]string{"Example.COM."}, []string{"Sub.Example.COM."})
	if err != nil {
		t.Fatalf("NewKeySelector: %v", err)
	}
	for _, spelling := range []string{"example.com.", "EXAMPLE.COM.", "Example.COM", "example.com"} {
		if !sel.Matches(spelling) {
			t.Errorf("selector built from %q does not match %q", "Example.COM.", spelling)
		}
	}
	for _, spelling := range []string{"a.sub.example.com.", "A.SUB.EXAMPLE.COM."} {
		if !sel.Matches(spelling) {
			t.Errorf("subtree selector does not match %q", spelling)
		}
	}
	if sel.Matches("other.example.com.") {
		t.Error("an exact selector matched a different zone")
	}
	// Subtree matching is on label boundaries, which is what the doc promises.
	if sel.Matches("notsub.example.com.") {
		t.Error("subtree selector matched across a label boundary")
	}
	// And the entries really are canonical, since Matches compares strings.
	for _, e := range sel.Exact {
		if e != core.CanonicalizeName(e) {
			t.Errorf("selector entry %q is not canonical", e)
		}
	}

	// The ASCII cases above pass under strings.ToLower too, so they do not
	// show why the folder matters. This does: a selector naming the zone whose
	// first label is U+212A must not select the zone whose first label is "k".
	// Under Unicode folding it selected both -- and this selector decides which
	// PRIVATE KEYS a bulk export writes out.
	kelvin, ascii := "\u212a.example.", "k.example."
	if strings.ToLower(kelvin) != ascii {
		t.Skip("this Go version no longer folds U+212A onto k")
	}
	ksel, err := NewKeySelector([]string{kelvin}, nil)
	if err != nil {
		t.Fatalf("NewKeySelector: %v", err)
	}
	if !ksel.Matches(kelvin) {
		t.Error("the selector does not match the zone it names")
	}
	if ksel.Matches(ascii) {
		t.Errorf("a selector for %q also selects %q: two different zones, and "+
			"this selector decides which private keys get exported", kelvin, ascii)
	}
}
