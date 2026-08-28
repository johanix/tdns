/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Regression tests for the four case-sensitivity defects at the name/index
 * boundary. Each was confirmed against the code before the fix, and each of
 * these tests fails without it.
 *
 * See docs/2026-08-28-case-insensitive-names-scope.md and tdns#415.
 */
package tdns

import (
	"sort"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Owners spelled in several cases, INCLUDING the zone-name part. A hand-written
// zone file, or $ORIGIN EXAMPLE.com. with relative names, produces exactly
// this.
const mixedCaseZone = `example.com.	3600	IN	SOA	ns.example.com. hostmaster.example.com. 1 7200 1800 604800 7200
example.com.	3600	IN	NS	ns.example.com.
ns.example.com.	3600	IN	A	192.0.2.1
lower.example.com.	3600	IN	A	192.0.2.2
Upper.example.com.	3600	IN	A	192.0.2.3
mixedzone.EXAMPLE.com.	3600	IN	A	192.0.2.4
`

func mixedCaseZoneData(t *testing.T) *ZoneData {
	t.Helper()
	zd := testZone(t, "example.com.", mixedCaseZone)
	registerZones(t, zd)
	// Explicitly empty, so nothing here depends on the fold-case option that
	// used to gate all of this and that no shipped config sets.
	zd.Options = map[ZoneOption]bool{}
	return zd
}

// DEFECT 1: SILENT DATA LOSS AT LOAD.
//
// SortFunc gated each RR on strings.HasSuffix(owner, zd.ZoneName). An owner
// spelling the zone-name part in another case failed a byte-wise suffix test
// against a zone name that had been lowercased, and was dropped -- with a log
// line, no error, and no way to reach the record afterwards by any spelling.
//
// Before the fix this zone loaded with four owners and a log line reading
// "RR mixedzone.EXAMPLE.com. ... is not in zone. Ignored."
func TestZoneLoadKeepsOwnersSpellingTheZoneNameInAnotherCase(t *testing.T) {
	zd := mixedCaseZoneData(t)

	names, err := zd.GetOwnerNames()
	if err != nil {
		t.Fatalf("GetOwnerNames: %v", err)
	}
	sort.Strings(names)
	want := []string{"example.com.", "lower.example.com.", "mixedzone.example.com.",
		"ns.example.com.", "upper.example.com."}
	if len(names) != len(want) {
		t.Fatalf("zone loaded with %d owners %v, want %d %v -- a record was dropped at load",
			len(names), names, len(want), want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("owner %d = %q, want %q", i, names[i], want[i])
		}
	}

	// And the dropped one is really there, with its data.
	od, err := zd.GetOwner("mixedzone.example.com.")
	if err != nil || od == nil {
		t.Fatalf("GetOwner(mixedzone.example.com.) = (%v, %v), want the owner", od, err)
	}
	if rrset, ok := od.RRtypes.Get(1); !ok || len(rrset.RRs) != 1 {
		t.Error("the recovered owner has no A record")
	}
}

// DEFECT 2: A NAME FINDABLE ONLY BY ITS STORED SPELLING.
//
// GetOwner is an exact map lookup, and the store folded case only under the
// fold-case option, which defaults off. So Upper.example.com. was retrievable
// as written and NOT as upper.example.com. -- NXDOMAIN for a name that exists.
func TestGetOwnerFindsAnySpelling(t *testing.T) {
	zd := mixedCaseZoneData(t)

	for _, spelling := range []string{
		"upper.example.com.", "Upper.example.com.", "UPPER.EXAMPLE.COM.", "uPpEr.ExAmPlE.cOm.",
	} {
		t.Run(spelling, func(t *testing.T) {
			od, err := zd.GetOwner(spelling)
			if err != nil {
				t.Fatalf("GetOwner(%q): %v", spelling, err)
			}
			if od == nil {
				t.Fatalf("GetOwner(%q) = nil -- NXDOMAIN for a name the zone publishes", spelling)
			}
			if !zd.NameExists(spelling) {
				t.Errorf("NameExists(%q) = false", spelling)
			}
			rrset, err := zd.GetRRset(spelling, 1)
			if err != nil || rrset == nil || len(rrset.RRs) != 1 {
				t.Errorf("GetRRset(%q, A) = (%v, %v)", spelling, rrset, err)
			}
		})
	}

	// Folding is not suffix or prefix matching: a genuinely absent name stays
	// absent, or this test would pass with GetOwner returning anything at all.
	if od, _ := zd.GetOwner("absent.example.com."); od != nil {
		t.Error("GetOwner invented an owner for a name that is not in the zone")
	}
}

// The arrived spelling is kept even though the key is folded. That is the whole
// "store as it arrives, compare with a function" rule: what the zone published
// is what an AXFR, a written zone file and a get-name report reproduce.
func TestOwnerKeepsTheSpellingItArrivedWith(t *testing.T) {
	zd := mixedCaseZoneData(t)

	for _, tc := range []struct{ query, stored string }{
		{"upper.example.com.", "Upper.example.com."},
		{"UPPER.EXAMPLE.COM.", "Upper.example.com."},
		{"mixedzone.example.com.", "mixedzone.EXAMPLE.com."},
		{"lower.example.com.", "lower.example.com."},
	} {
		od, err := zd.GetOwner(tc.query)
		if err != nil || od == nil {
			t.Fatalf("GetOwner(%q): %v", tc.query, err)
		}
		if od.Name != tc.stored {
			t.Errorf("GetOwner(%q).Name = %q, want the spelling the zone file used, %q",
				tc.query, od.Name, tc.stored)
		}
	}
}

// Two spellings of one name are ONE owner. Otherwise a zone file naming the
// same owner both ways yields two owners, one shadowing the other, and which
// one is served depends on map iteration order.
func TestTwoSpellingsOfOneOwnerAreOneOwner(t *testing.T) {
	const zone = `example.com.	3600	IN	SOA	ns.example.com. hostmaster.example.com. 1 7200 1800 604800 7200
example.com.	3600	IN	NS	ns.example.com.
ns.example.com.	3600	IN	A	192.0.2.1
WWW.example.com.	3600	IN	A	192.0.2.10
www.example.com.	3600	IN	AAAA	2001:db8::10
`
	zd := testZone(t, "example.com.", zone)
	registerZones(t, zd)

	names, err := zd.GetOwnerNames()
	if err != nil {
		t.Fatalf("GetOwnerNames: %v", err)
	}
	for _, n := range names {
		if n != core.CanonicalizeName(n) {
			t.Errorf("owner key %q is not canonical", n)
		}
	}
	if len(names) != 3 {
		t.Fatalf("zone has %d owners %v, want 3: the two spellings of www did not merge",
			len(names), names)
	}

	od, err := zd.GetOwner("www.example.com.")
	if err != nil || od == nil {
		t.Fatalf("GetOwner(www): %v", err)
	}
	// Both RRsets landed on the one owner rather than on two rival owners.
	if a, ok := od.RRtypes.Get(1); !ok || len(a.RRs) != 1 {
		t.Error("the merged owner lost its A record")
	}
	if aaaa, ok := od.RRtypes.Get(28); !ok || len(aaaa.RRs) != 1 {
		t.Error("the merged owner lost its AAAA record")
	}
}

// DEFECT 3: THE APEX-ONLY FOLD. tdns#415.
//
// FindZone tried the qname as written and only folded on a second pass, telling
// the caller which pass had won so it could lowercase the qname to match. A
// query whose ZONE SUFFIX matched exactly but whose left-hand labels did not
// took the first pass, kept its spelling, and missed the exact-keyed owner
// lookup: the zone was found and the name inside it was not.
//
// WWW.example.com. is the shape that breaks: "example.com." matches byte for
// byte, "WWW" does not.
func TestFindZoneAndOwnerAgreeOnMixedCaseLeftLabels(t *testing.T) {
	zd := mixedCaseZoneData(t)

	for _, qname := range []string{
		"Upper.example.com.", // stored mixed, asked mixed
		"UPPER.example.com.", // suffix exact, left labels not
		"upper.EXAMPLE.COM.", // suffix folded, left labels exact
		"UPPER.EXAMPLE.COM.", // nothing exact
		"lower.example.com.", // the case that always worked
	} {
		t.Run(qname, func(t *testing.T) {
			found := FindZone(qname)
			if found == nil {
				t.Fatalf("FindZone(%q) = nil", qname)
			}
			if found != zd {
				t.Fatalf("FindZone(%q) returned a different zone", qname)
			}
			// The half that used to be missed: having found the zone, the name
			// inside it must be found too, with the SAME string.
			od, err := found.GetOwner(qname)
			if err != nil || od == nil {
				t.Fatalf("FindZone found %s but GetOwner(%q) = (%v, %v): "+
					"zone located, name inside it not", found.ZoneName, qname, od, err)
			}
		})
	}
}

// DEFECT 4: A ZONE DECLARED IN MIXED CASE.
//
// Zones was keyed by the zone name as written in config, and FindZone's fold
// lowercased the qname but not the keys -- so the fold rescued lowercase-keyed
// zones and nothing else, and a zone configured as Example.COM. answered
// nothing at all.
func TestZoneDeclaredInMixedCaseIsReachable(t *testing.T) {
	zd := testZone(t, "Example.COM.", mixedCaseZone)
	registerZones(t, zd)

	// The name is folded on the way in, so everything that indexes by it --
	// including the zone's own apex lookup -- uses the same key.
	if zd.ZoneName != "example.com." {
		t.Errorf("zd.ZoneName = %q, want it canonical", zd.ZoneName)
	}
	if apex, err := zd.GetOwner(zd.ZoneName); err != nil || apex == nil {
		t.Fatalf("the zone cannot find its own apex: (%v, %v)", apex, err)
	}
	if _, err := zd.GetSOA(); err != nil {
		t.Errorf("GetSOA on a mixed-case zone: %v", err)
	}

	for _, qname := range []string{"ns.example.com.", "NS.EXAMPLE.COM.", "Example.COM."} {
		if found := FindZone(qname); found != zd {
			t.Errorf("FindZone(%q) did not reach the zone declared as Example.COM.", qname)
		}
	}
}

// The invariant the rest of the server rests on, asserted directly: a zone that
// has data has a canonical name. Every index -- Zones, zd.Data, the published
// snapshot, the working set -- is keyed canonically, so a zone whose own name
// is not would fail to find its own apex.
func TestZoneNameIsCanonicalAfterLoad(t *testing.T) {
	for _, declared := range []string{
		"example.com.", "Example.COM.", "EXAMPLE.COM.", "eXaMpLe.CoM.",
	} {
		zd := testZone(t, declared, strings.ReplaceAll(mixedCaseZone, "example.com.", declared))
		if zd.ZoneName != core.CanonicalizeName(zd.ZoneName) {
			t.Errorf("zone declared %q kept ZoneName %q, which is not canonical",
				declared, zd.ZoneName)
		}
		if _, err := zd.GetSOA(); err != nil {
			t.Errorf("zone declared %q cannot read its own SOA: %v", declared, err)
		}
	}
}

// zoneNameKey decides whether two config declarations are the same zone, and
// the Zones registry decides which entry a query reaches. They have to agree:
// two declarations quarantined as duplicates must land on one registry entry,
// and one that is NOT a duplicate must be reachable on its own.
//
// They are the same function now. This pins that, because two functions that
// agree today are two functions that can drift -- and the old comment here
// claimed zones stayed registered in the case they were written in, which
// stopped being true when zd.ZoneName started being folded.
func TestZoneNameKeyAgreesWithTheRegistry(t *testing.T) {
	for _, name := range []string{
		"example.com.", "Example.COM.", "EXAMPLE.COM", "  eXaMpLe.CoM  ",
		"child.example.com.", "_dns.example.com.",
	} {
		key := zoneNameKey(name)
		zd := &ZoneData{ZoneName: core.CanonicalizeName(dns.Fqdn(strings.TrimSpace(name)))}
		Zones.Set(zd.ZoneName, zd)

		got, ok := Zones.Get(key)
		if !ok || got != zd {
			t.Errorf("zoneNameKey(%q) = %q, which does not reach the zone the registry "+
				"stored under %q", name, key, zd.ZoneName)
		}
		Zones.Remove(zd.ZoneName)
	}

	// Folding is ASCII-only in both. strings.ToLower would make these one key,
	// quarantining two distinct zones as duplicates of each other.
	kelvin, ascii := "K.example.", "k.example."
	if strings.ToLower(kelvin) != ascii {
		t.Skip("this Go version no longer folds U+212A onto k")
	}
	if zoneNameKey(kelvin) == zoneNameKey(ascii) {
		t.Errorf("zoneNameKey collapses %q and %q onto one key: two different zones "+
			"would be reported as duplicate declarations", kelvin, ascii)
	}
	// ...while the ordinary ASCII case still collapses, which is the point.
	if zoneNameKey("Example.COM") != zoneNameKey("example.com.") {
		t.Error("zoneNameKey no longer recognises two spellings of one zone")
	}
}
