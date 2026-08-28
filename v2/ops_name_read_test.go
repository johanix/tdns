/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// A zone with the shape get-name exists for: names a client provisions and then
// has to read back. ns1.provider.example. is out-of-bailiwick glue for somebody
// else's delegation -- exactly the case where the records are maintained over
// the API and nothing else in the zone implies what they should be.
// ns1 deliberately carries TWO A records: a one-element RRset makes
// sort.Strings a no-op, so a stability test built on it would pass with the
// sort deleted. They are listed out of order so the sort has something to do.
//
// The apex carries RRSIG, NSEC3PARAM and ZONEMD so the server-managed skip is
// load-bearing. Asserting their absence from a zone that never had any would
// pass whatever the code does.
const nameReadZone = `provider.example.	3600	IN	SOA	ns.provider.example. hostmaster.provider.example. 1 7200 1800 604800 7200
provider.example.	3600	IN	NS	ns.provider.example.
provider.example.	3600	IN	NSEC3PARAM	1 0 0 -
provider.example.	3600	IN	ZONEMD	1 1 1 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
provider.example.	3600	IN	RRSIG	SOA 15 2 3600 20260911000000 20260828000000 12345 provider.example. c29tZXNpZ25hdHVyZWJ5dGVzaGVyZXNvbWVzaWduYXR1cmVieXRlc2hlcmVzb21lc2lnbmF0dXJlYnl0ZXNoZXJlYWFhYWE9
ns1.provider.example.	300	IN	A	192.0.2.49
ns1.provider.example.	300	IN	A	192.0.2.48
ns1.provider.example.	300	IN	AAAA	2001:db8::48
ns2.provider.example.	300	IN	A	192.0.2.99
www.provider.example.	3600	IN	CNAME	ns1.provider.example.
`

// nameReadZoneData loads the fixture above as a registered MapZone. Options is
// reset to an empty map rather than left nil: ApiZoneGetName reaches the owner
// through the published snapshot, and a zone carrying stray options from an
// earlier test would change which path it takes.
func nameReadZoneData(t *testing.T) *ZoneData {
	t.Helper()
	zd := testZone(t, "provider.example.", nameReadZone)
	registerZones(t, zd)
	zd.Options = map[ZoneOption]bool{}
	return zd
}

// The whole point: a client that wrote these records can read exactly them
// back, keyed by type, in a form it can re-parse.
func TestApiZoneGetNameReportsEveryType(t *testing.T) {
	zd := nameReadZoneData(t)

	rep, err := zd.ApiZoneGetName(ZonePost{UpdateName: "ns1.provider.example."})
	if err != nil {
		t.Fatalf("ApiZoneGetName: %v", err)
	}
	if rep.Zone != "provider.example." || rep.Name != "ns1.provider.example." {
		t.Errorf("unexpected report header: %+v", rep)
	}
	if got := rep.RRsets["A"]; len(got) != 2 {
		t.Errorf("A: got %v, want both records at the name", got)
	}
	if got := rep.RRsets["AAAA"]; len(got) != 1 || !strings.Contains(got[0], "2001:db8::48") {
		t.Errorf("AAAA: got %v", got)
	}
	// Only what is at THIS name. ns2's address belongs to a different report.
	for _, rrs := range rep.RRsets {
		for _, rr := range rrs {
			if strings.Contains(rr, "192.0.2.99") {
				t.Errorf("report leaked another name's record: %q", rr)
			}
		}
	}
}

// THE REGRESSION FROM REVIEW (#408 F1). DNS names are case-insensitive, and
// dns.IsSubDomain folds case, but GetOwner indexes a map by the exact key. So a
// mixed-case name cleared the in-zone gate and then missed the map, returning a
// SUCCESSFUL EMPTY REPORT for a name that has records.
//
// That is the exact failure this command exists to prevent: a client reading
// "nothing there" republishes, and on a signed zone that re-signs and bumps the
// serial, every pass, for ever. Confirmed against a live server before the fix.
func TestApiZoneGetNameIsCaseInsensitive(t *testing.T) {
	zd := nameReadZoneData(t)

	want, err := zd.ApiZoneGetName(ZonePost{UpdateName: "ns1.provider.example."})
	if err != nil {
		t.Fatalf("baseline lookup: %v", err)
	}
	if len(want.RRsets["A"]) == 0 {
		t.Fatal("baseline has no A records; the fixture is wrong")
	}

	for _, spelling := range []string{
		"NS1.provider.example.",
		"Ns1.Provider.Example.",
		"NS1.PROVIDER.EXAMPLE.",
		"ns1.PROVIDER.example.",
	} {
		t.Run(spelling, func(t *testing.T) {
			got, err := zd.ApiZoneGetName(ZonePost{UpdateName: spelling})
			if err != nil {
				t.Fatalf("ApiZoneGetName(%q): %v", spelling, err)
			}
			if len(got.RRsets["A"]) != len(want.RRsets["A"]) {
				t.Fatalf("%q returned %d A records, want %d — an empty report here "+
					"is what makes a client republish for ever",
					spelling, len(got.RRsets["A"]), len(want.RRsets["A"]))
			}
			// The report must name the owner as STORED, not as asked. A client
			// diffing successive reports must not see a difference that is
			// only how it happened to spell the query.
			if got.Name != want.Name {
				t.Errorf("report Name = %q, want the stored spelling %q", got.Name, want.Name)
			}
		})
	}
}

// A name with nothing at it is an ANSWER, not an error: it is what a client
// provisioning a name for the first time gets, and it has to be
// distinguishable from a read that failed.
func TestApiZoneGetNameEmptyIsNotAnError(t *testing.T) {
	zd := nameReadZoneData(t)

	rep, err := zd.ApiZoneGetName(ZonePost{UpdateName: "ns9.provider.example."})
	if err != nil {
		t.Fatalf("an absent name must not be an error: %v", err)
	}
	if rep == nil || len(rep.RRsets) != 0 {
		t.Errorf("expected an empty report, got %+v", rep)
	}
	if rep.Name != "ns9.provider.example." {
		t.Errorf("an empty report must still say which name it is about, got %q", rep.Name)
	}
}

// Out of zone is an error, because answering "nothing" would read as "that name
// has no records" -- a different and wrong answer, and one a client would act
// on by trying to create the name here.
func TestApiZoneGetNameRejectsAnOutOfZoneName(t *testing.T) {
	zd := nameReadZoneData(t)

	if _, err := zd.ApiZoneGetName(ZonePost{UpdateName: "ns1.elsewhere.example."}); err == nil {
		t.Fatal("expected an out-of-zone name to be refused")
	}
	if _, err := zd.ApiZoneGetName(ZonePost{}); err == nil {
		t.Fatal("expected a missing name to be refused")
	}
}

// Two reads of unchanged data must compare equal. A client diffing against this
// to decide whether to publish would otherwise see map iteration order as a
// change and republish on every pass -- which on a signed zone re-signs and
// bumps the serial forever. That failure is the reason this command exists, so
// it is worth a test of its own.
func TestApiZoneGetNameIsStable(t *testing.T) {
	zd := nameReadZoneData(t)

	first, err := zd.ApiZoneGetName(ZonePost{UpdateName: "ns1.provider.example."})
	if err != nil {
		t.Fatalf("ApiZoneGetName: %v", err)
	}
	// The multi-RR RRset is the point: sort.Strings on one element is a no-op,
	// so a fixture with a single A per name would pass this test with the sort
	// deleted. ns1 has two, listed out of order in the fixture.
	if len(first.RRsets["A"]) < 2 {
		t.Fatalf("fixture has %d A records at ns1; this test cannot detect an "+
			"unsorted result with fewer than 2", len(first.RRsets["A"]))
	}
	// And they must come back sorted, not in whatever order the zone was read.
	if first.RRsets["A"][0] > first.RRsets["A"][1] {
		t.Errorf("A records not sorted: %v", first.RRsets["A"])
	}
	for i := 0; i < 8; i++ {
		again, err := zd.ApiZoneGetName(ZonePost{UpdateName: "ns1.provider.example."})
		if err != nil {
			t.Fatalf("ApiZoneGetName: %v", err)
		}
		if len(again.RRsets) != len(first.RRsets) {
			t.Fatalf("read %d has %d RRsets, first had %d", i, len(again.RRsets), len(first.RRsets))
		}
		for rrtype, rrs := range first.RRsets {
			got := again.RRsets[rrtype]
			if len(got) != len(rrs) {
				t.Fatalf("read %d: %s has %d RRs, first had %d", i, rrtype, len(got), len(rrs))
			}
			for j := range rrs {
				if got[j] != rrs[j] {
					t.Errorf("read %d: %s[%d] = %q, first was %q", i, rrtype, j, got[j], rrs[j])
				}
			}
		}
	}
}

// The apex is an ordinary name to this command. Worth pinning: it is the one
// name whose records a client must NOT try to reconcile wholesale, so the
// report has to be honest about what is there rather than hiding it.
func TestApiZoneGetNameHandlesTheApex(t *testing.T) {
	zd := nameReadZoneData(t)

	rep, err := zd.ApiZoneGetName(ZonePost{UpdateName: "provider.example."})
	if err != nil {
		t.Fatalf("ApiZoneGetName on the apex: %v", err)
	}
	if len(rep.RRsets["SOA"]) != 1 || len(rep.RRsets["NS"]) != 1 {
		t.Errorf("apex report should carry SOA and NS, got %v", rep.RRsets)
	}

	// The skip has to be load-bearing: asserting absence from a zone that never
	// had these types passes whatever the code does. So check the fixture
	// really holds them before checking the report does not.
	apex, oerr := zd.GetOwner("provider.example.")
	if oerr != nil || apex == nil {
		t.Fatalf("cannot read the apex owner to verify the fixture: %v", oerr)
	}
	for _, rrtype := range []uint16{dns.TypeNSEC3PARAM, dns.TypeZONEMD} {
		if rrset, ok := apex.RRtypes.Get(rrtype); !ok || len(rrset.RRs) == 0 {
			t.Fatalf("fixture has no %s at the apex; the skip assertion below "+
				"would pass whatever the code does", dns.TypeToString[rrtype])
		}
	}
	// Signatures are a different shape: the parser hangs them off the RRset
	// they cover rather than making them an RRtype, so verify the fixture that
	// way and then that none leaked into the report.
	if soa, ok := apex.RRtypes.Get(dns.TypeSOA); !ok || len(soa.RRSIGs) == 0 {
		t.Fatal("fixture has no RRSIG covering the apex SOA; the signature " +
			"assertion below would pass whatever the code does")
	}

	// Server-managed types are the signer's and the zone policy's. Returning
	// them would invite a read-modify-write that tries to author them.
	for _, managed := range []string{"RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "ZONEMD"} {
		if _, present := rep.RRsets[managed]; present {
			t.Errorf("%s must not appear in a get-name report", managed)
		}
	}
	for _, rrs := range rep.RRsets {
		for _, rr := range rrs {
			if strings.Contains(rr, "\tRRSIG\t") {
				t.Errorf("a signature leaked into an RRset: %q", rr)
			}
		}
	}
}
