/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"
	"testing"
)

// A zone with the shape get-name exists for: names a client provisions and then
// has to read back. ns1.provider.example. is out-of-bailiwick glue for somebody
// else's delegation -- exactly the case where the records are maintained over
// the API and nothing else in the zone implies what they should be.
const nameReadZone = `provider.example.	3600	IN	SOA	ns.provider.example. hostmaster.provider.example. 1 7200 1800 604800 7200
provider.example.	3600	IN	NS	ns.provider.example.
ns1.provider.example.	300	IN	A	192.0.2.48
ns1.provider.example.	300	IN	AAAA	2001:db8::48
ns2.provider.example.	300	IN	A	192.0.2.49
www.provider.example.	3600	IN	CNAME	ns1.provider.example.
`

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
	if got := rep.RRsets["A"]; len(got) != 1 || !strings.Contains(got[0], "192.0.2.48") {
		t.Errorf("A: got %v", got)
	}
	if got := rep.RRsets["AAAA"]; len(got) != 1 || !strings.Contains(got[0], "2001:db8::48") {
		t.Errorf("AAAA: got %v", got)
	}
	// Only what is at THIS name. ns2's address belongs to a different report.
	for _, rrs := range rep.RRsets {
		for _, rr := range rrs {
			if strings.Contains(rr, "192.0.2.49") {
				t.Errorf("report leaked another name's record: %q", rr)
			}
		}
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
	// Derived types are the signer's. Returning them would invite a
	// read-modify-write that tries to author them.
	for _, derived := range []string{"RRSIG", "NSEC", "NSEC3"} {
		if _, present := rep.RRsets[derived]; present {
			t.Errorf("%s must not appear in a get-name report", derived)
		}
	}
}
