/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"
	"testing"
)

const delegationParentZone = `parent.example.	3600	IN	SOA	ns.parent.example. hostmaster.parent.example. 1 7200 1800 604800 7200
parent.example.	3600	IN	NS	ns.parent.example.
alpha.parent.example.	3600	IN	NS	ns.alpha.parent.example.
ns.alpha.parent.example.	3600	IN	A	192.0.2.51
ns.alpha.parent.example.	3600	IN	AAAA	2001:db8::51
bravo.parent.example.	3600	IN	NS	ns.bravo.parent.example.
`

func delegationParent(t *testing.T) *ZoneData {
	t.Helper()
	zd := testZone(t, "parent.example.", delegationParentZone)
	registerZones(t, zd)
	zd.Options = map[ZoneOption]bool{}
	zd.DelegationBackend = &DirectDelegationBackend{zd: zd}
	return zd
}

// The read half of "zone update": what the parent holds for one child, glue
// included. Glue is the part a caller cannot derive on its own -- it lives at
// names taken from the NS records, so "the delegation" is not just the records
// at the child name.
func TestApiZoneGetDelegationReportsOneChild(t *testing.T) {
	zd := delegationParent(t)

	rep, err := zd.ApiZoneGetDelegation(ZonePost{ChildZone: "alpha.parent.example."})
	if err != nil {
		t.Fatalf("ApiZoneGetDelegation: %v", err)
	}
	if rep.Child != "alpha.parent.example." || rep.Backend != "direct" {
		t.Errorf("unexpected report header: %+v", rep)
	}
	if got := rep.RRsets["alpha.parent.example."]["NS"]; len(got) != 1 {
		t.Errorf("expected the child's NS RRset, got %v", got)
	}
	glue := rep.RRsets["ns.alpha.parent.example."]
	if len(glue["A"]) != 1 || len(glue["AAAA"]) != 1 {
		t.Errorf("expected both glue records, got %v", glue)
	}
}

// With no child named, the question is which children exist -- what a client
// reconciling its own store has to ask before it can ask anything else.
func TestApiZoneGetDelegationListsChildren(t *testing.T) {
	zd := delegationParent(t)

	rep, err := zd.ApiZoneGetDelegation(ZonePost{})
	if err != nil {
		t.Fatalf("ApiZoneGetDelegation: %v", err)
	}
	if rep.Child != "" {
		t.Errorf("a listing must not name a child: %q", rep.Child)
	}
	for _, want := range []string{"alpha.parent.example.", "bravo.parent.example."} {
		if _, ok := rep.RRsets[want]; !ok {
			t.Errorf("%s missing from the child listing: %v", want, rep.RRsets)
		}
	}
}

// A zone that does not accept child updates has no backend by design. Saying so
// beats an empty result, which reads as "this child has no delegation".
func TestApiZoneGetDelegationWithoutABackendSaysSo(t *testing.T) {
	zd := delegationParent(t)
	zd.DelegationBackend = nil

	_, err := zd.ApiZoneGetDelegation(ZonePost{ChildZone: "alpha.parent.example."})
	if err == nil {
		t.Fatal("expected an error when the zone has no delegation backend")
	}
	if !strings.Contains(err.Error(), "no delegation backend") {
		t.Errorf("the error should name the cause, got: %v", err)
	}
}

// A name outside the zone is a caller mistake, not an empty delegation.
func TestApiZoneGetDelegationRejectsAnOutOfZoneChild(t *testing.T) {
	zd := delegationParent(t)

	if _, err := zd.ApiZoneGetDelegation(ZonePost{ChildZone: "elsewhere.example."}); err == nil {
		t.Error("expected an error for a child outside the zone")
	}
	if _, err := zd.ApiZoneGetDelegation(ZonePost{ChildZone: "parent.example."}); err == nil {
		t.Error("expected an error for the apex, which is not a delegated child")
	}
}
