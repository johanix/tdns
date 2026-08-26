/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"os"
	"testing"

	"github.com/miekg/dns"
)

// childUpdate builds a CHILD-UPDATE that adds one delegation NS.
func childUpdate(t *testing.T, rrstr string) UpdateRequest {
	t.Helper()
	rr, err := dns.NewRR(rrstr)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", rrstr, err)
	}
	return UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: "example.", Actions: []dns.RR{rr}}
}

func directBackendZone(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()
	zd := testZone(t, "example.", deltaZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{}
	// The child path consults UpdatePolicy.Child, not .Zone.
	zd.UpdatePolicy = UpdatePolicy{
		Child: UpdatePolicyDetail{Type: "selfsub", RRtypes: map[uint16]bool{dns.TypeNS: true}, TTL: 3600},
	}
	// A path that does NOT exist. WriteZone would create it, so its absence
	// afterwards is the assertion.
	zd.Zonefile = t.TempDir() + "/example.zone"
	return zd
}

// A child update is durable via the delta journal, so the direct backend must
// NOT also rewrite the zone file. Doing so folds the journal away as fast as it
// is written and rewrites the whole file once per delegation change -- on a
// parent that receives them continuously, that is the cost the journal exists
// to avoid. Folding is "zone sync"'s job.
func TestDirectBackendLeavesTheZoneFileToSync(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := directBackendZone(t, kdb)
	b := &DirectDelegationBackend{zd: zd, kdb: kdb}

	if err := b.ApplyChildUpdate("example.", childUpdate(t, "child.example. 3600 IN NS ns.child.example.")); err != nil {
		t.Fatalf("ApplyChildUpdate: %v", err)
	}

	if _, err := os.Stat(zd.Zonefile); err == nil {
		t.Errorf("the zone file was rewritten on a child update; the journal already holds the change")
	}
	deltas, err := kdb.LoadZoneDeltas("example.")
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	if len(deltas) == 0 {
		t.Error("no delta persisted: the change is durable nowhere, which is worse than the eager write")
	}
}

// An API-managed primary has no other on-disk home for its content, so it keeps
// the eager write -- the same condition the ZONE-UPDATE path uses.
func TestDirectBackendStillWritesForApiManagedPrimary(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := directBackendZone(t, kdb)
	zd.Options[OptApiManagedZone] = true
	b := &DirectDelegationBackend{zd: zd, kdb: kdb}

	if err := b.ApplyChildUpdate("example.", childUpdate(t, "child.example. 3600 IN NS ns.child.example.")); err != nil {
		t.Fatalf("ApplyChildUpdate: %v", err)
	}

	if _, err := os.Stat(zd.Zonefile); err != nil {
		t.Errorf("an api-managed primary must still persist to its zone file: %v", err)
	}
}

// With no keystore there is no journal to carry the change, so memory really
// would be the only copy. The eager write still earns its keep there.
func TestDirectBackendStillWritesWithoutAKeystore(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := directBackendZone(t, kdb)
	b := &DirectDelegationBackend{zd: zd, kdb: nil}

	if err := b.ApplyChildUpdate("example.", childUpdate(t, "child.example. 3600 IN NS ns.child.example.")); err != nil {
		t.Fatalf("ApplyChildUpdate: %v", err)
	}

	if _, err := os.Stat(zd.Zonefile); err != nil {
		t.Errorf("without a journal the zone file is the only copy and must be written: %v", err)
	}
}
