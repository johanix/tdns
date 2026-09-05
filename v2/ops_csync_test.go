/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

const csyncTestZone = `example. 3600 IN SOA ns.example. hostmaster.example. 17 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.1
`

// TestPublishCsyncSetsImmediateFlag pins the flags word explicitly, because
// the bug it guards against was a zero value from an unassigned variable --
// which reads as a deliberate "no flags" and is invisible in a diff. A parent
// refuses a CSYNC without the immediate flag (ProcessCSYNCNotify), so this is
// the difference between the NOTIFY scheme working and not.
func TestPublishCsyncSetsImmediateFlag(t *testing.T) {
	q := make(chan UpdateRequest, 1)
	zd := testZone(t, "example.", csyncTestZone)
	zd.KeyDB = &KeyDB{UpdateQ: q}
	zd.CurrentSerial = 17

	if err := zd.PublishCsyncRR(); err != nil {
		t.Fatal(err)
	}

	csync := onlyPublishedCsync(t, (<-q).Actions)
	if csync.Flags != csyncFlagImmediate {
		t.Errorf("published CSYNC flags = 0x%04x, want 0x%04x (immediate)",
			csync.Flags, csyncFlagImmediate)
	}
	immediate, soaMinimum, err := csyncFlags(csync)
	if err != nil {
		t.Fatalf("the parent would refuse the published flags: %v", err)
	}
	if !immediate {
		t.Error("immediate flag not set; the parent refuses such a CSYNC")
	}
	if soaMinimum {
		t.Error("soaminimum set; not intended, see the comment in PublishCsyncRR")
	}
	if csync.Serial != 17 {
		t.Errorf("published serial = %d, want the zone's current serial 17", csync.Serial)
	}
}

// TestPublishCsyncReplacesRatherThanAppends asserts the update carries a
// delete of the whole RRset BEFORE the new record. Without it the apex grows
// by one CSYNC per republish -- they are not duplicates, since each carries a
// different serial -- and a parent has no defined way to pick among them.
func TestPublishCsyncReplacesRatherThanAppends(t *testing.T) {
	q := make(chan UpdateRequest, 1)
	zd := testZone(t, "example.", csyncTestZone)
	zd.KeyDB = &KeyDB{UpdateQ: q}

	if err := zd.PublishCsyncRR(); err != nil {
		t.Fatal(err)
	}
	actions := (<-q).Actions

	if len(actions) != 2 {
		t.Fatalf("publish sent %d actions, want 2 (delete RRset, then add)", len(actions))
	}
	del, add := actions[0], actions[1]

	// Order matters: an add followed by a delete would remove what was just
	// published and leave the apex with no CSYNC at all.
	if del.Header().Class != dns.ClassANY {
		t.Errorf("first action class = %d, want ClassANY (delete RRset) -- publish must delete before it adds",
			del.Header().Class)
	}
	if add.Header().Class != dns.ClassINET {
		t.Errorf("second action class = %d, want ClassINET (the new record)", add.Header().Class)
	}
	for i, rr := range actions {
		if rr.Header().Rrtype != dns.TypeCSYNC {
			t.Errorf("action %d rrtype = %s, want CSYNC", i, dns.TypeToString[rr.Header().Rrtype])
		}
		if rr.Header().Name != "example." {
			t.Errorf("action %d owner = %q, want the zone apex", i, rr.Header().Name)
		}
	}
}

// TestUnpublishCsyncDeletesTheSameRRset guards the pairing: publish and
// unpublish must name the same RRset, or an unpublish leaves records behind.
func TestUnpublishCsyncDeletesTheSameRRset(t *testing.T) {
	q := make(chan UpdateRequest, 1)
	zd := testZone(t, "example.", csyncTestZone)
	zd.KeyDB = &KeyDB{UpdateQ: q}

	if err := zd.UnpublishCsyncRR(); err != nil {
		t.Fatal(err)
	}
	actions := (<-q).Actions

	if len(actions) != 1 {
		t.Fatalf("unpublish sent %d actions, want 1 (delete RRset)", len(actions))
	}
	if got := actions[0].Header().Class; got != dns.ClassANY {
		t.Errorf("unpublish class = %d, want ClassANY", got)
	}
	if got := actions[0].Header().Rrtype; got != dns.TypeCSYNC {
		t.Errorf("unpublish rrtype = %s, want CSYNC", dns.TypeToString[got])
	}
	if got := actions[0].Header().Name; got != "example." {
		t.Errorf("unpublish owner = %q, want the zone apex", got)
	}
}

// onlyPublishedCsync returns the single class-INET CSYNC among actions.
func onlyPublishedCsync(t *testing.T, actions []dns.RR) *dns.CSYNC {
	t.Helper()
	var found *dns.CSYNC
	for _, rr := range actions {
		c, ok := rr.(*dns.CSYNC)
		if !ok || rr.Header().Class != dns.ClassINET {
			continue
		}
		if found != nil {
			t.Fatal("more than one CSYNC published in a single update")
		}
		found = c
	}
	if found == nil {
		t.Fatal("no class-INET CSYNC in the published update")
	}
	return found
}
