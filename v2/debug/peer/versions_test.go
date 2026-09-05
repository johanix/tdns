/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return rr
}

// seedZone is the minimal servable zone every test in this package starts from.
func seedZone(t *testing.T) *Zone {
	t.Helper()
	return ZoneFromRRs("relay.test.", []dns.RR{
		mustRR(t, "relay.test. 3600 IN SOA ns.relay.test. hostmaster.relay.test. 1 7200 1800 604800 3600"),
		mustRR(t, "relay.test. 3600 IN NS ns.relay.test."),
		mustRR(t, "ns.relay.test. 3600 IN A 127.0.0.1"),
		mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1"),
	})
}

func TestZoneAddRemoveAndSerial(t *testing.T) {
	z := seedZone(t)
	if got := z.Serial(); got != 1 {
		t.Fatalf("Serial() = %d, want 1", got)
	}
	if got := z.Len(); got != 4 {
		t.Fatalf("Len() = %d, want 4", got)
	}

	// Adding the same RR twice collapses, as a receiving server would.
	z.Add(mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1"))
	if got := z.Len(); got != 4 {
		t.Fatalf("after duplicate Add, Len() = %d, want 4", got)
	}

	// A TTL-only difference is a DIFFERENT record, not the same one. If this
	// ever collapses, a TTL rewrite by the SUT becomes invisible to N4.
	z.Add(mustRR(t, "host1.relay.test. 60 IN A 10.0.0.1"))
	if got := z.Len(); got != 5 {
		t.Fatalf("after TTL-only Add, Len() = %d, want 5", got)
	}

	if !z.Remove(mustRR(t, "host1.relay.test. 60 IN A 10.0.0.1")) {
		t.Fatal("Remove of a present RR returned false")
	}
	if z.Remove(mustRR(t, "absent.relay.test. 3600 IN A 10.9.9.9")) {
		t.Fatal("Remove of an absent RR returned true")
	}

	if err := z.SetSerial(42); err != nil {
		t.Fatalf("SetSerial: %v", err)
	}
	if got := z.Serial(); got != 42 {
		t.Fatalf("after SetSerial, Serial() = %d, want 42", got)
	}
	// The SOA is keyed by its canonical text, which the serial is part of.
	// A stale entry left behind would give the zone two apex SOAs.
	soas := 0
	for _, rr := range z.RRs() {
		if _, ok := rr.(*dns.SOA); ok {
			soas++
		}
	}
	if soas != 1 {
		t.Fatalf("zone has %d apex SOAs after SetSerial, want 1", soas)
	}
}

// Owner-name case must not create a second record: tdns lowercases names at
// the index boundary, so the same name in two cases is one record.
func TestZoneOwnerCaseIsOneRecord(t *testing.T) {
	z := seedZone(t)
	before := z.Len()
	z.Add(mustRR(t, "HOST1.RELAY.TEST. 3600 IN A 10.0.0.1"))
	if got := z.Len(); got != before {
		t.Fatalf("case-differing owner added a record: Len() = %d, want %d", got, before)
	}
}

func TestZoneCloneIsIndependent(t *testing.T) {
	z := seedZone(t)
	c := z.Clone()
	c.Add(mustRR(t, "host2.relay.test. 3600 IN A 10.0.0.2"))
	if err := c.SetSerial(99); err != nil {
		t.Fatalf("SetSerial: %v", err)
	}
	if z.Len() != 4 {
		t.Fatalf("clone leaked into the original: Len() = %d, want 4", z.Len())
	}
	if z.Serial() != 1 {
		t.Fatalf("clone leaked a serial into the original: %d, want 1", z.Serial())
	}
}

func TestDiffExcludesApexSOA(t *testing.T) {
	from := seedZone(t)
	to := from.Clone()
	to.Add(mustRR(t, "host2.relay.test. 3600 IN A 10.0.0.2"))
	if !to.Remove(mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1")) {
		t.Fatal("setup: Remove failed")
	}
	if err := to.SetSerial(2); err != nil {
		t.Fatalf("SetSerial: %v", err)
	}

	d := Diff(from, to)
	if d.From != 1 || d.To != 2 {
		t.Fatalf("Diff framing = %d->%d, want 1->2", d.From, d.To)
	}
	// The serial moved, so the apex SOA differs in both directions. It is the
	// framing, not content: a Delta that carried it could not be compared
	// against a Change, which never contains an SOA.
	for _, rr := range append(append([]dns.RR{}, d.Added...), d.Removed...) {
		if _, ok := rr.(*dns.SOA); ok {
			t.Fatalf("Diff put the apex SOA in the delta: %s", oneLine(rr))
		}
	}
	if len(d.Added) != 1 || d.Added[0].Header().Name != "host2.relay.test." {
		t.Fatalf("Added = %v, want just host2", SortedTexts(d.Added))
	}
	if len(d.Removed) != 1 || d.Removed[0].Header().Name != "host1.relay.test." {
		t.Fatalf("Removed = %v, want just host1", SortedTexts(d.Removed))
	}
}

func TestHistoryApplyAdvancesSerialAndRecordsDelta(t *testing.T) {
	h := NewHistory("relay.test.", 8)
	if err := h.Seed(seedZone(t)); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	v, err := h.Apply(Change{
		Label: "add-host2",
		Add:   []dns.RR{mustRR(t, "host2.relay.test. 3600 IN A 10.0.0.2")},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if v.Serial != 2 {
		t.Fatalf("Serial = %d, want 2", v.Serial)
	}
	if len(v.Delta.Added) != 1 {
		t.Fatalf("Delta.Added = %v, want one RR", SortedTexts(v.Delta.Added))
	}
	if h.Current().Serial != 2 {
		t.Fatalf("Current().Serial = %d, want 2", h.Current().Serial)
	}
}

// The rig authors its own changes, so removing something absent means the rig
// is confused about its own state. Fail loudly rather than publish a version
// that silently did less than it said.
func TestHistoryApplyRefusesRemovalOfAbsentRR(t *testing.T) {
	h := NewHistory("relay.test.", 8)
	if err := h.Seed(seedZone(t)); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	_, err := h.Apply(Change{
		Label:  "remove-ghost",
		Remove: []dns.RR{mustRR(t, "ghost.relay.test. 3600 IN A 10.9.9.9")},
	})
	if err == nil {
		t.Fatal("Apply accepted a removal of an RR the zone does not hold")
	}
	if !strings.Contains(err.Error(), "does not hold") {
		t.Fatalf("unhelpful error: %v", err)
	}
	if h.Current().Serial != 1 {
		t.Fatalf("a refused Apply advanced the serial to %d", h.Current().Serial)
	}
}

func TestHistorySeedRefusesZoneWithoutSOA(t *testing.T) {
	h := NewHistory("relay.test.", 8)
	z := ZoneFromRRs("relay.test.", []dns.RR{mustRR(t, "relay.test. 3600 IN NS ns.relay.test.")})
	if err := h.Seed(z); err == nil {
		t.Fatal("Seed accepted a zone with no apex SOA")
	}
}

func TestDeltasSince(t *testing.T) {
	h := NewHistory("relay.test.", 8)
	if err := h.Seed(seedZone(t)); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	for i := 2; i <= 4; i++ {
		if _, err := h.Apply(Change{
			Label: "add",
			Add:   []dns.RR{mustRR(t, dns.Fqdn(strings.Repeat("x", i)+".relay.test")+" 3600 IN A 10.0.1."+strconv.Itoa(i))},
		}); err != nil {
			t.Fatalf("Apply %d: %v", i, err)
		}
	}

	deltas, ok := h.DeltasSince(1)
	if !ok {
		t.Fatal("DeltasSince(1) reported the serial unknown")
	}
	if len(deltas) != 3 {
		t.Fatalf("DeltasSince(1) = %d deltas, want 3", len(deltas))
	}

	// A client already current gets an empty, KNOWN answer — the RFC 1995
	// "no changes" case, which must not be confused with an unknown serial.
	deltas, ok = h.DeltasSince(4)
	if !ok || len(deltas) != 0 {
		t.Fatalf("DeltasSince(current) = (%d deltas, ok=%v), want (0, true)", len(deltas), ok)
	}

	if _, ok := h.DeltasSince(999); ok {
		t.Fatal("DeltasSince reported an unknown serial as known; the caller would serve a bogus IXFR instead of falling back to AXFR")
	}
}

// The cap is what makes the too-old-serial AXFR fallback reachable on purpose.
func TestHistoryCapAgesOutOldSerials(t *testing.T) {
	h := NewHistory("relay.test.", 3)
	if err := h.Seed(seedZone(t)); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := h.Apply(Change{
			Label: "add",
			Add:   []dns.RR{mustRR(t, "h"+strconv.Itoa(i)+".relay.test. 3600 IN A 10.0.2."+strconv.Itoa(i))},
		}); err != nil {
			t.Fatalf("Apply %d: %v", i, err)
		}
	}
	if got := len(h.Versions()); got != 3 {
		t.Fatalf("history holds %d versions, want the cap of 3", got)
	}
	if _, ok := h.DeltasSince(1); ok {
		t.Fatal("the seed serial survived the cap; the AXFR-fallback path would never be exercised")
	}
	if _, ok := h.DeltasSince(h.Current().Serial); !ok {
		t.Fatal("the current serial aged out of its own history")
	}
}
