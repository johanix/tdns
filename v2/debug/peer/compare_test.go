/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// signedLike returns the seed zone as a signing SUT would re-serve it: same
// content, a rewritten serial, and a full complement of signer-owned records.
func signedLike(t *testing.T, serial uint32) *Zone {
	t.Helper()
	z := seedZone(t)
	if err := z.SetSerial(serial); err != nil {
		t.Fatalf("SetSerial: %v", err)
	}
	for _, s := range []string{
		"relay.test. 3600 IN DNSKEY 257 3 15 kRBqRMzUZ6PJyDXkkyOJXHZTRlAvNRTOZUqbXkMDBHo=",
		"relay.test. 3600 IN RRSIG SOA 15 2 3600 20260930000000 20260901000000 12345 relay.test. deadbeef==",
		"relay.test. 3600 IN NSEC host1.relay.test. NS SOA RRSIG NSEC DNSKEY",
		"relay.test. 3600 IN ZONEMD 1 1 241 aabbcc",
	} {
		z.Add(mustRR(t, s))
	}
	return z
}

func TestCompareContentIgnoresDNSSECAndSerial(t *testing.T) {
	up := seedZone(t)
	down := signedLike(t, 4711)
	d := CompareContent(up, down)
	if !d.Equal() {
		t.Fatalf("identical content compared unequal:\n%s", d)
	}
}

// Section 0, in unit form. A comparator that cannot report a difference makes
// every PASS above it worthless, so each planted difference gets its own case.
func TestCompareContentDetectsPlantedDifferences(t *testing.T) {
	tests := []struct {
		name  string
		plant func(t *testing.T, down *Zone)
		want  string // substring the report must contain
	}{
		{
			name:  "missing record",
			plant: func(t *testing.T, down *Zone) { down.Remove(mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1")) },
			want:  "only upstream",
		},
		{
			name:  "extra record",
			plant: func(t *testing.T, down *Zone) { down.Add(mustRR(t, "ghost.relay.test. 3600 IN A 10.9.9.9")) },
			want:  "only downstream",
		},
		{
			name: "rewritten rdata",
			plant: func(t *testing.T, down *Zone) {
				down.Remove(mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1"))
				down.Add(mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.99"))
			},
			want: "only downstream",
		},
		{
			name: "rewritten TTL",
			plant: func(t *testing.T, down *Zone) {
				down.Remove(mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1"))
				down.Add(mustRR(t, "host1.relay.test. 60 IN A 10.0.0.1"))
			},
			want: "only downstream",
		},
		{
			name: "SOA rewritten beyond the serial",
			plant: func(t *testing.T, down *Zone) {
				down.Remove(down.SOA())
				down.Add(mustRR(t, "relay.test. 3600 IN SOA ns.relay.test. hostmaster.relay.test. 4711 60 1800 604800 3600"))
			},
			want: "SOA differs beyond SERIAL",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			up := seedZone(t)
			down := signedLike(t, 4711)
			tc.plant(t, down)
			d := CompareContent(up, down)
			if d.Equal() {
				t.Fatal("comparator reported equal despite a planted difference")
			}
			if !strings.Contains(d.String(), tc.want) {
				t.Fatalf("report does not name the difference (want %q):\n%s", tc.want, d)
			}
		})
	}
}

func TestCompareContentReportsAMissingSOA(t *testing.T) {
	up := seedZone(t)
	down := signedLike(t, 4711)
	down.Remove(down.SOA())
	d := CompareContent(up, down)
	if d.Equal() {
		t.Fatal("a downstream zone with no apex SOA compared equal")
	}
	if !strings.Contains(d.SOAMismatch, "downstream has no apex SOA") {
		t.Fatalf("SOAMismatch = %q", d.SOAMismatch)
	}
}

func TestNetDeltaCancelsAddThenRemove(t *testing.T) {
	rr := mustRR(t, "tmp.relay.test. 3600 IN A 10.0.3.1")
	keep := mustRR(t, "keep.relay.test. 3600 IN A 10.0.3.2")
	deltas := []Delta{
		{From: 1, To: 2, Added: []dns.RR{rr, keep}},
		{From: 2, To: 3, Removed: []dns.RR{rr}},
	}
	removed, added := NetDelta(deltas)
	if len(removed) != 0 {
		t.Fatalf("net removed = %v, want none: a record added and withdrawn inside the window nets to nothing", SortedTexts(removed))
	}
	if len(added) != 1 || added[0].Header().Name != "keep.relay.test." {
		t.Fatalf("net added = %v, want just keep", SortedTexts(added))
	}
}

func TestNetDeltaCancelsRemoveThenAdd(t *testing.T) {
	rr := mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1")
	deltas := []Delta{
		{From: 1, To: 2, Removed: []dns.RR{rr}},
		{From: 2, To: 3, Added: []dns.RR{rr}},
	}
	removed, added := NetDelta(deltas)
	if len(removed) != 0 || len(added) != 0 {
		t.Fatalf("removed=%v added=%v, want both empty", SortedTexts(removed), SortedTexts(added))
	}
}

func TestCompareDeltaAcceptsTheAuthoredChange(t *testing.T) {
	add := mustRR(t, "host2.relay.test. 3600 IN A 10.0.0.2")
	rm := mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1")
	c := Change{Label: "swap", Add: []dns.RR{add}, Remove: []dns.RR{rm}}

	// Two published states, as a signing SUT produces: the content change,
	// then a signer-only republish. N5 is about the net of the round.
	deltas := []Delta{
		{From: 1, To: 2, Added: []dns.RR{add}, Removed: []dns.RR{rm}},
		{From: 2, To: 3,
			Added:   []dns.RR{mustRR(t, "relay.test. 3600 IN RRSIG SOA 15 2 3600 20260930000000 20260901000000 12345 relay.test. bmV3==")},
			Removed: []dns.RR{mustRR(t, "relay.test. 3600 IN RRSIG SOA 15 2 3600 20260929000000 20260831000000 12345 relay.test. b2xk==")}},
	}
	d := CompareDelta(c, deltas)
	if !d.Equal() {
		t.Fatalf("deltas expressing exactly the change compared unequal:\n%s", d)
	}
}

func TestCompareDeltaDetectsPlantedDifferences(t *testing.T) {
	add := mustRR(t, "host2.relay.test. 3600 IN A 10.0.0.2")
	c := Change{Label: "add-host2", Add: []dns.RR{add}}

	t.Run("change not carried at all", func(t *testing.T) {
		d := CompareDelta(c, []Delta{{From: 1, To: 2}})
		if d.Equal() {
			t.Fatal("an empty delta compared equal to a non-empty change")
		}
		if len(d.MissingAdds) != 1 {
			t.Fatalf("MissingAdds = %v, want the one authored RR", SortedTexts(d.MissingAdds))
		}
	})

	t.Run("delta carries content nobody authored", func(t *testing.T) {
		d := CompareDelta(c, []Delta{{From: 1, To: 2, Added: []dns.RR{
			add,
			mustRR(t, "ghost.relay.test. 3600 IN A 10.9.9.9"),
		}}})
		if d.Equal() {
			t.Fatal("an unauthored addition compared equal")
		}
		if len(d.ExtraAdds) != 1 || d.ExtraAdds[0].Header().Name != "ghost.relay.test." {
			t.Fatalf("ExtraAdds = %v, want just ghost", SortedTexts(d.ExtraAdds))
		}
	})

	t.Run("delta withdraws content nobody removed", func(t *testing.T) {
		d := CompareDelta(c, []Delta{{From: 1, To: 2,
			Added:   []dns.RR{add},
			Removed: []dns.RR{mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1")}}})
		if d.Equal() {
			t.Fatal("an unauthored removal compared equal")
		}
		if len(d.ExtraRemoves) != 1 {
			t.Fatalf("ExtraRemoves = %v, want the one unauthored removal", SortedTexts(d.ExtraRemoves))
		}
	})

	// The signer-only republish above must not read as an unauthored change.
	// If DNSSEC records leaked into the N5 comparison, every round would fail.
	t.Run("signer records are not unauthored changes", func(t *testing.T) {
		d := CompareDelta(c, []Delta{{From: 1, To: 2, Added: []dns.RR{
			add,
			mustRR(t, "relay.test. 3600 IN RRSIG A 15 2 3600 20260930000000 20260901000000 12345 relay.test. c2ln=="),
			mustRR(t, "host2.relay.test. 3600 IN NSEC relay.test. A RRSIG NSEC"),
		}}})
		if !d.Equal() {
			t.Fatalf("signer-owned records leaked into the N5 comparison:\n%s", d)
		}
	})
}

func TestStripDNSSECRemovesEverySignerType(t *testing.T) {
	rrs := []dns.RR{
		mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1"),
		mustRR(t, "relay.test. 3600 IN DNSKEY 257 3 15 kRBqRMzUZ6PJyDXkkyOJXHZTRlAvNRTOZUqbXkMDBHo="),
		mustRR(t, "relay.test. 3600 IN CDNSKEY 257 3 15 kRBqRMzUZ6PJyDXkkyOJXHZTRlAvNRTOZUqbXkMDBHo="),
		mustRR(t, "relay.test. 3600 IN CDS 12345 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		mustRR(t, "relay.test. 3600 IN NSEC host1.relay.test. NS SOA RRSIG NSEC DNSKEY"),
		mustRR(t, "relay.test. 3600 IN NSEC3PARAM 1 0 0 -"),
		mustRR(t, "relay.test. 3600 IN ZONEMD 1 1 241 aabbcc"),
		mustRR(t, "relay.test. 3600 IN RRSIG SOA 15 2 3600 20260930000000 20260901000000 12345 relay.test. deadbeef=="),
	}
	got := StripDNSSEC(rrs)
	if len(got) != 1 || got[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("StripDNSSEC left %v, want only the A record", SortedTexts(got))
	}
}

// A mirroring secondary did not originate the signer-owned records either, so
// it must reproduce them too. CompareContent must NOT see that difference and
// CompareMirrored must.
func TestCompareMirroredSeesSignerRecordsThatCompareContentIgnores(t *testing.T) {
	up := signedLike(t, 4711)
	down := signedLike(t, 4711)
	down.Remove(mustRR(t, "relay.test. 3600 IN RRSIG SOA 15 2 3600 20260930000000 20260901000000 12345 relay.test. deadbeef=="))

	if d := CompareContent(up, down); !d.Equal() {
		t.Fatalf("CompareContent objected to a missing RRSIG, which a signing SUT is free to change:\n%s", d)
	}
	if d := CompareMirrored(up, down); d.Equal() {
		t.Fatal("CompareMirrored ignored a dropped RRSIG; a mirror may not change one")
	}
}

func TestCompareMirroredIgnoresTheSerialButNotTheRestOfTheSOA(t *testing.T) {
	up := seedZone(t)
	down := seedZone(t)
	if err := down.SetSerial(999); err != nil {
		t.Fatalf("SetSerial: %v", err)
	}
	if d := CompareMirrored(up, down); !d.Equal() {
		t.Fatalf("CompareMirrored objected to a serial difference, which N8 owns:\n%s", d)
	}
	down.Remove(down.SOA())
	down.Add(mustRR(t, "relay.test. 3600 IN SOA ns2.relay.test. hostmaster.relay.test. 999 7200 1800 604800 3600"))
	if d := CompareMirrored(up, down); d.Equal() {
		t.Fatal("CompareMirrored ignored a rewritten MNAME")
	}
}
