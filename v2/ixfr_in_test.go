/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Inbound IXFR: the difference-sequence parser (§4.3 of
 * docs/2026-07-25-inbound-ixfr-plan.md).
 *
 * Every malformed case here has to come out as an error rather than as a
 * partly-parsed stream, because the caller's response to an error is a full
 * AXFR -- wasteful and correct -- while its response to a wrong answer is to
 * apply it.
 */
package tdns

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func ixSOA(t *testing.T, serial uint32) dns.RR {
	t.Helper()
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns.example.",
		Mbox:    "hostmaster.example.",
		Serial:  serial,
		Refresh: 7200, Retry: 1800, Expire: 604800, Minttl: 7200,
	}
}

func ixA(t *testing.T, name, addr string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(name + "\t3600\tIN\tA\t" + addr)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	return rr
}

func TestParseIxfrDeltas(t *testing.T) {
	for _, tc := range []struct {
		what         string
		rrs          func(t *testing.T) []dns.RR
		clientSerial uint32
		wantSteps    int
		wantErr      bool
	}{
		{
			what:         "single difference sequence",
			clientSerial: 7,
			wantSteps:    1,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "old.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "new.example.", "10.0.0.2"),
					ixSOA(t, 8),
				}
			},
		},
		{
			what:         "multi-step, contiguous",
			clientSerial: 7,
			wantSteps:    2,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 9),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 9), ixA(t, "c.example.", "10.0.0.3"),
					ixSOA(t, 9),
				}
			},
		},
		{
			// A primary is allowed to condense several changes into one
			// sequence spanning the whole range. Nothing special is needed:
			// it is a single step whose from/to are the endpoints.
			what:         "condensed into a single sequence",
			clientSerial: 5,
			wantSteps:    1,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 9),
					ixSOA(t, 5), ixA(t, "a.example.", "10.0.0.1"), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 9), ixA(t, "c.example.", "10.0.0.3"),
					ixSOA(t, 9),
				}
			},
		},
		{
			what:         "empty add section is legal",
			clientSerial: 7,
			wantSteps:    1,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "gone.example.", "10.0.0.1"),
					ixSOA(t, 8),
					ixSOA(t, 8),
				}
			},
		},
		{
			what:         "bookend serials disagree",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 9),
				}
			},
		},
		{
			what:         "does not start where we are",
			clientSerial: 6,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 8),
				}
			},
		},
		{
			what:         "non-contiguous sequences",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 10),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 9), ixA(t, "c.example.", "10.0.0.3"), // gap: 8 -> 9
					ixSOA(t, 10), ixA(t, "d.example.", "10.0.0.4"),
					ixSOA(t, 10),
				}
			},
		},
		{
			what:         "sequences do not reach the bookend serial",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 9),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 9),
				}
			},
		},
		{
			what:         "delete section not followed by an add section",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8),
				}
			},
		},
		{
			what:         "missing trailing bookend",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
				}
			},
		},
		{
			what:         "adds an out-of-bailiwick name",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "elsewhere.test.", "10.0.0.2"),
					ixSOA(t, 8),
				}
			},
		},
		{
			// The AXFR-shaped reply. IsIxfr routes this away before the
			// parser sees it; if it ever does see one, it must refuse rather
			// than invent sections.
			what:         "full-zone reply (SOA, then non-SOA)",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixA(t, "a.example.", "10.0.0.1"),
					ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 8),
				}
			},
		},
		{
			what:         "too short to be a difference stream",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{ixSOA(t, 8), ixSOA(t, 8)}
			},
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			steps, err := parseIxfrDeltas("example.", tc.rrs(t), tc.clientSerial)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %d steps", len(steps))
				}
				if steps != nil {
					t.Errorf("returned %d steps alongside an error; the caller must get nothing to apply", len(steps))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(steps) != tc.wantSteps {
				t.Fatalf("%d steps, want %d", len(steps), tc.wantSteps)
			}
			// Boundary SOAs are delimiters: nothing in a section is an SOA.
			for _, st := range steps {
				for _, rr := range append(append([]dns.RR{}, st.removed...), st.added...) {
					if _, isSOA := rr.(*dns.SOA); isSOA {
						t.Errorf("step %d→%d carries an SOA inside a section; boundary SOAs are delimiters",
							st.from, st.to)
					}
				}
			}
		})
	}
}

// TestParseIxfrDeltasChainsToTheBookend pins the contiguity guarantee the apply
// depends on: steps run from the serial we hold to the serial the primary says
// it has, with no gaps.
func TestParseIxfrDeltasChainsToTheBookend(t *testing.T) {
	rrs := []dns.RR{
		ixSOA(t, 10),
		ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
		ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
		ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
		ixSOA(t, 9), ixA(t, "c.example.", "10.0.0.3"),
		ixSOA(t, 9), ixA(t, "c.example.", "10.0.0.3"),
		ixSOA(t, 10), ixA(t, "d.example.", "10.0.0.4"),
		ixSOA(t, 10),
	}
	steps, err := parseIxfrDeltas("example.", rrs, 7)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := ixfrTargetSerial(steps); got != 10 {
		t.Errorf("target serial %d, want 10", got)
	}
	prev := uint32(7)
	for _, st := range steps {
		if st.from != prev {
			t.Errorf("step starts at %d, previous ended at %d", st.from, prev)
		}
		prev = st.to
	}
	if removed, added := countIxfrRRs(steps); removed != 3 || added != 3 {
		t.Errorf("counted %d removed / %d added, want 3 / 3", removed, added)
	}
}

// ---------------------------------------------------------------- apply

const ixApplyZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 7 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
www.example.	3600	IN	AAAA	2001:db8::3
`

// ixBase builds a published snapshot to materialize from, without registering
// the zone globally.
func ixBase(t *testing.T, zoneStr string) *ZoneData {
	t.Helper()
	zd := &ZoneData{ZoneName: "example.", ZoneStore: MapZone, Logger: discardLogger()}
	if _, _, err := zd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.stopPublisher)
	if zd.publishedSnapshot() == nil {
		t.Fatal("precondition: no published snapshot")
	}
	return zd
}

func ixOwnerRRs(t *testing.T, data *core.NameMap[OwnerData], name string, rrtype uint16) []dns.RR {
	t.Helper()
	nod, ok := data.Get(name)
	if !ok {
		return nil
	}
	rs, ok := nod.RRtypes.Get(rrtype)
	if !ok {
		return nil
	}
	return rs.RRs
}

// TestMaterializeForIxfrIsADeepCopy is the Project B invariant: applying a
// delta must not reach into the snapshot that is being served.
//
// The assertion is on RR POINTER independence, not on slice contents, because
// that is what actually breaks. RRTypeStore.Get returns core.RRset by value, so
// a store-to-store copy hands back RRsets whose slices hold the SAME *dns.RR
// pointers as the published snapshot — and signing the adopted zone rewrites
// TTLs in place (applyClampToRRset assigns Header().Ttl), which would change
// records underneath a snapshot still being answered from.
//
// An earlier version of this test asserted that a removal did not shorten the
// snapshot's RRset. That could not fail: removeExact caps the slice
// (rrs[:i:i]) so append always allocates. It looked like coverage and was not.
func TestMaterializeForIxfrIsADeepCopy(t *testing.T) {
	zd := ixBase(t, ixApplyZone)
	snap := zd.publishedSnapshot()

	data, _ := materializeForIxfr(snap)

	live := snap.Data["www.example."].RRtypes.GetOnlyRRSet(dns.TypeA).RRs
	if len(live) != 1 {
		t.Fatalf("precondition: %d A RRs in the snapshot, want 1", len(live))
	}
	liveTTL := live[0].Header().Ttl

	copied := ixOwnerRRs(t, data, "www.example.", dns.TypeA)
	if len(copied) != 1 {
		t.Fatalf("%d A RRs in the copy, want 1", len(copied))
	}
	if copied[0] == live[0] {
		t.Fatal("the copy shares RR pointers with the published snapshot")
	}

	// Stand in for what signing does to the adopted zone.
	copied[0].Header().Ttl = liveTTL + 999
	if got := live[0].Header().Ttl; got != liveTTL {
		t.Errorf("snapshot RR TTL changed from %d to %d underneath a served zone", liveTTL, got)
	}

	// And removal still leaves the snapshot alone.
	before := len(snap.Data["www.example."].RRtypes.GetOnlyRRSet(dns.TypeA).RRs)
	if err := applyIxfrRemove(data, ixA(t, "www.example.", "10.0.0.3")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if after := len(snap.Data["www.example."].RRtypes.GetOnlyRRSet(dns.TypeA).RRs); after != before {
		t.Errorf("published snapshot changed under the apply: %d A RRs before, %d after", before, after)
	}
}

// TestMaterializeForIxfrCarriesNSEC: NSEC is a field beside RRtypes, so an
// RRtypes-only copy drops the denial chain — and the apply would SUCCEED,
// leaving nothing to fall back from and a zone that resolvers call bogus.
func TestMaterializeForIxfrCarriesNSEC(t *testing.T) {
	signedZone := ixApplyZone +
		"example.\t3600\tIN\tNSEC\tns.example. NS SOA RRSIG NSEC\n"
	zd := ixBase(t, signedZone)
	snap := zd.publishedSnapshot()
	if len(snap.Data["example."].NSEC.RRs) == 0 {
		t.Fatal("precondition: the base snapshot should carry an apex NSEC")
	}

	data, _ := materializeForIxfr(snap)
	nod, ok := data.Get("example.")
	if !ok {
		t.Fatal("no apex in the materialized copy")
	}
	if len(nod.NSEC.RRs) == 0 {
		t.Error("materialized copy dropped OwnerData.NSEC; the zone would be " +
			"published with no denial chain and the apply would report success")
	}
}

// TestApplyIxfrRoutesSignatureAndNSECDeletes: RemoveRR searches .RRs only, so
// a delete of an RRSIG or NSEC handled that way would never match and would be
// read as divergence — aborting every signed-zone IXFR to AXFR forever.
func TestApplyIxfrRoutesSignatureAndNSECDeletes(t *testing.T) {
	sig := "www.example.\t3600\tIN\tRRSIG\tA 13 2 3600 20260101000000 20251201000000 12345 example. AAAA"
	nsec := "example.\t3600\tIN\tNSEC\tns.example. NS SOA RRSIG NSEC"
	zd := ixBase(t, ixApplyZone+sig+"\n"+nsec+"\n")
	data, _ := materializeForIxfr(zd.publishedSnapshot())

	sigRR, err := dns.NewRR(sig)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	nsecRR, err := dns.NewRR(nsec)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}

	if err := applyIxfrRemove(data, sigRR); err != nil {
		t.Errorf("delete of an RRSIG did not match: %v", err)
	}
	if err := applyIxfrRemove(data, nsecRR); err != nil {
		t.Errorf("delete of an NSEC did not match: %v", err)
	}
}

// TestApplyIxfrRefusesUnsignedLeftovers: an RRset left standing without the
// signatures it had is the failure §1's invariant does NOT surface — it aborts
// nothing and shows up as validation failures at other people's resolvers.
func TestApplyIxfrRefusesUnsignedLeftovers(t *testing.T) {
	sig := "www.example.\t3600\tIN\tRRSIG\tA 13 2 3600 20260101000000 20251201000000 12345 example. AAAA"
	zd := ixBase(t, ixApplyZone+sig+"\n")
	data, signed := materializeForIxfr(zd.publishedSnapshot())
	if len(signed) == 0 {
		t.Fatal("precondition: the base should have at least one signed RRset")
	}
	sigRR, err := dns.NewRR(sig)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}

	// A step that removes the signature and leaves the A RRset in place.
	steps := []ixfrStep{{from: 7, to: 8, removed: []dns.RR{sigRR}}}
	if err := applyIxfrSteps("example.", data, signed, steps); err == nil {
		t.Error("apply accepted a delta that leaves www.example. A unsigned; " +
			"it would publish and fail validation at resolvers, with nothing " +
			"in our own logs")
	}

	// The same removal is fine when the RRset goes with it.
	data2, signed2 := materializeForIxfr(zd.publishedSnapshot())
	steps2 := []ixfrStep{{from: 7, to: 8, removed: []dns.RR{
		sigRR, ixA(t, "www.example.", "10.0.0.3"),
	}}}
	if err := applyIxfrSteps("example.", data2, signed2, steps2); err != nil {
		t.Errorf("apply refused a delta that removed an RRset and its signature together: %v", err)
	}
}

// TestApplyIxfrAbortsOnUnmatchedDelete: a delete that matches nothing means our
// base is not the base the delta was computed against.
func TestApplyIxfrAbortsOnUnmatchedDelete(t *testing.T) {
	zd := ixBase(t, ixApplyZone)
	data, signed := materializeForIxfr(zd.publishedSnapshot())
	steps := []ixfrStep{{from: 7, to: 8, removed: []dns.RR{
		ixA(t, "www.example.", "192.0.2.99"), // never in the zone
	}}}
	if err := applyIxfrSteps("example.", data, signed, steps); err == nil {
		t.Error("apply accepted a delete of an RR we do not hold")
	}
}

// TestApplyIxfrEndToEnd walks a two-step delta and checks the result against an
// independently-built expectation, including the apex SOA replacement.
func TestApplyIxfrEndToEnd(t *testing.T) {
	zd := ixBase(t, ixApplyZone)
	data, signed := materializeForIxfr(zd.publishedSnapshot())

	rrs := []dns.RR{
		ixSOA(t, 9),
		ixSOA(t, 7), ixA(t, "www.example.", "10.0.0.3"),
		ixSOA(t, 8), ixA(t, "www.example.", "10.0.0.4"),
		ixSOA(t, 8),
		ixSOA(t, 9), ixA(t, "extra.example.", "10.0.0.9"),
		ixSOA(t, 9),
	}
	steps, err := parseIxfrDeltas("example.", rrs, 7)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := applyIxfrSteps("example.", data, signed, steps); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := replaceApexSOA("example.", data, ixSOA(t, 9).(*dns.SOA)); err != nil {
		t.Fatalf("replaceApexSOA: %v", err)
	}

	got := ixOwnerRRs(t, data, "www.example.", dns.TypeA)
	if len(got) != 1 || got[0].(*dns.A).A.String() != "10.0.0.4" {
		t.Errorf("www.example. A = %v, want the replacement 10.0.0.4", got)
	}
	if len(ixOwnerRRs(t, data, "extra.example.", dns.TypeA)) != 1 {
		t.Error("extra.example. was not added")
	}
	// Untouched names survive.
	if len(ixOwnerRRs(t, data, "ns.example.", dns.TypeA)) != 1 {
		t.Error("ns.example. lost its A RRset")
	}
	if len(ixOwnerRRs(t, data, "www.example.", dns.TypeAAAA)) != 1 {
		t.Error("www.example. lost its AAAA RRset, which the delta never mentioned")
	}

	// The apex SOA carries S, not the serial the snapshot was materialized at.
	soaRRs := ixOwnerRRs(t, data, "example.", dns.TypeSOA)
	if len(soaRRs) != 1 {
		t.Fatalf("apex has %d SOA RRs", len(soaRRs))
	}
	if serial := soaRRs[0].(*dns.SOA).Serial; serial != 9 {
		t.Errorf("apex SOA serial = %d, want 9; publishing would serve the old "+
			"SOA while CurrentSerial says 9, tripping the serial-mirror check", serial)
	}
}

// TestApplyIxfrRemovesEmptiedOwners: a name whose last RRset goes away stops
// existing, rather than lingering with only its signatures.
func TestApplyIxfrRemovesEmptiedOwners(t *testing.T) {
	zd := ixBase(t, ixApplyZone)
	data, signed := materializeForIxfr(zd.publishedSnapshot())
	steps := []ixfrStep{{from: 7, to: 8, removed: []dns.RR{
		ixA(t, "www.example.", "10.0.0.3"),
		mustRR(t, "www.example.\t3600\tIN\tAAAA\t2001:db8::3"),
	}}}
	if err := applyIxfrSteps("example.", data, signed, steps); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := data.Get("www.example."); ok {
		t.Error("www.example. still exists after both its RRsets were removed")
	}
}
