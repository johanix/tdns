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
	"context"
	"net"
	"testing"
	"time"

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

// ------------------------------------------------------ end to end, over TCP

// ixfrTestPrimary builds a primary that serves this zone and returns both it
// and its address, so a test can bump it to build an outbound IXFR chain.
func ixfrTestPrimary(t *testing.T, zoneStr string) (*ZoneData, string, func()) {
	t.Helper()
	pzd := &ZoneData{
		ZoneName:    "example.",
		ZoneStore:   MapZone,
		ZoneType:    Primary,
		Logger:      discardLogger(),
		Ready:       true,
		Status:      ZoneStatusReady,
		Downstreams: []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}},
	}
	if _, _, err := pzd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("primary ReadZoneData: %v", err)
	}
	pzd.InstallInitialSnapshot()
	t.Cleanup(pzd.stopPublisher)
	addr, stop := serveTestPrimary(t, pzd)
	return pzd, addr, stop
}

// ixfrTestSecondary is a secondary holding the given zone, pointed at addr,
// with IXFR-in enabled. Registered so publishes are not dropped by the
// liveness guard; the primary is deliberately not registered, since both
// carry the same name.
func ixfrTestSecondary(t *testing.T, zoneStr, addr string, opts map[ZoneOption]bool) *ZoneData {
	t.Helper()
	if opts == nil {
		opts = map[ZoneOption]bool{}
	}
	zd := &ZoneData{
		ZoneName:  "example.",
		ZoneStore: MapZone,
		ZoneType:  Secondary,
		Logger:    discardLogger(),
		Options:   opts,
		Upstreams: []PeerConf{{Addr: addr}},
	}
	if _, _, err := zd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("secondary ReadZoneData: %v", err)
	}
	zd.InstallInitialSnapshot()
	registerZones(t, zd)
	t.Cleanup(zd.stopPublisher)
	return zd
}

// TestIxfrInConvergesViaDelta is the payoff test: a tdns secondary pulls a
// real difference stream from a tdns primary (#328's outbound side) and ends
// up with the primary's content.
func TestIxfrInConvergesViaDelta(t *testing.T) {
	authApp(t)
	pzd, addr, stop := ixfrTestPrimary(t, ixApplyZone)
	defer stop()

	base := pzd.publishedSnapshot().Serial

	// Two publishes, so the primary has a contiguous chain to serve from.
	// Registered while they happen: publishWorkingSetLocked drops a publish
	// for a zone that is not live in the Zones map, so an unregistered primary
	// silently accumulates no chain at all. Unregistered again immediately --
	// the chain lives in its snapshot and the transfer-out path reads that
	// directly, while the secondary needs the same name in the map.
	// Registered only while the chain is built, and removed via cleanup as
	// well as inline: a t.Fatalf between the two would otherwise leave the
	// primary in the global map and break whatever test ran next.
	Zones.Set("example.", pzd)
	t.Cleanup(func() { Zones.Remove("example.") })
	stageAndPublish(t, pzd, stageAddA(t, pzd, "one.example.", "10.1.0.1"))
	stageAndPublish(t, pzd, stageAddA(t, pzd, "two.example.", "10.1.0.2"))
	Zones.Remove("example.")
	if len(chainOf(pzd)) < 2 {
		t.Fatalf("precondition: primary chain has %d links, want at least 2", len(chainOf(pzd)))
	}

	zd := ixfrTestSecondary(t, ixApplyZone, addr, nil)
	zd.IncomingSerial = base
	zd.CurrentSerial = base

	// Convergence alone would not prove a delta was used -- the full-zone
	// fallback converges too, and identically. Ask the transfer directly what
	// the primary sent before letting the refresh path apply it.
	outcome, rrs, err := zd.ixfrTransferIn(context.Background(), zd.Upstreams[0], base, &Config{})
	if err != nil {
		t.Fatalf("ixfrTransferIn: %v", err)
	}
	if outcome != ixfrDelta {
		t.Fatalf("primary answered %s, want delta; this test would pass on the "+
			"full-zone fallback and prove nothing about the delta path", outcome)
	}
	if steps, perr := parseIxfrDeltas("example.", rrs, base); perr != nil {
		t.Fatalf("the delta the primary sent does not parse: %v", perr)
	} else if len(steps) < 2 {
		t.Errorf("%d difference sequences, want the 2 the primary has links for", len(steps))
	}

	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}

	if got, want := zd.IncomingSerial, pzd.publishedSnapshot().Serial; got != want {
		t.Errorf("secondary serial %d, want the primary's %d", got, want)
	}
	for _, name := range []string{"one.example.", "two.example."} {
		owner, _ := zd.GetOwner(name)
		if owner == nil {
			t.Errorf("%s missing: the delta was not applied", name)
		}
	}
	// The names the delta never mentioned are still there.
	if owner, _ := zd.GetOwner("www.example."); owner == nil {
		t.Error("www.example. was lost; a delta must not replace the whole zone")
	}
}

// TestIxfrInFallsBackToFullZone: a primary with no chain to serve from answers
// the IXFR with an entire zone, which RFC 1995 §4 allows. No delta logic
// involved, and the most important fallback to get right.
func TestIxfrInFallsBackToFullZone(t *testing.T) {
	authApp(t)
	newer := `example.	3600	IN	SOA	ns.example. hostmaster.example. 20 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
fresh.example.	3600	IN	A	10.9.9.9
`
	_, addr, stop := ixfrTestPrimary(t, newer)
	defer stop()

	zd := ixfrTestSecondary(t, ixApplyZone, addr, nil)
	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}
	if zd.IncomingSerial != 20 {
		t.Errorf("secondary serial %d, want 20", zd.IncomingSerial)
	}
	if owner, _ := zd.GetOwner("fresh.example."); owner == nil {
		t.Error("the full-zone answer was not adopted")
	}
}

// TestIxfrInDisabledUsesAxfr: with no-request-ixfr the transfer path behaves
// exactly as it did before C2.
func TestIxfrInDisabledUsesAxfr(t *testing.T) {
	authApp(t)
	newer := `example.	3600	IN	SOA	ns.example. hostmaster.example. 20 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
`
	_, addr, stop := ixfrTestPrimary(t, newer)
	defer stop()

	zd := ixfrTestSecondary(t, ixApplyZone, addr, map[ZoneOption]bool{OptNoRequestIxfr: true})
	if zd.requestIxfr() {
		t.Fatal("no-request-ixfr did not turn the option off")
	}
	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}
	if zd.IncomingSerial != 20 {
		t.Errorf("secondary serial %d, want 20", zd.IncomingSerial)
	}
}

// TestRequestIxfrDefaultsOn: absence means enabled, and the explicit spellings
// both work, with off winning over on.
func TestRequestIxfrDefaultsOn(t *testing.T) {
	for _, tc := range []struct {
		what string
		opts map[ZoneOption]bool
		want bool
	}{
		{"absent", nil, true},
		{"explicitly on", map[ZoneOption]bool{OptRequestIxfr: true}, true},
		{"explicitly off", map[ZoneOption]bool{OptNoRequestIxfr: true}, false},
		{"both: off wins", map[ZoneOption]bool{OptRequestIxfr: true, OptNoRequestIxfr: true}, false},
	} {
		t.Run(tc.what, func(t *testing.T) {
			zd := &ZoneData{ZoneName: "example.", Options: tc.opts}
			if got := zd.requestIxfr(); got != tc.want {
				t.Errorf("requestIxfr() = %v, want %v", got, tc.want)
			}
		})
	}
}

// -------------------------------------------------------- onward relay (§5)

// ixfrPrimedSecondary builds a primary with a chain, pulls it into a secondary
// via a delta, and returns both plus the primary's shutdown.
func ixfrPrimedSecondary(t *testing.T, secOpts map[ZoneOption]bool) (*ZoneData, *ZoneData, func()) {
	t.Helper()
	pzd, addr, stop := ixfrTestPrimary(t, ixApplyZone)
	base := pzd.publishedSnapshot().Serial

	Zones.Set("example.", pzd)
	stageAndPublish(t, pzd, stageAddA(t, pzd, "one.example.", "10.1.0.1"))
	stageAndPublish(t, pzd, stageAddA(t, pzd, "two.example.", "10.1.0.2"))
	Zones.Remove("example.")

	zd := ixfrTestSecondary(t, ixApplyZone, addr, secOpts)
	zd.IncomingSerial = base
	zd.CurrentSerial = base
	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}
	return pzd, zd, stop
}

// TestIxfrInKeepsTheOutboundChain is §5: a mirroring secondary that applied a
// delta has NOT started a new IXFR epoch, so its own downstreams can still be
// served incrementally across the refresh boundary.
//
// Before this, every inbound refresh set wsIxfrEpochReset and every cascaded
// secondary forced all of its downstreams to a full transfer on every change.
func TestIxfrInKeepsTheOutboundChain(t *testing.T) {
	authApp(t)
	_, zd, stop := ixfrPrimedSecondary(t, nil)
	defer stop()

	chain := chainOf(zd)
	if len(chain) == 0 {
		t.Fatal("the secondary reset its outbound IXFR chain after applying a delta; " +
			"every downstream would be forced to AXFR across each refresh")
	}
	last := chain[len(chain)-1]
	if last.ToSerial != zd.IncomingSerial {
		t.Errorf("chain ends at serial %d, zone is at %d: the link does not describe "+
			"the copy being served", last.ToSerial, zd.IncomingSerial)
	}
}

// TestSignsItsOwnContent covers the predicate §5 scopes onward relay by. It
// does NOT cover the chain actually resetting for a signing secondary -- the
// name it used to carry claimed that and this only tests the predicate.
func TestSignsItsOwnContent(t *testing.T) {
	zd := &ZoneData{
		ZoneName: "example.", Options: map[ZoneOption]bool{OptInlineSigning: true},
	}
	if !zd.signsItsOwnContent() {
		t.Fatal("a zone with inline-signing should count as signing its own content")
	}
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	if !zd.signsItsOwnContent() {
		t.Error("a zone with online-signing should count as signing its own content")
	}
	zd.Options = map[ZoneOption]bool{}
	if zd.signsItsOwnContent() {
		t.Error("a plain mirror should not count as signing its own content")
	}
}

// TestIxfrRelayToADownstream is the three-instance case §6 asks for:
// primary → secondary → edge, all IXFR-enabled. The edge must pull the change
// from the secondary AS A DELTA, not as a full zone.
//
// This is the whole point of §5. Asserting only that the edge converges would
// prove nothing, because the AXFR fallback converges identically — so the
// outcome of the edge's transfer is what is checked.
func TestIxfrRelayToADownstream(t *testing.T) {
	authApp(t)
	_, sec, stopPrimary := ixfrPrimedSecondary(t, nil)
	defer stopPrimary()

	if len(chainOf(sec)) == 0 {
		t.Fatal("precondition: the secondary should have kept its chain")
	}
	secSerial := sec.IncomingSerial

	// Serve the secondary to a downstream of its own.
	sec.Ready = true
	sec.Status = ZoneStatusReady
	sec.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}}
	secAddr, stopSec := serveTestPrimary(t, sec)
	defer stopSec()

	// An edge sitting at the serial the secondary held before the delta.
	edge := &ZoneData{
		ZoneName: "example.", ZoneStore: MapZone, ZoneType: Secondary,
		Logger:    discardLogger(),
		Upstreams: []PeerConf{{Addr: secAddr}},
	}
	if _, _, err := edge.ReadZoneData(ixApplyZone, true); err != nil {
		t.Fatalf("edge ReadZoneData: %v", err)
	}
	edge.InstallInitialSnapshot()
	t.Cleanup(edge.stopPublisher)
	from := chainOf(sec)[0].FromSerial

	outcome, rrs, err := edge.ixfrTransferIn(context.Background(), edge.Upstreams[0], from, &Config{})
	if err != nil {
		t.Fatalf("edge ixfrTransferIn: %v", err)
	}
	if outcome != ixfrDelta {
		t.Fatalf("the secondary answered its downstream with %s, want delta: the "+
			"inbound refresh reset the outbound chain after all", outcome)
	}
	steps, perr := parseIxfrDeltas("example.", rrs, from)
	if perr != nil {
		t.Fatalf("the delta the secondary relayed does not parse: %v", perr)
	}
	if got := ixfrTargetSerial(steps); got != secSerial {
		t.Errorf("relayed delta ends at serial %d, secondary serves %d", got, secSerial)
	}
}

// ------------------------------------------------- self-healing (§1)

// startBadIxfrPrimary answers IXFR with a deliberately broken difference
// stream and AXFR with the real zone, so a test can watch the fallback work.
//
// A real tdns primary cannot be made to send a bad delta, which is the point:
// the invariant in §1 is about surviving primaries that are wrong, and the only
// way to test it is to be one.
func startBadIxfrPrimary(t *testing.T, zoneStr string, bad []dns.RR) (string, func()) {
	t.Helper()
	pzd := &ZoneData{
		ZoneName: "example.", ZoneStore: MapZone, ZoneType: Primary,
		Logger: discardLogger(), Ready: true, Status: ZoneStatusReady,
		Downstreams: []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}},
	}
	if _, _, err := pzd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	pzd.InstallInitialSnapshot()
	t.Cleanup(pzd.stopPublisher)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srvCtx, srvCancel := context.WithCancel(context.Background())
	mux := dns.NewServeMux()
	mux.HandleFunc("example.", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeIXFR {
			// Buffered: if tr.Out returns without receiving -- which it does
			// on a write error -- an unbuffered send would strand this
			// goroutine for the life of the test binary.
			ch := make(chan *dns.Envelope, 1)
			tr := new(dns.Transfer)
			go func() { ch <- &dns.Envelope{RR: bad}; close(ch) }()
			_ = tr.Out(w, r, ch)
			// Close explicitly once the body is out. A real primary ends the
			// stream with a record the client can recognise as the end; a
			// stream this broken has none, so without an EOF the client waits
			// out its read timeout before giving up. The fallback works either
			// way -- this just keeps the test measuring the parse refusal
			// rather than two seconds of miekg's default timeout.
			w.Close()
			return
		}
		_, _ = pzd.ZoneTransferOut(srvCtx, w, r, nil)
	})
	started := make(chan struct{})
	srv := &dns.Server{Listener: ln, Handler: mux, MsgAcceptFunc: MsgAcceptFunc,
		NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("bad-ixfr primary did not start")
	}
	return ln.Addr().String(), func() {
		srvCancel()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	}
}

// TestIxfrInSelfHealsOnABadDelta is §1's invariant, which is the reason the
// whole delta path is allowed to be as intricate as it is: any doubt costs a
// wasteful full transfer and never a corrupt local zone.
func TestIxfrInSelfHealsOnABadDelta(t *testing.T) {
	authApp(t)
	newer := `example.	3600	IN	SOA	ns.example. hostmaster.example. 20 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
healed.example.	3600	IN	A	10.7.7.7
`
	for _, tc := range []struct {
		what string
		bad  func(t *testing.T) []dns.RR
	}{
		{
			what: "non-contiguous difference sequences",
			bad: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 20),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 12), ixA(t, "b.example.", "10.0.0.2"), // gap
					ixSOA(t, 20),
				}
			},
		},
		{
			what: "deletes a record we do not hold",
			bad: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 20),
					ixSOA(t, 7), ixA(t, "nowhere.example.", "192.0.2.99"),
					ixSOA(t, 20), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 20),
				}
			},
		},
		{
			what: "adds an out-of-bailiwick name",
			bad: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 20),
					ixSOA(t, 7), ixA(t, "www.example.", "10.0.0.3"),
					ixSOA(t, 20), ixA(t, "evil.test.", "10.0.0.2"),
					ixSOA(t, 20),
				}
			},
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			addr, stop := startBadIxfrPrimary(t, newer, tc.bad(t))
			defer stop()

			zd := ixfrTestSecondary(t, ixApplyZone, addr, nil)
			zd.IncomingSerial = 7
			zd.CurrentSerial = 7

			if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
				t.Fatalf("FetchFromUpstream: %v", err)
			}
			// Converged through the AXFR fallback, on the SAME upstream.
			if zd.IncomingSerial != 20 {
				t.Errorf("serial %d, want 20 from the AXFR fallback", zd.IncomingSerial)
			}
			if owner, _ := zd.GetOwner("healed.example."); owner == nil {
				t.Error("the zone did not converge: the bad delta was not recovered from")
			}
			// And nothing from the bad delta leaked in.
			if owner, _ := zd.GetOwner("evil.test."); owner != nil {
				t.Error("an out-of-bailiwick name from the refused delta is in the zone")
			}
			if owner, _ := zd.GetOwner("b.example."); owner != nil {
				t.Error("a record from the refused delta is in the zone")
			}
		})
	}
}

// TestIxfrInAgainstAnAxfrOnlyPrimary is the compatibility case: a primary that
// has never heard of IXFR and REFUSES the qtype outright, rather than
// answering it with a full zone.
//
// Distinct from TestIxfrInFallsBackToFullZone, which covers a primary that
// answers the IXFR (with everything). Here the request itself is rejected, so
// the recovery is the transport-level fallback rather than the classification
// one -- and since request-ixfr is ON by default, every secondary in an
// existing deployment meets this on its first refresh after an upgrade.
func TestIxfrInAgainstAnAxfrOnlyPrimary(t *testing.T) {
	authApp(t)
	newer := `example.	3600	IN	SOA	ns.example. hostmaster.example. 20 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
old.example.	3600	IN	A	10.5.5.5
`
	pzd := &ZoneData{
		ZoneName: "example.", ZoneStore: MapZone, ZoneType: Primary,
		Logger: discardLogger(), Ready: true, Status: ZoneStatusReady,
		Downstreams: []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}},
	}
	if _, _, err := pzd.ReadZoneData(newer, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	pzd.InstallInitialSnapshot()
	t.Cleanup(pzd.stopPublisher)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srvCtx, srvCancel := context.WithCancel(context.Background())
	mux := dns.NewServeMux()
	mux.HandleFunc("example.", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeIXFR {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNotImplemented)
			_ = w.WriteMsg(m)
			return
		}
		_, _ = pzd.ZoneTransferOut(srvCtx, w, r, nil)
	})
	started := make(chan struct{})
	srv := &dns.Server{Listener: ln, Handler: mux, MsgAcceptFunc: MsgAcceptFunc,
		NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("axfr-only primary did not start")
	}
	defer func() {
		srvCancel()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	}()

	zd := ixfrTestSecondary(t, ixApplyZone, ln.Addr().String(), nil)
	if !zd.requestIxfr() {
		t.Fatal("precondition: request-ixfr should be on by default")
	}

	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream against an AXFR-only primary: %v", err)
	}
	if zd.IncomingSerial != 20 {
		t.Errorf("serial %d, want 20: the AXFR fallback did not run", zd.IncomingSerial)
	}
	if owner, _ := zd.GetOwner("old.example."); owner == nil {
		t.Error("the zone did not converge against an AXFR-only primary")
	}
}

// --------------------------------------------------- option parsing (F1)

// TestRequestIxfrOptionsAreSecondaryOnly: the option decides whether a zone
// asks its PRIMARY for a delta, so on a primary it is inert -- and an inert
// option produces no symptom at all, which is exactly why the config mistake
// has to be reported rather than silently accepted.
func TestRequestIxfrOptionsAreSecondaryOnly(t *testing.T) {
	for _, opt := range []string{"request-ixfr", "no-request-ixfr"} {
		t.Run(opt+" on a secondary is accepted", func(t *testing.T) {
			zd := &ZoneData{ZoneName: "example."}
			zconf := &ZoneConf{Name: "example.", Type: "secondary", OptionsStrs: []string{opt}}
			options := parseZoneOptions(&Config{}, "example.", zconf, zd)

			if !options[StringToZoneOption[opt]] {
				t.Errorf("%s was not enabled on a secondary: %v", opt, options)
			}
			for _, e := range zd.ErrorList() {
				t.Errorf("unexpected %s error on a valid option: %q", ErrorTypeToString[e.Type], e.Msg)
			}
		})

		t.Run(opt+" on a primary warns and is dropped", func(t *testing.T) {
			zd := &ZoneData{ZoneName: "example."}
			zconf := &ZoneConf{Name: "example.", Type: "primary", OptionsStrs: []string{opt}}
			options := parseZoneOptions(&Config{}, "example.", zconf, zd)

			if options[StringToZoneOption[opt]] {
				t.Errorf("%s was accepted on a primary, where it does nothing", opt)
			}
			var warned bool
			for _, e := range zd.ErrorList() {
				switch e.Type {
				case ConfigWarning:
					warned = true
				case ConfigError:
					t.Errorf("an inert option raised a ConfigError, which is "+
						"service-impacting: a healthy zone would go dark over a "+
						"setting that does nothing. msg=%q", e.Msg)
				}
			}
			if !warned {
				t.Errorf("%s on a primary was dropped silently; the operator gets "+
					"no signal that their config does nothing", opt)
			}
		})
	}
}

// TestConfigWarningIsNotServiceImpacting pins the property the choice above
// depends on. If ConfigWarning is ever added to serviceImpactingErrors, the
// warning above becomes an outage.
func TestConfigWarningIsNotServiceImpacting(t *testing.T) {
	zd := &ZoneData{ZoneName: "example."}
	zd.SetError(ConfigWarning, "an inert option")
	if zd.HasServiceImpactingError() {
		t.Error("ConfigWarning is service-impacting; a zone would stop answering " +
			"because of a config setting that has no effect")
	}
}

// TestApplyIxfrRefusesDuplicateAdds: the plan lists an add that duplicates
// alongside a delete that matches nothing, and for the same reason -- both mean
// our base is not the base the delta was computed against. Appending anyway
// would also be a way for a primary to grow one of our RRsets without bound.
func TestApplyIxfrRefusesDuplicateAdds(t *testing.T) {
	zd := ixBase(t, ixApplyZone)
	data, signed := materializeForIxfr(zd.publishedSnapshot())

	// www.example. already holds 10.0.0.3 in the base zone.
	steps := []ixfrStep{{from: 7, to: 8, added: []dns.RR{ixA(t, "www.example.", "10.0.0.3")}}}
	if err := applyIxfrSteps("example.", data, signed, steps); err == nil {
		t.Error("apply accepted an add of a record already present; the zone would " +
			"hold the same RR twice")
	}
	// The same record at a different value is an ordinary add.
	data2, signed2 := materializeForIxfr(zd.publishedSnapshot())
	steps2 := []ixfrStep{{from: 7, to: 8, added: []dns.RR{ixA(t, "www.example.", "10.0.0.99")}}}
	if err := applyIxfrSteps("example.", data2, signed2, steps2); err != nil {
		t.Errorf("apply refused a genuine add: %v", err)
	}
}

// TestApplyIxfrRefusesStrippedNSECSignature is the denial-chain half of the
// leftover-unsigned rule. An NSEC left standing without its RRSIG is a name
// asserting what does not exist with nothing to prove it -- the same failure as
// an unsigned RRset, on the record that the whole negative-answer path rests on.
func TestApplyIxfrRefusesStrippedNSECSignature(t *testing.T) {
	nsec := "example.\t3600\tIN\tNSEC\tns.example. NS SOA RRSIG NSEC"
	nsig := "example.\t3600\tIN\tRRSIG\tNSEC 13 2 3600 20260101000000 20251201000000 12345 example. AAAA"
	zd := ixBase(t, ixApplyZone+nsec+"\n"+nsig+"\n")

	data, signed := materializeForIxfr(zd.publishedSnapshot())
	if !signed[signedKey{owner: "example.", rrtype: dns.TypeNSEC}] {
		t.Fatal("the NSEC's signature was not recorded; the check below cannot fire")
	}

	steps := []ixfrStep{{from: 7, to: 8, removed: []dns.RR{mustRR(t, nsig)}}}
	if err := applyIxfrSteps("example.", data, signed, steps); err == nil {
		t.Error("apply accepted a delta that strips an NSEC's signature while " +
			"leaving the NSEC in place")
	}

	// Removing the NSEC together with its signature is fine.
	data2, signed2 := materializeForIxfr(zd.publishedSnapshot())
	steps2 := []ixfrStep{{from: 7, to: 8, removed: []dns.RR{mustRR(t, nsig), mustRR(t, nsec)}}}
	if err := applyIxfrSteps("example.", data2, signed2, steps2); err != nil {
		t.Errorf("apply refused removing an NSEC and its signature together: %v", err)
	}
}

// ---------------------------------------------- the named failure modes

// TestForcedRetransferUsesAxfr: a forced retransfer of an UNCHANGED serial is
// how a wedged downstream gets the zone re-fetched. An IXFR from our own
// serial answers with a single SOA, which is either read as a no-op --
// defeating the force -- or run through the full-zone apply, publishing a zone
// consisting of one record. Neither may happen, so force never asks.
func TestForcedRetransferUsesAxfr(t *testing.T) {
	authApp(t)
	pzd, addr, stop := ixfrTestPrimary(t, ixApplyZone)
	defer stop()

	zd := ixfrTestSecondary(t, ixApplyZone, addr, nil)
	serial := pzd.publishedSnapshot().Serial
	zd.IncomingSerial = serial
	zd.CurrentSerial = serial

	before := len(zd.publishedSnapshot().Data)
	if _, err := zd.FetchFromUpstream(context.Background(), false, false, true, nil, &Config{}); err != nil {
		t.Fatalf("forced retransfer: %v", err)
	}

	// The zone is whole, not a lone SOA, and the serial did not move.
	if got := len(zd.publishedSnapshot().Data); got != before {
		t.Errorf("zone has %d owners after a forced retransfer, had %d; a single-SOA "+
			"reply was applied as if it were a zone", got, before)
	}
	if zd.IncomingSerial != serial {
		t.Errorf("serial moved to %d on a forced retransfer of %d", zd.IncomingSerial, serial)
	}
	if owner, _ := zd.GetOwner("www.example."); owner == nil {
		t.Error("the forced retransfer left the zone without its records")
	}
}

// TestUpToDateReplyChangesNothing: the single-SOA answer is neither an error
// nor a zone. It must leave the served copy exactly as it was -- no swap, no
// serial move -- rather than being run through the full-zone apply.
func TestUpToDateReplyChangesNothing(t *testing.T) {
	authApp(t)
	pzd, addr, stop := ixfrTestPrimary(t, ixApplyZone)
	defer stop()

	zd := ixfrTestSecondary(t, ixApplyZone, addr, nil)
	serial := pzd.publishedSnapshot().Serial
	zd.IncomingSerial = serial
	zd.CurrentSerial = serial

	// Asking from the serial the primary already has is the up-to-date case.
	outcome, rrs, err := zd.ixfrTransferIn(context.Background(), zd.Upstreams[0], serial, &Config{})
	if err != nil {
		t.Fatalf("ixfrTransferIn: %v", err)
	}
	if outcome != ixfrUpToDate {
		t.Fatalf("outcome %s, want up-to-date", outcome)
	}
	if len(rrs) != 1 {
		t.Errorf("up-to-date reply carried %d records, want the single SOA", len(rrs))
	}

	before := len(zd.publishedSnapshot().Data)
	updated, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{})
	if err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}
	if updated {
		t.Error("an up-to-date reply reported the zone as updated")
	}
	if got := len(zd.publishedSnapshot().Data); got != before {
		t.Errorf("zone has %d owners after an up-to-date reply, had %d", got, before)
	}
	if zd.IncomingSerial != serial {
		t.Errorf("serial moved to %d on an up-to-date reply", zd.IncomingSerial)
	}
}

// TestSigningSecondaryDoesNotAskForDeltas is what the old
// TestIxfrInResetsTheChainForASigningSecondary name claimed and did not do.
// A signing secondary's baseline is its own signatures, so a delta computed
// against the primary's copy cannot apply to it -- asking costs a round trip
// that could not have worked.
func TestSigningSecondaryDoesNotAskForDeltas(t *testing.T) {
	authApp(t)
	newer := `example.	3600	IN	SOA	ns.example. hostmaster.example. 20 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
signed.example.	3600	IN	A	10.4.4.4
`
	_, addr, stop := ixfrTestPrimary(t, newer)
	defer stop()

	zd := ixfrTestSecondary(t, ixApplyZone, addr, map[ZoneOption]bool{OptInlineSigning: true})
	if !zd.signsItsOwnContent() {
		t.Fatal("precondition: inline-signing should count as signing its own content")
	}
	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}
	if zd.IncomingSerial != 20 {
		t.Errorf("serial %d, want 20 -- the AXFR did not run", zd.IncomingSerial)
	}
	// No delta was even attempted.
	if zd.ixfrDerived {
		t.Error("a signing secondary applied a delta; its baseline is its own " +
			"signatures, not the primary's")
	}
}

// TestShouldRequestIxfr asserts the attempt decision directly, clause by
// clause.
//
// The end-to-end tests below cannot do this. A test primary with no delta
// history answers a full zone whether or not we asked for one, so removing a
// clause from the predicate leaves every observable outcome identical --
// verified by mutation: dropping !force and dropping !signsItsOwnContent both
// left the behavioural tests green.
func TestShouldRequestIxfr(t *testing.T) {
	base := func(t *testing.T) *ZoneData {
		zd := ixBase(t, ixApplyZone)
		zd.ZoneType = Secondary
		zd.IncomingSerial = 7
		zd.Options = map[ZoneOption]bool{}
		return zd
	}

	for _, tc := range []struct {
		what  string
		setup func(*ZoneData)
		force bool
		want  bool
	}{
		{"a plain mirror with a baseline asks", nil, false, true},
		{"turned off by the operator",
			func(z *ZoneData) { z.Options[OptNoRequestIxfr] = true }, false, false},
		{"no serial to ask from",
			func(z *ZoneData) { z.IncomingSerial = 0 }, false, false},
		{"forced retransfer wants the whole zone", nil, true, false},
		{"inline-signing: our baseline is our own signatures",
			func(z *ZoneData) { z.Options[OptInlineSigning] = true }, false, false},
		{"online-signing likewise",
			func(z *ZoneData) { z.Options[OptOnlineSigning] = true }, false, false},
	} {
		t.Run(tc.what, func(t *testing.T) {
			zd := base(t)
			if tc.setup != nil {
				tc.setup(zd)
			}
			if got := zd.shouldRequestIxfr(tc.force); got != tc.want {
				t.Errorf("shouldRequestIxfr(force=%v) = %v, want %v", tc.force, got, tc.want)
			}
		})
	}

	t.Run("no baseline to apply onto", func(t *testing.T) {
		zd := &ZoneData{ZoneName: "example.", ZoneType: Secondary, IncomingSerial: 7}
		if zd.shouldRequestIxfr(false) {
			t.Error("asked for a delta with no published snapshot to apply it to")
		}
	})
}

// TestIxfrResponseCapFallsBackToAxfr: unlike AXFR, this path must buffer, so
// an upstream that keeps sending is one we accumulate for. The cap turns that
// into an ordinary IXFR failure -- which means it has to abort and drain the
// stream first, exactly as cancellation does, or the reader parks on its next
// send while we open a second connection for the AXFR.
//
// The leak itself is not asserted here: goroutine counting is shared with every
// other test in the binary and moves under -race, which is a flake rather than
// a check. What this does assert is that hitting the cap is survivable and the
// zone still converges -- and if abort/drain ever deadlocked, this test hangs.
func TestIxfrResponseCapFallsBackToAxfr(t *testing.T) {
	authApp(t)
	newer := `example.	3600	IN	SOA	ns.example. hostmaster.example. 20 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
capped.example.	3600	IN	A	10.6.6.6
`
	// Any well-formed delta will do; the cap fires before it is ever parsed.
	bad := []dns.RR{
		ixSOA(t, 20),
		ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
		ixSOA(t, 20), ixA(t, "b.example.", "10.0.0.2"),
		ixSOA(t, 20),
	}
	addr, stop := startBadIxfrPrimary(t, newer, bad)
	defer stop()

	prev := maxIxfrResponseRRs
	maxIxfrResponseRRs = 2
	t.Cleanup(func() { maxIxfrResponseRRs = prev })

	zd := ixfrTestSecondary(t, ixApplyZone, addr, nil)
	zd.IncomingSerial = 7
	zd.CurrentSerial = 7

	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream after a capped IXFR: %v", err)
	}
	if zd.IncomingSerial != 20 {
		t.Errorf("serial %d, want 20 from the AXFR fallback", zd.IncomingSerial)
	}
	if owner, _ := zd.GetOwner("capped.example."); owner == nil {
		t.Error("the zone did not converge after the response cap fired")
	}
}
