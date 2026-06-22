/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func init() {
	// HSYNCPARAM is a private RR type that must be registered before
	// dns.NewRR can parse it.
	_ = core.RegisterHsyncparamRR()
}

// mustRR parses an RR string or fails the test.
func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", s, err)
	}
	return rr
}

// newMapZone builds a ready MapZone with the given owners pre-populated. Each
// entry in owners maps an owner name to its RRs (grouped into RRsets by type).
func newMapZone(name string, ztype ZoneType, owners map[string][]dns.RR) *ZoneData {
	zd := &ZoneData{
		ZoneName:  name,
		ZoneType:  ztype,
		ZoneStore: MapZone,
		Ready:     true,
		Data:      core.NewCmap[OwnerData](),
		Options:   map[ZoneOption]bool{},
	}
	for oname, rrs := range owners {
		od := OwnerData{Name: oname, RRtypes: NewRRTypeStore()}
		byType := map[uint16][]dns.RR{}
		for _, rr := range rrs {
			byType[rr.Header().Rrtype] = append(byType[rr.Header().Rrtype], rr)
		}
		for rrtype, list := range byType {
			od.RRtypes.Set(rrtype, core.RRset{Name: oname, RRtype: rrtype, RRs: list})
		}
		zd.Data.Set(oname, od)
	}
	return zd
}

// registerZones puts the zones in the global registry for FindZone and removes
// them on cleanup so tests don't leak into each other.
func registerZones(t *testing.T, zds ...*ZoneData) {
	t.Helper()
	for _, zd := range zds {
		Zones.Set(zd.ZoneName, zd)
	}
	t.Cleanup(func() {
		for _, zd := range zds {
			Zones.Remove(zd.ZoneName)
		}
	})
}

func TestApexHsyncparamFlags(t *testing.T) {
	tests := []struct {
		name   string
		rr     string
		pubkey bool
		pubcds bool
	}{
		{"none", "", false, false},
		{"pubkey", "example. 3600 IN HSYNCPARAM pubkey", true, false},
		{"pubcds", "example. 3600 IN HSYNCPARAM pubcds", false, true},
		{"both", "example. 3600 IN HSYNCPARAM pubkey pubcds", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owners := map[string][]dns.RR{}
			if tc.rr != "" {
				owners["example."] = []dns.RR{mustRR(t, tc.rr)}
			}
			zd := newMapZone("example.", Secondary, owners)
			hp := zd.apexHsyncparam()
			if tc.rr == "" {
				if hp != nil {
					t.Fatalf("expected nil HSYNCPARAM, got %+v", hp)
				}
				return
			}
			if hp == nil {
				t.Fatal("expected HSYNCPARAM, got nil")
			}
			if hp.HasPubkey() != tc.pubkey {
				t.Errorf("HasPubkey()=%v, want %v", hp.HasPubkey(), tc.pubkey)
			}
			if hp.HasPubcds() != tc.pubcds {
				t.Errorf("HasPubcds()=%v, want %v", hp.HasPubcds(), tc.pubcds)
			}
		})
	}
}

func TestApexNSNames(t *testing.T) {
	zd := newMapZone("example.", Secondary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN NS ns1.example."),
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
		},
	})
	names := zd.apexNSNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 NS names, got %d: %v", len(names), names)
	}
	want := map[string]bool{"ns1.example.": true, "ns.foobar.com.": true}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected NS name %q", n)
		}
	}
}

func TestReownRRs(t *testing.T) {
	src := []dns.RR{mustRR(t, "example. 3600 IN KEY 256 3 15 dGVzdA==")}
	out := reownRRs(src, "_sig0key.example._signal.ns.foobar.com.")
	if len(out) != 1 {
		t.Fatalf("expected 1 RR, got %d", len(out))
	}
	if got := out[0].Header().Name; got != "_sig0key.example._signal.ns.foobar.com." {
		t.Errorf("owner = %q, want re-owned signal name", got)
	}
	// Source must be untouched (dns.Copy, not mutation).
	if src[0].Header().Name != "example." {
		t.Errorf("source RR was mutated: name = %q", src[0].Header().Name)
	}
}

func TestRrsetContentEqual(t *testing.T) {
	a1 := mustRR(t, "x. 3600 IN KEY 256 3 15 AAAA")
	a2 := mustRR(t, "x. 3600 IN KEY 257 3 15 BBBB")
	// Same content, different TTL and order.
	b1 := mustRR(t, "x. 60 IN KEY 257 3 15 BBBB")
	b2 := mustRR(t, "x. 60 IN KEY 256 3 15 AAAA")

	if !rrsetContentEqual([]dns.RR{a1, a2}, []dns.RR{b1, b2}) {
		t.Error("expected equal (TTL- and order-insensitive)")
	}
	if rrsetContentEqual([]dns.RR{a1}, []dns.RR{a1, a2}) {
		t.Error("expected unequal (different cardinality)")
	}
	c := mustRR(t, "x. 3600 IN KEY 258 3 15 CCCC")
	if rrsetContentEqual([]dns.RR{a1, a2}, []dns.RR{a1, c}) {
		t.Error("expected unequal (different content)")
	}
}

// drainUpdateQ collects all pending UpdateRequests without blocking.
func drainUpdateQ(q chan UpdateRequest) []UpdateRequest {
	var out []UpdateRequest
	for {
		select {
		case ur := <-q:
			out = append(out, ur)
		default:
			return out
		}
	}
}

// signalTarget builds a primary target zone (foobar.com.) wired with an
// UpdateQ we can drain.
func signalTarget(name string, owners map[string][]dns.RR) (*ZoneData, chan UpdateRequest) {
	q := make(chan UpdateRequest, 16)
	zd := newMapZone(name, Primary, owners)
	zd.KeyDB = &KeyDB{UpdateQ: q}
	return zd, q
}

func TestRepublishPubkey_PublishesToLocalPrimary(t *testing.T) {
	child := newMapZone("example.", Secondary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubkey"),
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			mustRR(t, "example. 3600 IN KEY 256 3 15 dGVzdGtleQ=="),
		},
	})
	target, q := signalTarget("foobar.com.", nil)
	registerZones(t, child, target)

	child.RepublishAtSignalNames()

	urs := drainUpdateQ(q)
	if len(urs) != 1 {
		t.Fatalf("expected 1 UpdateRequest, got %d", len(urs))
	}
	ur := urs[0]
	if ur.Cmd != "ZONE-UPDATE" || ur.ZoneName != "foobar.com." || !ur.InternalUpdate {
		t.Fatalf("unexpected UpdateRequest: %+v", ur)
	}
	owner := "_sig0key.example._signal.ns.foobar.com."
	var sawDelete, sawAdd bool
	for _, rr := range ur.Actions {
		if rr.Header().Name != owner {
			t.Errorf("action owner = %q, want %q", rr.Header().Name, owner)
		}
		switch rr.Header().Class {
		case dns.ClassANY:
			sawDelete = true
			if rr.Header().Rrtype != dns.TypeKEY {
				t.Errorf("delete rrtype = %s, want KEY", dns.TypeToString[rr.Header().Rrtype])
			}
		case dns.ClassINET:
			sawAdd = true
			if _, ok := rr.(*dns.KEY); !ok {
				t.Errorf("add action is not a KEY: %T", rr)
			}
		}
	}
	if !sawDelete || !sawAdd {
		t.Errorf("expected both a delete-RRset and an add (delete=%v add=%v)", sawDelete, sawAdd)
	}
}

func TestRepublishPubcds_PublishesCDSAndCDNSKEY(t *testing.T) {
	child := newMapZone("example.", Secondary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubcds"),
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			mustRR(t, "example. 3600 IN CDS 12345 15 2 ABCDEF"),
			mustRR(t, "example. 3600 IN CDNSKEY 257 3 15 dGVzdA=="),
		},
	})
	target, q := signalTarget("foobar.com.", nil)
	registerZones(t, child, target)

	child.RepublishAtSignalNames()

	urs := drainUpdateQ(q)
	if len(urs) != 1 {
		t.Fatalf("expected 1 UpdateRequest, got %d", len(urs))
	}
	owner := "_dsboot.example._signal.ns.foobar.com."
	var cds, cdnskey, deletes int
	for _, rr := range urs[0].Actions {
		if rr.Header().Name != owner {
			t.Errorf("action owner = %q, want %q", rr.Header().Name, owner)
		}
		if rr.Header().Class == dns.ClassANY {
			deletes++
			continue
		}
		switch rr.(type) {
		case *dns.CDS:
			cds++
		case *dns.CDNSKEY:
			cdnskey++
		}
	}
	if cds != 1 || cdnskey != 1 {
		t.Errorf("expected 1 CDS and 1 CDNSKEY add, got cds=%d cdnskey=%d", cds, cdnskey)
	}
	if deletes != 2 {
		t.Errorf("expected 2 delete-RRset actions (CDS + CDNSKEY), got %d", deletes)
	}
}

func TestRepublish_SkipsNonPrimaryTarget(t *testing.T) {
	child := newMapZone("example.", Secondary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubkey"),
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			mustRR(t, "example. 3600 IN KEY 256 3 15 dGVzdA=="),
		},
	})
	// Target zone exists but we are only SECONDARY for it: must be skipped.
	target, q := signalTarget("foobar.com.", nil)
	target.ZoneType = Secondary
	registerZones(t, child, target)

	child.RepublishAtSignalNames()

	if urs := drainUpdateQ(q); len(urs) != 0 {
		t.Fatalf("expected no publish for a non-primary target, got %d", len(urs))
	}
}

func TestRepublish_SkipsNSWithNoLocalZone(t *testing.T) {
	child := newMapZone("example.", Secondary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubkey"),
			mustRR(t, "example. 3600 IN NS ns.elsewhere.net."),
			mustRR(t, "example. 3600 IN KEY 256 3 15 dGVzdA=="),
		},
	})
	registerZones(t, child) // no zone covering ns.elsewhere.net.

	// Should not panic and should produce no updates.
	child.RepublishAtSignalNames()
}

func TestRepublish_ChangeGateNoOpWhenAlreadyPublished(t *testing.T) {
	owner := "_sig0key.example._signal.ns.foobar.com."
	child := newMapZone("example.", Secondary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubkey"),
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			mustRR(t, "example. 3600 IN KEY 256 3 15 dGVzdGtleQ=="),
		},
	})
	// Target ALREADY has the signal KEY (same content, different TTL).
	target, q := signalTarget("foobar.com.", map[string][]dns.RR{
		owner: {mustRR(t, owner+" 60 IN KEY 256 3 15 dGVzdGtleQ==")},
	})
	registerZones(t, child, target)

	child.RepublishAtSignalNames()

	if urs := drainUpdateQ(q); len(urs) != 0 {
		t.Fatalf("expected no-op when signal RRset already matches, got %d updates", len(urs))
	}
}

func TestRepublish_FlagsGatedIndependently(t *testing.T) {
	pubkeyOwner := "_sig0key.example._signal.ns.foobar.com."
	child := newMapZone("example.", Secondary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubkey pubcds"),
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			mustRR(t, "example. 3600 IN KEY 256 3 15 dGVzdGtleQ=="),
			mustRR(t, "example. 3600 IN CDS 12345 15 2 ABCDEF"),
		},
	})
	// pubkey is already published and matches; pubcds is not. Only the
	// pubcds (_dsboot) update should be emitted.
	target, q := signalTarget("foobar.com.", map[string][]dns.RR{
		pubkeyOwner: {mustRR(t, pubkeyOwner+" 3600 IN KEY 256 3 15 dGVzdGtleQ==")},
	})
	registerZones(t, child, target)

	child.RepublishAtSignalNames()

	urs := drainUpdateQ(q)
	if len(urs) != 1 {
		t.Fatalf("expected exactly 1 update (pubcds only), got %d", len(urs))
	}
	sawDsboot := false
	for _, rr := range urs[0].Actions {
		if rr.Header().Name == "_dsboot.example._signal.ns.foobar.com." {
			sawDsboot = true
		}
		if rr.Header().Name == pubkeyOwner {
			t.Error("pubkey should have been change-gated (already published)")
		}
	}
	if !sawDsboot {
		t.Error("expected a _dsboot (pubcds) action")
	}
}

func TestRepublish_NoHsyncparamIsNoOp(t *testing.T) {
	child := newMapZone("example.", Secondary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			mustRR(t, "example. 3600 IN KEY 256 3 15 dGVzdA=="),
		},
	})
	target, q := signalTarget("foobar.com.", nil)
	registerZones(t, child, target)

	child.RepublishAtSignalNames()

	if urs := drainUpdateQ(q); len(urs) != 0 {
		t.Fatalf("expected no-op without HSYNCPARAM, got %d updates", len(urs))
	}
}
