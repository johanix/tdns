/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func init() {
	// HSYNCPARAM is a private RR type that must be registered before
	// dns.NewRR can parse it.
	_ = core.RegisterHsyncparamRR()
}

// mustRR is shared with childsync_replace_test.go (same package).

// newMapZone builds a ready MapZone with the given owners pre-populated. Each
// entry in owners maps an owner name to its RRs (grouped into RRsets by type).
func newMapZone(name string, ztype ZoneType, owners map[string][]dns.RR) *ZoneData {
	zd := &ZoneData{
		ZoneName:  name,
		ZoneType:  ztype,
		ZoneStore: MapZone,
		Ready:     true,
		Data:      core.NewNameMap[OwnerData](),
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
	// Publish the initial snapshot so post-cutover readers (GetOwner, etc.) see
	// the data, mirroring what the refresh engine does for real zones.
	zd.InstallInitialSnapshot()
	return zd
}

// newOptedInChild builds a secondary customer zone whose operator has enabled
// use-hsyncparam -- the transfer-driven republish does nothing without it, so
// every republish test needs it. The tests that exercise the option gate
// itself construct their zone with newMapZone and set (or omit) it in view.
func newOptedInChild(name string, owners map[string][]dns.RR) *ZoneData {
	zd := newMapZone(name, Secondary, owners)
	zd.Options[OptUseHsyncparam] = true
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
		case ur, ok := <-q:
			if !ok {
				return out
			}
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
	// A real primary always has an apex SOA; inject one (merged with any
	// caller-supplied apex records) so InstallInitialSnapshot produces a
	// servable snapshot — the apex guard refuses apex-less zones.
	soa, _ := dns.NewRR(name + " 3600 IN SOA ns." + name + " hostmaster." + name + " 1 3600 600 604800 300")
	ns, _ := dns.NewRR(name + " 3600 IN NS ns." + name)
	full := map[string][]dns.RR{name: {soa, ns}}
	for oname, rrs := range owners {
		full[oname] = append(full[oname], rrs...)
	}
	zd := newMapZone(name, Primary, full)
	zd.KeyDB = &KeyDB{UpdateQ: q}
	return zd, q
}

func TestRepublishPubkey_PublishesToLocalPrimary(t *testing.T) {
	child := newOptedInChild("example.", map[string][]dns.RR{
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
	child := newOptedInChild("example.", map[string][]dns.RR{
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
	child := newOptedInChild("example.", map[string][]dns.RR{
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
	child := newOptedInChild("example.", map[string][]dns.RR{
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
	child := newOptedInChild("example.", map[string][]dns.RR{
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
	child := newOptedInChild("example.", map[string][]dns.RR{
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
	child := newOptedInChild("example.", map[string][]dns.RR{
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

// The option gate. Everything the republish needs is present -- pubkey flag,
// an apex KEY, an NS whose signal name falls in a local primary zone -- and
// the ONLY thing missing is the operator's use-hsyncparam. Nothing may be
// written: publishing into our own primary zone on the strength of a customer
// zone's signaling is exactly what the option authorizes.
func TestRepublish_WithoutUseHsyncparamIsNoOp(t *testing.T) {
	child := newMapZone("example.", Secondary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN HSYNCPARAM pubkey pubcds"),
			mustRR(t, "example. 3600 IN NS ns.foobar.com."),
			mustRR(t, "example. 3600 IN KEY 256 3 15 dGVzdGtleQ=="),
			mustRR(t, "example. 3600 IN CDS 12345 15 2 0102"),
		},
	})
	if child.Options[OptUseHsyncparam] {
		t.Fatal("newMapZone must not enable use-hsyncparam; the gate would not be under test")
	}
	target, q := signalTarget("foobar.com.", nil)
	registerZones(t, child, target)

	child.RepublishAtSignalNames()

	if urs := drainUpdateQ(q); len(urs) != 0 {
		t.Fatalf("republished without use-hsyncparam: %d updates", len(urs))
	}

	// And the same zone with the option on does publish -- so the no-op above
	// is the gate, not a broken fixture.
	child.Options[OptUseHsyncparam] = true
	child.RepublishAtSignalNames()
	if urs := drainUpdateQ(q); len(urs) != 2 {
		t.Fatalf("expected 2 updates (pubkey + pubcds) once opted in, got %d", len(urs))
	}
}

func TestSignalOwnerName(t *testing.T) {
	if got := signalOwnerName(signalPrefixSig0Key, "child.example.", "ns.provider.example."); got != "_sig0key.child.example._signal.ns.provider.example." {
		t.Fatalf("sig0key: %q", got)
	}
	// Unqualified inputs are qualified rather than producing a broken name.
	if got := signalOwnerName(signalPrefixDsboot, "child.example", "ns.provider.example"); got != "_dsboot.child.example._signal.ns.provider.example." {
		t.Fatalf("dsboot: %q", got)
	}
}

// ackUpdates drains q in the background, recording each request and answering
// its Resp (if any) with the given result, until the test ends. It does not
// apply anything to the zone, so the change gate does not see its "applies".
func ackUpdates(t *testing.T, q chan UpdateRequest, res ZoneUpdateResult) *[]UpdateRequest {
	t.Helper()
	var mu sync.Mutex
	var seen []UpdateRequest
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			case ur := <-q:
				mu.Lock()
				seen = append(seen, ur)
				mu.Unlock()
				if ur.Resp != nil {
					ur.Resp <- res
				}
			}
		}
	}()
	// Callers read after the publish returned, which happens after the ack,
	// so the slice is complete by then; the mutex covers the append.
	return &seen
}

// D-6: when the child selects at-ns, its keystore KEY is published at
// _sig0key.<child>._signal.<ns> for every NS whose signal name is in a local
// primary zone. The source is the keystore key, not the apex RRset, so this
// works before the asynchronous apex publication has landed.
func TestPublishSig0KeyAtSignalNames(t *testing.T) {
	// signalTarget gives child.example. an in-bailiwick NS (ns.child.example.),
	// whose signal name the zone itself owns; the second NS lives nowhere we serve.
	child, q := signalTarget("child.example.", map[string][]dns.RR{
		"child.example.": {mustRR(t, "child.example. 3600 IN NS ns.elsewhere.net.")},
	})
	registerZones(t, child)
	seen := ackUpdates(t, q, ZoneUpdateResult{Applied: true})

	key := mustRR(t, "child.example. 3600 IN KEY 256 3 15 dGVzdGtleQ==")
	if n := child.publishSig0KeyAtSignalNames(context.Background(), []dns.RR{key}); n != 1 {
		t.Fatalf("satisfied = %d, want 1 (one local signal name, one elsewhere)", n)
	}
	urs := *seen
	if len(urs) != 1 {
		t.Fatalf("expected 1 UpdateRequest, got %d", len(urs))
	}
	ur := urs[0]
	if ur.Cmd != "ZONE-UPDATE" || ur.ZoneName != "child.example." || !ur.InternalUpdate || ur.Resp == nil {
		t.Fatalf("unexpected UpdateRequest (a confirmed publish carries Resp): %+v", ur)
	}
	owner := "_sig0key.child.example._signal.ns.child.example."
	var sawDelete, sawAdd bool
	for _, rr := range ur.Actions {
		if rr.Header().Name != owner {
			t.Errorf("action owner = %q, want %q", rr.Header().Name, owner)
		}
		switch rr.Header().Class {
		case dns.ClassANY:
			sawDelete = true
		case dns.ClassINET:
			k, ok := rr.(*dns.KEY)
			if !ok || k.PublicKey != "dGVzdGtleQ==" {
				t.Errorf("add action = %s, want the keystore KEY", rr)
			}
			sawAdd = true
		}
	}
	if !sawDelete || !sawAdd {
		t.Errorf("expected delete-RRset + add (delete=%v add=%v)", sawDelete, sawAdd)
	}

	// The fake updater acknowledged without applying anything to the zone,
	// so the change gate (which reads zone data) still sees no KEY and a
	// second publish enqueues again. The gate itself is exercised by
	// TestRepublish_ChangeGateNoOpWhenAlreadyPublished, whose zone is seeded
	// with the record.
	if n := child.publishSig0KeyAtSignalNames(context.Background(), []dns.RR{key}); n != 1 {
		t.Fatalf("second publish satisfied = %d, want 1", n)
	}
	if len(*seen) != 2 {
		t.Fatalf("expected a second request against an unapplied zone, got %d", len(*seen))
	}
}

// A confirmed publish counts only an APPLIED update: a refused apply, or an
// updater that never answers, is "not published" -- the at-ns bootstrap then
// errors instead of sending a ceremony the parent cannot verify.
func TestPublishSig0KeyAtSignalNamesRequiresApply(t *testing.T) {
	key := mustRR(t, "child.example. 3600 IN KEY 256 3 15 dGVzdGtleQ==")

	t.Run("refused apply", func(t *testing.T) {
		child, q := signalTarget("child.example.", nil)
		registerZones(t, child)
		ackUpdates(t, q, ZoneUpdateResult{Err: errors.New("zone updater says no")})
		if n := child.publishSig0KeyAtSignalNames(context.Background(), []dns.RR{key}); n != 0 {
			t.Fatalf("satisfied = %d, want 0 for a refused apply", n)
		}
	})

	t.Run("updater never answers", func(t *testing.T) {
		prev := signalPublishApplyTimeout
		signalPublishApplyTimeout = 50 * time.Millisecond
		t.Cleanup(func() { signalPublishApplyTimeout = prev })
		child, q := signalTarget("child.example.", nil)
		registerZones(t, child)
		go func() { <-q }() // take the request, never respond
		if n := child.publishSig0KeyAtSignalNames(context.Background(), []dns.RR{key}); n != 0 {
			t.Fatalf("satisfied = %d, want 0 on apply timeout", n)
		}
	})

	t.Run("nil ctx only enqueues", func(t *testing.T) {
		child, q := signalTarget("child.example.", nil)
		registerZones(t, child)
		if n := child.publishAtSignalNames(nil, "test", signalSourceAtNs, signalPrefixSig0Key, []uint16{dns.TypeKEY}, []dns.RR{key}, child.apexNSNames(), false); n != 1 {
			t.Fatalf("fire-and-forget satisfied = %d, want 1", n)
		}
		urs := drainUpdateQ(q)
		if len(urs) != 1 || urs[0].Resp != nil {
			t.Fatalf("fire-and-forget must enqueue exactly one request without Resp: %+v", urs)
		}
	})
}

// After a SIG(0) rollover the signal names a bootstrap once populated are
// refreshed with the new key; ones never populated are left alone.
func TestRefreshSig0KeyAtSignalNamesOnlyExisting(t *testing.T) {
	owner := "_sig0key.child.example._signal.ns.child.example."
	child, q := signalTarget("child.example.", map[string][]dns.RR{
		owner: {mustRR(t, owner+" 3600 IN KEY 256 3 15 b2xk")},
	})
	fresh, q2 := signalTarget("fresh.example.", nil)
	registerZones(t, child, fresh)
	seen := ackUpdates(t, q, ZoneUpdateResult{Applied: true})

	if n := child.refreshSig0KeyAtSignalNames(context.Background(), []dns.RR{mustRR(t, "child.example. 3600 IN KEY 256 3 15 bmV3")}); n != 1 {
		t.Fatalf("refresh satisfied = %d, want 1", n)
	}
	urs := *seen
	if len(urs) != 1 {
		t.Fatalf("expected 1 UpdateRequest, got %d", len(urs))
	}
	var sawNew bool
	for _, rr := range urs[0].Actions {
		if k, ok := rr.(*dns.KEY); ok && rr.Header().Class == dns.ClassINET && k.PublicKey == "bmV3" {
			sawNew = true
		}
	}
	if !sawNew {
		t.Fatalf("refresh did not add the new key: %v", urs[0].Actions)
	}

	if n := fresh.refreshSig0KeyAtSignalNames(context.Background(), []dns.RR{mustRR(t, "fresh.example. 3600 IN KEY 256 3 15 bmV3")}); n != 0 {
		t.Fatalf("refresh of a never-populated zone satisfied %d, want 0", n)
	}
	if len(drainUpdateQ(q2)) != 0 {
		t.Fatal("refresh must not start populating a signal name a bootstrap never used")
	}
}

func TestCanPublishSig0KeyAtSignal(t *testing.T) {
	local, _ := signalTarget("local.example.", nil)
	away := newMapZone("away.example.", Primary, map[string][]dns.RR{
		"away.example.": {
			mustRR(t, "away.example. 3600 IN SOA ns.elsewhere.net. h.away.example. 1 3600 600 604800 300"),
			mustRR(t, "away.example. 3600 IN NS ns.elsewhere.net."),
		},
	})
	// A secondary cannot be updated, so a signal name in it does not count.
	sec := newMapZone("sec.example.", Secondary, map[string][]dns.RR{
		"sec.example.": {
			mustRR(t, "sec.example. 3600 IN SOA ns.sec.example. h.sec.example. 1 3600 600 604800 300"),
			mustRR(t, "sec.example. 3600 IN NS ns.sec.example."),
		},
	})
	registerZones(t, local, away, sec)

	if !local.canPublishSig0KeyAtSignal() {
		t.Fatal("local primary owning the signal name: want true")
	}
	if away.canPublishSig0KeyAtSignal() {
		t.Fatal("NS in a zone not served here: want false")
	}
	if sec.canPublishSig0KeyAtSignal() {
		t.Fatal("signal name in a local secondary: want false")
	}
}
