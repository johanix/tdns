/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * An RRset that arrives with differing TTLs -- from a zone file, an AXFR or an
 * IXFR delta -- is served at the largest of them, and a relayed signed copy
 * never above its signatures' original TTL (#996, part 1).
 */
package tdns

import (
	"bytes"
	"context"
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// servedTTLs returns the TTLs of the RRset the zone serves at (owner, rrtype),
// and those of its RRSIGs' original TTL.
func servedTTLs(t *testing.T, zd *ZoneData, owner string, rrtype uint16) (ttls, origTTLs []uint32, rs core.RRset) {
	t.Helper()
	od := zd.publishedSnapshot().Data[owner]
	if od == nil {
		t.Fatalf("%s is not served", owner)
	}
	rs = od.RRtypes.GetOnlyRRSet(rrtype)
	if len(rs.RRs) == 0 {
		t.Fatalf("no %s RRset served at %s", dns.TypeToString[rrtype], owner)
	}
	for _, rr := range rs.RRs {
		ttls = append(ttls, rr.Header().Ttl)
	}
	for _, rr := range rs.RRSIGs {
		origTTLs = append(origTTLs, rr.(*dns.RRSIG).OrigTtl)
	}
	return ttls, origTTLs, rs
}

func assertServedAt(t *testing.T, zd *ZoneData, how, owner string, rrtype uint16, want uint32, wantCount int) core.RRset {
	t.Helper()
	ttls, _, rs := servedTTLs(t, zd, owner, rrtype)
	if len(ttls) != wantCount {
		t.Errorf("%s: %s %s holds %d records, want %d", how, owner, dns.TypeToString[rrtype], len(ttls), wantCount)
	}
	for _, ttl := range ttls {
		if ttl != want {
			t.Errorf("%s: %s %s served at TTLs %v, want all %d", how, owner, dns.TypeToString[rrtype], ttls, want)
			break
		}
	}
	return rs
}

// loadZoneFile stands up a zone over a file and loads it as a server start
// does, through the refresh path, so the first published content is what a
// load makes of the file.
func loadZoneFile(t *testing.T, kdb *KeyDB, text string) *ZoneData {
	t.Helper()
	path := filepath.Join(t.TempDir(), "example.zone")
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		t.Fatalf("writing the zone file: %v", err)
	}
	zd := &ZoneData{
		ZoneName:      "example.",
		ZoneStore:     MapZone,
		ZoneType:      Primary,
		Zonefile:      path,
		Logger:        log.New(os.Stderr, "", 0),
		Options:       map[ZoneOption]bool{},
		KeyDB:         kdb,
		FirstZoneLoad: true,
		Data:          core.NewNameMap[OwnerData](),
	}
	Zones.Set("example.", zd)
	t.Cleanup(func() { Zones.Remove("example.") })
	t.Cleanup(zd.stopPublisher)
	if _, err := zd.Refresh(context.Background(), false, false, false, &Config{}); err != nil {
		t.Fatalf("first load: %v", err)
	}
	zd.InstallInitialSnapshot()
	return zd
}

// A zone file with an RRset at two TTLs is served at the larger, at the first
// load and at a reload; an RRset at one TTL keeps it.
func TestLoadOfMixedTTLsServesTheLargest(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := loadZoneFile(t, kdb, reloadText("100",
		"www.example.\t300\tIN\tA\t192.0.2.1\n"+
			"www.example.\t3600\tIN\tA\t192.0.2.2\n"+
			"www.example.\t600\tIN\tAAAA\t2001:db8::1\n"))
	assertServedAt(t, zd, "first load", "www.example.", dns.TypeA, 3600, 2)
	assertServedAt(t, zd, "first load", "www.example.", dns.TypeAAAA, 600, 1)

	operatorEdit(t, zd, reloadText("101",
		"www.example.\t3600\tIN\tA\t192.0.2.1\n"+
			"www.example.\t7200\tIN\tA\t192.0.2.2\n"+
			"www.example.\t60\tIN\tA\t192.0.2.3\n"))
	mustReload(t, zd, false)
	assertServedAt(t, zd, "reload", "www.example.", dns.TypeA, 7200, 3)
}

// A primary that serves an RRset at two TTLs (it loaded them as they were,
// without this unification) hands them to a secondary over AXFR, which serves
// the larger.
func TestAxfrOfMixedTTLsServesTheLargest(t *testing.T) {
	authApp(t)
	_, addr, stop := ixfrTestPrimary(t, `example.	3600	IN	SOA	ns.example. hostmaster.example. 20 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	300	IN	A	10.0.0.3
www.example.	3600	IN	A	10.0.0.4
`)
	defer stop()

	zd := ixfrTestSecondary(t, ixApplyZone, addr, map[ZoneOption]bool{OptNoRequestIxfr: true})
	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}
	if zd.IncomingSerial != 20 {
		t.Fatalf("secondary serial %d, want 20: the AXFR was not adopted", zd.IncomingSerial)
	}
	assertServedAt(t, zd, "AXFR", "www.example.", dns.TypeA, 3600, 2)
}

// A delta that adds a record above an RRset's TTL raises the RRset; one below
// leaves it. A later delta that deletes a record at the TTL it was added with
// still matches it: the delete is not taken for divergence.
func TestIxfrOfMixedTTLsServesTheLargest(t *testing.T) {
	authApp(t)
	zd := ixfrTestSecondary(t, ixApplyZone, "127.0.0.1:1", nil)
	rr := func(s string) dns.RR {
		t.Helper()
		r, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("NewRR %q: %v", s, err)
		}
		return r
	}

	applyIxfrAndPublish(t, zd, ixDeltaStream(t, 7, 8, nil, []dns.RR{rr("www.example. 7200 IN A 10.0.0.4")}))
	assertServedAt(t, zd, "a higher TTL added", "www.example.", dns.TypeA, 7200, 2)

	applyIxfrAndPublish(t, zd, ixDeltaStream(t, 8, 9, nil, []dns.RR{rr("www.example. 300 IN A 10.0.0.5")}))
	assertServedAt(t, zd, "a lower TTL added", "www.example.", dns.TypeA, 7200, 3)

	applyIxfrAndPublish(t, zd, ixDeltaStream(t, 9, 10, []dns.RR{rr("www.example. 300 IN A 10.0.0.5")}, nil))
	assertServedAt(t, zd, "the lower one deleted", "www.example.", dns.TypeA, 7200, 2)
	// The owners the deltas did not touch are untouched.
	assertServedAt(t, zd, "untouched", "ns.example.", dns.TypeA, 3600, 1)
}

// relayedSignedZone is a signed zone as a secondary receives it: www.example.
// A at two TTLs, under a signature whose original TTL is origTTL.
func relayedSignedZone(serial string, origTTL string) string {
	b64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, 64))
	return reloadText(serial,
		"www.example.\t300\tIN\tA\t192.0.2.1\n"+
			"www.example.\t3600\tIN\tA\t192.0.2.2\n") +
		"example.\t3600\tIN\tRRSIG\tSOA 15 1 3600 20991231000000 20260101000000 12345 example. " + b64 + "\n" +
		"www.example.\t" + origTTL + "\tIN\tRRSIG\tA 15 2 " + origTTL + " 20991231000000 20260101000000 12345 example. " + b64 + "\n"
}

// A signed copy this server relays keeps its signatures, so a unified RRset
// is never raised above their original TTL: below it, the largest TTL; above
// it, the original TTL. The signature is kept as it came, at the RRset's TTL.
func TestRelayedSignedCopyIsNeverRaisedAboveTheOriginalTTL(t *testing.T) {
	for _, tc := range []struct {
		origTTL string
		want    uint32
	}{{"1800", 1800}, {"7200", 3600}} {
		t.Run("orig "+tc.origTTL, func(t *testing.T) {
			authApp(t)
			_, addr, stop := ixfrTestPrimary(t, relayedSignedZone("20", tc.origTTL))
			defer stop()
			zd := ixfrTestSecondary(t, ixApplyZone, addr, map[ZoneOption]bool{OptNoRequestIxfr: true})
			if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
				t.Fatalf("FetchFromUpstream: %v", err)
			}
			rs := assertServedAt(t, zd, "relayed", "www.example.", dns.TypeA, tc.want, 2)
			if len(rs.RRSIGs) != 1 {
				t.Fatalf("the relayed RRset carries %d signatures, want the 1 it came with", len(rs.RRSIGs))
			}
			sig := rs.RRSIGs[0].(*dns.RRSIG)
			if sig.Hdr.Ttl != tc.want {
				t.Errorf("the RRSIG is served at TTL %d, want the RRset's %d", sig.Hdr.Ttl, tc.want)
			}
			if sig.Signature != base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, 64)) ||
				itoa(int(sig.OrigTtl)) != tc.origTTL {
				t.Errorf("the relayed signature was changed: %s", sig)
			}
		})
	}
}

// A file signed elsewhere with an RRset at two TTLs, reloaded unchanged,
// publishes nothing: the reloaded content is unified as the published content
// was, so the two compare equal.
func TestReloadOfAnUnchangedSignedFileWithMixedTTLsPublishesNothing(t *testing.T) {
	zd := loadZoneFile(t, newTestKeyDB(t), relayedSignedZone("100", "1800"))
	assertServedAt(t, zd, "first load", "www.example.", dns.TypeA, 1800, 2)
	before := zd.publishedSnapshot()
	mustReload(t, zd, true)
	if zd.publishedSnapshot() != before {
		t.Error("an unchanged signed file with mixed TTLs was published again")
	}
}

// A zone that signs its own content unifies an RRset to the largest TTL and
// signs it there, and then the signer's max-served clamp lowers it: unify
// first, then clamp. Clamping first would serve the RRset at the TTL of
// whichever record came first.
func TestSignedZoneUnifiesThenClamps(t *testing.T) {
	mixed := strings.Replace(resignZoneText,
		"alpha.resign.example.\t3600\tIN\tA\t192.0.2.1", "alpha.resign.example.\t300\tIN\tA\t192.0.2.1", 1)
	mixed = strings.Replace(mixed, "alpha.resign.example.\t3600\tIN\tA\t192.0.2.2",
		"alpha.resign.example.\t7200\tIN\tA\t192.0.2.2", 1)
	if mixed == resignZoneText {
		t.Fatal("setup: the zone text was not edited")
	}

	t.Run("no clamp", func(t *testing.T) {
		zd := resignTestZone(t, newTestKeyDB(t))
		serial := itoa(int(zd.publishedSnapshot().Serial) + 1)
		reloadSignedText(t, zd, strings.Replace(strings.Replace(mixed, "SERIAL", serial, 1), "BRAVO", "bravo", 1))
		assertServedTTL(t, zd, "signed here", "alpha.resign.example.", dns.TypeA, 7200)
		assertPublishedRRsetVerifies(t, zd, "alpha.resign.example.", dns.TypeA)
	})

	t.Run("max-served 600", func(t *testing.T) {
		zd := resignTestZone(t, newTestKeyDB(t))
		zd.DnssecPolicy.TTLS.MaxServed = 600
		serial := itoa(int(zd.publishedSnapshot().Serial) + 1)
		reloadSignedText(t, zd, strings.Replace(strings.Replace(mixed, "SERIAL", serial, 1), "BRAVO", "bravo", 1))
		assertServedTTL(t, zd, "signed here, clamped", "alpha.resign.example.", dns.TypeA, 600)
		assertPublishedRRsetVerifies(t, zd, "alpha.resign.example.", dns.TypeA)
	})
}

// A signed reload whose file holds an RRset at mixed TTLs, unified to what the
// zone already serves, keeps that RRset's signature: unification comes before
// the signatures of unchanged RRsets are carried.
func TestSignedReloadOfMixedTTLsKeepsTheSignature(t *testing.T) {
	zd := resignTestZone(t, newTestKeyDB(t))
	before := zd.publishedSnapshot()
	sigs := before.Data["alpha.resign.example."].RRtypes.GetOnlyRRSet(dns.TypeA).RRSIGs
	mixed := strings.Replace(resignZoneText,
		"alpha.resign.example.\t3600\tIN\tA\t192.0.2.1", "alpha.resign.example.\t300\tIN\tA\t192.0.2.1", 1)
	reloadSignedText(t, zd, strings.Replace(strings.Replace(mixed, "SERIAL", itoa(int(before.Serial)+1), 1), "BRAVO", "bravo-edited", 1))
	after := zd.publishedSnapshot()
	if after.Serial == before.Serial {
		t.Fatal("the edit was not published")
	}
	got := after.Data["alpha.resign.example."].RRtypes.GetOnlyRRSet(dns.TypeA).RRSIGs
	if len(got) != len(sigs) || got[0].String() != sigs[0].String() {
		t.Errorf("an RRset that unified to what was served was re-signed:\n before %v\n after  %v", sigs, got)
	}
	assertServedTTL(t, zd, "carried", "alpha.resign.example.", dns.TypeA, 3600)
}

// The unifier itself: what it leaves alone, and what it rewrites.
func TestUnifyAdoptedTTLs(t *testing.T) {
	build := func(text string) *core.NameMap[OwnerData] {
		t.Helper()
		zd := &ZoneData{ZoneName: "example.", ZoneStore: MapZone, Logger: discardLogger()}
		if _, _, err := zd.ReadZoneData(text, true); err != nil {
			t.Fatalf("ReadZoneData: %v", err)
		}
		return zd.Data
	}
	ttlsOf := func(data *core.NameMap[OwnerData], owner string, rrtype uint16) []uint32 {
		od, _ := data.Get(owner)
		var out []uint32
		for _, rr := range od.RRtypes.GetOnlyRRSet(rrtype).RRs {
			out = append(out, rr.Header().Ttl)
		}
		return out
	}
	text := reloadText("1",
		"example.\t300\tIN\tDNSKEY\t257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=\n"+
			"example.\t3600\tIN\tDNSKEY\t256 3 15 aCoBwkLT7u8LnBQJHfUObHqBsRlAcUSIQeq5ZbNLlSQ=\n"+
			"www.example.\t300\tIN\tA\t192.0.2.1\n"+
			"www.example.\t3600\tIN\tA\t192.0.2.2\n"+
			"one.example.\t300\tIN\tA\t192.0.2.3\n")

	// A zone that signs here leaves DNSKEY to its keystore (part 2).
	data := build(text)
	shared, _ := data.Get("www.example.")
	sharedRR := shared.RRtypes.GetOnlyRRSet(dns.TypeA).RRs[0]
	if n := unifyAdoptedTTLs(data, nil, true); n != 1 {
		t.Errorf("signs here: rewrote %d RRsets, want 1 (www A)", n)
	}
	if got := ttlsOf(data, "example.", dns.TypeDNSKEY); got[0] == got[1] {
		t.Errorf("signs here: the DNSKEY RRset was unified: %v", got)
	}
	if got := ttlsOf(data, "www.example.", dns.TypeA); got[0] != 3600 || got[1] != 3600 {
		t.Errorf("signs here: www A at %v, want 3600", got)
	}
	if sharedRR.Header().Ttl != 300 {
		t.Error("a record was rewritten in place rather than copied")
	}

	// A relay unifies DNSKEY too; an owner outside the set given is not walked.
	data = build(text)
	if n := unifyAdoptedTTLs(data, map[string]bool{"example.": true}, false); n != 1 {
		t.Errorf("relay, apex only: rewrote %d RRsets, want 1 (DNSKEY)", n)
	}
	if got := ttlsOf(data, "example.", dns.TypeDNSKEY); got[0] != 3600 || got[1] != 3600 {
		t.Errorf("relay: DNSKEY at %v, want 3600", got)
	}
	if got := ttlsOf(data, "www.example.", dns.TypeA); got[0] == got[1] {
		t.Errorf("relay, apex only: www A was walked: %v", got)
	}
}
