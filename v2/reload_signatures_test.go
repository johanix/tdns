/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #1006 part D: a reload of a signed zone keeps the signatures of what did not
// change, so its IXFR link holds the edit and nothing else.

const resignZoneText = `resign.example.	3600	IN	SOA	ns.resign.example. hostmaster.resign.example. SERIAL 7200 1800 604800 7200
resign.example.	3600	IN	NS	ns.resign.example.
resign.example.	3600	IN	MX	10 alpha.resign.example.
ns.resign.example.	3600	IN	A	192.0.2.53
ns.resign.example.	3600	IN	AAAA	2001:db8::53
alpha.resign.example.	3600	IN	A	192.0.2.1
alpha.resign.example.	3600	IN	A	192.0.2.2
alpha.resign.example.	3600	IN	AAAA	2001:db8::1
bravo.resign.example.	3600	IN	TXT	"BRAVO"
child.resign.example.	3600	IN	NS	ns1.child.resign.example.
ns1.child.resign.example.	3600	IN	A	192.0.2.54
`

// reloadSigned reloads the zone with the given serial and bravo TXT.
func reloadSigned(t *testing.T, zd *ZoneData, serial, bravo string) {
	t.Helper()
	reloadSignedText(t, zd, strings.Replace(strings.Replace(resignZoneText, "SERIAL", serial, 1), "BRAVO", bravo, 1))
}

// reloadSignedText replaces the zone with text as a reload of its file does.
func reloadSignedText(t *testing.T, zd *ZoneData, text string) {
	t.Helper()
	newZd := &ZoneData{ZoneName: zd.ZoneName, ZoneStore: MapZone, ZoneType: Primary, Logger: log.New(os.Stderr, "", 0)}
	if _, _, err := newZd.ReadZoneData(text, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.mu.Lock()
	err := zd.applyRefreshReplacementLocked(newZd, nil, false, true)
	zd.mu.Unlock()
	if err != nil {
		t.Fatalf("applyRefreshReplacementLocked: %v", err)
	}
}

func TestSignedReloadKeepsTheSignaturesOfWhatDidNotChange(t *testing.T) {
	zd := resignTestZone(t, newTestKeyDB(t))
	zd.SetOption(OptIxfrFromDifferences, true)
	before := zd.publishedSnapshot()
	base := servedRRs(before, zd.ZoneName)
	alphaSigs := before.Data["alpha.resign.example."].RRtypes.GetOnlyRRSet(dns.TypeA).RRSIGs

	reloadSigned(t, zd, itoa(int(before.Serial)+1), "bravo-edited")
	after := zd.publishedSnapshot()
	if after.Serial == before.Serial {
		t.Fatal("the edit was not published")
	}

	// The untouched RRset kept its signature.
	got := after.Data["alpha.resign.example."].RRtypes.GetOnlyRRSet(dns.TypeA).RRSIGs
	if len(got) != len(alphaSigs) || got[0].String() != alphaSigs[0].String() {
		t.Errorf("an unchanged RRset was re-signed:\n before %v\n after  %v", alphaSigs, got)
	}
	// The edited one is signed, over its new contents.
	bravo := after.Data["bravo.resign.example."].RRtypes.GetOnlyRRSet(dns.TypeTXT)
	if len(bravo.RRSIGs) == 0 || !strings.Contains(bravo.RRs[0].String(), "bravo-edited") {
		t.Fatalf("the edited RRset is not signed over its new contents: %v", bravo)
	}
	if bravo.RRSIGs[0].String() == before.Data["bravo.resign.example."].RRtypes.GetOnlyRRSet(dns.TypeTXT).RRSIGs[0].String() {
		t.Error("the edited RRset kept its old signature")
	}

	// One link, holding what an incremental update of the TXT would hold: the
	// TXT and its signature, the apex SOA's and DNSKEY's new signatures (the
	// file carries no DNSKEY, so the signer puts it back), and the NSEC
	// signatures the restitch rewrote around the edit and the apex. No other
	// RRset is re-signed.
	chain := chainOf(zd)
	if len(chain) == 0 {
		t.Fatal("the reload left no IXFR link")
	}
	link := chain[len(chain)-1]
	allowed := map[uint16]bool{dns.TypeTXT: true, dns.TypeSOA: true, dns.TypeDNSKEY: true, dns.TypeNSEC: true}
	for _, rs := range append(append([]core.RRset(nil), link.Removed...), link.Added...) {
		for _, rr := range rs.RRSIGs {
			if sig, ok := rr.(*dns.RRSIG); ok && !allowed[sig.TypeCovered] {
				t.Errorf("the reload re-signed an unchanged RRset: %s", rr)
			}
		}
		for _, rr := range rs.RRs {
			if rr.Header().Name != "bravo.resign.example." || rr.Header().Rrtype != dns.TypeTXT {
				t.Errorf("the reload's link carries a record the edit did not touch: %s", rr)
			}
		}
	}
	checkReplay(t, zd, before.Serial, base)
}

// Every NSEC takes the SOA's negative TTL, so when that changes no NSEC may be
// carried across the reload: the whole chain is rebuilt and re-signed at the
// new TTL. Checked on the served snapshot itself, since a link and a snapshot
// built from the same stale NSECs would agree with each other.
func TestSignedReloadRebuildsTheNsecChainWhenTheNegativeTTLChanges(t *testing.T) {
	zd := resignTestZone(t, newTestKeyDB(t))
	zd.SetOption(OptIxfrFromDifferences, true)
	before := zd.publishedSnapshot()
	base := servedRRs(before, zd.ZoneName)

	nsecTTLs := func(snap *zoneSnapshot, want uint32) {
		t.Helper()
		n := 0
		for name, od := range snap.Data {
			if od == nil {
				continue
			}
			for _, rr := range od.NSEC.RRs {
				n++
				if rr.Header().Ttl != want {
					t.Errorf("%s: NSEC TTL %d, want %d", name, rr.Header().Ttl, want)
				}
			}
			for _, rr := range od.NSEC.RRSIGs {
				if sig, ok := rr.(*dns.RRSIG); ok && sig.OrigTtl != want {
					t.Errorf("%s: NSEC signed over TTL %d, want %d", name, sig.OrigTtl, want)
				}
			}
		}
		if n == 0 {
			t.Fatalf("serial %d serves no NSEC", snap.Serial)
		}
	}
	// The negative TTL is the lower of the SOA's TTL (3600) and its minimum.
	nsecTTLs(before, 3600)

	text := strings.Replace(resignZoneText, "SERIAL 7200 1800 604800 7200", itoa(int(before.Serial)+1)+" 7200 1800 604800 600", 1)
	reloadSignedText(t, zd, strings.Replace(text, "BRAVO", "bravo", 1))
	after := zd.publishedSnapshot()
	if after.Serial == before.Serial {
		t.Fatal("the change was not published")
	}
	nsecTTLs(after, 600)
	checkReplay(t, zd, before.Serial, base)
}

// A signature covers the TTL, so only records identical in TTL as well keep one.
func TestIdenticalRecordsComparesTTLs(t *testing.T) {
	a := []dns.RR{mustRR(t, "x.example. 300 IN A 192.0.2.1"), mustRR(t, "x.example. 300 IN A 192.0.2.2")}
	reordered := []dns.RR{a[1], a[0]}
	retimed := []dns.RR{mustRR(t, "x.example. 600 IN A 192.0.2.1"), mustRR(t, "x.example. 600 IN A 192.0.2.2")}
	if !identicalRecords(a, reordered) {
		t.Error("the same records in another order compare as different")
	}
	if identicalRecords(a, retimed) {
		t.Error("records with a changed TTL compare as identical")
	}
	if identicalRecords(a, a[:1]) {
		t.Error("a record fewer compares as identical")
	}
}

// A TTL clamp the publish applies can lower the SOA's TTL, and with it the
// negative TTL, after the carry has compared the SOAs. Then no NSEC is
// carried: the whole chain is rebuilt at the clamped negative TTL.
func TestSignedReloadUnderALoweringClampRebuildsTheNsecChain(t *testing.T) {
	zd := resignTestZone(t, newTestKeyDB(t))
	zd.SetOption(OptIxfrFromDifferences, true)
	before := zd.publishedSnapshot()
	zd.DnssecPolicy.TTLS.MaxServed = 300

	reloadSigned(t, zd, itoa(int(before.Serial)+1), "bravo-edited")
	after := zd.publishedSnapshot()
	n := 0
	for name, od := range after.Data {
		if od == nil {
			continue
		}
		for _, rr := range od.NSEC.RRs {
			n++
			if rr.Header().Ttl != 300 {
				t.Errorf("%s: NSEC TTL %d, want the clamped 300", name, rr.Header().Ttl)
			}
		}
		if len(od.NSEC.RRs) > 0 && len(od.NSEC.RRSIGs) == 0 {
			t.Errorf("%s: NSEC served unsigned", name)
		}
		for _, rr := range od.NSEC.RRSIGs {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.OrigTtl != 300 {
				t.Errorf("%s: NSEC signed over TTL %d, want the clamped 300", name, sig.OrigTtl)
			}
		}
	}
	if n == 0 {
		t.Fatal("no NSEC served after the reload")
	}
}

// The clamp guard at the carry itself: under a clamp whose ceiling is below
// the negative TTL, no NSEC record or signature is carried. Without that clamp
// they are, which shows the guard is what stops them.
func TestCarryTakesNoNsecUnderALoweringClamp(t *testing.T) {
	zd := resignTestZone(t, newTestKeyDB(t))
	old := zd.publishedSnapshot()
	carried := func() int {
		t.Helper()
		zd.mu.Lock()
		defer zd.mu.Unlock()
		// The working set a reload of the same file builds: every RRset
		// unsigned, no NSEC.
		ws := map[string]*OwnerData{}
		for name, od := range old.Data {
			if od == nil || od.RRtypes == nil {
				continue
			}
			c := &OwnerData{Name: od.Name, RRtypes: NewRRTypeStore()}
			for _, rt := range od.RRtypes.Keys() {
				rs := od.RRtypes.GetOnlyRRSet(rt)
				c.RRtypes.Set(rt, core.RRset{Name: rs.Name, Class: rs.Class, RRtype: rs.RRtype, RRs: rs.RRs})
			}
			ws[name] = c
		}
		zd.workingSet = ws
		defer func() { zd.workingSet = nil }()
		zd.carrySignaturesLocked(old)
		n := 0
		for _, od := range zd.workingSet {
			if len(od.NSEC.RRs) > 0 || len(od.NSEC.RRSIGs) > 0 {
				n++
			}
		}
		return n
	}
	if carried() == 0 {
		t.Fatal("with no clamp below the negative TTL no NSEC was carried")
	}
	zd.DnssecPolicy.TTLS.MaxServed = 300
	if n := carried(); n != 0 {
		t.Errorf("under a clamp below the negative TTL %d owners kept their NSEC", n)
	}
}

// An NSEC whose signature is due for renewal is not carried: the restitch
// rebuilds and signs it, as the signing pass re-signs an RRset whose signature
// is due. Checked at a name the edit does not reach, which the restitch would
// otherwise leave alone.
func TestSignedReloadRenewsAnNsecSignatureThatIsDue(t *testing.T) {
	zd := resignTestZone(t, newTestKeyDB(t))
	before := zd.publishedSnapshot()
	const name = "child.resign.example."
	od := before.Data[name]
	if od == nil || len(od.NSEC.RRSIGs) == 0 {
		t.Fatalf("%s has no signed NSEC", name)
	}
	// Test-only: age the served signature into the renewal window.
	aged := dns.Copy(od.NSEC.RRSIGs[0]).(*dns.RRSIG)
	aged.Expiration = uint32(time.Now().Add(time.Minute).Unix())
	od.NSEC.RRSIGs = []dns.RR{aged}

	reloadSigned(t, zd, itoa(int(before.Serial)+1), "bravo-edited")
	after := zd.publishedSnapshot().Data[name]
	if after == nil || len(after.NSEC.RRSIGs) == 0 {
		t.Fatalf("%s: no signed NSEC after the reload", name)
	}
	for _, rr := range after.NSEC.RRSIGs {
		if sig := rr.(*dns.RRSIG); sig.Expiration == aged.Expiration {
			t.Errorf("%s: the NSEC kept a signature due for renewal", name)
		}
	}
}
