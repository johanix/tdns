/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"log"
	"os"
	"strings"
	"testing"

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

// reloadSigned replaces the zone with text as a reload of its file does.
func reloadSigned(t *testing.T, zd *ZoneData, serial, bravo string) {
	t.Helper()
	text := strings.Replace(strings.Replace(resignZoneText, "SERIAL", serial, 1), "BRAVO", bravo, 1)
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
