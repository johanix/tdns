/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// A parentsync-proxy agent relays the DS its signer's CDS asks for (#752;
// design docs/2026-09-24-cds-publication-and-rfc-conformance.md §1.2 (e)).
// Test numbers are the design's §1.3 numbers.

// proxyCdsZone is a proxied zone whose upstream serves DNSKEY {A retired, B
// active, C standby} -- all three published SEP keys -- and, when cds is
// non-nil, that CDS.
func proxyCdsZone(t *testing.T, cds []dns.RR) *ZoneData {
	t.Helper()
	zd := testZone(t, "example.", csyncTestZone)
	registerZones(t, zd) // an unregistered zone's publishes are dropped
	zd.Options = map[ZoneOption]bool{OptParentSyncProxy: true}
	stageApexRRset(t, zd, dns.TypeDNSKEY, []dns.RR{
		testKSK("example.", pubA), testKSK("example.", pubB), testKSK("example.", pubC),
	}, nil)
	if cds != nil {
		stageCDS(t, zd, cds)
	}
	return zd
}

func dsOfKeys(pubkeys ...string) []dns.RR {
	var out []dns.RR
	for _, pk := range pubkeys {
		out = append(out, testKSK("example.", pk).ToDS(dns.SHA256))
	}
	return out
}

func sameDS(a, b []dns.RR) bool { return sameRecords(a, b) }

// Test 29. The replace-form UPDATE carries the DS the CDS asks for, not the DS
// of every published SEP key: the retired A is still published, and is not
// wanted at the parent.
func TestAProxyUpdateCarriesTheCdsNotTheSepKeys(t *testing.T) {
	zd := proxyCdsZone(t, cdsFor("example.", pubB, pubC))

	dss := zd.proxyReplaceSyncState(nil, nil)

	if !dss.NewDSKnown || !sameDS(dss.NewDS, dsOfKeys(pubB, pubC)) {
		t.Errorf("NewDS = %v (known %v), want the DS of B and C", dss.NewDS, dss.NewDSKnown)
	}
}

// Test 30. A signer that publishes no CDS: the DS comes from the SEP keys, as
// before.
func TestAProxyWithoutACdsUsesTheSepKeys(t *testing.T) {
	zd := proxyCdsZone(t, nil)

	dss := zd.proxyReplaceSyncState(nil, nil)

	if !dss.NewDSKnown || !sameDS(dss.NewDS, dsOfKeys(pubA, pubB, pubC)) {
		t.Errorf("NewDS = %v (known %v), want the DS of A, B and C", dss.NewDS, dss.NewDSKnown)
	}
}

// Test 31. The startup reconcile's comparison: a parent still holding A is out
// of step with a CDS asking for B and C, and one holding B and C is in step.
func TestAProxyComparesTheParentsDSWithTheCds(t *testing.T) {
	zd := proxyCdsZone(t, cdsFor("example.", pubB, pubC))

	behind := DelegationSyncStatus{InSync: true}
	if !zd.proxyCompareDS(&behind, dsOfKeys(pubA)) {
		t.Fatal("a proxy zone serving a usable CDS was not compared")
	}
	if behind.InSync || !sameDS(behind.DSAdds, dsOfKeys(pubB, pubC)) || !sameDS(behind.DSRemoves, dsOfKeys(pubA)) {
		t.Errorf("parent {A}: in sync %v, adds %v, removes %v; want out of step, +B +C -A",
			behind.InSync, behind.DSAdds, behind.DSRemoves)
	}

	inStep := DelegationSyncStatus{InSync: true}
	zd.proxyCompareDS(&inStep, dsOfKeys(pubB, pubC))
	if !inStep.InSync || len(inStep.DSAdds)+len(inStep.DSRemoves) != 0 {
		t.Errorf("parent {B, C}: in sync %v, adds %v, removes %v; want in step",
			inStep.InSync, inStep.DSAdds, inStep.DSRemoves)
	}

	notProxy := proxyCdsZone(t, cdsFor("example.", pubB, pubC))
	notProxy.Options = map[ZoneOption]bool{OptParentSync: true}
	if notProxy.proxyCompareDS(&DelegationSyncStatus{}, dsOfKeys(pubA)) {
		t.Error("a zone that is not a proxy zone was compared with its CDS")
	}
}

// Test 32. A CDS holding an algorithm-0 record leaves the parent's DS alone
// until Part 2 decides which such sets are the delete: no DS in the UPDATE, no
// comparison, no DS in the API payload.
func TestAProxyLeavesTheDSAloneForAnAlgorithmZeroCds(t *testing.T) {
	zd := proxyCdsZone(t, append(cdsFor("example.", pubB), mustRR(t, "example. 120 IN CDS 0 0 0 00")))

	if dss := zd.proxyReplaceSyncState(nil, nil); dss.NewDSKnown || len(dss.NewDS) != 0 {
		t.Errorf("UPDATE: NewDS = %v (known %v), want the parent's DS left alone", dss.NewDS, dss.NewDSKnown)
	}
	if zd.proxyCompareDS(&DelegationSyncStatus{}, dsOfKeys(pubA)) {
		t.Error("the parent's DS was compared with an algorithm-0 CDS")
	}
	for _, rrset := range zd.proxyApiRRsets(nil, nil) {
		if rrset.Type == "DS" {
			t.Errorf("the API payload declares a DS RRset: %v", rrset.RRs)
		}
	}
}

// The API payload declares the DS the CDS asks for, and none without a CDS.
func TestAProxyApiPayloadCarriesTheCds(t *testing.T) {
	dsRRset := func(zd *ZoneData) []string {
		for _, rrset := range zd.proxyApiRRsets(nil, nil) {
			if rrset.Type == "DS" {
				return rrset.RRs
			}
		}
		return nil
	}

	if got := dsRRset(proxyCdsZone(t, cdsFor("example.", pubB, pubC))); len(got) != 2 {
		t.Errorf("DS RRset = %v, want the two records the CDS asks for", got)
	}
	if got := dsRRset(proxyCdsZone(t, nil)); got != nil {
		t.Errorf("DS RRset = %v without a CDS, want none declared", got)
	}
}

// Test 31, joined. AnalyseZoneDelegation, which the proxy's startup reconcile
// runs, compares a proxy zone's parent DS with the CDS its signer serves: a
// parent that missed a KSK change while the agent was down is found behind.
func TestAProxysDelegationAnalysisComparesTheParentsDSWithTheCds(t *testing.T) {
	zd := childZone(t, ddcngServedZone(), OptParentSyncProxy)
	registerZones(t, zd)
	ksk1 := mustRR(t, ddcngKSK1).(*dns.DNSKEY)
	ksk2 := mustRR(t, ddcngKSK2).(*dns.DNSKEY)
	stageApexRRset(t, zd, dns.TypeDNSKEY, []dns.RR{ksk1, ksk2}, nil)
	stageCDS(t, zd, cdsFromDS(zd.ZoneName, []dns.RR{ksk2.ToDS(dns.SHA256)}))
	fakeParent(t, zd, []string{ddcngNS1, ddcngNS2, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A,
		ksk1.ToDS(dns.SHA256).String()})

	resp, err := zd.AnalyseZoneDelegation(nil)
	if err != nil {
		t.Fatalf("AnalyseZoneDelegation: %v", err)
	}
	if resp.InSync {
		t.Fatal("a parent holding the old KSK's DS was found in step with a CDS naming the new one")
	}
	if !sameDS(resp.DSAdds, []dns.RR{ksk2.ToDS(dns.SHA256)}) || !sameDS(resp.DSRemoves, []dns.RR{ksk1.ToDS(dns.SHA256)}) {
		t.Errorf("adds %v, removes %v; want +KSK2 -KSK1", resp.DSAdds, resp.DSRemoves)
	}
}

// A proxy zone's CDS read back from text (upper-case digest) is in step with a
// parent holding the same DS from the wire (lower case).
func TestAProxyComparesDigestsWithoutCase(t *testing.T) {
	zd := proxyCdsZone(t, fromText(t, cdsFor("example.", pubB)))
	resp := DelegationSyncStatus{InSync: true}
	zd.proxyCompareDS(&resp, dsOfKeys(pubB))
	if !resp.InSync {
		t.Errorf("in sync = false (adds %v, removes %v); a digest's case is not a difference", resp.DSAdds, resp.DSRemoves)
	}
}
