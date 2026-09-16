package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dsFor is the DS set of the given KSK public keys, what an owner's DS
// intent carries.
func dsFor(zone string, pubkeys ...string) []dns.RR {
	var out []dns.RR
	for _, pk := range pubkeys {
		out = append(out, testKSK(zone, pk).ToDS(dns.SHA256))
	}
	return out
}

// T5.3, arrow 1: the signer of an owned multi-provider zone serves the CDS
// of the owner's DS set, and the refresh-time collector carries it over a
// transfer like the DNSKEYs; nothing while the set is unknown; and never
// on an instance that does not sign the zone (the agent, T5.6).
func TestOwnedZoneCDSIsRestoredAfterATransfer(t *testing.T) {
	r := buildDSEngineRig(t, 0, false)
	r.zd.Options = map[ZoneOption]bool{OptAllowUpdates: true, OptMultiProvider: true, OptInlineSigning: true}
	owner := &testOwner{owns: map[string]bool{"example.": true}, intent: map[string]DSIntent{"example.": {Set: dsFor("example.", pubA), Known: true}}}
	installOwner(t, owner)
	collected := func() []dns.RR {
		for _, rs := range r.zd.CollectDynamicRRs(&Config{}) {
			if rs.RRtype == dns.TypeCDS {
				return rs.RRs
			}
		}
		return nil
	}
	if got, want := cdsTuplesOf(collected()), cdsTuplesOf(cdsFor("example.", pubA)); !cdsTupleSetsEqual(got, want) {
		t.Errorf("the collector's CDS keyids %v, want the owner's DS set %v", tupleKeyids(got), tupleKeyids(want))
	}
	owner.intent["example."] = DSIntent{Known: false}
	if got := collected(); len(got) != 0 {
		t.Errorf("with the DS set unknown the collector carries CDS %v, want none", got)
	}
	owner.intent["example."] = DSIntent{Set: dsFor("example.", pubA), Known: true}
	r.zd.Options[OptInlineSigning] = false // the agent's copy: not signed here
	if got := collected(); len(got) != 0 {
		t.Errorf("an instance that does not sign the zone carries CDS %v, want none (T5.6)", got)
	}
	delete(owner.owns, "example.")
	r.zd.Options[OptInlineSigning] = true
	if got := collected(); len(got) != 0 {
		t.Errorf("a zone nobody owns carries CDS from an owner %v, want none", got)
	}
}

// The DS engine on the signer brings an owned zone's CDS in step with the
// owner's DS set as it does for a zone whose keys tdns runs; on the agent
// of the same zone (nothing signed here) it publishes nothing (T5.6).
func TestOwnedZoneCDSFollowsTheOwnersDSSet(t *testing.T) {
	r := buildDSEngineRig(t, 0, false)
	r.zd.Options = map[ZoneOption]bool{OptAllowUpdates: true, OptMultiProvider: true, OptInlineSigning: true}
	stageCDS(t, r.zd, cdsFor("example.", pubB))
	owner := &testOwner{owns: map[string]bool{"example.": true}, intent: map[string]DSIntent{"example.": {Set: dsFor("example.", pubA), Known: true}}}
	installOwner(t, owner)

	r.kdb.followKeysWithCDS(context.Background(), r.zd)
	if got, want := servedCDS(t, r.zd), cdsTuplesOf(cdsFor("example.", pubA)); !cdsTupleSetsEqual(got, want) {
		t.Errorf("on the signer, served CDS keyids %v, want the owner's %v", tupleKeyids(got), tupleKeyids(want))
	}
	if res := r.kdb.ensureCDS(context.Background(), r.zd); res.err != nil || !cdsTupleSetsEqual(cdsTuplesOf(res.cds), cdsTuplesOf(cdsFor("example.", pubA))) {
		t.Errorf("ensureCDS on the signer: err=%v cds %v, want the owner's set", res.err, cdsKeyids(res.cds))
	}

	// the agent's copy: served CDS pubB, not signed here; the engine leaves it
	stageCDS(t, r.zd, cdsFor("example.", pubB))
	r.zd.Options[OptInlineSigning] = false
	before := len(r.log.events)
	r.kdb.followKeysWithCDS(context.Background(), r.zd)
	if got, want := servedCDS(t, r.zd), cdsTuplesOf(cdsFor("example.", pubB)); !cdsTupleSetsEqual(got, want) {
		t.Errorf("on the agent, served CDS keyids %v changed, want %v left alone (T5.6)", tupleKeyids(got), tupleKeyids(want))
	}
	if res := r.kdb.ensureCDS(context.Background(), r.zd); res.err != nil || !cdsTupleSetsEqual(cdsTuplesOf(res.cds), cdsTuplesOf(cdsFor("example.", pubB))) {
		t.Errorf("ensureCDS on the agent: err=%v cds %v, want the served CDS", res.err, cdsKeyids(res.cds))
	}
	if len(r.log.events) != before {
		t.Errorf("the agent published: %v", r.log.events[before:])
	}
}

// A change of an owned zone's DS set that the served DNSKEY RRset does not
// show (a standby KSK's ds flipping) reaches the engine through KeysChanged,
// and the signer serves the CDS from the first key that warrants a DS, with
// no CDS served before.
func TestOwnedZoneDSChangesReachTheEngine(t *testing.T) {
	r := newDSEngineRig(t, 0, false)
	r.zd.Options = map[ZoneOption]bool{OptAllowUpdates: true, OptMultiProvider: true, OptInlineSigning: true}
	owner := &testOwner{owns: map[string]bool{"example.": true}, intent: map[string]DSIntent{"example.": {Set: dsFor("example.", pubA), Known: true}}}
	installOwner(t, owner)
	if got := servedCDS(t, r.zd); len(got) != 0 {
		t.Fatalf("CDS served before anything happened: %v", tupleKeyids(got))
	}
	r.kdb.KeysChanged(r.zd)
	waitFor := func(step string, want []string) {
		t.Helper()
		wantSet := cdsTuplesOf(cdsFor("example.", want...))
		deadline := time.Now().Add(2 * time.Second)
		for !cdsTupleSetsEqual(servedCDS(t, r.zd), wantSet) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: served CDS keyids %v two seconds later, want %v", step, tupleKeyids(servedCDS(t, r.zd)), tupleKeyids(wantSet))
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor("first key with a DS", []string{pubA})
	owner.intent["example."] = DSIntent{Set: dsFor("example.", pubA, pubB), Known: true} // a standby KSK's ds=1
	r.kdb.KeysChanged(r.zd)
	waitFor("standby's DS pre-published", []string{pubA, pubB})
	owner.intent["example."] = DSIntent{Set: dsFor("example.", pubB), Known: true} // the old key's withdrawal
	r.kdb.KeysChanged(r.zd)
	waitFor("old key's DS withdrawn", []string{pubB})
}
