package tdns

import (
	"github.com/miekg/dns"
	"log"
	"os"
	"testing"
)

// The pre-refresh hook runs on a SCRATCH zone: FetchFromUpstream/FetchFromFile
// parse the new zone into a throwaway ZoneData, set Ready=true by hand, and
// publish a snapshot only afterwards, at the hard flip. GetOwner serves from the
// published snapshot, so a scratch zone read that way is empty for every name --
// which is how the delegation diff came to dereference a nil apex and kill the
// process on every transfer after the first load.
//
// These tests pin the behaviour that matters: the analysis reads the incoming
// zone's real data, and an absent apex is never mistaken for "the child
// withdrew its delegation".

const preRefreshZoneName = "proxy.example."

func preRefreshBaseZone() string {
	return `proxy.example.	3600 IN SOA ns1.proxy.example. hostmaster.proxy.example. 1 7200 1800 604800 3600
proxy.example.	3600 IN NS ns1.proxy.example.
ns1.proxy.example.	3600 IN A 192.0.2.1
`
}

// Adds a second nameserver and its glue: an ns_or_glue change.
func preRefreshChangedZone() string {
	return `proxy.example.	3600 IN SOA ns1.proxy.example. hostmaster.proxy.example. 2 7200 1800 604800 3600
proxy.example.	3600 IN NS ns1.proxy.example.
proxy.example.	3600 IN NS ns2.proxy.example.
ns1.proxy.example.	3600 IN A 192.0.2.1
ns2.proxy.example.	3600 IN A 192.0.2.2
`
}

// A zone carrying every dimension the proxy watches, so an apex-less incoming
// zone has something in each to be falsely reported as removed.
func preRefreshSignedBaseZone() string {
	return `proxy.example.	3600 IN SOA ns1.proxy.example. hostmaster.proxy.example. 1 7200 1800 604800 3600
proxy.example.	3600 IN NS ns1.proxy.example.
proxy.example.	3600 IN DNSKEY 257 3 15 C4RKfg3IUwpjc+CnISaCuDX4OGpxsUIe7dqRVXj0KdU=
proxy.example.	3600 IN CDS 59146 15 2 6E96FA2CBCB8229C738737ADCCB54F582418171D1A306761367C3C2DE5741531
proxy.example.	3600 IN CSYNC 66 3 A NS AAAA
ns1.proxy.example.	3600 IN A 192.0.2.1
`
}

// Same delegation, higher serial: the case that first crashed the agent.
func preRefreshSerialOnlyZone() string {
	return `proxy.example.	3600 IN SOA ns1.proxy.example. hostmaster.proxy.example. 2 7200 1800 604800 3600
proxy.example.	3600 IN NS ns1.proxy.example.
ns1.proxy.example.	3600 IN A 192.0.2.1
`
}

// scratchZoneLikeTransfer builds the ZoneData shape the refresh paths hand to
// the pre-refresh callbacks: parsed data, Ready=true, and deliberately NO
// published snapshot. Exactly what newTransferScratchZone produces.
func scratchZoneLikeTransfer(t *testing.T, zoneStr string) *ZoneData {
	t.Helper()
	zd := &ZoneData{
		ZoneName:  preRefreshZoneName,
		ZoneStore: MapZone,
		Logger:    log.New(os.Stderr, "", 0),
	}
	if _, _, err := zd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.Ready = true // exactly what newTransferScratchZone does
	if snap := zd.publishedSnapshot(); snap != nil {
		t.Fatal("scratch zone must have no published snapshot; the test would not " +
			"be exercising the pre-refresh shape")
	}
	return zd
}

// The load-bearing test. Before the fix this panicked with a nil dereference in
// DelegationDataChangedNG; a guard-only fix would stop the panic but leave the
// analysis reading an empty zone, so asserting the change IS detected is what
// keeps the proxy from silently going blind again.
func TestProxyPreRefreshReadsUnpublishedIncomingZone(t *testing.T) {
	zd := testZone(t, preRefreshZoneName, preRefreshBaseZone())
	newzd := scratchZoneLikeTransfer(t, preRefreshChangedZone())

	zd.ProxyDelegationPreRefresh(newzd) // must not panic

	zd.mu.Lock()
	analysis := zd.ProxyRefreshAnalysis
	zd.mu.Unlock()
	if analysis == nil {
		t.Fatal("ProxyDelegationPreRefresh recorded no analysis")
	}
	if !analysis.NsOrGlueChanged {
		t.Fatal("an added NS + glue in the incoming zone was not detected;" +
			" the proxy would forward nothing")
	}
	if !analysis.anyChange() {
		t.Error("anyChange() is false despite an NS/glue change")
	}
	if !analysis.wantCSYNCNotify() {
		t.Error("an NS/glue change must map to a CSYNC notify (D4)")
	}
}

// The deltas must name the nameserver that was actually added -- proof the diff
// read the incoming zone rather than comparing against an empty set.
func TestProxyPreRefreshRecordsTheAddedNameserver(t *testing.T) {
	zd := testZone(t, preRefreshZoneName, preRefreshBaseZone())
	newzd := scratchZoneLikeTransfer(t, preRefreshChangedZone())

	zd.ProxyDelegationPreRefresh(newzd)

	zd.mu.Lock()
	analysis := zd.ProxyRefreshAnalysis
	zd.mu.Unlock()
	if analysis == nil {
		t.Fatal("no analysis recorded")
	}
	var found bool
	for _, rr := range analysis.DelegationStatus.NsAdds {
		if ns, ok := rr.(*dns.NS); ok && ns.Ns == "ns2.proxy.example." {
			found = true
		}
	}
	if !found {
		t.Fatalf("ns2.proxy.example. missing from NsAdds (got %v)",
			analysis.DelegationStatus.NsAdds)
	}
	if len(analysis.DelegationStatus.NsRemoves) != 0 {
		t.Errorf("nothing was removed, but NsRemoves = %v",
			analysis.DelegationStatus.NsRemoves)
	}
}

// A serial-only transfer must survive and report no delegation change. This is
// the exact case that first crashed the agent in the field.
func TestProxyPreRefreshSerialOnlyTransferIsNotAChange(t *testing.T) {
	zd := testZone(t, preRefreshZoneName, preRefreshBaseZone())
	newzd := scratchZoneLikeTransfer(t, preRefreshSerialOnlyZone())

	zd.ProxyDelegationPreRefresh(newzd) // must not panic

	zd.mu.Lock()
	analysis := zd.ProxyRefreshAnalysis
	zd.mu.Unlock()
	if analysis == nil {
		t.Fatal("no analysis recorded")
	}
	if analysis.NsOrGlueChanged {
		t.Error("a serial-only transfer was reported as an NS/glue change")
	}
}

// An incoming zone with no apex at all is a broken transfer. It must not panic,
// and above all no dimension may be reported as REMOVED: a missing apex is not
// the child unsigning itself or withdrawing its delegation, and reporting it as
// such makes the proxy tell the parent to act on a failed transfer.
func TestProxyPreRefreshApexlessIncomingZoneIsNotAWithdrawal(t *testing.T) {
	zd := testZone(t, preRefreshZoneName, preRefreshSignedBaseZone())
	newzd := &ZoneData{
		ZoneName:  preRefreshZoneName,
		ZoneStore: MapZone,
		Logger:    log.New(os.Stderr, "", 0),
		Ready:     true,
	}

	zd.ProxyDelegationPreRefresh(newzd) // must not panic

	zd.mu.Lock()
	analysis := zd.ProxyRefreshAnalysis
	zd.mu.Unlock()
	if analysis == nil {
		t.Fatal("no analysis recorded")
	}
	if analysis.NsOrGlueChanged {
		t.Error("apex-less incoming zone reported as an NS/glue change;" +
			" that would drive a delegation withdrawal at the parent")
	}
	if analysis.CdsChanged {
		t.Error("apex-less incoming zone reported as a CDS change;" +
			" the current zone's CDS would look withdrawn")
	}
	if analysis.CsyncChanged {
		t.Error("apex-less incoming zone reported as a CSYNC change")
	}
	if analysis.DnskeyChanged {
		t.Error("apex-less incoming zone reported as a DNSKEY change;" +
			" a signed zone would look as though it had unsigned itself")
	}
	if analysis.anyChange() {
		t.Error("a failed transfer must not queue a proxy sync at all")
	}
}

// The other half of the apex rule: a real removal, from a zone that still HAS
// an apex, must stay detectable. Refusing to report changes whenever the
// incoming side is missing something would be an over-correction that made the
// proxy blind to an intentional unsigning or CDS withdrawal.
func TestProxyPreRefreshIntentionalRemovalIsStillDetected(t *testing.T) {
	zd := testZone(t, preRefreshZoneName, preRefreshSignedBaseZone())
	// Same zone, apex intact, but CDS/CSYNC/DNSKEY deliberately gone.
	newzd := scratchZoneLikeTransfer(t, preRefreshBaseZone())

	zd.ProxyDelegationPreRefresh(newzd)

	zd.mu.Lock()
	analysis := zd.ProxyRefreshAnalysis
	zd.mu.Unlock()
	if analysis == nil {
		t.Fatal("no analysis recorded")
	}
	if !analysis.CdsChanged {
		t.Error("an intentional CDS removal was not detected")
	}
	if !analysis.CsyncChanged {
		t.Error("an intentional CSYNC removal was not detected")
	}
	if !analysis.DnskeyChanged {
		t.Error("an intentional DNSKEY removal (zone unsigned) was not detected")
	}
}
