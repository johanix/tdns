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
// and above all must not look like "the child withdrew its delegation".
func TestProxyPreRefreshApexlessIncomingZoneIsNotAWithdrawal(t *testing.T) {
	zd := testZone(t, preRefreshZoneName, preRefreshBaseZone())
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
		t.Error("an apex-less incoming zone was reported as an NS/glue change;" +
			" that would drive a delegation withdrawal at the parent")
	}
}
