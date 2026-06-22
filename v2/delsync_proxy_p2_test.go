package tdns

import (
	"testing"
)

// P-2: the change-detection trigger. ProxyDelegationPreRefresh diffs the
// incoming zone against the served one across CDS / CSYNC / NS+glue / DNSKEY
// and records the result; ProxyDelegationPostRefresh enqueues a PROXY-NOTIFY
// only when a NOTIFY-relevant dimension changed.

// A minimal signed delegation apex. Variants below flip exactly one dimension.
const proxyBaseZone = `child.example.	3600 IN SOA ns1.child.example. hostmaster.child.example. 1 7200 1800 604800 3600
child.example.	3600 IN NS ns1.child.example.
child.example.	3600 IN NS ns2.child.example.
ns1.child.example.	3600 IN A 192.0.2.1
ns2.child.example.	3600 IN A 192.0.2.2
child.example.	3600 IN DNSKEY 257 3 15 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=
child.example.	3600 IN CDS 12345 15 2 0000000000000000000000000000000000000000000000000000000000000000
child.example.	3600 IN CSYNC 1 3 A NS AAAA
`

func proxyAnalysisFor(t *testing.T, oldZoneStr, newZoneStr string) *ProxyDelegationAnalysis {
	t.Helper()
	zd := testZone(t, "child.example.", oldZoneStr)
	newzd := testZone(t, "child.example.", newZoneStr)
	zd.ProxyDelegationPreRefresh(newzd)
	if zd.ProxyRefreshAnalysis == nil {
		t.Fatal("ProxyDelegationPreRefresh did not record an analysis")
	}
	return zd.ProxyRefreshAnalysis
}

// No change between old and new ⇒ nothing flagged, nothing to NOTIFY.
func TestProxyPreRefreshNoChange(t *testing.T) {
	a := proxyAnalysisFor(t, proxyBaseZone, proxyBaseZone)
	if a.anyChange() {
		t.Fatalf("identical zones must report no change: %+v", a)
	}
}

// A changed CDS ⇒ CdsChanged, and (D4) wantCDSNotify.
func TestProxyPreRefreshCDSChange(t *testing.T) {
	newZone := `child.example.	3600 IN SOA ns1.child.example. hostmaster.child.example. 2 7200 1800 604800 3600
child.example.	3600 IN NS ns1.child.example.
child.example.	3600 IN NS ns2.child.example.
ns1.child.example.	3600 IN A 192.0.2.1
ns2.child.example.	3600 IN A 192.0.2.2
child.example.	3600 IN DNSKEY 257 3 15 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=
child.example.	3600 IN CDS 54321 15 2 1111111111111111111111111111111111111111111111111111111111111111
child.example.	3600 IN CSYNC 1 3 A NS AAAA
`
	a := proxyAnalysisFor(t, proxyBaseZone, newZone)
	if !a.CdsChanged {
		t.Fatal("CDS change not detected")
	}
	if !a.wantCDSNotify() {
		t.Fatal("a CDS change must drive a NOTIFY(CDS)")
	}
	if a.CsyncChanged {
		t.Fatal("CSYNC must not be flagged when only CDS changed")
	}
}

// A changed CSYNC ⇒ CsyncChanged, and (D4) wantCSYNCNotify.
func TestProxyPreRefreshCSYNCChange(t *testing.T) {
	newZone := `child.example.	3600 IN SOA ns1.child.example. hostmaster.child.example. 2 7200 1800 604800 3600
child.example.	3600 IN NS ns1.child.example.
child.example.	3600 IN NS ns2.child.example.
ns1.child.example.	3600 IN A 192.0.2.1
ns2.child.example.	3600 IN A 192.0.2.2
child.example.	3600 IN DNSKEY 257 3 15 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=
child.example.	3600 IN CDS 12345 15 2 0000000000000000000000000000000000000000000000000000000000000000
child.example.	3600 IN CSYNC 2 3 A NS AAAA
`
	a := proxyAnalysisFor(t, proxyBaseZone, newZone)
	if !a.CsyncChanged {
		t.Fatal("CSYNC change not detected")
	}
	if !a.wantCSYNCNotify() {
		t.Fatal("a CSYNC change must drive a NOTIFY(CSYNC)")
	}
}

// An NS/glue change ⇒ NsOrGlueChanged, and (D4) wantCSYNCNotify even without a
// CSYNC RRset change.
func TestProxyPreRefreshNSChange(t *testing.T) {
	newZone := `child.example.	3600 IN SOA ns1.child.example. hostmaster.child.example. 2 7200 1800 604800 3600
child.example.	3600 IN NS ns1.child.example.
child.example.	3600 IN NS ns3.child.example.
ns1.child.example.	3600 IN A 192.0.2.1
ns3.child.example.	3600 IN A 192.0.2.3
child.example.	3600 IN DNSKEY 257 3 15 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=
child.example.	3600 IN CDS 12345 15 2 0000000000000000000000000000000000000000000000000000000000000000
child.example.	3600 IN CSYNC 1 3 A NS AAAA
`
	a := proxyAnalysisFor(t, proxyBaseZone, newZone)
	if !a.NsOrGlueChanged {
		t.Fatal("NS/glue change not detected")
	}
	if !a.wantCSYNCNotify() {
		t.Fatal("an NS/glue change must drive a NOTIFY(CSYNC)")
	}
}

// A DNSKEY change ⇒ DnskeyChanged, and (D4) wantCDSNotify even without a CDS
// RRset change.
func TestProxyPreRefreshDNSKEYChange(t *testing.T) {
	newZone := `child.example.	3600 IN SOA ns1.child.example. hostmaster.child.example. 2 7200 1800 604800 3600
child.example.	3600 IN NS ns1.child.example.
child.example.	3600 IN NS ns2.child.example.
ns1.child.example.	3600 IN A 192.0.2.1
ns2.child.example.	3600 IN A 192.0.2.2
child.example.	3600 IN DNSKEY 257 3 15 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbB=
child.example.	3600 IN CDS 12345 15 2 0000000000000000000000000000000000000000000000000000000000000000
child.example.	3600 IN CSYNC 1 3 A NS AAAA
`
	a := proxyAnalysisFor(t, proxyBaseZone, newZone)
	if !a.DnskeyChanged {
		t.Fatal("DNSKEY change not detected")
	}
	if !a.wantCDSNotify() {
		t.Fatal("a DNSKEY change must drive a NOTIFY(CDS)")
	}
}

// PostRefresh enqueues a PROXY-NOTIFY when something changed, and enqueues
// nothing when the analysis is absent or empty. It also clears the analysis.
func TestProxyPostRefreshEnqueue(t *testing.T) {
	zd := testZone(t, "child.example.", proxyBaseZone)
	q := make(chan DelegationSyncRequest, 1)

	// Change present ⇒ one PROXY-NOTIFY enqueued.
	zd.ProxyRefreshAnalysis = &ProxyDelegationAnalysis{CdsChanged: true}
	zd.ProxyDelegationPostRefresh(q)
	select {
	case req := <-q:
		if req.Command != "PROXY-NOTIFY" {
			t.Fatalf("enqueued command = %q, want PROXY-NOTIFY", req.Command)
		}
		if req.ZoneName != "child.example." {
			t.Fatalf("enqueued zone = %q", req.ZoneName)
		}
	default:
		t.Fatal("expected a PROXY-NOTIFY to be enqueued on change")
	}
	if zd.ProxyRefreshAnalysis != nil {
		t.Fatal("analysis must be cleared after PostRefresh")
	}

	// No analysis ⇒ nothing enqueued.
	zd.ProxyDelegationPostRefresh(q)
	select {
	case <-q:
		t.Fatal("nothing should be enqueued when there is no analysis")
	default:
	}

	// Empty analysis (no change) ⇒ nothing enqueued.
	zd.ProxyRefreshAnalysis = &ProxyDelegationAnalysis{}
	zd.ProxyDelegationPostRefresh(q)
	select {
	case <-q:
		t.Fatal("nothing should be enqueued when no dimension changed")
	default:
	}
}
