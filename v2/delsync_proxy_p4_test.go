package tdns

import (
	"testing"
)

// P-4: loop/debounce. The trigger is content-edge-triggered (it diffs the
// served zone against the incoming one), so a CDS/CSYNC change fires exactly
// once — on the transfer where the content changed — and a subsequent transfer
// carrying the SAME (already-forwarded) content does NOT re-fire, even though
// the SOA serial advanced. This is the Q6 self-debounce: no extra state needed.

// simulateRefresh runs one PreRefresh+PostRefresh cycle and reports whether a
// PROXY-SYNC was enqueued. It mutates served (the running zone) to the new
// content, mirroring the hard flip, so the next call diffs against it.
func simulateRefresh(t *testing.T, served **ZoneData, newZoneStr string, q chan DelegationSyncRequest) bool {
	t.Helper()
	incoming := testZone(t, "child.example.", newZoneStr)
	(*served).ProxyDelegationPreRefresh(incoming)
	// Hard flip: the served zone becomes the incoming one (carrying the
	// analysis recorded on the old served zone forward to PostRefresh).
	incoming.ProxyRefreshAnalysis = (*served).ProxyRefreshAnalysis
	*served = incoming
	before := len(q)
	(*served).ProxyDelegationPostRefresh(q)
	return len(q) > before
}

func TestProxySelfDebounceOnRepeatedTransfer(t *testing.T) {
	q := make(chan DelegationSyncRequest, 8)

	// Initial served zone (base).
	served := testZone(t, "child.example.", proxyBaseZone)

	// Transfer #1: same content as served, only the SOA serial differs.
	// No RRset changed ⇒ no NOTIFY.
	bumpedSameContent := `child.example.	3600 IN SOA ns1.child.example. hostmaster.child.example. 2 7200 1800 604800 3600
child.example.	3600 IN NS ns1.child.example.
child.example.	3600 IN NS ns2.child.example.
ns1.child.example.	3600 IN A 192.0.2.1
ns2.child.example.	3600 IN A 192.0.2.2
child.example.	3600 IN DNSKEY 257 3 15 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=
child.example.	3600 IN CDS 12345 15 2 0000000000000000000000000000000000000000000000000000000000000000
child.example.	3600 IN CSYNC 1 3 A NS AAAA
`
	if simulateRefresh(t, &served, bumpedSameContent, q) {
		t.Fatal("serial-only bump must not enqueue a proxy NOTIFY")
	}

	// Transfer #2: the CDS changes ⇒ exactly one NOTIFY.
	cdsChanged := `child.example.	3600 IN SOA ns1.child.example. hostmaster.child.example. 3 7200 1800 604800 3600
child.example.	3600 IN NS ns1.child.example.
child.example.	3600 IN NS ns2.child.example.
ns1.child.example.	3600 IN A 192.0.2.1
ns2.child.example.	3600 IN A 192.0.2.2
child.example.	3600 IN DNSKEY 257 3 15 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=
child.example.	3600 IN CDS 54321 15 2 1111111111111111111111111111111111111111111111111111111111111111
child.example.	3600 IN CSYNC 1 3 A NS AAAA
`
	if !simulateRefresh(t, &served, cdsChanged, q) {
		t.Fatal("a CDS change must enqueue a proxy NOTIFY")
	}

	// Transfer #3: the SAME (already-forwarded) CDS, serial bumped again.
	// The change is no longer "new" relative to the now-served zone ⇒ NO
	// re-NOTIFY. This is the self-debounce.
	cdsChangedAgainSameContent := `child.example.	3600 IN SOA ns1.child.example. hostmaster.child.example. 4 7200 1800 604800 3600
child.example.	3600 IN NS ns1.child.example.
child.example.	3600 IN NS ns2.child.example.
ns1.child.example.	3600 IN A 192.0.2.1
ns2.child.example.	3600 IN A 192.0.2.2
child.example.	3600 IN DNSKEY 257 3 15 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=
child.example.	3600 IN CDS 54321 15 2 1111111111111111111111111111111111111111111111111111111111111111
child.example.	3600 IN CSYNC 1 3 A NS AAAA
`
	if simulateRefresh(t, &served, cdsChangedAgainSameContent, q) {
		t.Fatal("re-transferring the same already-forwarded CDS must NOT re-enqueue (self-debounce)")
	}

	// Exactly one NOTIFY request total across the three refreshes.
	if len(q) != 1 {
		t.Fatalf("total enqueued PROXY-SYNC = %d, want exactly 1", len(q))
	}
}
