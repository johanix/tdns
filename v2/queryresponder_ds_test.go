package tdns

import (
	"testing"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// TestHandleDSQueryParentSelection verifies that a DS query is answered from the
// nearest hosted ancestor of qname, resolved from the local Zones map — never
// via the resolver. It exercises the three delegation relationships plus the
// no-ancestor case. All cases are non-DNSSEC (DO=0): the regression was in zone
// SELECTION, which is independent of signing.
func TestHandleDSQueryParentSelection(t *testing.T) {
	dsRR := "c.pq.example. 3600 IN DS 12345 8 2 " +
		"E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766"

	t.Run("immediate_parent_serves_DS", func(t *testing.T) {
		// We host BOTH the parent (which delegates to, and holds the DS for, the
		// child) and the child itself. This is the foffe regression: the query
		// exact-matches the child zone, and DS must still be served from the
		// parent — from local data, without any resolver walk-up.
		parent := `pq.example.	3600	IN	SOA	ns.pq.example. hostmaster.pq.example. 1 7200 1800 604800 7200
pq.example.	3600	IN	NS	ns.pq.example.
ns.pq.example.	3600	IN	A	192.0.2.1
c.pq.example.	3600	IN	NS	ns.c.pq.example.
` + dsRR + `
ns.c.pq.example.	3600	IN	A	192.0.2.2
`
		child := `c.pq.example.	3600	IN	SOA	ns.c.pq.example. hostmaster.c.pq.example. 1 7200 1800 604800 7200
c.pq.example.	3600	IN	NS	ns.c.pq.example.
ns.c.pq.example.	3600	IN	A	192.0.2.2
`
		testSnapshotZone(t, "pq.example.", parent)
		childZd := testSnapshotZone(t, "c.pq.example.", child)

		rw := &fakeRW{}
		if err := childZd.handleDSQuery(new(dns.Msg), rw, "c.pq.example.", &edns0.MsgOptions{}, nil); err != nil {
			t.Fatalf("handleDSQuery: %v", err)
		}
		resp := rw.written
		if resp == nil || resp.MsgHdr.Rcode != dns.RcodeSuccess {
			t.Fatalf("want NOERROR, got %+v", resp)
		}
		var gotDS bool
		for _, rr := range resp.Answer {
			if ds, ok := rr.(*dns.DS); ok && ds.Header().Name == "c.pq.example." {
				gotDS = true
			}
		}
		if !gotDS {
			t.Fatalf("DS-at-child-apex should be served from the parent zone; answer=%v", resp.Answer)
		}
		if !resp.MsgHdr.Authoritative {
			t.Fatal("DS answer from the parent should be authoritative")
		}
	})

	t.Run("grandparent_refers_to_parent", func(t *testing.T) {
		// We host a grandparent (which delegates to the child's real parent) and
		// the child, but NOT the immediate parent. All we can do is refer down to
		// the parent.
		grandparent := `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	192.0.2.1
p.example.	3600	IN	NS	ns.p.example.
ns.p.example.	3600	IN	A	192.0.2.3
`
		child := `x.p.example.	3600	IN	SOA	ns.x.p.example. hostmaster.x.p.example. 1 7200 1800 604800 7200
x.p.example.	3600	IN	NS	ns.x.p.example.
ns.x.p.example.	3600	IN	A	192.0.2.4
`
		testSnapshotZone(t, "example.", grandparent)
		childZd := testSnapshotZone(t, "x.p.example.", child)

		rw := &fakeRW{}
		if err := childZd.handleDSQuery(new(dns.Msg), rw, "x.p.example.", &edns0.MsgOptions{}, nil); err != nil {
			t.Fatalf("handleDSQuery: %v", err)
		}
		resp := rw.written
		if resp == nil {
			t.Fatal("no response written")
		}
		if resp.MsgHdr.Authoritative {
			t.Fatal("a referral must NOT set the AA bit")
		}
		var refersToParent bool
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok && ns.Header().Name == "p.example." {
				refersToParent = true
			}
		}
		if !refersToParent {
			t.Fatalf("expected a referral to p.example.; authority=%v", resp.Ns)
		}
		if len(resp.Answer) != 0 {
			t.Fatalf("a referral has no answer records; got %v", resp.Answer)
		}
	})

	t.Run("child_only_refused", func(t *testing.T) {
		// We host the child but no ancestor at all. The DS lives in a parent we
		// don't host and there is nothing to refer to → REFUSED (never a NODATA
		// that would deny parent-side data we don't own).
		child := `lonely.example.	3600	IN	SOA	ns.lonely.example. hostmaster.lonely.example. 1 7200 1800 604800 7200
lonely.example.	3600	IN	NS	ns.lonely.example.
ns.lonely.example.	3600	IN	A	192.0.2.5
`
		childZd := testSnapshotZone(t, "lonely.example.", child)

		rw := &fakeRW{}
		if err := childZd.handleDSQuery(new(dns.Msg), rw, "lonely.example.", &edns0.MsgOptions{}, nil); err != nil {
			t.Fatalf("handleDSQuery: %v", err)
		}
		resp := rw.written
		if resp == nil || resp.MsgHdr.Rcode != dns.RcodeRefused {
			t.Fatalf("want REFUSED, got %+v", resp)
		}
		if resp.MsgHdr.Authoritative {
			t.Fatal("REFUSED must not set the AA bit")
		}
	})
}
