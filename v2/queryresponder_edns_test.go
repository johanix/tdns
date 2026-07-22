/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"testing"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// TestQueryResponderEDNSOPTEcho locks in RFC 6891 §6.1.1: an authoritative
// QUERY response MUST carry an EDNS OPT record iff the query carried one.
//
// Regression test for the pre-existing bug where QueryResponder built its reply
// with SetReply(r) but never re-attached an OPT, so every EDNS query (plain
// +dnssec, +oots, SVCB, ...) got an OPT-less answer. A strict resolver that
// sends EDNS and sees no OPT may downgrade to plain DNS, dropping the DO bit and
// breaking DNSSEC validation against tdns-auth.
func TestQueryResponderEDNSOPTEcho(t *testing.T) {
	kdb := newTestKeyDB(t)
	// A legitimately unsigned zone: signRRsetForZone serves its RRsets as-is
	// even for a DO query, so the positive-answer path stays NOERROR and we can
	// assert on the OPT without dragging in the signing machinery.
	zd := testSnapshotZone(t, "example.", `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 10.0.0.1
www.example. 3600 IN A 10.0.0.2
`)
	ctx := context.Background()

	// respFor drives QueryResponder for www.example./A the way the real handler
	// does — deriving msgoptions from the request via ExtractFlagsAndEDNS0Options
	// — and returns the written response.
	respFor := func(t *testing.T, edns, do bool) *dns.Msg {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion("www.example.", dns.TypeA)
		if edns {
			// Client advertises 1232; the server must advertise its OWN size
			// (dns.DefaultMsgSize) back, not echo the client's.
			req.SetEdns0(1232, do)
		}
		msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
		}
		rw := &fakeRW{}
		if err := zd.QueryResponder(ctx, rw, req, "www.example.", dns.TypeA, msgo, kdb); err != nil {
			t.Fatalf("QueryResponder: %v", err)
		}
		if rw.written == nil {
			t.Fatal("no response written")
		}
		return rw.written
	}

	// 1. A non-EDNS query MUST NOT get an OPT in the response.
	t.Run("non-EDNS query gets no OPT", func(t *testing.T) {
		resp := respFor(t, false, false)
		if opt := resp.IsEdns0(); opt != nil {
			t.Fatalf("non-EDNS query got an OPT in the response: %s", opt.String())
		}
	})

	// 2. An EDNS query (DO=0) MUST get an OPT echoing EDNS version 0 and the
	//    server's advertised UDP size, with the DO bit reflected off.
	t.Run("EDNS query gets OPT, DO off", func(t *testing.T) {
		resp := respFor(t, true, false)
		opt := resp.IsEdns0()
		if opt == nil {
			t.Fatal("EDNS query got no OPT in the response (RFC 6891 §6.1.1 violation)")
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
		}
		if opt.Version() != 0 {
			t.Fatalf("OPT EDNS version = %d, want 0", opt.Version())
		}
		if got := opt.UDPSize(); got != dns.DefaultMsgSize {
			t.Fatalf("OPT advertised UDP size = %d, want server's %d", got, uint16(dns.DefaultMsgSize))
		}
		if opt.Do() {
			t.Fatal("response OPT has DO set for a non-DO query")
		}
	})

	// 3. An EDNS query with DO=1 MUST get an OPT with the DO bit reflected on
	//    (RFC 3225 §3: copy the query's DO into the response).
	t.Run("EDNS query gets OPT, DO on", func(t *testing.T) {
		resp := respFor(t, true, true)
		opt := resp.IsEdns0()
		if opt == nil {
			t.Fatal("EDNS+DO query got no OPT in the response")
		}
		if !opt.Do() {
			t.Fatal("response OPT does not reflect the query's DO bit")
		}
	})

	// 4. The EDE error paths must reuse the OPT attached up front rather than
	//    adding a second one. A TypeNXNAME query (RFC 9824) is rejected FORMERR
	//    with an EDE; the response must carry exactly one OPT, and it must hold
	//    the EDE. This guards the "leave room for EDE, no duplicate OPT" contract
	//    against AttachEDEToResponse.
	t.Run("EDE path reuses the OPT (no duplicate)", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("www.example.", dns.TypeNXNAME)
		req.SetEdns0(1232, true)
		msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
		}
		rw := &fakeRW{}
		if err := zd.QueryResponder(ctx, rw, req, "www.example.", dns.TypeNXNAME, msgo, kdb); err != nil {
			t.Fatalf("QueryResponder: %v", err)
		}
		resp := rw.written
		if resp == nil {
			t.Fatal("no response written")
		}
		if resp.Rcode != dns.RcodeFormatError {
			t.Fatalf("TypeNXNAME query: expected FORMERR, got %s", dns.RcodeToString[resp.Rcode])
		}
		opts := 0
		for _, rr := range resp.Extra {
			if _, ok := rr.(*dns.OPT); ok {
				opts++
			}
		}
		if opts != 1 {
			t.Fatalf("expected exactly one OPT in the response, got %d", opts)
		}
		if ok, _, _ := edns0.ExtractEDEFromMsg(resp); !ok {
			t.Fatal("EDE response carries no EDE option")
		}
	})
}
