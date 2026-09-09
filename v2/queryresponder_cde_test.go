/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The synthesised denial is one NSEC, owned by the denied name, and what it
// means depends on who reads it. RFC 9824 settles the two readings with the
// CO flag: NXDOMAIN for a client that reads NXNAME, NOERROR for one that would
// read the NSEC as existence. The NXNAME in the bitmap is what a resolver uses
// to tell the two denials apart and does not depend on the flag.
//
// The CO flag on the RESPONSE is not this function's: QueryResponder echoes it
// onto every answer to a CO query (RFC 9824 section 5.1), which is what
// TestQueryResponderEchoesCO covers.
func TestAddCDEResponseFollowsCO(t *testing.T) {
	zd := testSnapshotZone(t, "example.", `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 10.0.0.1
`)
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("no published snapshot")
	}
	apex := getOwnerFrom(snap, "example.")
	if apex == nil {
		t.Fatal("no apex owner")
	}
	// The record's shape is under test, not its signature.
	noSign := func(rrset core.RRset, _ string) (core.RRset, error) { return rrset, nil }

	const qname = "nosuch.example."
	build := func(t *testing.T, co bool, existing []uint16) *dns.Msg {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion(qname, dns.TypeMX)
		req.SetEdns0(4096, true)
		if co {
			edns0.SetCO(req)
		}
		msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
		}
		m := new(dns.Msg)
		m.SetReply(req)
		edns0.EnsureResponseOPT(m, req, dns.DefaultMsgSize)
		// As the callers do: NXDOMAIN is set before the denial is built, a
		// NODATA is NOERROR.
		m.MsgHdr.Rcode = dns.RcodeNameError
		if existing != nil {
			m.MsgHdr.Rcode = dns.RcodeSuccess
		}
		zd.addCDEResponse(m, qname, apex, existing, msgo, noSign)
		return m
	}
	nsecOf := func(t *testing.T, m *dns.Msg) *dns.NSEC {
		t.Helper()
		for _, rr := range m.Ns {
			if nsec, ok := rr.(*dns.NSEC); ok {
				return nsec
			}
		}
		t.Fatalf("no NSEC in AUTHORITY: %v", m.Ns)
		return nil
	}
	hasNXNAME := func(nsec *dns.NSEC) bool {
		for _, typ := range nsec.TypeBitMap {
			if typ == dns.TypeNXNAME {
				return true
			}
		}
		return false
	}

	t.Run("NXDOMAIN, DO and CO", func(t *testing.T) {
		m := build(t, true, nil)
		if m.Rcode != dns.RcodeNameError {
			t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
		}
		if nsec := nsecOf(t, m); nsec.Hdr.Name != qname || !hasNXNAME(nsec) {
			t.Errorf("NSEC = %s, want owner %s with NXNAME", nsec, qname)
		}
	})

	t.Run("NXDOMAIN, DO without CO", func(t *testing.T) {
		m := build(t, false, nil)
		if m.Rcode != dns.RcodeSuccess {
			t.Errorf("rcode = %s, want NOERROR beside an owner=qname NSEC", dns.RcodeToString[m.Rcode])
		}
		// The bitmap signal is for resolvers and does not depend on CO.
		if nsec := nsecOf(t, m); !hasNXNAME(nsec) {
			t.Errorf("NXNAME missing from the bitmap: %s", nsec)
		}
	})

	t.Run("NODATA, DO and CO", func(t *testing.T) {
		m := build(t, true, []uint16{dns.TypeA})
		if m.Rcode != dns.RcodeSuccess {
			t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
		}
		if nsec := nsecOf(t, m); hasNXNAME(nsec) {
			t.Errorf("NXNAME in a NODATA bitmap: %s", nsec)
		}
	})
}

// RFC 9824 section 5.1: "In responses to such queries, an authoritative server
// implementing both Compact Denial of Existence and this signaling scheme will
// set the Compact Answers OK EDNS header flag and, for nonexistent names, will
// additionally set the response code field to NXDOMAIN."
//
// Two acts. The flag goes on EVERY response to a CO query -- it is how a client
// learns this server speaks CO -- and the NXDOMAIN is the additional step for
// nonexistent names. Setting the flag only on the NXDOMAIN left a CO client
// with no way to record the capability from a NODATA, which section 5.1 asks
// downstream resolvers to do.
func TestQueryResponderEchoesCO(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testSnapshotZone(t, "example.", `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 10.0.0.1
www.example. 3600 IN A 10.0.0.2
`)
	ctx := context.Background()

	ask := func(t *testing.T, qname string, qtype uint16, do, co bool) *dns.Msg {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion(qname, qtype)
		req.SetEdns0(4096, do)
		if co {
			edns0.SetCO(req)
		}
		msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
		}
		rw := &fakeRW{}
		if err := zd.QueryResponder(ctx, rw, req, qname, qtype, msgo, kdb, nil); err != nil {
			t.Fatalf("QueryResponder: %v", err)
		}
		if rw.written == nil {
			t.Fatal("no response written")
		}
		return rw.written
	}

	for _, tc := range []struct {
		name   string
		qname  string
		qtype  uint16
		do, co bool
		rcode  int
		wantCO bool
	}{
		{"NXDOMAIN to a DO+CO client", "nosuch.example.", dns.TypeMX, true, true, dns.RcodeNameError, true},
		// The gap this closes: a CO client asking about a name that exists.
		{"NODATA to a DO+CO client", "www.example.", dns.TypeMX, true, true, dns.RcodeSuccess, true},
		// CO without DO still says "I speak CO"; there is just no proof to read.
		{"NXDOMAIN to a CO client without DO", "nosuch.example.", dns.TypeMX, false, true, dns.RcodeNameError, true},
		// And a client that never asked is told nothing.
		{"nothing back to a client that did not ask", "nosuch.example.", dns.TypeMX, true, false, dns.RcodeSuccess, false},
		{"a positive answer to a CO client", "www.example.", dns.TypeA, true, true, dns.RcodeSuccess, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := ask(t, tc.qname, tc.qtype, tc.do, tc.co)
			if resp.Rcode != tc.rcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.rcode])
			}
			if got := edns0.HasCO(resp); got != tc.wantCO {
				t.Errorf("CO on response = %v, want %v", got, tc.wantCO)
			}
		})
	}
}
