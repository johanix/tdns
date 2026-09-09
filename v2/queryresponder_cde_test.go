/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The synthesised denial is one NSEC, owned by the denied name, and what it
// means depends on who reads it. RFC 9824 settles the two readings with the
// CO flag: NXDOMAIN, marked CO on the response, for a client that reads
// NXNAME; NOERROR for one that would read the NSEC as existence. The NXNAME
// in the bitmap is what a resolver uses to tell the two denials apart and
// does not depend on the flag.
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
		if !edns0.HasCO(m) {
			t.Error("CO not set on a compact NXDOMAIN response")
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
		if edns0.HasCO(m) {
			t.Error("CO set on a response to a client that did not ask for compact answers")
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
		if edns0.HasCO(m) {
			t.Error("CO set on a NODATA; only the NXDOMAIN form is marked")
		}
		if nsec := nsecOf(t, m); hasNXNAME(nsec) {
			t.Errorf("NXNAME in a NODATA bitmap: %s", nsec)
		}
	})
}
