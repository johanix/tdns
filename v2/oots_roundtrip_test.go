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

func TestTransportSignalToSVCBOots_RoundTrip(t *testing.T) {
	oots, err := transportSignalToSVCBOots("doq:20,dot:10,do53:0")
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if oots == nil {
		t.Fatal("expected non-nil SVCBOots")
	}
	if oots.Key() != dns.SVCB_OOTS {
		t.Fatalf("key=%v, want SVCB_OOTS", oots.Key())
	}

	svcb := &dns.SVCB{
		Hdr:      dns.RR_Header{Name: "_dns.ns.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 10800},
		Priority: 1,
		Target:   ".",
		Value:    []dns.SVCBKeyValue{oots},
	}
	// Pack/unpack through presentation form to exercise the fork codec.
	parsed, err := dns.NewRR(svcb.String())
	if err != nil {
		t.Fatalf("reparse presentation %q: %v", svcb.String(), err)
	}
	got, ok := parsed.(*dns.SVCB)
	if !ok {
		t.Fatalf("reparsed type %T", parsed)
	}
	m, present, err := GetTransportParam(got)
	if err != nil || !present {
		t.Fatalf("GetTransportParam: present=%v err=%v", present, err)
	}
	if m["doq"] != 20 || m["dot"] != 10 || m["do53"] != 0 {
		t.Errorf("round-trip map=%v", m)
	}
}

func TestTransportSignalToSVCBOots_OmitsImplicitZeros(t *testing.T) {
	oots, err := transportSignalToSVCBOots("doq:20,dot:10")
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	for _, e := range oots.Oots {
		if e.Proto == "doh" {
			t.Errorf("should not emit implicit doh:0, got %#v", oots.Oots)
		}
	}
	// Absent do53 defaults to 100 and should be emitted explicitly.
	foundDo53 := false
	for _, e := range oots.Oots {
		if e.Proto == "do53" {
			foundDo53 = true
			if e.Weight != 100 {
				t.Errorf("do53 weight=%d, want 100", e.Weight)
			}
		}
	}
	if !foundDo53 {
		t.Error("expected explicit do53:100 in emitted oots")
	}
}

func TestAddOTSOption_ZeroLengthPresence(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.", dns.TypeA)
	if err := edns0.AddOTSToMessage(msg); err != nil {
		t.Fatalf("AddOTSToMessage: %v", err)
	}
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("missing OPT")
	}
	var found *dns.EDNS0_LOCAL
	for _, o := range opt.Option {
		if loc, ok := o.(*dns.EDNS0_LOCAL); ok && loc.Code == edns0.EDNS0_OTS_OPTION_CODE {
			found = loc
			break
		}
	}
	if found == nil {
		t.Fatal("OOTS option not found")
	}
	if len(found.Data) != 0 {
		t.Errorf("OPTION-LENGTH must be 0, got %d bytes", len(found.Data))
	}
	opts, err := edns0.ExtractFlagsAndEDNS0Options(msg)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !opts.OtsOptIn {
		t.Error("presence must set OtsOptIn")
	}
}

func TestTSYNCPathStillParses(t *testing.T) {
	m, err := core.ParseTransportString("doq:40,dot:10")
	if err != nil {
		t.Fatalf("TSYNC-style string: %v", err)
	}
	if m["doq"] != 40 || m["do53"] != 100 {
		t.Errorf("map=%v", m)
	}
}
