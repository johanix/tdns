/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"testing"

	"github.com/miekg/dns"
)

// TestFakeExchangeWithResult verifies the ExchangeResult reporting: a plain
// Do53 answer reports WireTransport=Do53/Truncated=false, while a TC=1
// (truncated) Do53 response reports WireTransport=Do53TCP/Truncated=true.
func TestFakeExchangeWithResult(t *testing.T) {
	f := NewFakeDNSClient(TransportDo53)

	q := new(dns.Msg)
	q.SetQuestion("plain.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(q)
	f.Set("plain.example.", "1.2.3.4", FakeResponse{Msg: resp})

	_, _, res, err := f.ExchangeWithResult(q, "1.2.3.4", false)
	if err != nil {
		t.Fatalf("plain exchange err: %v", err)
	}
	if res.WireTransport != TransportDo53 || res.Truncated {
		t.Fatalf("plain: got %+v, want {Do53,false}", res)
	}

	tq := new(dns.Msg)
	tq.SetQuestion("trunc.example.", dns.TypeA)
	tresp := new(dns.Msg)
	tresp.SetReply(tq)
	tresp.Truncated = true
	f.Set("trunc.example.", "1.2.3.4", FakeResponse{Msg: tresp})

	_, _, res2, err := f.ExchangeWithResult(tq, "1.2.3.4", false)
	if err != nil {
		t.Fatalf("truncated exchange err: %v", err)
	}
	if res2.WireTransport != TransportDo53TCP || !res2.Truncated {
		t.Fatalf("truncated: got %+v, want {Do53TCP,true}", res2)
	}
}
