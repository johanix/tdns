/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The response-direction signal is only for clients that asked. A client that
// sent no PRIVACY option gets an unchanged response -- no option, and, when it
// sent no OPT at all, no OPT invented for it.
func TestSetPrivacyStatusOnlyForClientsThatAsked(t *testing.T) {
	m := new(dns.Msg)
	setPrivacyStatus(m, &edns0.MsgOptions{HasPrivacy: false}, edns0.PrivacyEncrypted)
	if m.IsEdns0() != nil {
		t.Error("response gained an OPT RR for a client that never asked")
	}
}

func TestSetPrivacyStatusValues(t *testing.T) {
	for _, status := range []edns0.PrivacyStatus{
		edns0.PrivacyCleartext, edns0.PrivacyEncrypted, edns0.PrivacyCached,
	} {
		m := new(dns.Msg)
		setPrivacyStatus(m, &edns0.MsgOptions{HasPrivacy: true, Privacy: edns0.PrivacyStrict}, status)
		got, found := edns0.ExtractPrivacyStatus(m.IsEdns0())
		if !found {
			t.Errorf("status %s: no PRIVACY option in the response", status)
			continue
		}
		if got != status {
			t.Errorf("status %s: response carries %s", status, got)
		}
	}
}

// A response OPT must mirror the query's DO bit (RFC 3225 §3). The flag-bit
// code this replaced built its OPT with DO hardcoded to false, silently
// clearing DO on exactly the responses it touched.
func TestSetPrivacyStatusPreservesDO(t *testing.T) {
	m := new(dns.Msg)
	setPrivacyStatus(m, &edns0.MsgOptions{HasPrivacy: true, DO: true}, edns0.PrivacyEncrypted)
	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("no OPT RR in the response")
	}
	if !opt.Do() {
		t.Error("response OPT dropped the DO bit")
	}
}

// An OPT the response already has (built by the EDE or KeyState paths) must be
// reused, not duplicated: two OPT RRs in one message is a format error.
func TestSetPrivacyStatusReusesExistingOPT(t *testing.T) {
	m := new(dns.Msg)
	m.SetEdns0(1232, true)
	setPrivacyStatus(m, &edns0.MsgOptions{HasPrivacy: true, DO: true}, edns0.PrivacyCached)

	opts := 0
	for _, rr := range m.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			opts++
		}
	}
	if opts != 1 {
		t.Errorf("got %d OPT RRs, want 1", opts)
	}
	if got, _ := edns0.ExtractPrivacyStatus(m.IsEdns0()); got != edns0.PrivacyCached {
		t.Errorf("got %s, want %s", got, edns0.PrivacyCached)
	}
	if m.IsEdns0().UDPSize() != 1232 {
		t.Errorf("existing OPT was rebuilt: udpsize is %d, want 1232", m.IsEdns0().UDPSize())
	}
}

// A negative answer is fetched over a transport just as a positive one is, so
// it must carry the same status. It did not: the live NXDOMAIN / NODATA arms
// of ProcessAuthDNSResponse wrote the response with no PRIVACY option at all,
// while the cached-negative paths attached PrivacyCached. A strict client,
// following this feature's own migration note, would read that silence as a
// resolver that ignored the request.
func TestLiveNegativesCarryPrivacyStatus(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cacheCtx  cache.CacheContext
		transport core.Transport
		wantRcode int
		want      edns0.PrivacyStatus
	}{
		{"NXDOMAIN over DoT", cache.ContextNXDOMAIN, core.TransportDoT, dns.RcodeNameError, edns0.PrivacyEncrypted},
		{"NXDOMAIN over Do53", cache.ContextNXDOMAIN, core.TransportDo53, dns.RcodeNameError, edns0.PrivacyCleartext},
		{"NODATA over DoQ", cache.ContextNoErrNoAns, core.TransportDoQ, dns.RcodeSuccess, edns0.PrivacyEncrypted},
		{"NODATA over Do53", cache.ContextNoErrNoAns, core.TransportDo53, dns.RcodeSuccess, edns0.PrivacyCleartext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := newTestImr(t)

			r := new(dns.Msg)
			r.SetQuestion("nx.example.", dns.TypeA)
			if err := edns0.AddPrivacyLevelToMessage(r, edns0.PrivacyStrict); err != nil {
				t.Fatalf("AddPrivacyLevelToMessage: %v", err)
			}
			msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(r)
			if err != nil {
				t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
			}
			if !msgoptions.HasPrivacy {
				t.Fatal("setup: the query did not carry the PRIVACY option")
			}

			w := &fakeResponseWriter{}
			m := new(dns.Msg)
			done, err := imr.ProcessAuthDNSResponse(context.Background(), "nx.example.", dns.TypeA,
				nil, tc.wantRcode, tc.cacheCtx, msgoptions, m, w, r, tc.transport)
			if err != nil {
				t.Fatalf("ProcessAuthDNSResponse: %v", err)
			}
			if !done {
				t.Fatal("negative response was not treated as final")
			}
			if w.msg == nil {
				t.Fatal("nothing was written")
			}
			if w.msg.Rcode != tc.wantRcode {
				t.Errorf("got rcode %s, want %s", dns.RcodeToString[w.msg.Rcode], dns.RcodeToString[tc.wantRcode])
			}
			got, found := edns0.ExtractPrivacyStatus(w.msg.IsEdns0())
			if !found {
				t.Fatal("the response carries no PRIVACY status")
			}
			if got != tc.want {
				t.Errorf("got status %s, want %s", got, tc.want)
			}
		})
	}
}

// And a client that never asked still gets an untouched negative response.
func TestLiveNegativesStaySilentWhenNotAsked(t *testing.T) {
	imr := newTestImr(t)

	r := new(dns.Msg)
	r.SetQuestion("nx.example.", dns.TypeA)
	msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(r)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}

	w := &fakeResponseWriter{}
	m := new(dns.Msg)
	if _, err := imr.ProcessAuthDNSResponse(context.Background(), "nx.example.", dns.TypeA,
		nil, dns.RcodeNameError, cache.ContextNXDOMAIN, msgoptions, m, w, r, core.TransportDoT); err != nil {
		t.Fatalf("ProcessAuthDNSResponse: %v", err)
	}
	if w.msg == nil {
		t.Fatal("nothing was written")
	}
	if _, found := edns0.ExtractPrivacyStatus(w.msg.IsEdns0()); found {
		t.Error("a client that never asked got a PRIVACY status")
	}
}

// A SERVFAIL carries no PRIVACY status: there is no served answer whose
// privacy could be reported, and the EDE is the signal. The status used to be
// attached before DNSSEC validation ran, and validation failure clears Answer
// but not Extra -- so the option rode out on a response that carried nothing.
//
// Validation here cannot conclude: the test cache has no root hints and no
// servers, so the chain walk never starts and no packet is sent. That lands on
// the indeterminate arm, one of the three SERVFAIL exits below the point where
// the status used to be attached.
func TestValidationFailureLeavesNoPrivacyStatus(t *testing.T) {
	imr := newTestImr(t)

	r := new(dns.Msg)
	r.SetQuestion("www.example.", dns.TypeA)
	r.SetEdns0(4096, true) // DO=1, CD=0 -> validation is attempted
	if err := edns0.AddPrivacyLevelToMessage(r, edns0.PrivacyStrict); err != nil {
		t.Fatalf("AddPrivacyLevelToMessage: %v", err)
	}
	msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(r)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	if !msgoptions.DO || msgoptions.CD || !msgoptions.HasPrivacy {
		t.Fatalf("setup: DO=%v CD=%v HasPrivacy=%v", msgoptions.DO, msgoptions.CD, msgoptions.HasPrivacy)
	}

	rrset := &core.RRset{
		Name:   "www.example.",
		RRtype: dns.TypeA,
		RRs: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		}},
	}

	w := &fakeResponseWriter{}
	m := new(dns.Msg)
	// The error return distinguishes "the fetch blew up" from "the verdict was
	// not secure"; both end in SERVFAIL, and the assertion below is about the
	// response either way.
	_, _ = imr.ProcessAuthDNSResponse(context.Background(), "www.example.", dns.TypeA,
		rrset, dns.RcodeSuccess, cache.ContextAnswer, msgoptions, m, w, r, core.TransportDoT)
	if w.msg == nil {
		t.Fatal("nothing was written")
	}
	if w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("got rcode %s, want SERVFAIL: this test only means something on a failed-validation response",
			dns.RcodeToString[w.msg.Rcode])
	}
	if len(w.msg.Answer) != 0 {
		t.Errorf("SERVFAIL carries %d answer RRs", len(w.msg.Answer))
	}
	if status, found := edns0.ExtractPrivacyStatus(w.msg.IsEdns0()); found {
		t.Errorf("SERVFAIL carries PRIVACY status %s; it reports privacy for an answer that was not served", status)
	}
}

// The other side of the same move: an answer that IS served still reports its
// status. Without validation (DO=0) the answer goes straight out.
func TestServedAnswerCarriesPrivacyStatus(t *testing.T) {
	imr := newTestImr(t)

	r := new(dns.Msg)
	r.SetQuestion("www.example.", dns.TypeA)
	if err := edns0.AddPrivacyLevelToMessage(r, edns0.PrivacyOpportunistic); err != nil {
		t.Fatalf("AddPrivacyLevelToMessage: %v", err)
	}
	msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(r)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	if msgoptions.DO {
		t.Fatal("setup: DO must be off so validation is skipped")
	}

	rrset := &core.RRset{
		Name:   "www.example.",
		RRtype: dns.TypeA,
		RRs: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		}},
	}

	w := &fakeResponseWriter{}
	m := new(dns.Msg)
	done, err := imr.ProcessAuthDNSResponse(context.Background(), "www.example.", dns.TypeA,
		rrset, dns.RcodeSuccess, cache.ContextAnswer, msgoptions, m, w, r, core.TransportDoT)
	if err != nil || !done {
		t.Fatalf("ProcessAuthDNSResponse: done=%v err=%v", done, err)
	}
	if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("got %v", w.msg)
	}
	got, found := edns0.ExtractPrivacyStatus(w.msg.IsEdns0())
	if !found {
		t.Fatal("a served answer carries no PRIVACY status")
	}
	if got != edns0.PrivacyEncrypted {
		t.Errorf("got status %s, want %s", got, edns0.PrivacyEncrypted)
	}
}
