/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
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
