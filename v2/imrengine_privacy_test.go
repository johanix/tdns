/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"testing"

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
