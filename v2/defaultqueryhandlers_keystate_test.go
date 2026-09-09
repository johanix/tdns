/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// agentApp is authApp for a tdns-agent.
func agentApp(t *testing.T) {
	t.Helper()
	prevApp, prevKdb := Globals.App.Type, Conf.Internal.KeyDB
	t.Cleanup(func() { Globals.App.Type, Conf.Internal.KeyDB = prevApp, prevKdb })
	Globals.App.Type = AppTypeAgent
	Conf.Internal.KeyDB = newTestKeyDB(t)
}

// askKeyState sends what queryKeyState sends: a KEY query for the child's
// name carrying a KeyState inquiry option.
func askKeyState(t *testing.T, child string, keyid uint16) *dns.Msg {
	return askKeyStateFor(t, child, dns.TypeKEY, keyid)
}

func askKeyStateFor(t *testing.T, child string, qtype uint16, keyid uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(child, qtype)
	edns0.AttachKeyStateToResponse(req, &edns0.KeyStateOption{KeyID: keyid, KeyState: edns0.KeyStateInquiryKey})
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	rw := &fakeRW{remote: udpAddr("127.0.0.1")}
	if err := DefaultQueryHandler(context.Background(), &DnsQueryRequest{
		ResponseWriter: rw,
		Msg:            req,
		Qname:          child,
		Qtype:          qtype,
		Options:        msgo,
	}); err != nil {
		t.Fatalf("DefaultQueryHandler: %v", err)
	}
	if rw.written == nil {
		t.Fatal("no response written")
	}
	return rw.written
}

// An agent fronting a childsync parent must answer the KeyState inquiry a
// child sends to that parent's UPDATE target. It refused it, with the option
// attached to the refusal, and queryKeyState reads any rcode but NOERROR as
// failure -- so the channel was dead against every agent.
func TestAgentAnswersAKeyStateInquiryForAChildsyncZone(t *testing.T) {
	agentApp(t)
	zd := adoptParent(t, Conf.Internal.KeyDB)

	resp := askKeyState(t, "alpha.parent.example.", 4242)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("the agent answered a KeyState inquiry with %s; the child reads that as failure",
			dns.RcodeToString[resp.Rcode])
	}

	// The carve-out is the inquiry and nothing wider. The same name without
	// the option is an ordinary query, and the agent is not a nameserver.
	if plain := ask(t, "alpha.parent.example.", dns.TypeKEY); plain.Rcode != dns.RcodeRefused {
		t.Errorf("a plain KEY query to the agent got %s, want REFUSED", dns.RcodeToString[plain.Rcode])
	}

	// The option stapled to a query that is not the inquiry -- another qtype
	// -- does not open the agent either.
	if resp := askKeyStateFor(t, "alpha.parent.example.", dns.TypeA, 4242); resp.Rcode != dns.RcodeRefused {
		t.Errorf("a KeyState option on an A query got %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}

	// And the option alone does not open a zone that offers no childsync.
	zd.Options[OptChildSync] = false
	if resp := askKeyState(t, "alpha.parent.example.", 4242); resp.Rcode != dns.RcodeRefused {
		t.Errorf("a KeyState inquiry for a zone without childsync got %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}
