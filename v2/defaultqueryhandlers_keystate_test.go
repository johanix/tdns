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

// keyStateReceiver gives the server an UPDATE Receiver for its childsync
// zones, named updates.<zone>, with an active SIG(0) key for parent's
// receiver, and returns the receiver's name.
func keyStateReceiver(t *testing.T, kdb *KeyDB, parent string) string {
	t.Helper()
	prevCS, prevPS := *ChildSyncConfig(), *ParentSyncConfig()
	t.Cleanup(func() { _ = SetDelegationSyncConfig(prevCS, prevPS) })
	if err := SetDelegationSyncConfig(ChildSyncConf{
		Schemes: []string{"update"},
		Update: DsyncUpdateSchemeConf{
			DsyncDnsSchemeConf: DsyncDnsSchemeConf{
				Types:     []string{"ANY"},
				Port:      53,
				Target:    "updates.{ZONENAME}",
				Addresses: []string{"192.0.2.1"},
			},
		},
	}, ParentSyncConf{}); err != nil {
		t.Fatal(err)
	}
	receiver := DsyncUpdateTargetName(parent)
	genProxySig0Key(t, kdb, receiver)
	return receiver
}

// wantKeyStateAnswer checks that resp is the parent's answer to an inquiry
// for keyid: NOERROR, the KeyState option for that key, signed by receiver.
func wantKeyStateAnswer(t *testing.T, resp *dns.Msg, keyid uint16, receiver string) {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("the inquiry was answered with %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	ks, found := edns0.ExtractKeyStateOption(resp.IsEdns0())
	if !found {
		t.Fatal("the answer carries no KeyState option: the child reads that as \"KeyState option missing in response\"")
	}
	if ks.KeyID != keyid || ks.KeyState != edns0.KeyStateUnknown {
		t.Errorf("the answer says key %d is in state %d, want key %d in state %d (unknown: the truststore holds no such key)",
			ks.KeyID, ks.KeyState, keyid, edns0.KeyStateUnknown)
	}
	sig := keyStateSig0(resp)
	if sig == nil {
		t.Fatal("the answer is not SIG(0)-signed: a child MUST NOT act on an unsigned key state")
	}
	if !dns.IsFqdn(sig.SignerName) || dns.CanonicalName(sig.SignerName) != dns.CanonicalName(receiver) {
		t.Errorf("the answer is signed by %q, want the parent's UPDATE Receiver %q", sig.SignerName, receiver)
	}
}

const keyStateChildZone = `alpha.parent.example.	3600	IN	SOA	ns.alpha.parent.example. hostmaster.alpha.parent.example. 1 7200 1800 604800 7200
alpha.parent.example.	3600	IN	NS	ns.alpha.parent.example.
ns.alpha.parent.example.	3600	IN	A	192.0.2.51
`

// A server that hosts a childsync parent and the child zone as well: the
// owner's primary of a zone that is also the primary of the zone's parent.
// The inquiry names the child, and the longest match for that name is the
// child zone itself, which offers no childsync. The gate looked there, so the
// inquiry was answered as an ordinary KEY query: no KeyState option and no
// signature, and the child's every inquiry ended in "KeyState option missing
// in response". The parent side of the name answers, as for a DS query.
func TestAKeyStateInquiryIsAnsweredWhenTheChildZoneIsHostedToo(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	parent := adoptParent(t, kdb)
	receiver := keyStateReceiver(t, kdb, parent.ZoneName)

	// The parent alone: the case that worked.
	wantKeyStateAnswer(t, askKeyState(t, "alpha.parent.example.", 4242), 4242, receiver)

	// The same server now hosts the child too.
	child := testZone(t, "alpha.parent.example.", keyStateChildZone)
	registerZones(t, child)
	wantKeyStateAnswer(t, askKeyState(t, "alpha.parent.example.", 4242), 4242, receiver)

	// A zone that offers no childsync still answers nothing about keys: the
	// option on a query for a name below it gets an ordinary answer.
	parent.Options[OptChildSync] = false
	resp := askKeyState(t, "alpha.parent.example.", 4242)
	if _, found := edns0.ExtractKeyStateOption(resp.IsEdns0()); found {
		t.Error("a parent without childsync answered a KeyState inquiry with the option")
	}
	if keyStateSig0(resp) != nil {
		t.Error("a parent without childsync signed its answer as an UPDATE Receiver")
	}
}

// The inquiry is about the name's parent side also when the hosted child
// offers childsync for its own children: the child's key is held by the
// zone above it, and that zone's UPDATE Receiver signs the answer, not the
// child's.
func TestAKeyStateInquiryForAHostedChildsyncChildIsItsParents(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	parent := adoptParent(t, kdb)
	receiver := keyStateReceiver(t, kdb, parent.ZoneName)

	child := testZone(t, "alpha.parent.example.", keyStateChildZone)
	child.KeyDB = kdb
	child.Options = map[ZoneOption]bool{OptChildSync: true}
	registerZones(t, child)
	genProxySig0Key(t, kdb, DsyncUpdateTargetName(child.ZoneName))

	wantKeyStateAnswer(t, askKeyState(t, "alpha.parent.example.", 4242), 4242, receiver)
}
