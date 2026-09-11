/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A hosted root is a zone like any other: the query, UPDATE, KeyState and
 * NOTIFY(CDS/CSYNC) paths find it for names below it, as they find any other
 * hosted parent. FindZone never returned the root for a name below it, so a
 * root-only server REFUSED every query under the root, a TLD's DS included.
 */
package tdns

import (
	"context"
	"testing"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const rootDispatchZone = `.	3600	IN	SOA	ns.tld. hostmaster.tld. 1 7200 1800 604800 7200
.	3600	IN	NS	ns.tld.
tld.	3600	IN	NS	ns.tld.
tld.	3600	IN	DS	12345 8 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766
ns.tld.	3600	IN	A	192.0.2.6
`

// Through the real DefaultQueryHandler, on a server that hosts only the root.
func TestRootOnlyServerAnswersBelowTheRoot(t *testing.T) {
	authApp(t)
	testSnapshotZone(t, ".", rootDispatchZone)

	// The TLD's DS is the root's to serve.
	resp := ask(t, "tld.", dns.TypeDS)
	var gotDS bool
	for _, rr := range resp.Answer {
		if ds, ok := rr.(*dns.DS); ok && ds.Header().Name == "tld." {
			gotDS = true
		}
	}
	if resp.Rcode != dns.RcodeSuccess || !gotDS {
		t.Errorf("tld. DS: rcode %s answer %v, want the root's DS", dns.RcodeToString[resp.Rcode], resp.Answer)
	}

	// A name under the TLD gets the root's referral.
	resp = ask(t, "www.tld.", dns.TypeA)
	var refers bool
	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok && ns.Header().Name == "tld." {
			refers = true
		}
	}
	if resp.Rcode != dns.RcodeSuccess || resp.Authoritative || !refers {
		t.Errorf("www.tld. A: rcode %s AA=%v authority %v, want a referral to tld.",
			dns.RcodeToString[resp.Rcode], resp.Authoritative, resp.Ns)
	}

	// A TLD the root does not delegate does not exist.
	if resp = ask(t, "nope.", dns.TypeA); resp.Rcode != dns.RcodeNameError || !resp.Authoritative {
		t.Errorf("nope. A: rcode %s AA=%v, want an authoritative NXDOMAIN", dns.RcodeToString[resp.Rcode], resp.Authoritative)
	}
}

// A single-RR UPDATE is dispatched on the RR's owner, so a TLD's delegation
// update arrives as "tld." -- whose zone is the hosted root, not "not found".
func TestUpdateOfATLDDelegationFindsTheHostedRoot(t *testing.T) {
	zd := testSnapshotZone(t, ".", rootDispatchZone)
	zd.Options = map[ZoneOption]bool{OptAllowChildUpdates: true}

	m := new(dns.Msg)
	m.SetUpdate(".")
	rr, err := dns.NewRR("tld. 3600 IN NS ns2.tld.")
	if err != nil {
		t.Fatal(err)
	}
	m.Insert([]dns.RR{rr})
	cw := &captureWriter{}
	_ = UpdateResponder(context.Background(), &DnsUpdateRequest{ResponseWriter: cw, Msg: m, Qname: ".", Status: &UpdateStatus{}}, nil)

	if cw.got == nil {
		t.Fatal("responder wrote no response")
	}
	if found, code, _ := edns0.ExtractEDEFromMsg(cw.got); found && code == edns0.EDEZoneNotFound {
		t.Fatalf("UPDATE of tld.'s delegation: zone not found, but the server hosts its parent, the root")
	}
	// Found, it goes on to validation, which refuses the unsigned message as
	// malformed: proof the root took it.
	if cw.got.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode %s, want FORMERR from validating the unsigned UPDATE", dns.RcodeToString[cw.got.Rcode])
	}
}

// NOTIFY(CDS) for a TLD finds the hosted root as its parent. It stops at the
// next gate -- the root advertises no DSYNC -- which is the point: it used to
// be refused before the parent was even looked for.
func TestNotifyCDSForATLDFindsTheHostedRoot(t *testing.T) {
	testSnapshotZone(t, ".", rootDispatchZone)

	notify := func(qname string) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetNotify(qname)
		m.Question[0].Qtype = dns.TypeCDS
		cw := &captureWriter{}
		if err := NotifyResponder(context.Background(), &DnsNotifyRequest{
			ResponseWriter: cw, Msg: m, Qname: qname, Options: &edns0.MsgOptions{}, Status: &NotifyStatus{},
		}, nil, nil); err != nil {
			t.Fatalf("NotifyResponder(%s): %v", qname, err)
		}
		if cw.got == nil {
			t.Fatalf("NotifyResponder(%s): no response", qname)
		}
		return cw.got
	}

	resp := notify("tld.")
	if _, code, _ := edns0.ExtractEDEFromMsg(resp); code != edns0.EDENotifyDsyncSchemeNotAdvertised {
		t.Errorf("NOTIFY(CDS) tld.: EDE %d, want %d (the root found as parent, refused only for its missing DSYNC)",
			code, edns0.EDENotifyDsyncSchemeNotAdvertised)
	}

	// The root itself still has no parent.
	resp = notify(".")
	if _, code, _ := edns0.ExtractEDEFromMsg(resp); resp.Rcode != dns.RcodeRefused || code != edns0.EDENotifyTargetNotChildDelegation {
		t.Errorf("NOTIFY(CDS) .: rcode %s EDE %d, want REFUSED with %d", dns.RcodeToString[resp.Rcode], code, edns0.EDENotifyTargetNotChildDelegation)
	}
}

// A KeyState inquiry for a TLD is answered by its childsync parent, the root.
// The option is only ever sent SIG(0)-signed by the parent's UPDATE Receiver
// key (fail closed), so the root is given one: without it the inquiry is
// processed and the answer still omitted, which a test cannot tell from the
// inquiry never reaching the root.
func TestKeyStateInquiryForATLDReachesTheRoot(t *testing.T) {
	authApp(t)
	zd := testSnapshotZone(t, ".", rootDispatchZone)
	zd.Options = map[ZoneOption]bool{OptChildSync: true}

	t.Cleanup(func() { SetDelegationSyncConfig(ChildSyncConf{}, ParentSyncConf{}) })
	if err := SetDelegationSyncConfig(ChildSyncConf{
		Update: DsyncUpdateSchemeConf{DsyncDnsSchemeConf: DsyncDnsSchemeConf{Target: "updates.{ZONENAME}"}},
	}, ParentSyncConf{}); err != nil {
		t.Fatal(err)
	}
	genSig0Key(t, Conf.Internal.KeyDB, DsyncUpdateTargetName("."))

	resp := askKeyState(t, "tld.", 4242)
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("no OPT in the response: the KeyState inquiry was not processed")
	}
	if ks, found := edns0.ExtractKeyStateOption(opt); !found || ks.KeyID != 4242 {
		t.Errorf("KeyState option %+v (found=%v), want an answer for key 4242 from the root", ks, found)
	}
}
