/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Removing a nameserver goes to the parent first (#665, fix 2).
//
// The flow tests run the real channel -- ApiZoneUpdate, or the DNS UPDATE
// responder's parent-first arm -- against a running ZoneUpdater. The parent
// is a stand-in that runs the parent's own coherence check against what the
// child zone actually serves at the moment it is asked. That makes the ORDER
// part of what is tested: a parent asked after the zone has already dropped the
// nameserver, or before an addition is in the zone, answers differently.

const pfChild = "child.test."

const pfZone = `child.test.	3600	IN	SOA	ns1.child.test. hostmaster.child.test. 1 7200 1800 604800 7200
child.test.	3600	IN	NS	ns1.child.test.
child.test.	3600	IN	NS	ns3.child.test.
ns1.child.test.	3600	IN	A	192.0.2.1
ns3.child.test.	3600	IN	A	192.0.2.3
`

// pfParent is the parent's delegation for child.test.: what the child zone
// held before the test changed it.
type pfParent struct {
	t         *testing.T
	child     *ZoneData
	ns        []dns.RR
	glue      map[string][]dns.RR
	calls     int
	refuse    error    // answer every request with this, after recording it
	servedNS  []string // the child's NS set as it stood when the parent was asked
	sentRRset []DsyncApiRRset
}

func newPfParent(t *testing.T, child *ZoneData) *pfParent {
	return &pfParent{
		t:     t,
		child: child,
		ns: []dns.RR{
			withdrawalRR(t, "child.test. 3600 IN NS ns1.child.test."),
			withdrawalRR(t, "child.test. 3600 IN NS ns3.child.test."),
		},
		glue: map[string][]dns.RR{
			"ns1.child.test./A": {withdrawalRR(t, "ns1.child.test. 3600 IN A 192.0.2.1")},
			"ns3.child.test./A": {withdrawalRR(t, "ns3.child.test. 3600 IN A 192.0.2.3")},
		},
	}
}

// confirm is the parent: the DSYNC API payload the child would send, through
// the endpoint's action builder and the NS/glue coherence check, asking the
// child zone itself what it serves.
func (p *pfParent) confirm(_ context.Context, status DelegationSyncStatus) (string, error) {
	p.calls++
	apex, err := p.child.GetOwner(pfChild)
	if err != nil || apex == nil {
		p.t.Fatalf("reading the child's apex at the parent's turn: %v", err)
	}
	p.servedNS = withdrawalNSNames(apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)

	p.sentRRset = DsyncApiRRsetsFromSyncStatus(pfChild, status)
	if p.refuse != nil {
		return "", p.refuse
	}
	actions, err := dsyncApiBuildActions(&ZoneData{ZoneName: "test."}, pfChild, p.sentRRset)
	if err != nil {
		return "", err
	}
	currentGlue := func(owner string, qtype uint16) ([]dns.RR, bool) {
		rrs, ok := p.glue[strings.ToLower(dns.Fqdn(owner))+"/"+dns.TypeToString[qtype]]
		return rrs, ok
	}
	served := func(_ context.Context, name string, qtype uint16) ([]dns.RR, bool, error) {
		od, err := p.child.GetOwner(dns.Fqdn(name))
		if err != nil || od == nil {
			return nil, true, nil
		}
		return od.RRtypes.GetOnlyRRSet(qtype).RRs, true, nil
	}
	if err := CheckDelegationNSCoherence(context.Background(), pfChild, p.ns, currentGlue, actions, served); err != nil {
		return "", err
	}
	return "accepted by the stand-in parent", nil
}

func withParentConfirmer(t *testing.T, confirm parentConfirmer) {
	t.Helper()
	saved := parentConfirmerFor
	parentConfirmerFor = func(*ZoneData) parentConfirmer { return confirm }
	t.Cleanup(func() { parentConfirmerFor = saved })
}

// pfZoneWithUpdater registers a primary that syncs its own delegation, with a
// ZoneUpdater running for it for the rest of the test.
func pfZoneWithUpdater(t *testing.T, opts map[ZoneOption]bool) *ZoneData {
	t.Helper()
	zd := testZone(t, pfChild, pfZone)
	registerZones(t, zd)
	zd.ZoneType = Primary
	zd.Options = opts
	zd.UpdatePolicy = policyAllowing(dns.TypeNS, dns.TypeA, dns.TypeAAAA)
	kdb := newTestKeyDB(t)
	// Unbuffered, so that pfSettle can wait for the updater (see there).
	kdb.UpdateQ = make(chan UpdateRequest)
	zd.KeyDB = kdb
	zd.DelegationSyncQ = make(chan DelegationSyncRequest, 8)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = kdb.ZoneUpdaterEngine(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return zd
}

// pfSettle returns once the updater has finished everything it was handed. It
// answers a caller before it queues the delegation sync that follows an apply,
// so a test that reads the sync queue straight after ApiZoneUpdate returns is
// racing it. The queue is unbuffered and the updater is one goroutine, so it
// takes this PING only when the previous request is done with.
func pfSettle(t *testing.T, zd *ZoneData) {
	t.Helper()
	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{Cmd: "PING"}:
	case <-time.After(10 * time.Second):
		t.Fatal("the updater did not come back")
	}
}

func pfOptions() map[ZoneOption]bool {
	return map[ZoneOption]bool{OptParentSync: true, OptAllowApiUpdates: true}
}

func pfNS(t *testing.T, zd *ZoneData) []string {
	t.Helper()
	apex, err := zd.GetOwner(pfChild)
	if err != nil || apex == nil {
		t.Fatalf("GetOwner(apex): %v", err)
	}
	return withdrawalNSNames(apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
}

func pfHasA(zd *ZoneData, owner string) bool {
	od, err := zd.GetOwner(owner)
	return err == nil && od != nil && len(od.RRtypes.GetOnlyRRSet(dns.TypeA).RRs) > 0
}

func pfSameNames(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[strings.ToLower(g)] = true
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}

func pfDelrrNS3() ZonePost {
	return ZonePost{
		Command:    "update",
		Zone:       pfChild,
		UpdateVerb: VerbDelRR,
		UpdateRRs:  []string{"child.test. 3600 IN NS ns3.child.test.", "ns3.child.test. 3600 IN A 192.0.2.3"},
	}
}

// The parent is asked while the child still serves ns3, accepts, and only then
// does the zone drop it.
func TestParentFirstRemovalIsAppliedAfterTheParentConfirms(t *testing.T) {
	zd := pfZoneWithUpdater(t, pfOptions())
	parent := newPfParent(t, zd)
	withParentConfirmer(t, parent.confirm)

	msg, err := zd.ApiZoneUpdate(context.Background(), pfDelrrNS3())
	if err != nil {
		t.Fatalf("ApiZoneUpdate: %v", err)
	}
	if parent.calls != 1 {
		t.Fatalf("the parent was asked %d times, want 1", parent.calls)
	}
	if !pfSameNames(parent.servedNS, "ns1.child.test.", "ns3.child.test.") {
		t.Errorf("when the parent was asked the child served %v; the parent must be asked before the zone drops ns3", parent.servedNS)
	}
	if !withdrawalDeletes(parent.sentRRset, "ns3.child.test.", "A") {
		t.Errorf("the parent was not asked to delete ns3's glue: %s", dsyncApiRRsetsForLog(parent.sentRRset))
	}
	if got := pfNS(t, zd); !pfSameNames(got, "ns1.child.test.") {
		t.Errorf("after confirmation the zone's NS = %v, want [ns1]", got)
	}
	if pfHasA(zd, "ns3.child.test.") {
		t.Error("ns3's address was not removed from the zone")
	}
	// The parent already has it: no zone-first sync may follow and resend it.
	pfSettle(t, zd)
	if n := len(zd.DelegationSyncQ); n != 0 {
		t.Errorf("%d delegation sync(s) queued after a confirmed parent-first change, want 0", n)
	}
	if !strings.Contains(msg, "confirmed") {
		t.Errorf("msg = %q; want it to say the parent confirmed", msg)
	}
}

// Replacing ns3 with ns4: ns4 and its glue go into the zone first (the parent
// checks the child serves them), the parent is asked, and a refusal undoes the
// additions so the zone is exactly as it was.
func TestParentFirstRefusalUndoesTheAdditions(t *testing.T) {
	zd := pfZoneWithUpdater(t, pfOptions())
	parent := newPfParent(t, zd)
	parent.refuse = errors.New("no, says the parent")
	withParentConfirmer(t, parent.confirm)

	_, err := zd.ApiZoneUpdate(context.Background(), ZonePost{
		Command:    "update",
		Zone:       pfChild,
		UpdateVerb: VerbInstructions,
		UpdateInstructions: []ZoneDeltaRR{
			{Action: ZoneDeltaDel, RR: "child.test. 3600 IN NS ns3.child.test."},
			{Action: ZoneDeltaAdd, RR: "child.test. 3600 IN NS ns4.child.test."},
			{Action: ZoneDeltaAdd, RR: "ns4.child.test. 3600 IN A 192.0.2.4"},
		},
	})
	if err == nil {
		t.Fatal("a change the parent refused was reported as applied")
	}
	if !strings.Contains(err.Error(), "no, says the parent") || !strings.Contains(err.Error(), "--force") {
		t.Errorf("err = %q; want the parent's reason and the --force hint", err)
	}
	if !pfSameNames(parent.servedNS, "ns1.child.test.", "ns3.child.test.", "ns4.child.test.") {
		t.Errorf("when the parent was asked the child served %v; ns4 must already be served, ns3 still served", parent.servedNS)
	}
	if got := pfNS(t, zd); !pfSameNames(got, "ns1.child.test.", "ns3.child.test.") {
		t.Errorf("after the refusal the zone's NS = %v, want the original [ns1 ns3]", got)
	}
	if pfHasA(zd, "ns4.child.test.") {
		t.Error("ns4's address, added before asking, was not undone")
	}
	if !pfHasA(zd, "ns3.child.test.") {
		t.Error("ns3's address was removed although the parent refused")
	}
}

// The same replacement with a parent that accepts. The stand-in parent runs the
// real coherence check, so this passes only if ns4 was already served when it
// was asked and ns3 still was.
func TestParentFirstReplacementIsAcceptedByTheParent(t *testing.T) {
	zd := pfZoneWithUpdater(t, pfOptions())
	parent := newPfParent(t, zd)
	withParentConfirmer(t, parent.confirm)

	if _, err := zd.ApiZoneUpdate(context.Background(), ZonePost{
		Command:    "update",
		Zone:       pfChild,
		UpdateVerb: VerbInstructions,
		UpdateInstructions: []ZoneDeltaRR{
			{Action: ZoneDeltaDel, RR: "child.test. 3600 IN NS ns3.child.test."},
			{Action: ZoneDeltaAdd, RR: "child.test. 3600 IN NS ns4.child.test."},
			{Action: ZoneDeltaAdd, RR: "ns4.child.test. 3600 IN A 192.0.2.4"},
		},
	}); err != nil {
		t.Fatalf("ApiZoneUpdate: %v", err)
	}
	if got := pfNS(t, zd); !pfSameNames(got, "ns1.child.test.", "ns4.child.test.") {
		t.Errorf("zone NS = %v, want [ns1 ns4]", got)
	}
}

// --force applies a refused removal, and the ordinary zone-first sync follows.
func TestParentFirstForceAppliesARefusedRemoval(t *testing.T) {
	zd := pfZoneWithUpdater(t, pfOptions())
	parent := newPfParent(t, zd)
	parent.refuse = errors.New("parent unreachable")
	withParentConfirmer(t, parent.confirm)

	zp := pfDelrrNS3()
	zp.Force = true
	msg, err := zd.ApiZoneUpdate(context.Background(), zp)
	if err != nil {
		t.Fatalf("a forced update failed: %v", err)
	}
	if !strings.Contains(msg, "WITHOUT") {
		t.Errorf("msg = %q; want it to say the parent did not confirm", msg)
	}
	if got := pfNS(t, zd); !pfSameNames(got, "ns1.child.test.") {
		t.Errorf("zone NS = %v, want [ns1]", got)
	}
	pfSettle(t, zd)
	if n := len(zd.DelegationSyncQ); n != 1 {
		t.Errorf("%d delegation sync(s) queued after a forced change, want 1: the parent does not have it", n)
	}
}

// An update that removes no nameserver keeps the zone-first order and never
// waits on the parent.
func TestParentFirstLeavesAdditionsZoneFirst(t *testing.T) {
	zd := pfZoneWithUpdater(t, pfOptions())
	parent := newPfParent(t, zd)
	withParentConfirmer(t, parent.confirm)

	if _, err := zd.ApiZoneUpdate(context.Background(), ZonePost{
		Command:    "update",
		Zone:       pfChild,
		UpdateVerb: VerbAddRR,
		UpdateRRs:  []string{"child.test. 3600 IN NS ns4.child.test.", "ns4.child.test. 3600 IN A 192.0.2.4"},
	}); err != nil {
		t.Fatalf("ApiZoneUpdate: %v", err)
	}
	if parent.calls != 0 {
		t.Errorf("an addition asked the parent first (%d calls)", parent.calls)
	}
	pfSettle(t, zd)
	if n := len(zd.DelegationSyncQ); n != 1 {
		t.Errorf("%d delegation sync(s) queued after an addition, want 1", n)
	}
}

// A zone that does not sync its own delegation is not held up by its parent.
func TestParentFirstOnlyForZonesThatSyncTheirDelegation(t *testing.T) {
	zd := pfZoneWithUpdater(t, map[ZoneOption]bool{OptAllowApiUpdates: true})
	parent := newPfParent(t, zd)
	withParentConfirmer(t, parent.confirm)

	if _, err := zd.ApiZoneUpdate(context.Background(), pfDelrrNS3()); err != nil {
		t.Fatalf("ApiZoneUpdate: %v", err)
	}
	if parent.calls != 0 {
		t.Errorf("the parent was asked for a zone without parentsync (%d calls)", parent.calls)
	}
	if got := pfNS(t, zd); !pfSameNames(got, "ns1.child.test.") {
		t.Errorf("zone NS = %v, want [ns1]", got)
	}
}

// chanResponseWriter hands the written message to the test goroutine.
type chanResponseWriter struct {
	dns.ResponseWriter
	ch chan *dns.Msg
}

func (w *chanResponseWriter) WriteMsg(m *dns.Msg) error { w.ch <- m; return nil }

// DNS UPDATE has no --force: a removal the parent refuses is REFUSED, with the
// parent's reason in the EDE, and the zone is untouched.
func TestParentFirstDnsUpdateRefusalCarriesTheParentsReason(t *testing.T) {
	zd := pfZoneWithUpdater(t, map[ZoneOption]bool{OptParentSync: true, OptAllowUpdates: true})
	parent := newPfParent(t, zd)
	parent.refuse = errors.New("the parent has its reasons")
	withParentConfirmer(t, parent.confirm)

	actions, err := BuildZoneUpdateActions(pfChild, ZoneUpdateSpec{
		Verb: VerbDelRR,
		RRs:  []string{"child.test. 3600 IN NS ns3.child.test.", "ns3.child.test. 3600 IN A 192.0.2.3"},
	})
	if err != nil {
		t.Fatalf("BuildZoneUpdateActions: %v", err)
	}
	req := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: pfChild, Actions: actions, Validated: true, Trusted: true}
	w := &chanResponseWriter{ch: make(chan *dns.Msg, 1)}
	m := new(dns.Msg)
	m.SetUpdate(pfChild)

	go zd.answerParentFirst(context.Background(), w, m, req, zd.KeyDB.UpdateQ, dns.RcodeSuccess)

	var reply *dns.Msg
	select {
	case reply = <-w.ch:
	case <-time.After(10 * time.Second):
		t.Fatal("no answer")
	}
	if reply.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[reply.Rcode])
	}
	found := false
	if opt := reply.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if ede, ok := o.(*dns.EDNS0_EDE); ok && ede.InfoCode == edns0.EDEZoneUpdateNotApplied &&
				strings.Contains(ede.ExtraText, "the parent has its reasons") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no EDE carrying the parent's reason: %v", reply.IsEdns0())
	}
	if got := pfNS(t, zd); !pfSameNames(got, "ns1.child.test.", "ns3.child.test.") {
		t.Errorf("zone NS = %v after a refusal, want it unchanged", got)
	}
}

// A NOTIFY cannot confirm anything: the parent acts on it later, from what the
// child serves -- which for a removal sent first is what has not changed.
func TestConfirmingPlanKeepsOnlySchemesWithAVerdict(t *testing.T) {
	plan := &ParentSyncPlan{Parent: "test.", Candidates: []SyncCandidate{
		{Scheme: "NOTIFY"}, {Scheme: "API"}, {Scheme: "UPDATE"},
	}}
	got := confirmingPlan(plan)
	if len(got.Candidates) != 2 || got.Candidates[0].Scheme != "API" || got.Candidates[1].Scheme != "UPDATE" {
		t.Errorf("candidates = %+v, want API then UPDATE, in the plan's order", got.Candidates)
	}
	if onlyNotify := confirmingPlan(&ParentSyncPlan{Candidates: []SyncCandidate{{Scheme: "NOTIFY"}}}); onlyNotify.Usable() {
		t.Error("a NOTIFY-only plan was usable for a change that needs the parent's confirmation")
	}
}

// Glue changes for a nameserver that stays are child-first even inside an update
// that also removes a nameserver.
func TestPlanDelegationChangeGlueOfAKeptNameserverGoesFirst(t *testing.T) {
	zd := withdrawalChildZone(t)
	actions := []dns.RR{
		removalOf(withdrawalRR(t, "child.test. 3600 IN NS ns3.child.test.")),
		removalOf(withdrawalRR(t, "ns1.child.test. 3600 IN A 192.0.2.1")),
		withdrawalRR(t, "ns1.child.test. 3600 IN A 192.0.2.11"),
	}
	ch, err := zd.planDelegationChange(actions)
	if err != nil {
		t.Fatalf("planDelegationChange: %v", err)
	}
	if !ch.removesNS {
		t.Fatal("removing ns3 was not seen as a nameserver removal")
	}
	if len(ch.early) != 2 {
		t.Errorf("early = %v, want ns1's new A and the removal of its old one", ch.early)
	}
	if len(ch.status.NewA) != 1 || !strings.Contains(ch.status.NewA[0].String(), "192.0.2.11") {
		t.Errorf("NewA = %v, want only ns1's new address", ch.status.NewA)
	}
	if len(ch.status.AAdds) != 1 || len(ch.status.ARemoves) != 1 {
		t.Errorf("AAdds = %v, ARemoves = %v; want one each for ns1", ch.status.AAdds, ch.status.ARemoves)
	}
}
