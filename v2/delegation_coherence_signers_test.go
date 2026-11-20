/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #925: a child that two providers sign has one DNSKEY RRset per nameserver.
// Every nameserver serves the keys of both signers, and signs the RRset with
// its own signer's key only. The check used to judge the one copy a resolver
// returned, so withdrawing one signer's DS passed whenever the resolver's copy
// was the other signer's, and adding it back was refused whenever it was not.

const (
	nsA = "ns1.provider-a.example."
	nsB = "ns1.provider-b.example."
)

// signerPair is the two signers of a child: each a KSK, and its DS.
type signerPair struct {
	a, b     *signerTestKey
	dsA, dsB *dns.DS
	inc, exp time.Time
}

func newSignerPair(t *testing.T, child string) signerPair {
	t.Helper()
	a := newSignerTestKey(t, child, 257)
	b := newSignerTestKey(t, child, 257)
	now := time.Now()
	return signerPair{a: a, b: b, dsA: dsForKey(t, a), dsB: dsForKey(t, b),
		inc: now.Add(-time.Hour), exp: now.Add(time.Hour)}
}

// signedBy is the DNSKEY RRset both signers publish, signed by signers only.
func (p signerPair) signedBy(t *testing.T, signers ...*signerTestKey) *core.RRset {
	t.Helper()
	return signedDnskeys(t, testKeys(p.a, p.b), signers, p.inc, p.exp)
}

// copyOf is the copy nameserver server serves.
func copyOf(server string, rrset *core.RRset) dnskeyCopy {
	return dnskeyCopy{Server: server, RRset: rrset}
}

// silentServer is a nameserver that gave no copy.
func silentServer(server string) dnskeyCopy {
	return dnskeyCopy{Server: server, Err: errors.New("it gave no answer")}
}

// serversGive is a fetcher that hands over copies as they are.
func serversGive(copies ...dnskeyCopy) dnskeyFetcher {
	return func(string, childServers) ([]dnskeyCopy, error) { return copies, nil }
}

// Withdrawing one signer's DS leaves the DS RRset matching a key the child
// publishes, and leaves the other signer's nameservers serving an RRset that no
// DS vouches for. The copy the resolver returns can be the other signer's, so
// that copy alone says the change is fine.
func TestCoherenceRefusesWithdrawingASignersDSWhileItsNameserversServeItsCopy(t *testing.T) {
	p := newSignerPair(t, cohChild)
	current := []dns.RR{p.dsA, p.dsB}
	withdrawA := []dns.RR{delOneDS(p.dsA)}
	copyA := copyOf(nsA, p.signedBy(t, p.a))
	copyB := copyOf(nsB, p.signedBy(t, p.b))

	// What was judged before: whichever copy the resolver gave. B's is fine.
	if err := CheckDelegationCoherence(cohChild, childServers{}, current, withdrawA, serversGive(copyB)); err != nil {
		t.Fatalf("B's copy alone was refused, so this does not show why one copy is not enough: %v", err)
	}

	for _, tc := range []struct {
		name   string
		copies []dnskeyCopy
	}{
		{"A's copy first", []dnskeyCopy{copyA, copyB}},
		{"B's copy first", []dnskeyCopy{copyB, copyA}},
		{"both copies Secure to a resolver that holds the DS RRset from before",
			[]dnskeyCopy{
				{Server: nsA, RRset: copyA.RRset, State: cache.ValidationStateSecure},
				{Server: nsB, RRset: copyB.RRset, State: cache.ValidationStateSecure},
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckDelegationCoherence(cohChild, childServers{}, current, withdrawA, serversGive(tc.copies...))
			if err == nil {
				t.Fatal("a DS was withdrawn that the DNSKEY RRset at a nameserver is signed by," +
					" and no other DS vouches for")
			}
			if !strings.Contains(err.Error(), "nameserver "+nsA) {
				t.Errorf("the refusal does not name the nameserver whose copy would turn bogus: %v", err)
			}
			if errors.Is(err, ErrDelegationUnverifiable) {
				t.Errorf("a decided refusal is marked unverifiable: %v", err)
			}
			if got := delegationCoherenceEDE(err); got != edns0.EDEDelegationIncoherent {
				t.Errorf("EDE %d, want %d (incoherent)", got, edns0.EDEDelegationIncoherent)
			}
			if got := dsyncApiCoherenceStatus(err); got != http.StatusConflict {
				t.Errorf("status %d, want %d: waiting does not change what the copies are signed by",
					got, http.StatusConflict)
			}
		})
	}
}

// The right order for retiring a signer: its nameservers leave the delegation
// first, and then its DS. Then no copy is signed by the key being withdrawn.
func TestCoherenceAllowsWithdrawingTheDSOfASignerThatIsOutOfTheDelegation(t *testing.T) {
	p := newSignerPair(t, cohChild)
	current := []dns.RR{p.dsA, p.dsB}
	withdrawA := []dns.RR{delOneDS(p.dsA)}

	// Only B's nameservers are in the delegation, so only B's copy is asked.
	if err := CheckDelegationCoherence(cohChild, childServers{}, current, withdrawA,
		serversGive(copyOf(nsB, p.signedBy(t, p.b)))); err != nil {
		t.Fatalf("withdrawing A's DS after A's nameservers left the delegation was refused: %v", err)
	}

	// Both nameservers in the delegation, and both serve copies B signs: the
	// hand-over is complete.
	if err := CheckDelegationCoherence(cohChild, childServers{}, current, withdrawA,
		serversGive(copyOf(nsA, p.signedBy(t, p.b)), copyOf(nsB, p.signedBy(t, p.b)))); err != nil {
		t.Fatalf("withdrawing A's DS once every copy is signed by B was refused: %v", err)
	}
}

// Replacing one signer's DS by another's is a withdrawal too: the copies must
// be signed by a key the DS RRset that results matches.
func TestCoherenceRefusesReplacingADSThatTheCopiesAreNotSignedFor(t *testing.T) {
	p := newSignerPair(t, cohChild)
	swap := []dns.RR{delOneDS(p.dsA), addDS(p.dsB)}
	copies := []dnskeyCopy{copyOf(nsA, p.signedBy(t, p.a)), copyOf(nsB, p.signedBy(t, p.a))}

	err := CheckDelegationCoherence(cohChild, childServers{}, []dns.RR{p.dsA}, swap, serversGive(copies...))
	if err == nil {
		t.Fatal("A's DS was replaced by B's while every copy is signed by A only")
	}
	if !strings.Contains(err.Error(), "would not validate the DNSKEY RRset") {
		t.Errorf("unexpected refusal reason: %v", err)
	}
}

// A nameserver that gave no copy leaves open whether the DS being withdrawn is
// the one vouching for what it serves. Accepting the change on the copies that
// could be had would make the check a formality that a nameserver that is down
// bypasses: the change is refused, as one that can be retried.
func TestCoherenceWithdrawingADSNeedsEveryNameserversCopy(t *testing.T) {
	p := newSignerPair(t, cohChild)
	current := []dns.RR{p.dsA, p.dsB}
	withdrawA := []dns.RR{delOneDS(p.dsA)}
	copyB := copyOf(nsB, p.signedBy(t, p.b))

	err := CheckDelegationCoherence(cohChild, childServers{}, current, withdrawA, serversGive(copyB, silentServer(nsA)))
	if err == nil {
		t.Fatal("a DS was withdrawn with one nameserver's copy not seen")
	}
	if !errors.Is(err, ErrDelegationUnverifiable) {
		t.Errorf("not marked unverifiable: %v", err)
	}
	if !strings.Contains(err.Error(), nsA) {
		t.Errorf("the refusal does not name the nameserver that was not heard from: %v", err)
	}
	if got := dsyncApiCoherenceStatus(err); got != http.StatusServiceUnavailable {
		t.Errorf("status %d, want %d: the nameserver may answer next time", got, http.StatusServiceUnavailable)
	}

	// A copy that is already wrong is what the child is told, not that a
	// nameserver was silent.
	err = CheckDelegationCoherence(cohChild, childServers{}, current, withdrawA,
		serversGive(copyOf(nsA, p.signedBy(t, p.a)), silentServer("ns2.provider-a.example.")))
	if err == nil || errors.Is(err, ErrDelegationUnverifiable) {
		t.Errorf("got %v, want the refusal for the copy that is signed by the withdrawn key", err)
	}
}

// Adding the DS back is the repair. The resolver may now give the copy that
// the DS being added is for: not Secure, and signed by nothing the parent
// publishes a DS for. That copy cannot be what refuses the change when another
// nameserver's copy is signed by a key the published DS matches, and it holds
// the same keys.
func TestCoherenceAllowsAddingASignersDSBackWhateverCopyAResolverWouldGive(t *testing.T) {
	p := newSignerPair(t, cohChild)
	published := []dns.RR{p.dsB}
	addA := []dns.RR{addDS(p.dsA)}
	copyA := copyOf(nsA, p.signedBy(t, p.a))
	copyB := copyOf(nsB, p.signedBy(t, p.b))

	// Judged on A's copy alone, as it was: refused.
	err := CheckDelegationCoherence(cohChild, childServers{}, published, addA, serversGive(copyA))
	if err == nil {
		t.Fatal("A's copy alone was accepted: a copy signed by the key being added is not authenticated by the DS published")
	}
	if !strings.Contains(err.Error(), "not signed by a key matching the DS this parent publishes") {
		t.Errorf("unexpected refusal reason: %v", err)
	}

	for _, tc := range []struct {
		name   string
		copies []dnskeyCopy
	}{
		{"A's copy first", []dnskeyCopy{copyA, copyB}},
		{"B's copy first", []dnskeyCopy{copyB, copyA}},
		{"a further nameserver gave no copy", []dnskeyCopy{copyA, copyB, silentServer("ns2.provider-b.example.")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckDelegationCoherence(cohChild, childServers{}, published, addA, serversGive(tc.copies...)); err != nil {
				t.Fatalf("adding A's DS back was refused: %v", err)
			}
		})
	}
}

// An addition is still judged: some copy has to be authenticated by the DS the
// parent publishes, and the DS RRset that results has to match a key that copy
// holds. A copy signed by the key being added, with no other nameserver's
// signed by a published DS's key, authenticates nothing.
func TestCoherenceAnAdditionStillNeedsACopyTheParentsDSAuthenticates(t *testing.T) {
	p := newSignerPair(t, cohChild)
	rogue := newSignerTestKey(t, cohChild, 257)
	published := []dns.RR{p.dsB}
	rogueSigned := func(signers ...*signerTestKey) *core.RRset {
		return signedDnskeys(t, testKeys(p.b, rogue), signers, p.inc, p.exp)
	}
	addRogue := []dns.RR{addDS(dsForKey(t, rogue))}

	// Every copy is signed by the rogue key, whose DS is the one being added.
	err := CheckDelegationCoherence(cohChild, childServers{}, published, addRogue,
		serversGive(copyOf(nsA, rogueSigned(rogue)), copyOf(nsB, rogueSigned(rogue))))
	if err == nil {
		t.Fatal("a DS was added on copies nothing the parent publishes authenticates")
	}
	if !strings.Contains(err.Error(), "not signed by a key matching the DS this parent publishes") {
		t.Errorf("unexpected refusal reason: %v", err)
	}

	// One copy is signed by B, whose DS is published: the keys it holds,
	// the rogue key among them, are then the child's.
	if err := CheckDelegationCoherence(cohChild, childServers{}, published, addRogue,
		serversGive(copyOf(nsA, rogueSigned(rogue)), copyOf(nsB, rogueSigned(p.b)))); err != nil {
		t.Fatalf("a DS for a key the authenticated copy holds was refused: %v", err)
	}

	// The keys of a copy nothing authenticates do not count: the DS being
	// added names a key only that copy holds.
	stranger := newSignerTestKey(t, cohChild, 257)
	err = CheckDelegationCoherence(cohChild, childServers{}, nil, []dns.RR{addDS(dsForKey(t, stranger))},
		serversGive(copyOf(nsB, signedDnskeys(t, testKeys(p.b), testKeys(p.b), p.inc, p.exp))))
	if err == nil || !strings.Contains(err.Error(), "matches none") {
		t.Errorf("a DS for a key no copy holds: %v, want it to match none", err)
	}
}

// A child with no DS has nothing to authenticate a copy with, and no copy
// signed by anything a DS vouches for. The first DS only has to match a key.
func TestCoherenceTheFirstDSIsJudgedOnAnyCopy(t *testing.T) {
	p := newSignerPair(t, cohChild)
	if err := CheckDelegationCoherence(cohChild, childServers{}, nil, []dns.RR{addDS(p.dsA)},
		serversGive(copyOf(nsA, p.signedBy(t, p.a)), silentServer(nsB))); err != nil {
		t.Fatalf("a first DS was refused: %v", err)
	}
}

// No nameserver gave a copy: nothing can be judged, and the child is told to
// try again.
func TestCoherenceNoCopyFromAnyNameserverIsUnverifiable(t *testing.T) {
	p := newSignerPair(t, cohChild)
	err := CheckDelegationCoherence(cohChild, childServers{}, []dns.RR{p.dsB}, []dns.RR{addDS(p.dsA)},
		serversGive(silentServer(nsA), silentServer(nsB)))
	if err == nil {
		t.Fatal("a DS was added with no copy of the DNSKEY RRset seen")
	}
	if !errors.Is(err, ErrDelegationUnverifiable) || !strings.Contains(err.Error(), "DNSKEY lookup failed") {
		t.Errorf("got %v, want a failed lookup, marked unverifiable", err)
	}
}

// The nameservers asked are the delegation the update leaves.
func TestCoherenceAsksTheNameserversTheDelegationHasAfterTheUpdate(t *testing.T) {
	p := newSignerPair(t, twoSignerChild)
	zd := twoSignerParent(t, p.dsA, p.dsB)

	var asked []string
	fetch := func(_ string, servers childServers) ([]dnskeyCopy, error) {
		asked = nil
		for _, rr := range servers.NS {
			asked = append(asked, rr.(*dns.NS).Ns)
		}
		return []dnskeyCopy{copyOf(nsB, p.signedBy(t, p.b))}, nil
	}
	dropA := mustRR(t, twoSignerChild+" 3600 IN NS "+nsA)
	dropA.Header().Class = dns.ClassNONE

	// A DS-only update: the nameservers as published.
	if err := zd.CheckDelegationCoherenceForUpdate([]dns.RR{addDS(dsForKey(t, newSignerTestKey(t, twoSignerChild, 257)))}, fetch); err != nil {
		t.Fatalf("a DS add: %v", err)
	}
	if len(asked) != 2 {
		t.Errorf("asked %v, want both nameservers of the delegation", asked)
	}

	// NS A leaves the delegation in the update that withdraws its DS: only B is
	// asked, and the update passes where it would not with A in the delegation.
	if err := zd.CheckDelegationCoherenceForUpdate([]dns.RR{dropA, delOneDS(p.dsA)}, fetch); err != nil {
		t.Fatalf("the update that retires signer A: %v", err)
	}
	if len(asked) != 1 || !core.EqualNames(asked[0], nsB) {
		t.Errorf("asked %v, want only %s", asked, nsB)
	}
}

// twoSignerChild is the child of twoSignerParent. Its nameservers are the
// providers' own, not in its zone.
const twoSignerChild = "child.parent.example."

// twoSignerParent is a parent that takes child updates of DS and NS, and
// publishes ds for twoSignerChild, delegated to the nameservers of both
// providers.
func twoSignerParent(t *testing.T, ds ...*dns.DS) *ZoneData {
	t.Helper()
	zone := `parent.example.	3600	IN	SOA	ns.parent.example. hostmaster.parent.example. 1 7200 1800 604800 7200
parent.example.	3600	IN	NS	ns.parent.example.
ns.parent.example.	3600	IN	A	192.0.2.53
` + twoSignerChild + `	3600	IN	NS	` + nsA + `
` + twoSignerChild + `	3600	IN	NS	` + nsB + "\n"
	for _, d := range ds {
		zone += d.String() + "\n"
	}
	zd := testSnapshotZone(t, "parent.example.", zone)
	zd.Options = map[ZoneOption]bool{OptAllowChildUpdates: true}
	zd.UpdatePolicy = UpdatePolicy{
		Child: UpdatePolicyDetail{Type: "selfsub", RRtypes: map[uint16]bool{dns.TypeDS: true, dns.TypeNS: true}, TTL: 120},
	}
	return zd
}

// The sequence #925 was seen in, through the UPDATE path as the child gets it:
// the removal of one signer's DS is refused, with an EDE that says the
// delegation would be incoherent; and when that signer's DS is the one
// missing, adding it back is approved whichever signer's copy the resolver
// holds.
func TestApproveChildUpdateJudgesEverySignersCopyOfTheDNSKEYs(t *testing.T) {
	p := newSignerPair(t, twoSignerChild)
	copyA, copyB := p.signedBy(t, p.a), p.signedBy(t, p.b)
	update := func(zd *ZoneData, actions ...dns.RR) (bool, *UpdateStatus, error) {
		r := new(dns.Msg)
		r.SetUpdate(zd.ZoneName)
		r.Ns = actions
		us := &UpdateStatus{
			Type:                  "CHILD-UPDATE",
			Validated:             true,
			ValidatedByTrustedKey: true,
			SignerName:            twoSignerChild,
			ValidationRcode:       dns.RcodeSuccess,
		}
		approved, _, err := zd.ApproveChildUpdate(zd.ZoneName, us, r)
		return approved, us, err
	}
	nameserversServe(t, map[string]*core.RRset{nsA: copyA, nsB: copyB})

	// Both DS published. The child's leader asks for A's DS to go.
	approved, us, err := update(twoSignerParent(t, p.dsA, p.dsB), delOneDS(p.dsA))
	if approved || err == nil {
		t.Fatal("A's DS was withdrawn while A's nameserver serves a copy signed by A only")
	}
	if !strings.Contains(err.Error(), "nameserver "+nsA) {
		t.Errorf("the refusal does not name the nameserver whose copy would turn bogus: %v", err)
	}
	if us.ValidationRcode != dns.RcodeRefused || us.RejectionEDE != edns0.EDEDelegationIncoherent {
		t.Errorf("rcode %s, EDE %d; want REFUSED with EDE %d",
			dns.RcodeToString[int(us.ValidationRcode)], us.RejectionEDE, edns0.EDEDelegationIncoherent)
	}

	// A's DS is already gone (it was taken away by a parent that judged one
	// copy). Adding it back is approved.
	if approved, _, err := update(twoSignerParent(t, p.dsB), addDS(p.dsA)); !approved || err != nil {
		t.Fatalf("adding A's DS back was not approved (err %v)", err)
	}

	// And a nameserver that is down holds the removal off, for a retry.
	nameserversServe(t, map[string]*core.RRset{nsB: copyB})
	approved, us, err = update(twoSignerParent(t, p.dsA, p.dsB), delOneDS(p.dsA))
	if approved || !errors.Is(err, ErrDelegationUnverifiable) {
		t.Fatalf("approved %v, err %v; want a refusal marked unverifiable", approved, err)
	}
	if us.RejectionEDE != edns0.EDEDelegationUnverifiable {
		t.Errorf("EDE %d, want %d", us.RejectionEDE, edns0.EDEDelegationUnverifiable)
	}
}

// The DSYNC API path runs the same check on the same copies.
func TestDsyncApiJudgesEverySignersCopyOfTheDNSKEYs(t *testing.T) {
	p := newSignerPair(t, twoSignerChild)
	nameserversServe(t, map[string]*core.RRset{nsA: p.signedBy(t, p.a), nsB: p.signedBy(t, p.b)})

	check := func(zd *ZoneData, ds ...*dns.DS) error {
		var rrs []string
		for _, d := range ds {
			rrs = append(rrs, d.String())
		}
		actions, err := dsyncApiBuildActions(zd, twoSignerChild, []DsyncApiRRset{{Owner: twoSignerChild, Type: "DS", RRs: rrs}})
		if err != nil {
			t.Fatalf("dsyncApiBuildActions: %v", err)
		}
		return zd.CheckDelegationCoherenceForUpdate(actions, coherenceDnskeyFetcher(&Conf))
	}

	// The request is the DS RRset the child wants: B's alone, with A's published.
	err := check(twoSignerParent(t, p.dsA, p.dsB), p.dsB)
	if err == nil {
		t.Fatal("the DS RRset without A's was accepted while A's nameserver serves a copy signed by A only")
	}
	if got := dsyncApiCoherenceStatus(err); got != http.StatusConflict {
		t.Errorf("status %d, want %d (err %v)", got, http.StatusConflict, err)
	}

	// B's alone is published; the request restores A's.
	if err := check(twoSignerParent(t, p.dsB), p.dsA, p.dsB); err != nil {
		t.Fatalf("restoring A's DS was refused: %v", err)
	}
}

// A DS digest is hex, and means the same in either case. One unpacked from a
// message is lowercase and one parsed from a zone file is as written, so a
// withdrawal a child sends has to match the DS the parent publishes whatever
// case it holds. It did not, and the check took the withdrawal for one that
// changes nothing: no lookup, no verdict, a silent pass.
func TestCoherenceJudgesAWithdrawalWhateverCaseTheDigestIsWrittenIn(t *testing.T) {
	p := newSignerPair(t, cohChild)

	m := new(dns.Msg)
	m.SetUpdate("example.")
	m.Ns = []dns.RR{delOneDS(p.dsA)}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	received := new(dns.Msg)
	if err := received.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	published, err := dns.NewRR(p.dsA.String()) // as a zone file holds it
	if err != nil {
		t.Fatal(err)
	}
	if got := published.(*dns.DS).Digest; got == received.Ns[0].(*dns.DS).Digest {
		t.Fatalf("the digest is %q in both forms: this no longer tests the case difference", got)
	}

	current := []dns.RR{published, p.dsB}
	called := false
	fetch := func(string, childServers) ([]dnskeyCopy, error) {
		called = true
		return []dnskeyCopy{copyOf(nsA, p.signedBy(t, p.a)), copyOf(nsB, p.signedBy(t, p.b))}, nil
	}
	err = CheckDelegationCoherence(cohChild, childServers{}, current, received.Ns, fetch)
	if !called {
		t.Fatal("the DNSKEY RRsets were not looked at: the withdrawal was taken for a no-op")
	}
	if err == nil {
		t.Fatal("A's DS was withdrawn while a nameserver serves a copy signed by A only")
	}
}
