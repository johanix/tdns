package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// D-3b, step 2: the RFC 7477 rules applied to an UPDATE's asserted NS/glue
// change, on the parent's own zone data.

const (
	cuParent = "example."
	cuChild  = "child.example."
)

// cuParentZone: example. delegates child.example. to ns1.child.example.
// (in-bailiwick, with A and AAAA glue) and ns.provider.net.
func cuParentZone(t *testing.T) *ZoneData {
	t.Helper()
	zd := newMapZone(cuParent, Primary, map[string][]dns.RR{
		cuParent: {
			mustRR(t, "example. 3600 IN SOA ns.example. h.example. 1 3600 600 604800 300"),
			mustRR(t, "example. 3600 IN NS ns.example."),
		},
		cuChild: {
			mustRR(t, "child.example. 3600 IN NS ns1.child.example."),
			mustRR(t, "child.example. 3600 IN NS ns.provider.net."),
		},
		"ns1.child.example.": {
			mustRR(t, "ns1.child.example. 3600 IN A 192.0.2.1"),
			mustRR(t, "ns1.child.example. 3600 IN AAAA 2001:db8::1"),
		},
	})
	return zd
}

// servedChild is what child.example.'s nameservers answer, keyed "name/TYPE".
func servedChild(t *testing.T) *stubChild {
	t.Helper()
	return &stubChild{rrs: map[string][]dns.RR{
		cuChild + "/NS": rrs(t,
			"child.example. 3600 IN NS ns1.child.example.",
			"child.example. 3600 IN NS ns.provider.net."),
		"ns1.child.example./A":    rrs(t, "ns1.child.example. 3600 IN A 192.0.2.1"),
		"ns1.child.example./AAAA": rrs(t, "ns1.child.example. 3600 IN AAAA 2001:db8::1"),
	}}
}

// askerFor records which nameservers were asked and hands out stub.fetch.
func askerFor(stub *stubChild, asked *[]dns.RR) childNameserverAsker {
	return func(child string, nameservers []dns.RR) childRRsetFetcher {
		*asked = nameservers
		return stub.fetch
	}
}

func addRR(t *testing.T, s string) dns.RR { return mustRR(t, s) }

func delRR(t *testing.T, s string) dns.RR {
	rr := mustRR(t, s)
	rr.Header().Class = dns.ClassNONE
	return rr
}

func delRRset(name string, rrtype uint16) dns.RR {
	return &dns.ANY{Hdr: dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassANY}}
}

// anyRR is RFC 2136 DELNAME: CLASS=ANY TYPE=ANY, every RRset at the name.
func anyRR(t *testing.T, name string) dns.RR {
	t.Helper()
	return delRRset(name, dns.TypeANY)
}

func expectRefusal(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want it to contain %q", err, want)
	}
}

func TestNSCoherenceIgnoresUpdatesThatTouchNeitherNSNorGlue(t *testing.T) {
	zd := cuParentZone(t)
	var asked []dns.RR
	ds := addRR(t, "child.example. 3600 IN DS 12345 15 2 ABCDEF")
	if err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(), []dns.RR{ds}, askerFor(servedChild(t), &asked)); err != nil {
		t.Fatalf("DS-only update: %v", err)
	}
	if asked != nil {
		t.Fatal("a DS-only update must not ask the child's nameservers")
	}
	// No scanner at all is fine when nothing needs asking.
	if err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(), []dns.RR{ds}, nil); err != nil {
		t.Fatalf("DS-only update without an asker: %v", err)
	}
}

func TestNSCoherenceAcceptsAnNSChangeTheChildServes(t *testing.T) {
	zd := cuParentZone(t)
	stub := servedChild(t)
	// The child now serves a third, out-of-bailiwick nameserver.
	stub.rrs[cuChild+"/NS"] = append(stub.rrs[cuChild+"/NS"], addRR(t, "child.example. 3600 IN NS ns2.provider.net."))
	var asked []dns.RR
	actions := []dns.RR{addRR(t, "child.example. 3600 IN NS ns2.provider.net.")}
	if err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(), actions, askerFor(stub, &asked)); err != nil {
		t.Fatal(err)
	}
	// It asked the parent's CURRENT nameservers for the child, not the resulting set.
	if len(asked) != 2 {
		t.Fatalf("asked %d nameservers, want the 2 currently delegated", len(asked))
	}
}

func TestNSCoherenceRefusesAnNSSetTheChildDoesNotServe(t *testing.T) {
	zd := cuParentZone(t)
	var asked []dns.RR
	actions := []dns.RR{addRR(t, "child.example. 3600 IN NS ns2.provider.net.")} // not served
	err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(), actions, askerFor(servedChild(t), &asked))
	expectRefusal(t, err, "not what its nameservers serve")
}

func TestNSCoherenceRefusesWhenTheNameserversDisagree(t *testing.T) {
	zd := cuParentZone(t)
	stub := servedChild(t)
	stub.inSync = map[string]bool{cuChild + "/NS": false}
	var asked []dns.RR
	actions := []dns.RR{delRR(t, "child.example. 3600 IN NS ns.provider.net.")}
	err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(), actions, askerFor(stub, &asked))
	expectRefusal(t, err, "do not agree")
}

func TestNSCoherenceRefusesWhenTheLookupFails(t *testing.T) {
	zd := cuParentZone(t)
	stub := servedChild(t)
	stub.errs = map[string]error{cuChild + "/NS": errors.New("timeout")}
	var asked []dns.RR
	actions := []dns.RR{delRR(t, "child.example. 3600 IN NS ns.provider.net.")}
	err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(), actions, askerFor(stub, &asked))
	expectRefusal(t, err, "cannot verify the NS RRset")
}

func TestNSCoherenceRefusesAnEmptyNSRRset(t *testing.T) {
	zd := cuParentZone(t)
	stub := servedChild(t)
	var asked []dns.RR
	for _, actions := range [][]dns.RR{
		{delRRset(cuChild, dns.TypeNS)},
		{delRRset(cuChild, dns.TypeANY)},
		{delRR(t, "child.example. 3600 IN NS ns1.child.example."), delRR(t, "child.example. 3600 IN NS ns.provider.net.")},
	} {
		err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(), actions, askerFor(stub, &asked))
		expectRefusal(t, err, "no NS records")
	}
	// Building the fetcher is cheap and does not query; refusing an empty
	// result must not have cost a single question to the child.
	if len(stub.calls) != 0 {
		t.Fatalf("an empty result is refused before anyone is asked; queries: %v", stub.calls)
	}
}

func TestNSCoherenceRefusesWithoutAScanner(t *testing.T) {
	zd := cuParentZone(t)
	actions := []dns.RR{addRR(t, "child.example. 3600 IN NS ns2.provider.net.")}
	err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(), actions, nil)
	expectRefusal(t, err, "no way to ask")
	// The production asker on a nil scanner is nil, which is that case.
	var sc *Scanner
	if sc.childNameserverAsker(nil) != nil {
		t.Fatal("nil scanner must yield a nil asker")
	}
}

func TestNSCoherenceNewInBailiwickNameserverNeedsItsServedGlue(t *testing.T) {
	zd := cuParentZone(t)
	stub := servedChild(t)
	stub.rrs[cuChild+"/NS"] = append(stub.rrs[cuChild+"/NS"], addRR(t, "child.example. 3600 IN NS ns2.child.example."))
	stub.rrs["ns2.child.example./A"] = rrs(t, "ns2.child.example. 3600 IN A 192.0.2.2")
	var asked []dns.RR

	// NS added without its glue: the child serves an A for it, so the
	// delegation the scanner would produce has that glue.
	err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(),
		[]dns.RR{addRR(t, "child.example. 3600 IN NS ns2.child.example.")}, askerFor(stub, &asked))
	expectRefusal(t, err, "A glue for ns2.child.example.")

	// With the glue the child serves: accepted.
	err = zd.CheckDelegationNSCoherenceForUpdate(context.Background(), []dns.RR{
		addRR(t, "child.example. 3600 IN NS ns2.child.example."),
		addRR(t, "ns2.child.example. 3600 IN A 192.0.2.2"),
	}, askerFor(stub, &asked))
	if err != nil {
		t.Fatal(err)
	}

	// With glue the child does NOT serve: refused.
	err = zd.CheckDelegationNSCoherenceForUpdate(context.Background(), []dns.RR{
		addRR(t, "child.example. 3600 IN NS ns2.child.example."),
		addRR(t, "ns2.child.example. 3600 IN A 192.0.2.99"),
	}, askerFor(stub, &asked))
	expectRefusal(t, err, "A glue for ns2.child.example.")
}

func TestNSCoherenceRefusesAddressRecordsThatAreNotGlue(t *testing.T) {
	zd := cuParentZone(t)
	var asked []dns.RR
	stub := servedChild(t)

	// At the delegation point itself.
	err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(),
		[]dns.RR{addRR(t, "child.example. 3600 IN A 192.0.2.50")}, askerFor(stub, &asked))
	expectRefusal(t, err, "delegation point")

	// Below the child but not a nameserver of the resulting set.
	err = zd.CheckDelegationNSCoherenceForUpdate(context.Background(),
		[]dns.RR{addRR(t, "www.child.example. 3600 IN A 192.0.2.50")}, askerFor(stub, &asked))
	expectRefusal(t, err, "not a nameserver of the resulting NS RRset")

	// In the parent zone but under no delegation at all: an orphan.
	err = zd.CheckDelegationNSCoherenceForUpdate(context.Background(),
		[]dns.RR{addRR(t, "ns.nowhere.example. 3600 IN A 192.0.2.50")}, askerFor(stub, &asked))
	expectRefusal(t, err, "not glue")
}

func TestNSCoherenceRemovedNameserverMustNotLeaveGlue(t *testing.T) {
	zd := cuParentZone(t)
	stub := servedChild(t)
	// The child dropped ns1 and serves only the provider.
	stub.rrs[cuChild+"/NS"] = rrs(t, "child.example. 3600 IN NS ns.provider.net.")
	var asked []dns.RR

	err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(),
		[]dns.RR{delRR(t, "child.example. 3600 IN NS ns1.child.example.")}, askerFor(stub, &asked))
	expectRefusal(t, err, "leaves its A glue")

	err = zd.CheckDelegationNSCoherenceForUpdate(context.Background(), []dns.RR{
		delRR(t, "child.example. 3600 IN NS ns1.child.example."),
		delRRset("ns1.child.example.", dns.TypeA),
		delRRset("ns1.child.example.", dns.TypeAAAA),
	}, askerFor(stub, &asked))
	if err != nil {
		t.Fatalf("NS removal with its glue deleted: %v", err)
	}
}

// Glue the update does not touch, for a nameserver it keeps, is not
// re-verified: the scanner fixes drift, this check does not punish it.
func TestNSCoherenceDoesNotReverifyUntouchedGlue(t *testing.T) {
	zd := cuParentZone(t)
	stub := servedChild(t)
	stub.rrs[cuChild+"/NS"] = append(stub.rrs[cuChild+"/NS"], addRR(t, "child.example. 3600 IN NS ns2.provider.net."))
	stub.rrs["ns1.child.example./A"] = rrs(t, "ns1.child.example. 3600 IN A 192.0.2.77") // drifted
	var asked []dns.RR
	err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(),
		[]dns.RR{addRR(t, "child.example. 3600 IN NS ns2.provider.net.")}, askerFor(stub, &asked))
	if err != nil {
		t.Fatalf("untouched drifted glue must not refuse an unrelated NS change: %v", err)
	}
	for _, c := range stub.calls {
		if strings.HasPrefix(c, "ns1.child.example./") {
			t.Fatalf("untouched glue was re-verified: %s", c)
		}
	}
	// Touching it, though, verifies it.
	err = zd.CheckDelegationNSCoherenceForUpdate(context.Background(), []dns.RR{
		delRR(t, "ns1.child.example. 3600 IN A 192.0.2.1"),
		addRR(t, "ns1.child.example. 3600 IN A 192.0.2.2"), // child serves .77
	}, askerFor(stub, &asked))
	expectRefusal(t, err, "A glue for ns1.child.example.")
}

// A delegation that does not exist yet has no current nameservers to ask, so
// the ones the update names are asked instead.
func TestNSCoherenceNewDelegationAsksTheNamedNameservers(t *testing.T) {
	zd := cuParentZone(t)
	stub := &stubChild{rrs: map[string][]dns.RR{
		"new.example./NS": rrs(t, "new.example. 3600 IN NS ns.provider.net."),
	}}
	var asked []dns.RR
	err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(),
		[]dns.RR{addRR(t, "new.example. 3600 IN NS ns.provider.net.")}, askerFor(stub, &asked))
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || !strings.Contains(asked[0].String(), "ns.provider.net.") {
		t.Fatalf("asked %v, want the nameserver the update names", asked)
	}
}

func TestDelegationsTouched(t *testing.T) {
	zd := cuParentZone(t)
	children, orphans := zd.delegationsTouched([]dns.RR{
		addRR(t, "child.example. 3600 IN NS ns2.provider.net."),
		addRR(t, "ns1.child.example. 3600 IN A 192.0.2.1"),      // existing delegation, via IsChildDelegation
		addRR(t, "new.example. 3600 IN NS ns.new.example."),     // new delegation in this update
		addRR(t, "ns.new.example. 3600 IN A 192.0.2.3"),         // glue for it, via the NS owner in the update
		addRR(t, "ns.nowhere.example. 3600 IN A 192.0.2.4"),     // orphan
		delRR(t, "old.nowhere.example. 3600 IN A 192.0.2.5"),    // a delete under no delegation is ignored
		addRR(t, "example. 3600 IN A 192.0.2.6"),                // the apex is not a delegation
		addRR(t, "elsewhere.net. 3600 IN NS ns.elsewhere.net."), // outside the zone
	})
	if len(children) != 2 || children[0] != "child.example." || children[1] != "new.example." {
		t.Fatalf("children = %v", children)
	}
	if len(orphans) != 1 || orphans[0] != "ns.nowhere.example." {
		t.Fatalf("orphans = %v", orphans)
	}
}

// M1 regression. A name-wide "CLASS=ANY TYPE=ANY" at an in-bailiwick
// nameserver hostname strips every address off it while the NS RRset stays --
// exactly the delegation the glue rules exist to refuse. It used to be
// invisible to discovery: not an NS action, not ANY at a delegation cut, not
// typed A/AAAA, so no child was returned and the check never ran.
//
// DNS UPDATE can send this. DSYNC's typed delrrset happens not to, which is
// why it survived the first round of tests.
func TestDelegationsTouchedFindsNameWideAnyAtGlueOwner(t *testing.T) {
	zd := cuParentZone(t)

	t.Run("name-wide delete at a glue owner reaches its child", func(t *testing.T) {
		children, orphans := zd.delegationsTouched([]dns.RR{
			anyRR(t, "ns1.child.example."),
		})
		if len(children) != 1 || children[0] != "child.example." {
			t.Fatalf("children = %v, want [child.example.] -- the check is skipped without this", children)
		}
		if len(orphans) != 0 {
			t.Errorf("orphans = %v, want none", orphans)
		}
	})

	t.Run("still found alongside an NS action for the same child", func(t *testing.T) {
		children, _ := zd.delegationsTouched([]dns.RR{
			addRR(t, "child.example. 3600 IN NS ns1.child.example."),
			anyRR(t, "ns1.child.example."),
		})
		if len(children) != 1 || children[0] != "child.example." {
			t.Fatalf("children = %v, want [child.example.] exactly once", children)
		}
	})

	t.Run("name-wide delete under no delegation is not an orphan", func(t *testing.T) {
		children, orphans := zd.delegationsTouched([]dns.RR{
			anyRR(t, "www.example."),
		})
		if len(children) != 0 || len(orphans) != 0 {
			t.Fatalf("children = %v, orphans = %v; a delete of a non-delegation name is neither", children, orphans)
		}
	})
}

// S1: mentioning the NS RRset is not changing it. A duplicate add or a delete
// of something that was not there leaves the parent exactly where it was, so
// it must not depend on the child being reachable and in agreement -- and must
// not be refused for being unverifiable when there is nothing to verify.
func TestCheckDelegationNSCoherenceNoOpNSChangeSkipsTheChild(t *testing.T) {
	currentNS := rrs(t, "child.example. 3600 IN NS ns1.child.example.")
	glue := func(owner string, qtype uint16) ([]dns.RR, bool) {
		if core.EqualNames(owner, "ns1.child.example.") && qtype == dns.TypeA {
			return rrs(t, "ns1.child.example. 3600 IN A 192.0.2.1"), true
		}
		return nil, false
	}
	asked := false
	fetch := func(ctx context.Context, zone string, rrtype uint16) ([]dns.RR, bool, error) {
		asked = true
		return nil, false, fmt.Errorf("child is unreachable")
	}

	// A re-send of the NS record the parent already publishes.
	err := CheckDelegationNSCoherence(context.Background(), "child.example.",
		currentNS, glue,
		[]dns.RR{addRR(t, "child.example. 3600 IN NS ns1.child.example.")}, fetch)
	if err != nil {
		t.Fatalf("a no-op NS change must be accepted without asking the child: %v", err)
	}
	if asked {
		t.Error("the child was queried for an update that changes nothing")
	}

	// And with no fetcher at all: nothing to verify, so nothing to refuse.
	if err := CheckDelegationNSCoherence(context.Background(), "child.example.",
		currentNS, glue,
		[]dns.RR{addRR(t, "child.example. 3600 IN NS ns1.child.example.")}, nil); err != nil {
		t.Fatalf("a no-op NS change must not be refused for lack of a scanner: %v", err)
	}
}

// S2: glue re-verification is OWNER-scoped, not per-type -- touching AAAA at a
// nameserver re-verifies its A as well. That is deliberate: an in-bailiwick
// nameserver's addresses are one unit, and a nameserver whose A has drifted
// from what the child serves is a broken delegation whether or not this
// particular update touched the A. Failing closed there is the safer
// direction, and refusing to grow a delegation that is already incoherent is
// the point of the rule.
//
// The cost is real and worth stating: an operator adding an AAAA can be
// blocked by a pre-existing A drift they did not cause. This test pins the
// choice so a later reader sees it was made rather than fallen into.
func TestCheckDelegationNSCoherenceGlueCheckIsOwnerScoped(t *testing.T) {
	currentNS := rrs(t, "child.example. 3600 IN NS ns1.child.example.")
	glue := func(owner string, qtype uint16) ([]dns.RR, bool) {
		if !core.EqualNames(owner, "ns1.child.example.") {
			return nil, false
		}
		switch qtype {
		case dns.TypeA:
			return rrs(t, "ns1.child.example. 3600 IN A 192.0.2.1"), true
		case dns.TypeAAAA:
			return rrs(t, "ns1.child.example. 3600 IN AAAA 2001:db8::1"), true
		}
		return nil, false
	}
	// The child serves a DIFFERENT A than the parent publishes, and agrees
	// with the parent on the resulting AAAA.
	fetch := func(ctx context.Context, zone string, rrtype uint16) ([]dns.RR, bool, error) {
		switch {
		case core.EqualNames(zone, "child.example.") && rrtype == dns.TypeNS:
			return rrs(t, "child.example. 3600 IN NS ns1.child.example."), true, nil
		case core.EqualNames(zone, "ns1.child.example.") && rrtype == dns.TypeA:
			return rrs(t, "ns1.child.example. 3600 IN A 198.51.100.9"), true, nil // drifted
		case core.EqualNames(zone, "ns1.child.example.") && rrtype == dns.TypeAAAA:
			return rrs(t, "ns1.child.example. 3600 IN AAAA 2001:db8::2"), true, nil
		}
		return nil, true, nil
	}

	// Touch AAAA only. Owner-scoped checking reaches the drifted A and refuses.
	err := CheckDelegationNSCoherence(context.Background(), "child.example.",
		currentNS, glue,
		[]dns.RR{addRR(t, "ns1.child.example. 3600 IN AAAA 2001:db8::2")}, fetch)
	if err == nil {
		t.Fatal("expected a refusal: the nameserver's A has drifted from what the child serves")
	}
	if !strings.Contains(err.Error(), "ns1.child.example.") {
		t.Errorf("the refusal should name the nameserver: %v", err)
	}
}

// rrsetAfterActions is dsAfterActions generalised; the DS tests still cover
// the DS shape, this covers a second type and the TypeANY delete.
func TestRRsetAfterActions(t *testing.T) {
	current := rrs(t, "ns1.child.example. 3600 IN A 192.0.2.1", "ns1.child.example. 3600 IN A 192.0.2.2")
	got, touched := rrsetAfterActions("ns1.child.example.", dns.TypeA, current, []dns.RR{
		delRR(t, "ns1.child.example. 0 IN A 192.0.2.1"),
		addRR(t, "ns1.child.example. 3600 IN A 192.0.2.3"),
		addRR(t, "ns1.child.example. 3600 IN A 192.0.2.2"),      // duplicate add is a no-op
		addRR(t, "ns1.child.example. 3600 IN AAAA 2001:db8::9"), // other type ignored
	})
	if !touched || len(got) != 2 {
		t.Fatalf("touched=%v got=%v", touched, names(got))
	}
	if _, touched := rrsetAfterActions("ns1.child.example.", dns.TypeA, current, []dns.RR{addRR(t, "other.child.example. 3600 IN A 192.0.2.1")}); touched {
		t.Fatal("another owner must not count as touched")
	}
	if got, touched := rrsetAfterActions("NS1.child.example.", dns.TypeA, current, []dns.RR{delRRset("ns1.child.example.", dns.TypeANY)}); !touched || len(got) != 0 {
		t.Fatalf("TypeANY delete (case-folded owner): touched=%v got=%v", touched, names(got))
	}
}
