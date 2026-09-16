package tdns

import (
	"context"
	"sort"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #677: at-ns built its signal names from the child's apex NS RRset, read
// through the IMR cache. A stale cached RRset sent every attempt to the old
// nameservers, so a KEY that was published, correct and validating at the
// provider's signal name failed its bootstrap. The names now come from the
// parent's own delegation of the child, without the nameservers inside the
// child while the parent holds no DS for it.

const atNsTestKey = "child.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE="

var (
	atNsInBailiwickName = signalOwnerName(signalPrefixSig0Key, cuChild, "ns1.child.example.")
	atNsProviderName    = signalOwnerName(signalPrefixSig0Key, cuChild, "ns.provider.net.")
)

// stubSignalKeys makes the at-ns KEY lookup answer from published, keyed by
// signal name, each answer DNSSEC-validated. Every name asked is recorded, in
// order, and returned.
func stubSignalKeys(t *testing.T, published map[string]string) *[]string {
	t.Helper()
	var asked []string
	orig := childKeyQuery
	t.Cleanup(func() { childKeyQuery = orig })
	childKeyQuery = func(ctx context.Context, imr *Imr, name string) (*ImrResponse, error) {
		asked = append(asked, name)
		keyText, ok := published[name]
		if !ok {
			return &ImrResponse{Msg: "NXDOMAIN (negative response type 3)"}, nil
		}
		rr := mustRR(t, keyText)
		rr.Header().Name = name // re-owned to the signal name, as the child publishes it
		return &ImrResponse{
			RRset:     &core.RRset{Name: name, RRtype: dns.TypeKEY, RRs: []dns.RR{rr}},
			Validated: true,
		}, nil
	}
	return &asked
}

// installParent puts zd into Zones under its name for the rest of the test.
func installParent(t *testing.T, zd *ZoneData) {
	t.Helper()
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
}

// oneNSParent is cuParentZone before the child added its provider: example.
// delegates child.example. to ns1.child.example. only, with no DS.
func oneNSParent(t *testing.T) *ZoneData {
	t.Helper()
	return newMapZone(cuParent, Primary, map[string][]dns.RR{
		cuParent: {
			mustRR(t, "example. 3600 IN SOA ns.example. h.example. 1 3600 600 604800 300"),
			mustRR(t, "example. 3600 IN NS ns.example."),
		},
		cuChild: {
			mustRR(t, "child.example. 3600 IN NS ns1.child.example."),
		},
	})
}

// dsParent is cuParentZone with a DS for the child: a child already signed and
// chained, re-keying.
func dsParent(t *testing.T) *ZoneData {
	t.Helper()
	return newMapZone(cuParent, Primary, map[string][]dns.RR{
		cuParent: {
			mustRR(t, "example. 3600 IN SOA ns.example. h.example. 1 3600 600 604800 300"),
			mustRR(t, "example. 3600 IN NS ns.example."),
		},
		cuChild: {
			mustRR(t, "child.example. 3600 IN NS ns1.child.example."),
			mustRR(t, "child.example. 3600 IN NS ns.provider.net."),
			mustRR(t, "child.example. 3600 IN DS 12345 15 2 "+
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		},
	})
}

// oneNSParentNamed is zone delegating child.<zone> to ns1.child.<zone> only,
// with no DS.
func oneNSParentNamed(t *testing.T, zone string) *ZoneData {
	t.Helper()
	child := "child." + zone
	return newMapZone(zone, Primary, map[string][]dns.RR{
		zone: {
			mustRR(t, zone+" 3600 IN SOA ns."+zone+" h."+zone+" 1 3600 600 604800 300"),
			mustRR(t, zone+" 3600 IN NS ns."+zone),
		},
		child: {
			mustRR(t, child+" 3600 IN NS ns1."+child),
		},
	})
}

func atNsOnly() DelegationPolicy {
	return DelegationPolicy{Name: "test-at-ns", Mechanisms: []string{"at-ns"}, RequireDnssec: true}
}

func sortedNames(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}

// The names asked come from the parent's delegation. With no DS, the
// nameserver inside the child is left out: its signal name is the child's own
// data and cannot validate. The key at the provider's signal name is found.
func TestAtNsAsksTheSignalNamesOfTheParentsDelegation(t *testing.T) {
	installParent(t, cuParentZone(t))
	asked := stubSignalKeys(t, map[string]string{atNsProviderName: atNsTestKey})

	// A nil IMR on purpose: the NS set must come from the parent's zone data.
	// Resolving it would dereference the IMR and fail the test.
	verified, dnssec, _ := VerifyChildKey(context.Background(), cuChild, cuParent, atNsTestKey, nil, atNsOnly())

	if got := strings.Join(*asked, " "); got != atNsProviderName {
		t.Errorf("at-ns asked %q, want only the provider's signal name %q: the parent holds"+
			" no DS, so the nameserver inside the child is not asked", got, atNsProviderName)
	}
	if !verified || !dnssec {
		t.Errorf("verified=%v dnssec=%v, want both true: the KEY is published and validating"+
			" at the provider's signal name, which the delegation names", verified, dnssec)
	}
}

// With a DS the child's chain of trust reaches the signal name inside the
// child, so that nameserver is asked too.
func TestAtNsAsksTheNameserverInsideTheChildWhenTheParentHoldsADS(t *testing.T) {
	installParent(t, dsParent(t))
	asked := stubSignalKeys(t, map[string]string{atNsInBailiwickName: atNsTestKey})

	verified, dnssec, _ := VerifyChildKey(context.Background(), cuChild, cuParent, atNsTestKey, nil, atNsOnly())

	want := sortedNames([]string{atNsInBailiwickName, atNsProviderName})
	if got := sortedNames(*asked); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("at-ns asked %v, want every nameserver of the delegation %v", got, want)
	}
	if !verified || !dnssec {
		t.Errorf("verified=%v dnssec=%v, want both true: the KEY validates at the signal name"+
			" inside the child, which a DS makes reachable", verified, dnssec)
	}
}

// The lab failure from #677, replayed. The child adds its provider to the
// parent's delegation after the first attempt. The next attempt must ask the
// provider's signal name, because the delegation is read at every attempt,
// not captured once.
func TestAtNsSeesADelegationChangeAtTheNextAttempt(t *testing.T) {
	installParent(t, oneNSParent(t))
	asked := stubSignalKeys(t, map[string]string{atNsProviderName: atNsTestKey})
	ctx := context.Background()

	if verified, _, _ := VerifyChildKey(ctx, cuChild, cuParent, atNsTestKey, nil, atNsOnly()); verified {
		t.Fatal("fixture: verified before the delegation names the provider")
	}
	if len(*asked) != 0 {
		t.Fatalf("first attempt asked %v; the only NS is inside the child and there is no DS", *asked)
	}

	// The delegation update lands: the same zone, now naming the provider too.
	installParent(t, cuParentZone(t))
	*asked = nil

	verified, dnssec, _ := VerifyChildKey(ctx, cuChild, cuParent, atNsTestKey, nil, atNsOnly())
	if !verified || !dnssec {
		t.Errorf("verified=%v dnssec=%v after the delegation gained the provider; the attempt"+
			" must read the delegation as it is now (asked %v)", verified, dnssec, *asked)
	}
}

// With no authoritative delegation, or none of its nameservers usable, there
// are no names to build, and the child's apex NS is not an acceptable
// substitute. at-ns asks nothing.
func TestAtNsAsksNothingWithoutAnAuthoritativeDelegation(t *testing.T) {
	installParent(t, cuParentZone(t))
	installParent(t, oneNSParentNamed(t, "inside.example."))

	for _, tc := range []struct {
		name, child, parent string
	}{
		{"no delegating zone named", cuChild, ""},
		{"delegating zone not held here", cuChild, "elsewhere.example."},
		{"held zone does not delegate the child", "stranger.example.", cuParent},
		{"the child named as its own parent", cuChild, cuChild},
		{"every NS inside the child and no DS", "child.inside.example.", "inside.example."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asked := stubSignalKeys(t, map[string]string{atNsProviderName: atNsTestKey})
			verified, _, _ := VerifyChildKey(context.Background(), tc.child, tc.parent, atNsTestKey, nil, atNsOnly())
			if len(*asked) != 0 {
				t.Errorf("at-ns asked %v with no authoritative delegation to build names from", *asked)
			}
			if verified {
				t.Error("verified a key without asking any signal name")
			}
		})
	}
}

// The policy and the delegation come from the same zone. An empty parent
// resolves to the closest enclosing zone held here for both; a named parent not
// held here keeps its name, so at-ns reports it rather than quietly using some
// other zone's delegation.
func TestChildKeyPolicyNamesTheZoneItsPolicyCameFrom(t *testing.T) {
	parent := cuParentZone(t)
	pol := DelegationPolicy{Name: "from-example", Mechanisms: []string{"at-ns"}, RequireDnssec: true}
	parent.DelegationPolicy = &pol
	installParent(t, parent)

	for _, tc := range []struct {
		name, parentIn, wantParent, wantPolicy string
	}{
		{"named and held", cuParent, cuParent, "from-example"},
		{"not named: the enclosing zone", "", cuParent, "from-example"},
		{"named, not held: default policy, name kept", "elsewhere.example.", "elsewhere.example.",
			compiledDefaultDelegationPolicy().Name},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotPol, gotParent := childKeyPolicy(cuChild, tc.parentIn)
			if gotParent != tc.wantParent {
				t.Errorf("delegating zone %q, want %q", gotParent, tc.wantParent)
			}
			if gotPol.Name != tc.wantPolicy {
				t.Errorf("policy %q, want %q", gotPol.Name, tc.wantPolicy)
			}
		})
	}
}
