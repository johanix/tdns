package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// The chain covers the zone's authoritative names and its delegation points,
// and nothing below a delegation. Checked against what BIND 9.18 generates for
// the same zone: an NSEC at the delegation point, none for the glue, and none
// for the empty non-terminal.
const scopeZone = `scope.example.	300	IN	SOA	ns.scope.example. hostmaster.scope.example. 1 1800 900 604800 300
scope.example.	300	IN	NS	ns.scope.example.
ns.scope.example.	300	IN	A	127.0.0.1
alpha.scope.example.	300	IN	A	10.0.0.1
deep.sub.scope.example.	300	IN	A	10.0.0.2
child.scope.example.	300	IN	NS	ns1.child.scope.example.
ns1.child.scope.example.	300	IN	A	10.0.0.3
`

func TestChainNamesExcludeEverythingBelowADelegation(t *testing.T) {
	zd := testZone(t, "scope.example.", scopeZone)
	zd.ensureWorkingSet()

	all := zd.workingOwnerNamesLocked()
	got := zd.chainNamesLocked(all)

	inChain := map[string]bool{}
	for _, n := range got {
		inChain[n] = true
	}

	// The delegation point is in the chain; its glue is not.
	if !inChain["child.scope.example."] {
		t.Error("the delegation point is missing from the chain; BIND emits an NSEC there")
	}
	if inChain["ns1.child.scope.example."] {
		t.Error("glue below a delegation is in the chain; it is the child's data," +
			" and BIND emits no NSEC for it")
	}
	// The ENT never had an owner entry to begin with, so it cannot be in the
	// chain -- which matches BIND, and RFC 4035 §2.3.
	if inChain["sub.scope.example."] {
		t.Error("an empty non-terminal is in the chain; under NSEC it gets no record")
	}
	// Ordinary names and the apex are.
	for _, want := range []string{"scope.example.", "alpha.scope.example.", "ns.scope.example.", "deep.sub.scope.example."} {
		if !inChain[want] {
			t.Errorf("%s is missing from the chain", want)
		}
	}
}

// A plain suffix test also matches "notscope.example." against
// "scope.example.". The occlusion test has to compare labels.
func TestOcclusionIsLabelAwareNotStringSuffix(t *testing.T) {
	const z = `d.example.	300	IN	SOA	ns.d.example. hostmaster.d.example. 1 1800 900 604800 300
d.example.	300	IN	NS	ns.d.example.
ns.d.example.	300	IN	A	127.0.0.1
sub.d.example.	300	IN	NS	ns1.sub.d.example.
ns1.sub.d.example.	300	IN	A	10.0.0.1
notsub.d.example.	300	IN	A	10.0.0.2
`
	zd := testZone(t, "d.example.", z)
	zd.ensureWorkingSet()
	got := zd.chainNamesLocked(zd.workingOwnerNamesLocked())

	inChain := map[string]bool{}
	for _, n := range got {
		inChain[n] = true
	}
	if !inChain["notsub.d.example."] {
		t.Fatal("notsub.d.example. was treated as occluded by the sub.d.example. delegation;" +
			" a string-suffix test does that, a label-aware one does not")
	}
	if inChain["ns1.sub.d.example."] {
		t.Error("real glue below the delegation is still in the chain")
	}
}

// RFC 4034 §4: the NSEC TTL should be the SOA minimum, which here is 300 --
// not dns.NewRR's default.
func TestNsecTTLIsTheSOAMinimum(t *testing.T) {
	zd := testZone(t, "scope.example.", scopeZone)
	zd.ensureWorkingSet()
	if got := zd.nsecTTLLocked(); got != 300 {
		t.Fatalf("NSEC TTL = %d, want the SOA minimum 300", got)
	}

	// And it reaches the record itself.
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true}
	if err := zd.GenerateNsecChainWithDak(&DnssecKeys{}); err != nil {
		t.Fatalf("GenerateNsecChainWithDak: %v", err)
	}
	od := zd.stagedOwner("alpha.scope.example.")
	if od == nil || len(od.NSEC.RRs) == 0 {
		t.Fatal("no NSEC generated for alpha")
	}
	if ttl := od.NSEC.RRs[0].Header().Ttl; ttl != 300 {
		t.Fatalf("generated NSEC carries TTL %d, want the SOA minimum 300", ttl)
	}
	if _, isNsec := od.NSEC.RRs[0].(*dns.NSEC); !isNsec {
		t.Fatalf("property holds a %T", od.NSEC.RRs[0])
	}
}
