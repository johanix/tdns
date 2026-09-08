package tdns

import (
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #569: the two verification mechanisms fetch the same key under different
// owner names -- at-ns deliberately re-owns the child's apex KEY to the RFC 9615
// signal name, because that re-owning IS the mechanism. Comparing rendered RRs
// therefore never matched, so at-ns could not verify a key in any configuration
// and the log reported "key not found" about a record that was present and
// validating.
func TestMatchKeyRRComparesTheKeyNotTheRecordCarryingIt(t *testing.T) {
	apex := mustRR(t, childKeyRR)

	// What the producer publishes at the signal name: same key, re-owned.
	signal := dns.Copy(apex)
	signal.Header().Name = "_sig0key.child.parent.example._signal.ns1.provider.net."

	// And what a warm cache hands back: same key, less TTL left.
	aged := dns.Copy(apex)
	aged.Header().Ttl = apex.Header().Ttl / 2

	for _, tc := range []struct {
		name string
		have []dns.RR
	}{
		{"the child's own apex copy", []dns.RR{apex}},
		{"re-owned to the signal name (at-ns)", []dns.RR{signal}},
		{"served from a warm cache with a decremented TTL", []dns.RR{aged}},
		{"among other records", []dns.RR{aged, signal}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !matchKeyRR(tc.have, childKeyRR) {
				t.Error("the offered key was not recognised; VerifyChildKey falls through to" +
					" foundUnvalidated and, with require-dnssec set, bootstrap can never complete")
			}
		})
	}
}

// The comparison must still be a comparison: a different key, or a different
// record type at the same name, is not a match.
func TestMatchKeyRRRejectsADifferentKey(t *testing.T) {
	apex := mustRR(t, childKeyRR).(*dns.KEY)

	other := dns.Copy(apex).(*dns.KEY)
	other.PublicKey = "AwEAAcMnWBKLuvG7VOZvqvT5kOxjuNGZkgJoRZWr6dsLPFCH+xLPnIzKq0aVAWjXCu8vGKhOFtgD1LHYQMFvXHOaSCUt"
	if matchKeyRR([]dns.RR{other}, childKeyRR) {
		t.Error("a different public key was accepted as the offered key")
	}

	notAKey := mustRR(t, "child.parent.example. 3600 IN TXT \"not a key\"")
	if matchKeyRR([]dns.RR{notAKey}, childKeyRR) {
		t.Error("a TXT record was accepted as a KEY")
	}

	if matchKeyRR([]dns.RR{apex}, "child.parent.example. 3600 IN TXT \"not a key\"") {
		t.Error("a non-KEY offered record matched something")
	}
}

// #570: with allow-unvalidated-upload false -- the DEFAULT -- the parent refuses
// the ceremony, and used to do it by falling through to the generic
// "signature did not validate" path with no EDE at all. The child then could not
// tell deliberate policy from a wrong target, an ACL, or an unconfigured zone.
func TestUnvalidatedUploadRefusalCarriesItsOwnEDE(t *testing.T) {
	zd := childKeyParent(t)
	zd.DelegationPolicy = &DelegationPolicy{Name: "test", AllowUnvalidatedUpload: false}

	key := mustRR(t, childKeyRR)
	del := dns.Copy(key)
	del.Header().Class = dns.ClassANY
	del.Header().Ttl = 0

	r := new(dns.Msg)
	r.SetUpdate(zd.ZoneName)
	r.Ns = []dns.RR{del, key}

	us := &UpdateStatus{
		Type:            "TRUSTSTORE-UPDATE",
		SignerName:      "child.parent.example.",
		ValidationRcode: dns.RcodeSuccess,
	}

	approved, _, err := zd.ApproveTrustUpdate(zd.ZoneName, us, r)
	if err != nil {
		t.Fatalf("ApproveTrustUpdate returned an error: %v", err)
	}
	if approved {
		t.Fatal("an unvalidated upload was approved although policy forbids it")
	}
	if us.RejectionEDE != edns0.EDESig0UnvalidatedUploadNotAccepted {
		t.Errorf("RejectionEDE = %d (%s), want EDESig0UnvalidatedUploadNotAccepted (%d)."+
			" A bare REFUSED cannot be told apart from a wrong target or an ACL, and the one"+
			" thing the child needs -- publish the KEY where it can be validated -- is exactly"+
			" what goes unsaid",
			us.RejectionEDE, edns0.EDECodeToString[us.RejectionEDE],
			edns0.EDESig0UnvalidatedUploadNotAccepted)
	}
}

// The default policy is the one that refuses, which is why this is reachable
// without configuring anything.
func TestDefaultDelegationPolicyRefusesUnvalidatedUploads(t *testing.T) {
	if DefaultDelegationPolicy().AllowUnvalidatedUpload {
		t.Skip("the default now allows unvalidated uploads; this test guarded the other case")
	}
	if txt := edns0.EDECodeToString[edns0.EDESig0UnvalidatedUploadNotAccepted]; txt == "" {
		t.Error("the EDE has no text, so the child receives a bare code")
	} else if !strings.Contains(txt, "publish") {
		t.Errorf("the EDE text does not say what to do instead: %q", txt)
	}
}
