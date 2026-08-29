/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The UPDATE path, and the child update policy in particular.
 */
package tdns

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

// approvalFor drives ApproveTrustUpdate for one KEY RR under one child policy,
// with the update already validated by a trusted key so the check under test is
// the only thing that can reject it.
func approvalFor(t *testing.T, policyType, signer, owner string) bool {
	t.Helper()

	zd := &ZoneData{
		ZoneName: "example.",
		UpdatePolicy: UpdatePolicy{
			Child: UpdatePolicyDetail{
				Type:    policyType,
				RRtypes: map[uint16]bool{dns.TypeKEY: true},
			},
		},
	}
	rr, err := dns.NewRR(owner + " 3600 IN KEY 512 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=")
	if err != nil {
		t.Fatalf("building the update RR for %q: %v", owner, err)
	}
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{rr}

	us := &UpdateStatus{
		SignerName:            signer,
		Validated:             true,
		ValidatedByTrustedKey: true,
		ValidationRcode:       dns.RcodeSuccess,
	}
	approved, _, err := zd.ApproveTrustUpdate("example.", us, msg)
	if err != nil {
		t.Fatalf("ApproveTrustUpdate(%s, signer=%q, owner=%q): %v", policyType, signer, owner, err)
	}
	return approved && us.Approved
}

// THE AUTHORISATION BUG. selfsub means "the signer may update names inside its
// own subtree". The check was strings.HasSuffix(owner, signerName), which
// compares bytes and knows nothing about label boundaries -- so
// evilchild.example. ends with child.example. and a signer holding a key for
// child.example. was authorised to write a name it has no claim to.
//
// This is a boundary test on a security decision, so both directions matter:
// the names outside the subtree must be refused AND the names inside it must
// still be allowed, or "fixing" it by refusing everything would pass.
func TestSelfsubPolicyIsBoundedByLabels(t *testing.T) {
	const signer = "child.example."

	for _, tc := range []struct {
		owner string
		want  bool
		why   string
	}{
		{"child.example.", true, "the signer's own name is inside its subtree"},
		{"sub.child.example.", true, "a genuine subdomain"},
		{"deep.sub.child.example.", true, "an indirect subdomain"},

		// Case must not decide authorisation either way.
		{"CHILD.EXAMPLE.", true, "the signer's own name, upper case"},
		{"SUB.child.example.", true, "a subdomain, left label upper"},
		{"sub.CHILD.EXAMPLE.", true, "a subdomain, signer part upper"},

		// The bug: a byte-wise suffix match calls all of these inside.
		{"evilchild.example.", false, "ends with the signer name but is a DIFFERENT name"},
		{"xchild.example.", false, "same, one letter"},
		{"notchild.example.", false, "same"},
		{"EVILCHILD.EXAMPLE.", false, "same, and upper case must not rescue it"},

		// And plain outsiders.
		{"other.example.", false, "unrelated name in the zone"},
		{"child.example.org.", false, "same labels, different tree"},
	} {
		t.Run(tc.owner, func(t *testing.T) {
			if got := approvalFor(t, "selfsub", signer, tc.owner); got != tc.want {
				verb := "refused"
				if got {
					verb = "APPROVED"
				}
				t.Errorf("selfsub signer=%s: %s %q -- %s", signer, verb, tc.owner, tc.why)
			}
		})
	}
}

// self means "the signer may update exactly its own name". Case-sensitivity
// here fails closed rather than open, so it denies legitimate updates instead
// of permitting illegitimate ones -- still wrong, just less alarming.
func TestSelfPolicyComparesNamesNotBytes(t *testing.T) {
	const signer = "child.example."

	for _, tc := range []struct {
		owner string
		want  bool
	}{
		{"child.example.", true},
		{"CHILD.EXAMPLE.", true},
		{"Child.Example.", true},
		{"sub.child.example.", false},
		{"evilchild.example.", false},
		{"other.example.", false},
	} {
		t.Run(tc.owner, func(t *testing.T) {
			if got := approvalFor(t, "self", signer, tc.owner); got != tc.want {
				t.Errorf("self signer=%s owner=%q: approved=%v, want %v", signer, tc.owner, got, tc.want)
			}
		})
	}
}

// A zone with a real child delegation, so IsChildDelegation has something to
// say yes to as well as something to say no to.
const delegationZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
example.	3600	IN	DNSKEY	257 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=
ns.example.	3600	IN	A	192.0.2.1
child.example.	3600	IN	NS	ns1.child.example.
ns1.child.example.	3600	IN	A	192.0.2.2
www.example.	3600	IN	A	192.0.2.3
`

// IsChildDelegation answers "is this owner a delegation point?", and the
// UPDATE classifier asks it about owner names taken off the wire.
//
// GetOwner folds, so the apex is found; the apex-exclusion test did not, so a
// mixed-case apex -- which has NS -- came back as a child cut. An UPDATE of the
// apex NS RRset spelled EXAMPLE. was then classified as a CHILD update and
// judged against allow-child-updates rather than allow-updates.
func TestIsChildDelegationIgnoresCase(t *testing.T) {
	zd := testZone(t, "example.", delegationZone)
	registerZones(t, zd)

	for _, apex := range []string{"example.", "EXAMPLE.", "Example."} {
		if zd.IsChildDelegation(apex) {
			t.Errorf("IsChildDelegation(%q) = true: the apex is not a child cut, "+
				"and an apex update classified as a child update is judged "+
				"against the wrong permission", apex)
		}
	}
	for _, child := range []string{"child.example.", "CHILD.EXAMPLE.", "Child.Example."} {
		if !zd.IsChildDelegation(child) {
			t.Errorf("IsChildDelegation(%q) = false, but it is a delegation point", child)
		}
	}
	// A name with records but no NS is not a delegation either, in any case.
	for _, plain := range []string{"www.example.", "WWW.EXAMPLE."} {
		if zd.IsChildDelegation(plain) {
			t.Errorf("IsChildDelegation(%q) = true for a name with no NS RRset", plain)
		}
	}
}

// ZoneUpdateChangesDelegationDataNG decides whether an update touches
// delegation data, which is what makes the parent resync. The ClassNONE arm --
// deleting one RR rather than a whole RRset -- compared the wire owner to the
// apex byte-wise, so a mixed-case apex NS or KSK DNSKEY delete was applied and
// then not reported: InSync stayed true and the removal was never recorded.
func TestApexDeletesAreTrackedInAnyCase(t *testing.T) {
	for _, spelling := range []string{"example.", "EXAMPLE.", "Example."} {
		t.Run(spelling, func(t *testing.T) {
			zd := testZone(t, "example.", delegationZone)
			registerZones(t, zd)
			zd.UpdatePolicy = policyAllowing(dns.TypeNS, dns.TypeDNSKEY)

			// RFC 2136 §2.5.4: delete one RR by giving it with class NONE.
			nsDel := &dns.NS{
				Hdr: dns.RR_Header{Name: spelling, Rrtype: dns.TypeNS, Class: dns.ClassNONE, Ttl: 3600},
				Ns:  "ns.example.",
			}
			dss, err := zd.ZoneUpdateChangesDelegationDataNG(UpdateRequest{
				Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{nsDel},
			})
			if err != nil {
				t.Fatalf("ZoneUpdateChangesDelegationDataNG: %v", err)
			}
			if dss.InSync {
				t.Errorf("an apex NS delete spelled %q left InSync true: the parent is "+
					"never told the delegation changed", spelling)
			}
			if len(dss.NsRemoves) != 1 {
				t.Errorf("apex NS delete spelled %q recorded %d removals, want 1",
					spelling, len(dss.NsRemoves))
			}
		})
	}
}

// The KSK half of the same arm: a SEP DNSKEY removal has to be recorded so the
// parent's DS can follow it.
func TestApexKskDeleteIsTrackedInAnyCase(t *testing.T) {
	for _, spelling := range []string{"example.", "EXAMPLE."} {
		zd := testZone(t, "example.", delegationZone)
		registerZones(t, zd)
		zd.UpdatePolicy = policyAllowing(dns.TypeDNSKEY)

		apex, err := zd.GetOwner("example.")
		if err != nil || apex == nil {
			t.Fatalf("reading the apex: %v", err)
		}
		rrset, ok := apex.RRtypes.Get(dns.TypeDNSKEY)
		if !ok || len(rrset.RRs) == 0 {
			t.Fatal("fixture has no apex DNSKEY; this test would pass whatever the code does")
		}
		key, ok := dns.Copy(rrset.RRs[0]).(*dns.DNSKEY)
		if !ok {
			t.Fatal("apex DNSKEY is not a DNSKEY")
		}
		if key.Flags&dns.SEP == 0 {
			t.Fatal("fixture DNSKEY is not a KSK; the SEP branch would not run")
		}
		key.Hdr.Name = spelling
		key.Hdr.Class = dns.ClassNONE

		dss, err := zd.ZoneUpdateChangesDelegationDataNG(UpdateRequest{
			Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{key},
		})
		if err != nil {
			t.Fatalf("ZoneUpdateChangesDelegationDataNG: %v", err)
		}
		if len(dss.DNSKEYRemoves) != 1 || dss.InSync {
			t.Errorf("a KSK delete spelled %q recorded %d removals (InSync=%v), want 1 and false",
				spelling, len(dss.DNSKEYRemoves), dss.InSync)
		}
	}
}

// Everything ZoneUpdateChangesDelegationDataNG reports must depend on the
// action, not on how the owner was spelled. Stated differentially on purpose:
// the guard this covers fires only for a DUPLICATE apex NS add -- every other
// path sets InSync from its own arm -- and whether "in sync" is the right
// answer for a duplicate add is a separate question from whether the spelling
// may change it.
func TestDelegationChangeReportIsSpellingIndependent(t *testing.T) {
	report := func(t *testing.T, owner string, class uint16) string {
		t.Helper()
		zd := testZone(t, "example.", delegationZone)
		registerZones(t, zd)
		zd.UpdatePolicy = policyAllowing(dns.TypeNS, dns.TypeDNSKEY)

		ns := &dns.NS{
			Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNS, Class: class, Ttl: 3600},
			Ns:  "ns.example.", // already in the zone: an add of this is a duplicate
		}
		dss, err := zd.ZoneUpdateChangesDelegationDataNG(UpdateRequest{
			Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{ns},
		})
		if err != nil {
			t.Fatalf("ZoneUpdateChangesDelegationDataNG(%q): %v", owner, err)
		}
		return fmt.Sprintf("insync=%v adds=%d removes=%d", dss.InSync, len(dss.NsAdds), len(dss.NsRemoves))
	}

	for _, class := range []uint16{dns.ClassINET, dns.ClassNONE, dns.ClassANY} {
		t.Run(dns.ClassToString[class], func(t *testing.T) {
			want := report(t, "example.", class)
			for _, spelling := range []string{"EXAMPLE.", "Example.", "eXaMpLe."} {
				if got := report(t, spelling, class); got != want {
					t.Errorf("apex NS action spelled %q reports %q, but %q reports %q",
						spelling, got, "example.", want)
				}
			}
		})
	}
}
