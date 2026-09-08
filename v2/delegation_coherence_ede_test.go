package tdns

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #571: every coherence failure was reported as EDE 518, "Zone does not allow
// DNS UPDATE", on a zone that allows child updates and had just APPROVED the
// update it was about to refuse. The EDE named the one thing demonstrably not
// wrong, and sent operators to check allow-child-updates and the update policy.
func TestCoherenceRefusalDoesNotClaimUpdatesAreDisallowed(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want uint16
	}{
		{
			// The case the check exists for: the child asked for something its
			// own nameservers do not serve. Its to fix, and waiting will not.
			name: "a real mismatch",
			err:  fmt.Errorf("the resulting NS RRset for child.example. is not what its nameservers serve: 0 record(s) not served, 1 served but absent"),
			want: edns0.EDEDelegationIncoherent,
		},
		{
			// A delegated nameserver that is down. Nothing about the update or
			// the policy is wrong; the parent simply could not ask.
			name: "a nameserver that refused the connection",
			err:  fmt.Errorf("cannot verify the NS RRset for child.example.: %v: %w", "dial tcp: connection refused", ErrDelegationUnverifiable),
			want: edns0.EDEDelegationUnverifiable,
		},
		{
			// A parent-side precondition. #503 was one of these, reported to
			// the child as a policy refusal.
			name: "a parent-side precondition",
			err:  fmt.Errorf("cannot verify the delegation for child.example.: no way to ask its nameservers what they serve: %w", ErrDelegationUnverifiable),
			want: edns0.EDEDelegationUnverifiable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := delegationCoherenceEDE(tc.err)
			if got == edns0.EDEZoneUpdatesNotAllowed {
				t.Fatal("still reported as 'Zone does not allow DNS UPDATE' on a zone that does")
			}
			if got != tc.want {
				t.Errorf("EDE %d (%s), want %d (%s)",
					got, edns0.EDECodeToString[got], tc.want, edns0.EDECodeToString[tc.want])
			}
		})
	}
}

// The classification has to come from the error, not from where it was raised,
// so the checks themselves must mark the unverifiable cases.
func TestUnverifiableCoherenceFailuresAreMarkedAsSuch(t *testing.T) {
	zd := cuParentZone(t)
	actions := []dns.RR{addRR(t, "child.example. 3600 IN NS ns2.provider.net.")}

	t.Run("no way to ask the child's nameservers", func(t *testing.T) {
		err := zd.CheckDelegationNSCoherenceForUpdate(context.Background(), actions, nil)
		if err == nil {
			t.Fatal("no error with no asker")
		}
		if !errors.Is(err, ErrDelegationUnverifiable) {
			t.Errorf("not marked unverifiable: %v."+
				" The child is told to fix a delegation the parent never managed to check", err)
		}
		if got := delegationCoherenceEDE(err); got != edns0.EDEDelegationUnverifiable {
			t.Errorf("EDE %d (%s), want unverifiable", got, edns0.EDECodeToString[got])
		}
	})

	t.Run("no way to look up the child's DNSKEYs", func(t *testing.T) {
		dsActions := []dns.RR{addRR(t, "child.example. 3600 IN DS 12345 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")}
		err := zd.CheckDelegationCoherenceForUpdate(dsActions, nil)
		if err == nil {
			t.Fatal("a DS change with no way to look up the child's DNSKEYs was accepted;" +
				" the DS arm of the coherence check is not being exercised at all")
		}
		if !errors.Is(err, ErrDelegationUnverifiable) {
			t.Errorf("not marked unverifiable: %v", err)
		}
	})
}

// And the codes have text, or the child receives a bare number.
func TestCoherenceEDEsHaveText(t *testing.T) {
	for _, code := range []uint16{edns0.EDEDelegationIncoherent, edns0.EDEDelegationUnverifiable} {
		if edns0.EDECodeToString[code] == "" {
			t.Errorf("EDE %d has no text", code)
		}
	}
}

// The wiring, not just the classifier: an update that reaches the coherence
// check and fails it must arrive at the child with a coherence EDE. Testing
// delegationCoherenceEDE alone leaves the two call sites free to keep sending
// 518, which is what shipped.
func TestApproveChildUpdateReportsCoherenceNotPolicy(t *testing.T) {
	zd := childKeyParent(t)

	// No scanner is configured here, so the parent has no way to ask the
	// child's nameservers what they serve -- the "unverifiable" arm, and the
	// shape a parent-side precondition takes.
	prev := Conf.Internal.GetScanner()
	Conf.Internal.PublishScanner(nil)
	t.Cleanup(func() { Conf.Internal.PublishScanner(prev) })

	r := new(dns.Msg)
	r.SetUpdate(zd.ZoneName)
	r.Ns = []dns.RR{mustRR(t, "child.parent.example. 3600 IN NS ns9.provider.net.")}

	us := &UpdateStatus{
		Type:                  "CHILD-UPDATE",
		Validated:             true,
		ValidatedByTrustedKey: true,
		SignerName:            "child.parent.example.",
		ValidationRcode:       dns.RcodeSuccess,
	}

	approved, _, err := zd.ApproveChildUpdate(zd.ZoneName, us, r)
	if approved {
		t.Fatal("the update was approved, so it never reached the coherence check." +
			" Skipping here would turn a broken fixture into a green test, which is" +
			" how the thing this test exists for shipped in the first place")
	}
	if err == nil {
		t.Fatal("refused with no error, so this is not the coherence path")
	}

	if us.RejectionEDE == edns0.EDEZoneUpdatesNotAllowed {
		t.Fatalf("refused with 'Zone does not allow DNS UPDATE' on a zone that allows child"+
			" updates and had just approved this one. The real reason was: %v", err)
	}
	if us.RejectionEDE != edns0.EDEDelegationUnverifiable {
		t.Errorf("RejectionEDE = %d (%s), want unverifiable (%d). err=%v",
			us.RejectionEDE, edns0.EDECodeToString[us.RejectionEDE],
			edns0.EDEDelegationUnverifiable, err)
	}
	if us.ValidationRcode != dns.RcodeRefused {
		t.Errorf("rcode %s, want REFUSED: a coherence refusal is permanent and must not"+
			" answer SERVFAIL", dns.RcodeToString[int(us.ValidationRcode)])
	}
}

// N2's twin: the DS arm. ApproveChildUpdate runs the DS coherence check before
// the NS one, so a test that only ever reaches the NS site leaves the DS call
// site free to go back to 518 unnoticed -- which is the exact failure mode this
// PR is about.
func TestApproveChildUpdateReportsCoherenceOnTheDSPathToo(t *testing.T) {
	zd := childKeyParent(t)

	// No IMR, so there is no way to look up the child's DNSKEYs: the DS arm's
	// "unverifiable" shape.
	prevImr := Conf.Internal.ImrEngine
	Conf.Internal.ImrEngine = nil
	t.Cleanup(func() { Conf.Internal.ImrEngine = prevImr })
	prevGlobal := Globals.ImrEngine
	Globals.ImrEngine = nil
	t.Cleanup(func() { Globals.ImrEngine = prevGlobal })

	r := new(dns.Msg)
	r.SetUpdate(zd.ZoneName)
	r.Ns = []dns.RR{mustRR(t,
		"child.parent.example. 3600 IN DS 12345 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")}

	us := &UpdateStatus{
		Type:                  "CHILD-UPDATE",
		Validated:             true,
		ValidatedByTrustedKey: true,
		SignerName:            "child.parent.example.",
		ValidationRcode:       dns.RcodeSuccess,
	}

	approved, _, err := zd.ApproveChildUpdate(zd.ZoneName, us, r)
	if approved {
		t.Fatal("a DS change was approved with no way to check that the child would still" +
			" validate; the DS coherence arm is not being exercised")
	}
	if err == nil {
		t.Fatal("refused with no error, so this is not the coherence path")
	}
	if us.RejectionEDE == edns0.EDEZoneUpdatesNotAllowed {
		t.Fatalf("the DS arm still reports 'Zone does not allow DNS UPDATE'. The real reason"+
			" was: %v", err)
	}
	if us.RejectionEDE != edns0.EDEDelegationUnverifiable {
		t.Errorf("RejectionEDE = %d (%s), want unverifiable (%d). err=%v",
			us.RejectionEDE, edns0.EDECodeToString[us.RejectionEDE],
			edns0.EDEDelegationUnverifiable, err)
	}
	if us.ValidationRcode != dns.RcodeRefused {
		t.Errorf("rcode %s, want REFUSED: a coherence refusal is permanent and must not"+
			" answer SERVFAIL, on this arm as much as the other",
			dns.RcodeToString[int(us.ValidationRcode)])
	}
}

// N1: nameservers that disagree with each other. The parent asked and got
// answers; they conflicted, so nothing was established about the delegation.
// That is the retryable arm, and the message has always said so -- "retry once
// they are in sync" is 544's advice, while 543 tells a child its delegation is
// wrong.
func TestDisagreeingNameserversAreUnverifiableNotIncoherent(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("the nameservers of child.example. do not agree on its NS RRset; retry once they are in sync: %w",
			ErrDelegationUnverifiable),
		fmt.Errorf("the nameservers of child.example. do not agree on the A records of ns1.child.example.; retry once they are in sync: %w",
			ErrDelegationUnverifiable),
	} {
		if got := delegationCoherenceEDE(err); got != edns0.EDEDelegationUnverifiable {
			t.Errorf("EDE %d (%s) for %q, want unverifiable: the message tells the child to"+
				" retry, and the code should not tell it its delegation is wrong",
				got, edns0.EDECodeToString[got], err)
		}
	}
}
