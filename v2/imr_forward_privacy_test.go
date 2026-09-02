/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The forward path has to honor the same three privacy levels as the iterative
// one, on the one thing it can choose: which upstreams to send to, in what
// order.
func TestForwardUpstreamsForPrivacy(t *testing.T) {
	fz := &ForwardZone{
		Zone: "example.",
		Upstreams: []*ForwardUpstream{
			{Label: "cleartext-1", Transport: core.TransportDo53},
			{Label: "dot", Transport: core.TransportDoT},
			{Label: "cleartext-2", Transport: core.TransportDo53TCP},
			{Label: "doq", Transport: core.TransportDoQ},
		},
	}

	for _, tc := range []struct {
		privacy edns0.PrivacyLevel
		want    []string
	}{
		// No signal: the operator's configured failover order is left alone.
		{edns0.PrivacyNone, []string{"cleartext-1", "dot", "cleartext-2", "doq"}},
		// Preference: encrypted first, cleartext still reachable, relative
		// order preserved inside each group.
		{edns0.PrivacyOpportunistic, []string{"dot", "doq", "cleartext-1", "cleartext-2"}},
		// Exclusion: the cleartext upstreams are not an option at all.
		{edns0.PrivacyStrict, []string{"dot", "doq"}},
	} {
		var got []string
		for _, up := range forwardUpstreamsForPrivacy(fz, tc.privacy) {
			got = append(got, up.Label)
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.privacy, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v, want %v", tc.privacy, got, tc.want)
				break
			}
		}
	}
}

// Strict privacy on a forward zone with no encrypted upstream must fail with
// the sentinel the responder matches on, not with a message that happens to
// contain the right words: ImrResponder attaches the privacy-unavailable EDE
// on errors.Is and nothing else.
func TestForwardStrictPrivacyReturnsSentinel(t *testing.T) {
	fz := &ForwardZone{
		Zone:      "example.",
		Upstreams: []*ForwardUpstream{{Label: "cleartext", Transport: core.TransportDo53}},
	}
	if fz.hasEncryptedUpstream() {
		t.Fatal("setup: zone should have no encrypted upstream")
	}
	if got := forwardUpstreamsForPrivacy(fz, edns0.PrivacyStrict); len(got) != 0 {
		t.Errorf("strict privacy: got %d upstreams, want none", len(got))
	}

	// The precheck is the first statement of forwardQuery and returns before
	// anything on the Imr is touched, so a zero-value Imr is enough to reach
	// it -- and the query never leaves the process.
	imr := &Imr{}
	_, rcode, _, _, err := imr.forwardQuery(context.Background(), "www.example.", dns.TypeA, fz, false, edns0.PrivacyStrict)
	if !errors.Is(err, ErrPrivacyUnavailable) {
		t.Errorf("got err %v, want one wrapping ErrPrivacyUnavailable", err)
	}
	if rcode != dns.RcodeServerFailure {
		t.Errorf("got rcode %s, want SERVFAIL", dns.RcodeToString[rcode])
	}
}
