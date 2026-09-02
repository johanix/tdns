/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

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

// startSilentUpstreamDoT starts an encrypted upstream that completes the TLS
// handshake, reads the query, and never answers it. That is the shape the
// exhaustion path needs: the upstream IS encrypted, so the strict-privacy
// precheck passes and the query is actually attempted, and it fails only
// because nothing comes back.
func startSilentUpstreamDoT(t *testing.T, cert tls.Certificate) (string, uint16, func()) {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	host, port := splitHostPort(t, l.Addr().String())

	started := make(chan struct{})
	srv := &dns.Server{
		Listener: l,
		// Long enough that the client's own timeout always fires first, short
		// enough that shutdown does not wait on it: ShutdownContext waits for
		// in-flight handlers, and this one is deliberately in flight.
		Handler:           dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) { time.Sleep(time.Second) }),
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("silent DoT upstream did not start")
	}
	return host, port, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	}
}

// Exhausting the encrypted upstreams is itself the privacy failure, and must
// wrap the sentinel: under strict privacy the cleartext upstreams were never
// tried, so a client that would have been served over Do53 gets nothing, and
// deserves to be told why. Until this was fixed the forward path returned a
// generic error here while the iterative path -- which it is supposed to
// mirror -- wrapped the sentinel.
//
// This is the case the precheck cannot cover: an encrypted upstream exists and
// is reachable, it just never answers.
func TestForwardStrictPrivacyExhaustionWrapsSentinel(t *testing.T) {
	cert, pool := newUpstreamTestCert(t)
	addr, port, stop := startSilentUpstreamDoT(t, cert)
	defer stop()

	imr := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{
			{Addr: addr, Port: port, Transport: "dot", TLSServerName: "dns.test.example"},
		}},
	})
	imr.errorRegistry = NewServerErrorRegistry()
	fz := imr.ForwardZones()[0]
	trustUpstreamCert(t, fz, pool)
	if !fz.hasEncryptedUpstream() {
		t.Fatal("setup: the zone must have an encrypted upstream, or this tests the precheck")
	}

	// The client must give up before the context does. With the deadline
	// firing first we would be exercising the cancellation path, which returns
	// the context error and never reaches the exhaustion return at all.
	c := fz.Upstreams[0].Client.(*core.DNSClient)
	c.Timeout = 300 * time.Millisecond
	c.DNSClientTLS.Timeout = c.Timeout

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, rcode, _, _, err := imr.forwardQuery(ctx, "www.fwd.example.", dns.TypeA, fz, false, edns0.PrivacyStrict)
	if err == nil {
		t.Fatal("a silent upstream produced no error")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("hit the cancellation path, not exhaustion: %v", err)
	}
	if !errors.Is(err, ErrPrivacyUnavailable) {
		t.Errorf("got err %v, want one wrapping ErrPrivacyUnavailable", err)
	}
	if rcode != dns.RcodeServerFailure {
		t.Errorf("got rcode %s, want SERVFAIL", dns.RcodeToString[rcode])
	}

	// Control: the same dead end without the privacy signal is an ordinary
	// forwarding failure and must NOT claim to be a privacy one -- otherwise
	// the assertion above would pass on a resolver that wraps everything.
	_, _, _, _, err = imr.forwardQuery(ctx, "www.fwd.example.", dns.TypeA, fz, false, edns0.PrivacyNone)
	if err == nil {
		t.Fatal("a silent upstream produced no error without the privacy signal")
	}
	if errors.Is(err, ErrPrivacyUnavailable) {
		t.Errorf("a query with no privacy signal failed as a privacy failure: %v", err)
	}
}
