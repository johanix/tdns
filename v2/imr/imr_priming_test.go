/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func primingErrorIn(sink *testErrorSink) string {
	for _, e := range sink.List() {
		if e.Category == ErrCatUpstream && e.Subtype == ErrSubImrPriming {
			return e.Message
		}
	}
	return ""
}

// unprimedImr is an Imr as New leaves one whose root has to be primed.
func unprimedImr(sink ErrorSink) *Imr {
	return &Imr{ready: make(chan struct{}), errorRegistry: sink}
}

func isReady(imr *Imr) bool {
	select {
	case <-imr.Ready():
		return true
	default:
		return false
	}
}

// A failed priming is retried, the failure is visible while it lasts, and it
// is gone once the resolver is up.
func TestPrimingIsRetriedUntilItSucceeds(t *testing.T) {
	sink := newTestErrorSink()
	imr := unprimedImr(sink)

	calls := 0
	var whileFailing string
	var errWhileFailing error
	prime := func(context.Context) error {
		calls++
		if calls == 2 {
			whileFailing = primingErrorIn(sink)
			errWhileFailing = imr.PrimingError()
		}
		if calls < 3 {
			return errors.New("priming: i/o timeout")
		}
		return nil
	}
	if !imr.primeRetrying(context.Background(), prime, func(int) time.Duration { return time.Millisecond }) {
		t.Fatal("primeRetrying gave up; want success at the third attempt")
	}
	if calls != 3 {
		t.Errorf("prime ran %d times, want 3", calls)
	}
	if !strings.Contains(whileFailing, "i/o timeout") {
		t.Errorf("while failing, the sink said %q; want the priming error", whileFailing)
	}
	if errWhileFailing == nil || !strings.Contains(errWhileFailing.Error(), "i/o timeout") {
		t.Errorf("while failing, PrimingError was %v; want the priming error", errWhileFailing)
	}
	if msg := primingErrorIn(sink); msg != "" {
		t.Errorf("after success the priming error is still registered: %q", msg)
	}
	if err := imr.PrimingError(); err != nil {
		t.Errorf("after success PrimingError is %v", err)
	}
	if !isReady(imr) {
		t.Error("primed, and not Ready")
	}
}

// Shutdown ends the retry, and leaves the failure visible.
func TestPrimingRetryStopsWithTheContext(t *testing.T) {
	sink := newTestErrorSink()
	imr := unprimedImr(sink)
	ctx, cancel := context.WithCancel(context.Background())

	calls := 0
	prime := func(context.Context) error {
		calls++
		cancel()
		return errors.New("root servers unreachable")
	}
	if imr.primeRetrying(ctx, prime, func(int) time.Duration { return time.Hour }) {
		t.Fatal("primeRetrying reported success")
	}
	if calls != 1 {
		t.Errorf("prime ran %d times after cancellation, want 1", calls)
	}
	if primingErrorIn(sink) == "" || imr.PrimingError() == nil {
		t.Error("gave up without the failure registered")
	}
	if isReady(imr) {
		t.Error("not primed, and Ready")
	}
}

// A resolver with nothing to prime is not primed again.
func TestPrimingIsSkippedWhenReady(t *testing.T) {
	imr := &Imr{} // built by hand: Ready
	if !imr.primeRetrying(context.Background(), func(context.Context) error {
		t.Error("primed a resolver that was Ready")
		return nil
	}, primingRetryDelay) {
		t.Error("primeRetrying reported a Ready resolver not ready")
	}
}

func TestPrimingRetryDelay(t *testing.T) {
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second,
		80 * time.Second, 2 * time.Minute, 2 * time.Minute}
	for attempt, w := range want {
		if got := primingRetryDelay(attempt); got != w {
			t.Errorf("attempt %d: %v, want %v", attempt, got, w)
		}
	}
	if got := primingRetryDelay(1000); got != 2*time.Minute {
		t.Errorf("attempt 1000: %v, want the two-minute cap", got)
	}
}

// An attempt starts as the first did: what an earlier one taught the root
// servers' backoff is forgotten. A routing error holds an address back for an
// hour, which is what an attempt made while the network comes up gets.
func TestPrimingForgetsTheRootServersFailures(t *testing.T) {
	restoreProcessWideTuning(t)
	imr, err := New(context.Background(), Config{}, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("seeding the hints: %v", err)
	}
	servers, _ := imr.Cache.ServerMapCopy(".")
	var server *cache.AuthServer
	var addr string
	for _, s := range servers {
		if addrs := s.GetAddrs(); len(addrs) > 0 {
			server, addr = s, addrs[0]
			break
		}
	}
	if server == nil {
		t.Fatal("no root server with an address in the hints")
	}
	server.RecordAddressFailure(addr, core.TransportDo53, errors.New("dial udp: connect: network is unreachable"))
	if server.IsAddrXportAvailable(addr, core.TransportDo53) {
		t.Fatal("a routing error did not back the address off")
	}

	// The attempt itself fails before it sends anything: the hints are gone.
	imr.bootConf.RootHints = filepath.Join(t.TempDir(), "no-such-hints")
	if err := imr.primeFromHints(context.Background()); err == nil {
		t.Fatal("primed with no root hints to read")
	}
	if !server.IsAddrXportAvailable(addr, core.TransportDo53) {
		t.Error("the attempt kept the earlier attempt's backoff")
	}
}

// New sends nothing, so a root that cannot be primed is not its error but
// Start's, retried and visible. Until it is primed, Query waits, within its
// context, and then says why it got no answer.
func TestNewSendsNothing(t *testing.T) {
	restoreProcessWideTuning(t)
	sink := newTestErrorSink()
	ic := Config{RootHints: filepath.Join(t.TempDir(), "no-such-hints")}
	imr, err := New(context.Background(), ic, Options{Errors: sink})
	if err != nil || imr == nil {
		t.Fatalf("New with no root hints to read: %v, %v; want an Imr, not yet Ready", imr, err)
	}
	if isReady(imr) {
		t.Fatal("Ready before Start primed the root")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	imr.Start(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for imr.PrimingError() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := imr.PrimingError(); err == nil || !strings.Contains(err.Error(), "no-such-hints") {
		t.Fatalf("PrimingError = %v; want the hints that cannot be read", err)
	}
	if !strings.Contains(primingErrorIn(sink), "no-such-hints") {
		t.Errorf("the sink says %q; want the priming error", primingErrorIn(sink))
	}

	qctx, qcancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer qcancel()
	resp, err := imr.Query(qctx, "www.example.", dns.TypeA, dns.ClassINET)
	if resp != nil || err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "no-such-hints") {
		t.Errorf("Query before priming: %+v, %v; want no answer, the deadline and the priming error", resp, err)
	}
}

// A resolver whose Start context ended before it was Ready will not become
// ready: WaitReady, Query and Serve's requests say so at once, with the
// priming error, instead of waiting out their deadlines.
func TestStoppedBeforeReadyFailsAtOnce(t *testing.T) {
	restoreProcessWideTuning(t)
	ic := Config{RootHints: filepath.Join(t.TempDir(), "no-such-hints")}
	imr, err := New(context.Background(), ic, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	imr.Tuning.QueryBudget = time.Hour // only the stop can end the waits below

	ctx, cancel := context.WithCancel(context.Background())
	imr.Start(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for imr.PrimingError() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if imr.PrimingError() == nil {
		t.Fatal("priming did not fail")
	}
	cancel()

	wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer wcancel()
	err = imr.WaitReady(wctx)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, imr.PrimingError()) ||
		!strings.Contains(err.Error(), "stopped before it was ready") {
		t.Fatalf("WaitReady once Start's context ended: %v; want the stop, wrapping the priming error", err)
	}

	start := time.Now()
	resp, err := imr.Query(context.Background(), "www.example.", dns.TypeA, dns.ClassINET)
	if resp != nil || err == nil || !strings.Contains(err.Error(), "stopped before it was ready") {
		t.Errorf("Query: %+v, %v; want the stop", resp, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Query took %v to fail; want at once", d)
	}

	requests := make(chan Request, 1)
	respch := make(chan Response, 1)
	requests <- Request{Qname: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET, ResponseCh: respch}
	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	go imr.Serve(sctx, requests)
	select {
	case resp := <-respch:
		if !resp.Error || !strings.Contains(resp.ErrorMsg, "stopped before it was ready") {
			t.Errorf("Serve answered %+v; want the stop", resp)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not answer")
	}
}

// A Query that comes before the resolver is Ready waits for it, and is
// answered once it is.
func TestQueryWaitsForReady(t *testing.T) {
	restoreProcessWideTuning(t)
	addr, port, _, stop := startTestUpstream(t)
	defer stop()
	imr, err := New(context.Background(), Config{Forward: rootForward(addr, port)}, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// As if the root were still being primed.
	imr.ready, imr.readyOnce = make(chan struct{}), sync.Once{}

	type result struct {
		resp *Response
		err  error
	}
	answered := make(chan result, 1)
	go func() {
		resp, err := imr.Query(context.Background(), "www.fwd.example.", dns.TypeA, dns.ClassINET)
		answered <- result{resp, err}
	}()
	select {
	case r := <-answered:
		t.Fatalf("answered before the resolver was Ready: %+v, %v", r.resp, r.err)
	case <-time.After(50 * time.Millisecond):
	}
	imr.markReady()
	select {
	case r := <-answered:
		if r.err != nil || r.resp == nil || r.resp.RRset == nil {
			t.Errorf("once Ready: %+v, %v; want the upstream's answer", r.resp, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not answered once Ready")
	}
}

// Serve answers what comes on its channel, and returns when the channel is
// closed.
func TestServeAnswersItsRequests(t *testing.T) {
	restoreProcessWideTuning(t)
	addr, port, _, stop := startTestUpstream(t)
	defer stop()
	imr, err := New(context.Background(), Config{Forward: rootForward(addr, port)}, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	requests := make(chan Request)
	served := make(chan struct{})
	go func() {
		defer close(served)
		imr.Serve(context.Background(), requests)
	}()
	respch := make(chan Response, 1)
	requests <- Request{Qname: "www.fwd.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET, ResponseCh: respch}
	select {
	case resp := <-respch:
		if resp.Error || resp.RRset == nil {
			t.Errorf("Serve answered %+v; want the upstream's answer", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not answer")
	}
	close(requests)
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return when its channel was closed")
	}
}

// A request Serve answers waits for the resolver to be Ready even when the
// cache already holds the answer, and is answered from the cache once it is.
func TestServeAnswersNoCacheHitBeforeReady(t *testing.T) {
	imr := newTestImr(t)
	const qname = "cached.example."
	imr.Cache.Set(qname, dns.TypeA, &cache.CachedRRset{
		Name: qname, RRtype: dns.TypeA, Context: cache.ContextAnswer,
		RRset: &core.RRset{Name: qname, Class: dns.ClassINET, RRtype: dns.TypeA,
			RRs: []dns.RR{mustRR(t, qname+" 3600 IN A 192.0.2.7")}},
	})
	// As if the root were still being primed.
	imr.ready, imr.readyOnce = make(chan struct{}), sync.Once{}

	respch := make(chan Response, 1)
	go imr.handleRecursorRequest(context.Background(), Request{
		Qname: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET, ResponseCh: respch,
	})
	select {
	case resp := <-respch:
		t.Fatalf("answered before the resolver was Ready: %+v", resp)
	case <-time.After(50 * time.Millisecond):
	}
	imr.markReady()
	select {
	case resp := <-respch:
		if resp.Error || resp.RRset == nil || len(resp.RRset.RRs) != 1 {
			t.Errorf("once Ready: %+v; want the cached answer", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not answered once Ready")
	}
}
