/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A resolver that forwards "." starts without priming, and without reading
// root-hints: a configured file that does not exist is not a reason to stop.
// It still applies its stub zones, and resolves through the forward.
func TestForwardedRootStartsWithoutRootHints(t *testing.T) {
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()

	savedImr := Globals.ImrEngine
	defer func() { Globals.ImrEngine = savedImr }()

	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	conf.Imr.RootHints = filepath.Join(t.TempDir(), "no-such-hints")
	conf.Imr.Forward = rootForward(addr, port)
	conf.Imr.Stubs = []ImrStubConf{{Zone: "stub.example.",
		Servers: []cache.AuthServer{{Name: "ns.stub.example.", Addrs: []string{"192.0.2.1"}}}}}
	if err := conf.InitImrEngine(context.Background(), true); err != nil {
		t.Fatalf("InitImrEngine with the root forwarded and no root hints: %v", err)
	}
	imr := conf.Internal.ImrEngine
	if imr.Cache.IsPrimed() {
		t.Error("a forwarded root was primed")
	}
	if crr := imr.Cache.Peek(".", dns.TypeNS); crr != nil {
		t.Errorf("a root NS was cached for a forwarded root: %+v", crr)
	}
	if _, ok := imr.Cache.ServerMapCopy("stub.example."); !ok {
		t.Error("the stub zone was not applied")
	}
	// Nothing at all: no priming fetch, and no ". NS" through the forward.
	logr.mu.Lock()
	sent := append([]upstreamQuery(nil), logr.queries...)
	logr.mu.Unlock()
	if len(sent) != 0 {
		t.Errorf("start-up sent %d query(ies) to the upstream: %+v", len(sent), sent)
	}

	resp, err := imr.ImrQuery(context.Background(), "www.fwd.example.", dns.TypeA, dns.ClassINET, nil)
	if err != nil || resp.RRset == nil || len(resp.RRset.RRs) != 1 {
		t.Fatalf("no answer through the forward: resp=%+v err=%v", resp, err)
	}
}

// The listeners do not wait for trust-anchor set-up. With the only upstream
// down, fetching the anchored zone's DNSKEY RRset takes until it times out,
// and the resolver used to bind only after that. A query that arrives before
// set-up has finished, once the upstream is back, still validates: the DNSKEY
// RRset is fetched on demand and checked against the configured anchor, which
// was loaded before anything else.
func TestListenersDoNotWaitForTrustAnchorSetup(t *testing.T) {
	parent := newFwdSecKey(t, fwdSecParent)
	www := parent.sign(t, fwdSecRR(t, "www."+fwdSecParent+" 300 IN A 192.0.2.11"))
	var open atomic.Bool
	addr, port := startGatedSignedForwardUpstream(t, map[string]*dns.Msg{
		fwdSecParent + " DNSKEY":     {Answer: parent.sign(t, dns.Copy(parent.dnskey))},
		"www." + fwdSecParent + " A": {Answer: www},
	}, &open)

	signerTestDnskeyCache(t) // the cache NewImr builds takes it: not the process-wide one
	// NewImr loads the configured anchor, and keeps the config for what Start
	// reads.
	imr := newForwardTestImrWith(t, ImrEngineConf{
		Forward:       rootForward(addr, port),
		TrustAnchorDS: parent.dnskey.ToDS(dns.SHA256).String(),
	}, ImrOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan struct{})
	started := make(chan struct{})
	go func(ctx context.Context) {
		defer close(started)
		imr.startServing(ctx, func(context.Context) { close(listening) })
	}(ctx)
	defer func() {
		cancel()
		select {
		case <-started:
		case <-time.After(30 * time.Second):
			t.Error("start-up did not return after its context ended")
		}
	}()
	select {
	case <-listening:
	case <-time.After(time.Second):
		t.Fatal("the listeners waited for trust-anchor set-up, whose upstream does not answer")
	}

	open.Store(true)
	r := new(dns.Msg)
	r.SetQuestion("www."+fwdSecParent, dns.TypeA)
	r.SetEdns0(4096, true)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, "www."+fwdSecParent, dns.TypeA, &edns0.MsgOptions{RD: true, DO: true})
	if cw.got == nil {
		t.Fatal("nothing written")
	}
	if cw.got.Rcode != dns.RcodeSuccess || len(cw.got.Answer) == 0 || !cw.got.AuthenticatedData {
		t.Errorf("rcode %s, %d answer RRs, AD=%v, EDE %d; want a validated answer",
			dns.RcodeToString[cw.got.Rcode], len(cw.got.Answer), cw.got.AuthenticatedData, edeOf(cw.got))
	}
}
