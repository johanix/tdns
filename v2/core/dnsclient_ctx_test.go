/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Cancellation behaviour of the context-aware exchange (#435). The shape
 * under test is the one that used to be impossible: an upstream that accepts
 * the query and never answers. Before ExchangeContext existed, such a server
 * held the caller for the full client timeout no matter what the caller's
 * context said, because dns.Client.ExchangeContext never watches ctx.Done().
 */

package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// hangingHandler accepts the query and never writes a reply.
func hangingHandler(hold time.Duration) dns.HandlerFunc {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(hold)
	})
}

// assertCancelledFast runs exchange under a ctx cancelled after `after` and
// requires that it returned promptly, with an error identifying the cancel.
func assertCancelledFast(t *testing.T, after time.Duration, exchange func(ctx context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(after)
		cancel()
	}()

	start := time.Now()
	err := exchange(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("exchange succeeded against a server that never replies")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error does not identify the cancel: %v", err)
	}
	// The client timeout is 5s below; anything near it means the cancel was
	// only observed when the socket deadline fired.
	if elapsed > 2*time.Second {
		t.Errorf("cancel took %s to take effect (client timeout is 5s): %v", elapsed, err)
	}
}

// TestExchangeContext_CancelInterruptsUDP: the query is on the wire and the
// server is silent. Cancelling must return, not wait out the timeout.
func TestExchangeContext_CancelInterruptsUDP(t *testing.T) {
	port, cleanup := testServers(t, hangingHandler(3*time.Second), nil)
	defer cleanup()

	c := NewDNSClient(TransportDo53, port, nil)
	c.Timeout = 5 * time.Second
	c.DNSClientUDP.Timeout = c.Timeout
	c.DisableFallback = true // isolate the UDP leg from the TCP retry

	assertCancelledFast(t, 100*time.Millisecond, func(ctx context.Context) error {
		_, _, err := c.ExchangeContext(ctx, mustQuery("hang.example."), "127.0.0.1", false)
		return err
	})
}

// TestExchangeContext_CancelInterruptsTCP: same, over a TCP connection the
// server accepts and then holds open. This is the literal case from #435.
func TestExchangeContext_CancelInterruptsTCP(t *testing.T) {
	port, cleanup := testServers(t, nil, hangingHandler(3*time.Second))
	defer cleanup()

	c := NewDNSClient(TransportDo53TCP, port, nil)
	c.Timeout = 5 * time.Second
	c.DNSClientTCP.Timeout = c.Timeout

	assertCancelledFast(t, 100*time.Millisecond, func(ctx context.Context) error {
		_, _, err := c.ExchangeContext(ctx, mustQuery("hang.example."), "127.0.0.1", false)
		return err
	})
}

// TestExchangeContext_UncancelledStillWorks: the cancellable path must not
// change what a normal exchange does.
func TestExchangeContext_UncancelledStillWorks(t *testing.T) {
	const qname = "ok.example."
	answer := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{aRR(qname, "192.0.2.9")}
		_ = w.WriteMsg(m)
	})
	port, cleanup := testServers(t, answer, answer)
	defer cleanup()

	c := NewDNSClient(TransportDo53, port, nil)
	c.Timeout = 2 * time.Second
	c.DNSClientUDP.Timeout = c.Timeout
	c.DNSClientTCP.Timeout = c.Timeout

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, _, err := c.ExchangeContext(ctx, mustQuery(qname), "127.0.0.1", false)
	if err != nil {
		t.Fatalf("ExchangeContext: %v", err)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected one answer, got %v", resp)
	}
}

// TestExchangeContext_AlreadyCancelled: a ctx that is already done must not
// put a packet on the wire at all.
func TestExchangeContext_AlreadyCancelled(t *testing.T) {
	var queries int
	count := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries++
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	port, cleanup := testServers(t, count, count)
	defer cleanup()

	c := NewDNSClient(TransportDo53, port, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := c.ExchangeContext(ctx, mustQuery("nope.example."), "127.0.0.1", false); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if queries != 0 {
		t.Errorf("server saw %d queries; a cancelled ctx must send none", queries)
	}
}

// TestExchangeCtx_FallsBackForPlainClient: a DNSClienter with no
// ContextExchanger half still runs, and still honours a ctx that is already
// cancelled — which is the pre-#435 guarantee, kept.
func TestExchangeCtx_FallsBackForPlainClient(t *testing.T) {
	answer := new(dns.Msg)
	answer.SetQuestion("fake.example.", dns.TypeA)
	answer.Answer = []dns.RR{aRR("fake.example.", "192.0.2.10")}

	fake := NewFakeDNSClient(TransportDo53)
	fake.Responses[FakeKey{}] = FakeResponse{Msg: answer}

	if _, ok := interface{}(fake).(ContextExchanger); ok {
		t.Fatalf("FakeDNSClient implements ContextExchanger; this test no longer covers the fallback")
	}

	resp, _, err := ExchangeCtx(context.Background(), fake, mustQuery("fake.example."), "127.0.0.1", false)
	if err != nil || resp == nil {
		t.Fatalf("ExchangeCtx via fallback: resp=%v err=%v", resp, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ExchangeCtx(ctx, fake, mustQuery("fake.example."), "127.0.0.1", false); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from the fallback path, got %v", err)
	}
}
