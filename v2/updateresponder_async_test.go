/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// heldUpdater stands in for the ZoneUpdater under the publish gate: it takes
// each update at once, in order, and answers none of them until released.
type heldUpdater struct {
	q       chan UpdateRequest
	got     chan UpdateRequest
	release chan struct{}
}

func newHeldUpdater(t *testing.T) *heldUpdater {
	t.Helper()
	h := &heldUpdater{
		q:       make(chan UpdateRequest, 64),
		got:     make(chan UpdateRequest, 64),
		release: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	release := h.release
	go func() {
		var held []UpdateRequest
		for {
			select {
			case ur := <-h.q:
				h.got <- ur
				held = append(held, ur)
			case <-release:
				for _, ur := range held {
					ur.Resp <- ZoneUpdateResult{Applied: true}
				}
				held = nil
				release = nil
			case <-ctx.Done():
				return
			}
		}
	}()
	return h
}

func updateMsg(zone string) *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate(zone)
	return m
}

// An update waiting for its publish does not hold up the next one: each call
// returns once the update is handed over, the updates reach the updater in
// the order they arrived, and each client is answered when its update is
// applied.
func TestAnswerWhenAppliedDoesNotHoldUpTheNextUpdate(t *testing.T) {
	h := newHeldUpdater(t)
	const n = 5
	writers := make([]*chanResponseWriter, n)

	start := time.Now()
	for i := 0; i < n; i++ {
		writers[i] = &chanResponseWriter{ch: make(chan *dns.Msg, 1)}
		zone := fmt.Sprintf("z%d.test.", i)
		req := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: zone}
		if err := answerWhenApplied(context.Background(), writers[i], updateMsg(zone), req, h.q, dns.RcodeSuccess); err != nil {
			t.Fatalf("answerWhenApplied %d: %v", i, err)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("%d hand-overs took %s: each waited for the one before", n, d)
	}

	for i := 0; i < n; i++ {
		select {
		case ur := <-h.got:
			if want := fmt.Sprintf("z%d.test.", i); ur.ZoneName != want {
				t.Errorf("update %d reached the updater as %s, want %s", i, ur.ZoneName, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("update %d never reached the updater", i)
		}
	}
	for i, w := range writers {
		select {
		case m := <-w.ch:
			t.Fatalf("client %d answered (%s) before its update was applied", i, dns.RcodeToString[m.Rcode])
		default:
		}
	}

	close(h.release)
	for i, w := range writers {
		select {
		case m := <-w.ch:
			if m.Rcode != dns.RcodeSuccess {
				t.Errorf("client %d: rcode %s, want NOERROR", i, dns.RcodeToString[m.Rcode])
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("client %d never answered", i)
		}
	}
}

// Past the limit an update is not handed over, and the client is told
// SERVFAIL at once.
func TestAnswerWhenAppliedIsBounded(t *testing.T) {
	prev := updatesAwaitingAnswer
	updatesAwaitingAnswer = make(chan struct{}, 1)
	t.Cleanup(func() { updatesAwaitingAnswer = prev })

	h := newHeldUpdater(t)
	first := &chanResponseWriter{ch: make(chan *dns.Msg, 1)}
	if err := answerWhenApplied(context.Background(), first, updateMsg("a.test."),
		UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: "a.test."}, h.q, dns.RcodeSuccess); err != nil {
		t.Fatalf("first: %v", err)
	}
	second := &chanResponseWriter{ch: make(chan *dns.Msg, 1)}
	if err := answerWhenApplied(context.Background(), second, updateMsg("b.test."),
		UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: "b.test."}, h.q, dns.RcodeSuccess); err != nil {
		t.Fatalf("second: %v", err)
	}

	select {
	case m := <-second.ch:
		if m.Rcode != dns.RcodeServerFailure {
			t.Errorf("over the limit: rcode %s, want SERVFAIL", dns.RcodeToString[m.Rcode])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the update over the limit was not answered at once")
	}
	select {
	case ur := <-h.got:
		if ur.ZoneName != "a.test." {
			t.Errorf("updater got %s, want only a.test.", ur.ZoneName)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first update never reached the updater")
	}
	select {
	case ur := <-h.got:
		t.Errorf("the update over the limit reached the updater: %s", ur.ZoneName)
	case <-time.After(200 * time.Millisecond):
	}

	// Once the first is answered its slot is free again.
	close(h.release)
	select {
	case <-first.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("the first update was never answered")
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(updatesAwaitingAnswer) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the slot was not released after the answer")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
