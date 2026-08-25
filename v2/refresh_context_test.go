package tdns

import (
	"context"
	"errors"
	"io"
	"log"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Cancellation of the refresh/transfer chain.
//
// NOTE on what is and is not worth asserting here. Most of this change is
// signature plumbing whose effect is already covered by the standard library:
// dns.Client.ExchangeContext honours ctx by itself, so the SOA-probe path
// returns a context error with or without tdns's own checks, and a test cannot
// tell the two apart. The genuinely NEW behaviour is the envelope drain loop --
// dns.Transfer.In has no context-aware variant, so without an explicit select
// the daemon would keep parsing and sorting a large zone long after the engine
// asked it to stop. That is what these tests target.

func drainTestZone() *ZoneData {
	return &ZoneData{
		ZoneName:  "example.",
		ZoneType:  Secondary,
		ZoneStore: MapZone,
		Options:   map[ZoneOption]bool{},
		Data:      core.NewCmap[OwnerData](),
		Logger:    log.New(io.Discard, "", 0),
	}
}

// TestDrainStopsOnCancellation is the core of this change: a stream that never
// closes (an upstream that accepted the connection and then went quiet, or
// simply a very large zone) must not pin the drain loop once ctx is cancelled.
//
// The channel is deliberately never closed and never written to, so the ONLY
// way this test can finish is the ctx branch of the select.
func TestDrainStopsOnCancellation(t *testing.T) {
	zd := drainTestZone()
	answerChan := make(chan *dns.Envelope) // never written, never closed

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := zd.drainTransferEnvelopes(ctx, answerChan, "192.0.2.1:53", false)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("drain returned %v, want a wrapped context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not stop on a cancelled context: it would keep consuming the stream")
	}
}

// TestDrainStopsWhenCancelledMidStream covers the realistic shape: the transfer
// is under way and delivering envelopes when the engine is asked to shut down.
func TestDrainStopsWhenCancelledMidStream(t *testing.T) {
	zd := drainTestZone()
	answerChan := make(chan *dns.Envelope)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		rr, _ := dns.NewRR("example. 3600 IN TXT \"one\"")
		answerChan <- &dns.Envelope{RR: []dns.RR{rr}}
		cancel() // engine shuts down mid-stream
		// Keep the stream "open" but silent, as a real peer would be.
	}()

	done := make(chan error, 1)
	go func() {
		_, err := zd.drainTransferEnvelopes(ctx, answerChan, "192.0.2.1:53", false)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("drain returned %v, want a wrapped context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not stop after mid-stream cancellation")
	}
}

// TestDrainCompletesNormally guards the other direction: the ctx branch must not
// short-circuit an ordinary, uncancelled transfer.
func TestDrainCompletesNormally(t *testing.T) {
	zd := drainTestZone()
	answerChan := make(chan *dns.Envelope, 2)

	soa, _ := dns.NewRR("example. 3600 IN SOA ns.example. hm.example. 42 3600 600 86400 3600")
	txt, _ := dns.NewRR("example. 3600 IN TXT \"one\"")
	answerChan <- &dns.Envelope{RR: []dns.RR{soa, txt}}
	close(answerChan)

	count, err := zd.drainTransferEnvelopes(context.Background(), answerChan, "192.0.2.1:53", false)
	if err != nil {
		t.Fatalf("normal drain returned an error: %v", err)
	}
	if count != 2 {
		t.Errorf("counted %d RRs, want 2", count)
	}
}

// TestDrainPropagatesEnvelopeError keeps the pre-existing failure path intact:
// an error carried on an envelope must still surface, clarified.
func TestDrainPropagatesEnvelopeError(t *testing.T) {
	zd := drainTestZone()
	answerChan := make(chan *dns.Envelope, 1)
	answerChan <- &dns.Envelope{Error: errors.New("bad TSIG")}
	close(answerChan)

	_, err := zd.drainTransferEnvelopes(context.Background(), answerChan, "192.0.2.1:53", false)
	if err == nil {
		t.Fatal("an envelope error must surface")
	}
}
