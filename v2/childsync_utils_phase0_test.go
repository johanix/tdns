package tdns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestSendUpdateForcesTCP asserts D-2a: delegation-sync UPDATEs go over TCP
// regardless of size. The responder listens on TCP only; a small UPDATE
// (which the removed size gate would have sent over UDP) still reaches it and
// gets NOERROR, proving TCP was forced.
func TestSendUpdateForcesTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	var gotTCP int32
	srv := &dns.Server{
		Listener: ln,
		Net:      "tcp",
		// The default MsgAcceptFunc rejects the UPDATE opcode as NOTIMP
		// before the handler runs; use tdns's own accept func (the one the
		// real server installs) so UPDATE messages reach the handler.
		MsgAcceptFunc: MsgAcceptFunc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			atomic.AddInt32(&gotTCP, 1)
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeSuccess
			_ = w.WriteMsg(m)
		}),
	}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	// dns.Server.Shutdown takes no context; wrap it in a watchdog so a shutdown
	// blocked on a lingering test connection fails the test instead of hanging it.
	defer func() {
		done := make(chan struct{})
		go func() {
			_ = srv.Shutdown()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("srv.Shutdown() timed out after 5s")
		}
	}()
	<-started

	// A small UPDATE — well under the 1232-byte UDP "safe" limit, so the old
	// size-gated path would have chosen UDP for it.
	m := new(dns.Msg)
	m.SetUpdate("child.example.")
	rr, err := dns.NewRR("child.example. 3600 IN NS ns1.child.example.")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	m.Insert([]dns.RR{rr})
	if m.Len() >= 1232 {
		t.Fatalf("test message unexpectedly large (%d bytes); it must be small to prove TCP is forced", m.Len())
	}

	rcode, _, err := SendUpdate(context.Background(), m, "child.example.", []string{ln.Addr().String()})
	if err != nil {
		t.Fatalf("SendUpdate: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[rcode])
	}
	if atomic.LoadInt32(&gotTCP) == 0 {
		t.Error("responder received no TCP query — the UPDATE was not delivered over TCP")
	}
}

// A cancelled context must abandon an UPDATE already on the wire, not wait out
// the client timeout. The sync plan could stop between candidates before this;
// what it could not do was stop during one, which is the half of a shutdown
// that actually takes time.
func TestSendUpdateHonoursCancellation(t *testing.T) {
	// A listener that accepts and then never answers, so the exchange is
	// pending for as long as it is allowed to be.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	m := new(dns.Msg)
	m.SetUpdate("child.example.")

	t.Run("already cancelled: returns without dialling", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		_, _, err := SendUpdate(ctx, m, "child.example.", []string{ln.Addr().String()})
		if err == nil {
			t.Fatal("a cancelled SendUpdate returned no error")
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("took %v to notice an already-cancelled context", took)
		}
	})

	t.Run("cancelled mid-flight: returns promptly", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _, _ = SendUpdate(ctx, m, "child.example.", []string{ln.Addr().String()})
		}()

		time.Sleep(150 * time.Millisecond) // let the exchange get under way
		cancel()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("SendUpdate did not return within 5s of cancellation;" +
				" a shutdown would wait out the client timeout instead")
		}
	})
}
