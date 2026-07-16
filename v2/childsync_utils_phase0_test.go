package tdns

import (
	"net"
	"sync/atomic"
	"testing"

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
	defer srv.Shutdown()
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

	rcode, _, err := SendUpdate(m, "child.example.", []string{ln.Addr().String()})
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
