package tdns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// lateResponder stands in for UpdateHandler: it takes each queued UPDATE and
// answers it NOERROR after delay; a negative delay never answers.
func lateResponder(t *testing.T, q chan DnsUpdateRequest, delay time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			select {
			case dur := <-q:
				if delay < 0 {
					continue
				}
				go func(dur DnsUpdateRequest) {
					time.Sleep(delay)
					m := new(dns.Msg)
					m.SetReply(dur.Msg)
					_ = dur.ResponseWriter.WriteMsg(m)
				}(dur)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// An UPDATE over TCP whose answer comes later than the server's idle timeout
// still gets its answer, TSIG-signed. The server is built as do53.go builds
// its TCP servers (keystore provider, tdns's MsgAcceptFunc, TsigSigningHandler
// around the real dispatch), except for a short IdleTimeout so that the test
// does not have to wait out miekg's default 8 s. Before the fix the handler
// returned once the UPDATE was queued, the server closed the idle connection,
// and the client got EOF.
func TestUpdateOverTCPAnsweredAfterIdleTimeout(t *testing.T) {
	conf := tsigTestConf(t)
	q := make(chan DnsUpdateRequest, 4)
	conf.Internal.DnsUpdateQ = q
	const idle = 300 * time.Millisecond
	const delay = 1500 * time.Millisecond // well past idle
	lateResponder(t, q, delay)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	started := make(chan struct{})
	srv := &dns.Server{
		Listener:          l,
		Net:               "tcp",
		TsigProvider:      conf.tsigProvider(),
		MsgAcceptFunc:     MsgAcceptFunc,
		IdleTimeout:       func() time.Duration { return idle },
		Handler:           dns.HandlerFunc(TsigSigningHandler(udpTruncate(createAuthDnsHandler(ctx, conf)))),
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	<-started

	upd := new(dns.Msg)
	upd.SetUpdate("example.test.")
	rr, _ := dns.NewRR("h1.example.test. 60 IN A 192.0.2.1")
	upd.RemoveRRset([]dns.RR{rr})
	upd.Insert([]dns.RR{rr})
	upd.SetTsig("tkey.", dns.HmacSHA256, 300, time.Now().Unix())

	c := &dns.Client{Net: "tcp", TsigProvider: conf.tsigProvider(), Timeout: 10 * time.Second}
	start := time.Now()
	resp, _, err := c.Exchange(upd, l.Addr().String())
	took := time.Since(start)
	if err != nil {
		t.Fatalf("after %v: %v (an answer later than the %v idle timeout was lost)", took.Round(10*time.Millisecond), err, idle)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if resp.IsTsig() == nil {
		t.Error("the late answer is not TSIG-signed")
	}
	if took < delay {
		t.Errorf("answered after %v, before the responder's %v: not the late answer", took, delay)
	}
}

// The wait ends at shutdown even if the UPDATE is never answered, so a
// stopping server does not keep the request held.
func TestUpdateHandlerReleasedAtShutdown(t *testing.T) {
	conf := tsigTestConf(t)
	q := make(chan DnsUpdateRequest, 4)
	conf.Internal.DnsUpdateQ = q
	lateResponder(t, q, -1) // never answers

	ctx, cancel := context.WithCancel(context.Background())
	handler := createAuthDnsHandler(ctx, conf)
	upd := new(dns.Msg)
	upd.SetUpdate("example.test.")

	returned := make(chan struct{})
	go func() {
		handler(&fakeWriteRW{}, upd)
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("the handler returned before the UPDATE was answered")
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("the handler is still waiting after shutdown")
	}
}

// The writer signals after the write, once, whichever write method answers.
func TestAnswerSignalWriter(t *testing.T) {
	for _, viaMsg := range []bool{true, false} {
		w := newAnswerSignalWriter(&fakeWriteRW{})
		select {
		case <-w.answered:
			t.Fatal("signalled before any answer")
		default:
		}
		m := new(dns.Msg)
		m.SetQuestion("example.test.", dns.TypeSOA)
		if viaMsg {
			_ = w.WriteMsg(m)
			_ = w.WriteMsg(m) // a second write must not panic on a closed channel
		} else {
			b, _ := m.Pack()
			_, _ = w.Write(b)
			_, _ = w.Write(b)
		}
		select {
		case <-w.answered:
		default:
			t.Errorf("viaMsg=%v: not signalled after the answer", viaMsg)
		}
	}
}

// The backstop covers the hand-over too. With the queue full for the whole
// backstop, the UPDATE was never handed over and nobody else will answer it,
// so the handler answers SERVFAIL itself and returns, instead of holding the
// connection until queue space appears.
func TestUpdateQueueFullAnsweredAtBackstop(t *testing.T) {
	prev := updateAnswerBackstop
	updateAnswerBackstop = func(string) time.Duration { return 200 * time.Millisecond }
	t.Cleanup(func() { updateAnswerBackstop = prev })

	conf := tsigTestConf(t)
	conf.Internal.DnsUpdateQ = make(chan DnsUpdateRequest) // nobody reads: always full
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := createAuthDnsHandler(ctx, conf)

	upd := new(dns.Msg)
	upd.SetUpdate("example.test.")
	cw := &captureWriter{}
	returned := make(chan struct{})
	go func() {
		handler(cw, upd)
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler is still blocked on a full queue past the backstop")
	}
	if cw.got == nil {
		t.Fatal("no answer: an UPDATE that was never queued must be answered by the handler")
	}
	if cw.got.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", dns.RcodeToString[cw.got.Rcode])
	}
	if found, code, _ := edns0.ExtractEDEFromMsg(cw.got); !found || code != edns0.EDEZoneUpdateNotApplied {
		t.Errorf("EDE = %d (found %v), want EDEZoneUpdateNotApplied", code, found)
	}
}
