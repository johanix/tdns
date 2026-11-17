/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// failingWriteRW stands in for a connection whose peer has hung up: every
// write is attempted and fails, as it does when the sender gave up first.
// attempts counts the writes, so a test can tell "the handler answered once"
// from "something answered again".
type failingWriteRW struct {
	fakeWriteRW
	attempts atomic.Int32
	err      error
}

func (f *failingWriteRW) WriteMsg(*dns.Msg) error {
	f.attempts.Add(1)
	return f.err
}

func (f *failingWriteRW) Write([]byte) (int, error) {
	f.attempts.Add(1)
	return 0, f.err
}

var errPeerGone = errors.New("write: broken pipe")

// claimTestRig builds the dispatcher with the given NOTIFY(CHUNK) handlers
// registered on the config, and a DnsNotifyQ the default responder would be
// reached through. send delivers one NOTIFY(CHUNK) to the dispatcher on w.
type claimTestRig struct {
	q    chan DnsNotifyRequest
	send func(w *failingWriteRW)
}

func newClaimTestRig(t *testing.T, handlers ...NotifyHandlerFunc) *claimTestRig {
	t.Helper()
	conf := &Config{}
	conf.Internal.DnsNotifyQ = make(chan DnsNotifyRequest, 4)
	conf.Internal.NotifyHandlers = map[uint16][]NotifyHandlerFunc{core.TypeCHUNK: handlers}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dispatch := createAuthDnsHandler(ctx, conf)

	return &claimTestRig{
		q: conf.Internal.DnsNotifyQ,
		send: func(w *failingWriteRW) {
			m := new(dns.Msg)
			m.SetNotify("chunk.example.test.")
			m.Question[0].Qtype = core.TypeCHUNK
			dispatch(w, m)
		},
	}
}

// reachedDefault reports whether the NOTIFY was queued for the default
// responder, and if it was, runs the responder on it as NotifyHandler does, so
// that what it would write to the connection is counted as well.
func (r *claimTestRig) reachedDefault(t *testing.T) bool {
	t.Helper()
	select {
	case dnr := <-r.q:
		if err := NotifyResponder(context.Background(), &dnr, nil, nil); err != nil {
			t.Errorf("NotifyResponder = %v", err)
		}
		return true
	default:
		return false
	}
}

// The case in #953: a handler has taken a NOTIFY, answers it, and the answer
// cannot be written because the sender has hung up. It returns that error.
// The message is the handler's: no further handler runs for it and the default
// responder does not answer it again ("unknown NOTIFY type", and a second
// failed write). Before the fix the dispatcher read any error that was not
// ErrNotHandled as "try the next one".
func TestNotifyHandlerThatFailedToWriteItsReplyDoesNotFallThrough(t *testing.T) {
	var first, second atomic.Int32
	rig := newClaimTestRig(t,
		func(_ context.Context, dnr *DnsNotifyRequest) error {
			first.Add(1)
			resp := new(dns.Msg)
			resp.SetReply(dnr.Msg)
			return dnr.ResponseWriter.WriteMsg(resp)
		},
		func(context.Context, *DnsNotifyRequest) error {
			second.Add(1)
			return ErrNotHandled
		},
	)
	w := &failingWriteRW{err: errPeerGone}
	rig.send(w)

	if got := first.Load(); got != 1 {
		t.Errorf("the handler that took the NOTIFY ran %d times, want 1", got)
	}
	if got := second.Load(); got != 0 {
		t.Errorf("the next handler ran %d times for a NOTIFY the first had answered, want 0", got)
	}
	if rig.reachedDefault(t) {
		t.Error("the NOTIFY reached the default responder after a handler had answered it")
	}
	if got := w.attempts.Load(); got != 1 {
		t.Errorf("%d write attempts, want exactly the handler's one", got)
	}
}

// The same holds when the reply went out and the handler then returns an
// error of its own: the sender has its answer, and a second one would be a
// duplicate on the wire.
func TestNotifyHandlerErrorAfterAnsweringDoesNotFallThrough(t *testing.T) {
	var second atomic.Int32
	rig := newClaimTestRig(t,
		func(_ context.Context, dnr *DnsNotifyRequest) error {
			resp := new(dns.Msg)
			resp.SetReply(dnr.Msg)
			_ = dnr.ResponseWriter.WriteMsg(resp)
			return errors.New("bookkeeping after the reply failed")
		},
		func(context.Context, *DnsNotifyRequest) error {
			second.Add(1)
			return ErrNotHandled
		},
	)
	w := &failingWriteRW{} // the write succeeds
	rig.send(w)

	if got := second.Load(); got != 0 {
		t.Errorf("the next handler ran %d times for a NOTIFY already answered, want 0", got)
	}
	if rig.reachedDefault(t) {
		t.Error("the NOTIFY reached the default responder after a handler had answered it")
	}
	if got := w.attempts.Load(); got != 1 {
		t.Errorf("%d write attempts, want 1", got)
	}
}

// Control: a handler that fails BEFORE it has written anything has not
// answered, so the documented fall-through stays. The next handler gets the
// message, and when none takes it the default responder does and the sender
// is not left without a reply.
func TestNotifyHandlerErrorBeforeAnsweringStillFallsThrough(t *testing.T) {
	var second atomic.Int32
	rig := newClaimTestRig(t,
		func(context.Context, *DnsNotifyRequest) error {
			return errors.New("router not configured")
		},
		func(_ context.Context, dnr *DnsNotifyRequest) error {
			second.Add(1)
			return ErrNotHandled
		},
	)
	rig.send(&failingWriteRW{err: errPeerGone})

	if got := second.Load(); got != 1 {
		t.Errorf("the next handler ran %d times after a handler failed without answering, want 1", got)
	}
	if !rig.reachedDefault(t) {
		t.Error("no handler answered, but the NOTIFY did not reach the default responder")
	}
}

// Control: success and ErrNotHandled behave as before. A nil return ends the
// dispatch with nothing queued for the default responder.
func TestNotifyHandlerSuccessEndsTheDispatch(t *testing.T) {
	var second atomic.Int32
	rig := newClaimTestRig(t,
		func(_ context.Context, dnr *DnsNotifyRequest) error {
			resp := new(dns.Msg)
			resp.SetReply(dnr.Msg)
			return dnr.ResponseWriter.WriteMsg(resp)
		},
		func(context.Context, *DnsNotifyRequest) error {
			second.Add(1)
			return nil
		},
	)
	w := &failingWriteRW{} // the write succeeds
	rig.send(w)

	if got := second.Load(); got != 0 {
		t.Errorf("the next handler ran %d times after a handler succeeded, want 0", got)
	}
	if rig.reachedDefault(t) {
		t.Error("a handled NOTIFY reached the default responder")
	}
	if got := w.attempts.Load(); got != 1 {
		t.Errorf("%d write attempts, want 1", got)
	}
}

// What a handler sees as its ResponseWriter is still the connection's
// writer: the tdns helpers that look through wrappers (requestWire,
// connectionState) reach the writer underneath.
func TestNotifyHandlerSeesThroughTheTrackingWriter(t *testing.T) {
	conf := &Config{}
	conf.Internal.DnsNotifyQ = make(chan DnsNotifyRequest, 1)
	var ran bool
	conf.Internal.NotifyHandlers = map[uint16][]NotifyHandlerFunc{
		core.TypeCHUNK: {func(_ context.Context, dnr *DnsNotifyRequest) error {
			ran = true
			if got := requestWire(dnr.ResponseWriter); string(got) != "wire" {
				t.Errorf("requestWire through the handler's writer = %q, want %q", got, "wire")
			}
			return nil
		}},
	}
	m := new(dns.Msg)
	m.SetNotify("chunk.example.test.")
	m.Question[0].Qtype = core.TypeCHUNK
	createAuthDnsHandler(context.Background(), conf)(&rawRequestRW{}, m)

	if !ran {
		t.Fatal("the handler did not run")
	}
}

// rawRequestRW is a connection writer that kept the request bytes, as the Do53
// server does for a request ending in a SIG RR.
type rawRequestRW struct{ fakeWriteRW }

func (*rawRequestRW) RawRequest() []byte { return []byte("wire") }

// The paths that answer from a channel do not fall through anywhere, so a
// failed write there ends the message. Pinned so that a change to the
// dispatcher is not read as having to touch them.

// NotifyResponder logs the failed write and returns; it answers once.
func TestNotifyResponderFailedWriteEndsQuietly(t *testing.T) {
	w := &failingWriteRW{err: errPeerGone}
	m := new(dns.Msg)
	m.SetNotify("chunk.example.test.")
	m.Question[0].Qtype = core.TypeCHUNK // not a type the responder serves: it refuses
	dnr := &DnsNotifyRequest{ResponseWriter: w, Msg: m, Qname: m.Question[0].Name}

	if err := NotifyResponder(context.Background(), dnr, nil, nil); err != nil {
		t.Errorf("NotifyResponder = %v, want nil", err)
	}
	if got := w.attempts.Load(); got != 1 {
		t.Errorf("%d write attempts, want 1", got)
	}
}

// NotifyHandlerWithCallback hands the message to the callback and takes the
// next one; the default responder is not involved.
func TestNotifyHandlerWithCallbackFailedWriteEndsQuietly(t *testing.T) {
	conf := &Config{}
	conf.Internal.DnsNotifyQ = make(chan DnsNotifyRequest, 1)

	called := make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = NotifyHandlerWithCallback(ctx, conf, func(_ context.Context, dnr *DnsNotifyRequest) error {
			resp := new(dns.Msg)
			resp.SetReply(dnr.Msg)
			err := dnr.ResponseWriter.WriteMsg(resp)
			called <- struct{}{}
			return err
		})
	}()

	w := &failingWriteRW{err: errPeerGone}
	m := new(dns.Msg)
	m.SetNotify("chunk.example.test.")
	m.Question[0].Qtype = core.TypeCHUNK
	conf.Internal.DnsNotifyQ <- DnsNotifyRequest{ResponseWriter: w, Msg: m, Qname: m.Question[0].Name}

	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("the callback was not called")
	}
	cancel()
	<-done

	if len(called) != 0 {
		t.Errorf("the callback ran more than once for one NOTIFY")
	}
	if got := w.attempts.Load(); got != 1 {
		t.Errorf("%d write attempts, want the callback's one", got)
	}
}
