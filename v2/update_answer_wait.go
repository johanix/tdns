/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// The DNS handler hands an UPDATE to UpdateResponder over DnsUpdateQ and
// UpdateResponder answers it later, from its own goroutine or from the one
// answerWhenApplied starts, once the change has been applied, persisted and
// published (RFC 2136 §3.4.2.5). The handler used to return as soon as the
// UPDATE was queued. The transport takes that return as "this request is
// done":
//
//   - A miekg TCP or DoT server then waits for the next message with its idle
//     timeout (8 s by default) and closes the connection when it runs out. An
//     answer later than that went to a closed connection and was lost: the
//     client saw EOF. The apply-timeout SERVFAIL, written at
//     updateWaitBound (at least 10 s), could never reach a TCP client at all.
//   - DoH copies its buffer into the HTTP response, which held nothing yet.
//
// So the handler now waits until the answer has been written. Each TCP
// connection and each UDP packet has a goroutine of its own in the server, so
// the wait holds only this request's connection, and it does not hold
// UpdateHandler, which goes on to the next UPDATE at once.

// answerSignalWriter closes answered once the first answer has been written.
type answerSignalWriter struct {
	dns.ResponseWriter
	once     sync.Once
	answered chan struct{}
}

func newAnswerSignalWriter(w dns.ResponseWriter) *answerSignalWriter {
	return &answerSignalWriter{ResponseWriter: w, answered: make(chan struct{})}
}

func (w *answerSignalWriter) signal() { w.once.Do(func() { close(w.answered) }) }

// WriteMsg signals after the write has returned, so the connection is not
// released before the answer is on it.
func (w *answerSignalWriter) WriteMsg(m *dns.Msg) error {
	defer w.signal()
	return w.ResponseWriter.WriteMsg(m)
}

func (w *answerSignalWriter) Write(b []byte) (int, error) {
	defer w.signal()
	return w.ResponseWriter.Write(b)
}

// Unwrap exposes the wrapped writer so connectionState (downstream_auth.go)
// can reach the TLS ConnectionState through the wrapper chain.
func (w *answerSignalWriter) Unwrap() dns.ResponseWriter { return w.ResponseWriter }

// updateAnswerBackstop bounds the wait. Every path through UpdateResponder
// answers, and every wait inside it is bounded: the longest is a zone that
// syncs its own delegation, which may ask the parent first (parentFirstTimeout)
// and then wait for the apply (updateWaitBound). The backstop sits beyond both,
// so it only ever fires on a bug, and then the request is released rather
// than held for ever.
func updateAnswerBackstop(zone string) time.Duration {
	return parentFirstTimeout + updateWaitBound(zone) + 5*time.Second
}

// waitForUpdateAnswer returns once w has been answered, at shutdown, or at the
// backstop.
func waitForUpdateAnswer(ctx context.Context, w *answerSignalWriter, zone string) {
	bound := updateAnswerBackstop(zone)
	t := time.NewTimer(bound)
	defer t.Stop()
	select {
	case <-w.answered:
	case <-ctx.Done():
	case <-t.C:
		lgDns.Error("UPDATE still unanswered at the backstop; releasing the request",
			"zone", zone, "backstop", bound)
	}
}
