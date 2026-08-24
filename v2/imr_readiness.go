/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"sync"
)

// ImrReadiness publishes "the IMR is up" from the engine that builds it to the
// engines that need it.
//
// It exists for the memory model, not for convenience. conf.Internal.ImrEngine
// is written by the ImrEngine goroutine and read by others, and a plain read of
// that field from another goroutine is a data race: the Go memory model gives no
// guarantee that the write is ever observed, and -- worse for a pointer -- no
// guarantee that observing the pointer means observing the fully constructed Imr
// behind it. Waiting for a value to change by re-reading it in a loop is exactly
// the shape that has no guarantee at all.
//
// Closing a channel after the write fixes both. The write happens-before the
// close, the close happens-before any receive, so a reader that has received
// from Ready() is guaranteed to see a fully initialised Imr in the field.
//
// The contract is therefore: publish the pointer FIRST, then Publish() -- and
// read the field only after receiving from Ready().
type ImrReadiness struct {
	ch   chan struct{}
	once sync.Once
}

// NewImrReadiness returns an unpublished readiness signal.
func NewImrReadiness() *ImrReadiness {
	return &ImrReadiness{ch: make(chan struct{})}
}

// Publish announces that the IMR pointer has been stored. Idempotent, so a
// second InitImrEngine cannot panic on a double close. A nil receiver is a
// no-op: paths that build an IMR without the daemon's channel setup (the CLI,
// for one) have no waiters to notify.
func (r *ImrReadiness) Publish() {
	if r == nil {
		return
	}
	r.once.Do(func() { close(r.ch) })
}

// Ready returns a channel closed once the IMR is available.
//
// A nil receiver returns nil, and a receive from a nil channel blocks forever --
// which is the right answer for a process that never builds an IMR, provided
// every caller also selects on its context. Callers must.
func (r *ImrReadiness) Ready() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.ch
}

// Published reports whether the IMR has been announced, without blocking.
func (r *ImrReadiness) Published() bool {
	if r == nil {
		return false
	}
	select {
	case <-r.ch:
		return true
	default:
		return false
	}
}

// Wait blocks until the IMR is available or ctx is done, and reports which.
func (r *ImrReadiness) Wait(ctx context.Context) bool {
	select {
	case <-r.Ready():
		return true
	case <-ctx.Done():
		return false
	}
}
