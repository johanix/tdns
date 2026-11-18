/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"
)

// Resolvers for tdns's own tests, built as an application builds one: NewImr
// from an imrengine: block and ImrOptions. The resolver's own tests build
// theirs field by field; a root test can set only what the module exports.

// newForwardTestImrWith builds a resolver from ic and opts, quiet. It primes as
// NewImr does: not at all when the root is forwarded.
func newForwardTestImrWith(t *testing.T, ic ImrEngineConf, opts ImrOptions) *Imr {
	t.Helper()
	restoreProcessWideTuning(t)
	opts.Quiet = true
	imr, err := NewImr(context.Background(), ic, opts)
	if err != nil {
		t.Fatalf("NewImr: %v", err)
	}
	return imr
}

// newForwardTestImr is a resolver whose forward table is conf. Without a
// forward for the root it is seeded from the compiled-in hints, and asks the
// roots nothing.
func newForwardTestImr(t *testing.T, conf []ImrForwardConf) *Imr {
	t.Helper()
	ic := ImrEngineConf{Forward: conf}
	ic.Testing.Priming = noPriming()
	return newForwardTestImrWith(t, ic, ImrOptions{})
}

func noPriming() *bool {
	off := false
	return &off
}
