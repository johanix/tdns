/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"strings"
	"testing"
)

// A resolver built with a logger logs through it, the engine and the cache
// both, and through neither of the process-wide loggers.
func TestTheResolverLogsThroughItsOwnLogger(t *testing.T) {
	restoreProcessWideTuning(t)
	var global bytes.Buffer
	prevSlog, prevLog := slog.Default(), log.Writer()
	slog.SetDefault(slog.New(slog.NewTextHandler(&global, nil)))
	log.SetOutput(&global)
	t.Cleanup(func() { slog.SetDefault(prevSlog); log.SetOutput(prevLog) })

	var own bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&own, nil))
	ic := Config{}
	off := false
	ic.Testing.Priming = &off // seeds from the hints, which the cache logs
	if _, err := NewImr(context.Background(), ic, Options{Logger: lg}); err != nil {
		t.Fatalf("NewImr: %v", err)
	}

	logged := own.String()
	for _, want := range []string{
		"imrengine.testing.priming is false",               // the engine
		"no root-hints config provided, using compiled-in", // the cache
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("the resolver's logger did not get %q:\n%s", want, logged)
		}
	}
	if global.Len() != 0 {
		t.Errorf("the process-wide loggers got:\n%s", global.String())
	}
}
