/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func primingErrorIn(errs *ServerErrorRegistry) string {
	for _, e := range errs.List() {
		if e.Category == ErrCatUpstream && e.Subtype == ErrSubImrPriming {
			return e.Message
		}
	}
	return ""
}

// While the root cannot be primed, the daemon's resolver is not announced and
// has no listeners, and `config status` says why. Start keeps retrying; here
// the root hints cannot be read, which no retry fixes, and shutdown ends it.
func TestImrIsAnnouncedOnlyOncePrimed(t *testing.T) {
	restoreProcessWideTuning(t)
	prevGlobal := Globals.ImrEngine
	t.Cleanup(func() { Globals.ImrEngine = prevGlobal })

	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	conf.Internal.ImrReady = NewImrReadiness()
	ic := ImrEngineConf{RootHints: filepath.Join(t.TempDir(), "no-such-hints")}
	imr, err := NewImr(context.Background(), ic, ImrOptions{Errors: conf.Internal.ServerErrors})
	if err != nil {
		t.Fatalf("NewImr sends nothing, and failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	listened := make(chan struct{})
	ready := make(chan bool, 1)
	go func() { ready <- conf.startImr(ctx, imr, func(context.Context) { close(listened) }) }()

	waitUntil(t, "the failed priming to show in config status", func() bool {
		return primingErrorIn(conf.Internal.ServerErrors) != ""
	})
	if msg := primingErrorIn(conf.Internal.ServerErrors); !strings.Contains(msg, "no-such-hints") {
		t.Errorf("config status says %q; want the priming error", msg)
	}
	if conf.Internal.ImrReady.Published() {
		t.Error("the resolver was announced before the root was primed")
	}
	select {
	case <-listened:
		t.Error("the listeners started before the root was primed")
	default:
	}

	cancel()
	if <-ready {
		t.Error("startImr reported the resolver Ready")
	}
}
