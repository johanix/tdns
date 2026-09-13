/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func primingErrorIn(conf *Config) string {
	for _, e := range conf.Internal.ServerErrors.List() {
		if e.Category == ErrCatUpstream && e.Subtype == ErrSubImrPriming {
			return e.Message
		}
	}
	return ""
}

func imrOutboundHookCount() int {
	globalImrOutboundQueryHooksMutex.RLock()
	defer globalImrOutboundQueryHooksMutex.RUnlock()
	return len(globalImrOutboundQueryHooks)
}

// A failed start is retried, the operator can see the failure while it lasts,
// and the DEGRADED entry goes away once the resolver is up.
func TestImrInitIsRetriedUntilItSucceeds(t *testing.T) {
	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()

	calls := 0
	var whileFailing string
	init := func() error {
		calls++
		if calls == 2 {
			whileFailing = primingErrorIn(conf)
		}
		if calls < 3 {
			return errors.New("priming: i/o timeout")
		}
		return nil
	}
	if err := conf.initImrEngineRetrying(context.Background(), init, func(int) time.Duration { return time.Millisecond }); err != nil {
		t.Fatalf("got %v, want success at the third attempt", err)
	}
	if calls != 3 {
		t.Errorf("init ran %d times, want 3", calls)
	}
	if !strings.Contains(whileFailing, "i/o timeout") {
		t.Errorf("while failing, config status said %q; want the priming error", whileFailing)
	}
	if msg := primingErrorIn(conf); msg != "" {
		t.Errorf("after success the priming error is still registered: %q", msg)
	}
}

// Shutdown ends the retry, and leaves the failure visible.
func TestImrInitRetryStopsWithTheContext(t *testing.T) {
	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	ctx, cancel := context.WithCancel(context.Background())

	calls := 0
	init := func() error {
		calls++
		cancel()
		return errors.New("root servers unreachable")
	}
	err := conf.initImrEngineRetrying(ctx, init, func(int) time.Duration { return time.Hour })
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("got %v, want the last init error", err)
	}
	if calls != 1 {
		t.Errorf("init ran %d times after cancellation, want 1", calls)
	}
	if primingErrorIn(conf) == "" {
		t.Error("gave up without the failure registered")
	}
}

func TestImrInitRetryDelay(t *testing.T) {
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second,
		80 * time.Second, 2 * time.Minute, 2 * time.Minute}
	for attempt, w := range want {
		if got := imrInitRetryDelay(attempt); got != w {
			t.Errorf("attempt %d: %v, want %v", attempt, got, w)
		}
	}
	if got := imrInitRetryDelay(1000); got != 2*time.Minute {
		t.Errorf("attempt 1000: %v, want the two-minute cap", got)
	}
}

// The retry runs InitImrEngine again after it failed, so that has to work: the
// second run builds the engine, and does not register a second set of debug
// hooks (which would log every query once per failed start).
func TestInitImrEngineRunsAgainAfterAFailedPriming(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	savedImr := Globals.ImrEngine
	defer func() { Globals.ImrEngine = savedImr }()

	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	conf.Imr.Logging.Enabled = true
	conf.Imr.Logging.File = filepath.Join(t.TempDir(), "imr-debug.log")
	conf.Imr.RootHints = filepath.Join(t.TempDir(), "no-such-hints")

	hooksBefore := imrOutboundHookCount()
	if err := conf.InitImrEngine(context.Background(), true); err == nil {
		t.Fatal("InitImrEngine succeeded with no root hints to read")
	}
	if conf.Internal.ImrEngine != nil {
		t.Fatal("a failed InitImrEngine published an engine")
	}

	// What changes between attempts in production is the network. Here it is
	// the config: the root is now forwarded to an upstream that answers.
	conf.Imr.RootHints = ""
	conf.Imr.Forward = []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}}
	if err := conf.InitImrEngine(context.Background(), true); err != nil {
		t.Fatalf("second InitImrEngine: %v", err)
	}
	if conf.Internal.ImrEngine == nil {
		t.Fatal("no engine after the second InitImrEngine")
	}
	if got := imrOutboundHookCount() - hooksBefore; got > 1 {
		t.Errorf("%d debug hooks registered over two starts, want at most one", got)
	}
}
