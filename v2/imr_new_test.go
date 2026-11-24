/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// restoreProcessWideTuning puts back what NewImr sets for the whole process.
func restoreProcessWideTuning(t *testing.T) {
	t.Helper()
	policy, limits := cache.GetBackoffPolicy(), cache.GetTTLLimits()
	t.Cleanup(func() {
		cache.SetBackoffPolicy(policy)
		cache.SetTTLLimits(limits)
	})
}

// goroutinesIn counts the goroutines that have fn on their stack.
func goroutinesIn(fn string) int {
	var b strings.Builder
	_ = pprof.Lookup("goroutine").WriteTo(&b, 2)
	return strings.Count(b.String(), fn)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// An application builds a resolver from the imrengine: configuration alone. No
// Config, nothing published, no listeners; Start runs what keeps it going and
// ends with its context.
func TestNewImrFromImrEngineConfAlone(t *testing.T) {
	restoreProcessWideTuning(t)
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	published := Globals.ImrEngine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	imr, err := NewImr(ctx, ImrEngineConf{Forward: rootForward(addr, port)}, ImrOptions{Quiet: true})
	if err != nil {
		t.Fatalf("NewImr: %v", err)
	}
	if Globals.ImrEngine != published {
		t.Error("NewImr published the Imr in Globals.ImrEngine")
	}

	refreshing, listening := goroutinesIn("(*Imr).refreshRootLoop("), goroutinesIn("StartImrEngineListeners(")
	imr.Start(ctx)
	waitUntil(t, "Start to run the root refresh", func() bool { return goroutinesIn("(*Imr).refreshRootLoop(") > refreshing })

	resp, err := imr.ImrQuery(ctx, "www.fwd.example.", dns.TypeA, dns.ClassINET, nil)
	if err != nil || resp == nil || resp.RRset == nil || len(resp.RRset.RRs) != 1 {
		t.Fatalf("www.fwd.example. A: %+v (err %v), want the upstream's answer", resp, err)
	}
	if a, ok := resp.RRset.RRs[0].(*dns.A); !ok || a.A.String() != "192.0.2.77" {
		t.Errorf("www.fwd.example. A = %v, want 192.0.2.77", resp.RRset.RRs[0])
	}
	if got := goroutinesIn("StartImrEngineListeners("); got != listening {
		t.Error("Start started listeners")
	}

	cancel()
	waitUntil(t, "Start's goroutines to end with its context", func() bool { return goroutinesIn("(*Imr).refreshRootLoop(") <= refreshing })
}

// A priming that fails is NewImr's error, and it has published nothing.
func TestNewImrReturnsThePrimingError(t *testing.T) {
	restoreProcessWideTuning(t)
	published := Globals.ImrEngine
	ic := ImrEngineConf{RootHints: filepath.Join(t.TempDir(), "no-such-hints")}
	if imr, err := NewImr(context.Background(), ic, ImrOptions{Quiet: true}); err == nil || imr != nil {
		t.Fatalf("NewImr with no root hints to read: %v, %v; want no Imr and an error", imr, err)
	}
	if Globals.ImrEngine != published {
		t.Error("a failed NewImr published an Imr")
	}
}
