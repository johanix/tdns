/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"io"
	"log"
	"sync"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func setUnlessEntry(t *testing.T, ctx CacheContext, addr string) *CachedRRset {
	t.Helper()
	rr, err := dns.NewRR("ns.example. 3600 IN A " + addr)
	if err != nil {
		t.Fatal(err)
	}
	return &CachedRRset{Name: "ns.example.", RRtype: dns.TypeA, Context: ctx,
		RRset: &core.RRset{Name: "ns.example.", Class: dns.ClassINET, RRtype: dns.TypeA, RRs: []dns.RR{rr}}}
}

func setUnlessAddr(rc *RRsetCacheT) string {
	c := rc.Peek("ns.example.", dns.TypeA)
	if c == nil || c.RRset == nil || len(c.RRset.RRs) == 0 {
		return ""
	}
	return c.RRset.RRs[0].(*dns.A).A.String()
}

// SetUnless stores the entry when there is none, and otherwise only when keep
// says the stored one need not stay. keep sees the stored entry.
func TestSetUnless(t *testing.T) {
	keepAnswers := func(stored CachedRRset) bool { return stored.Context == ContextAnswer }

	t.Run("nothing stored", func(t *testing.T) {
		rc := NewRRsetCache(log.New(io.Discard, "", 0), false, false)
		called := false
		ok := rc.SetUnless("ns.example.", dns.TypeA, setUnlessEntry(t, ContextGlue, "192.0.2.9"),
			func(CachedRRset) bool { called = true; return true })
		if !ok || called || setUnlessAddr(rc) != "192.0.2.9" {
			t.Errorf("stored=%v keep called=%v addr=%q; want stored, keep not called, 192.0.2.9", ok, called, setUnlessAddr(rc))
		}
	})
	t.Run("an entry keep says must stay", func(t *testing.T) {
		rc := NewRRsetCache(log.New(io.Discard, "", 0), false, false)
		rc.Set("ns.example.", dns.TypeA, setUnlessEntry(t, ContextAnswer, "192.0.2.1"))
		if rc.SetUnless("ns.example.", dns.TypeA, setUnlessEntry(t, ContextGlue, "192.0.2.9"), keepAnswers) {
			t.Error("stored over an entry keep says must stay")
		}
		if got := setUnlessAddr(rc); got != "192.0.2.1" {
			t.Errorf("address %q, want the answer's 192.0.2.1", got)
		}
	})
	t.Run("an entry keep lets go", func(t *testing.T) {
		rc := NewRRsetCache(log.New(io.Discard, "", 0), false, false)
		rc.Set("ns.example.", dns.TypeA, setUnlessEntry(t, ContextGlue, "192.0.2.1"))
		if !rc.SetUnless("ns.example.", dns.TypeA, setUnlessEntry(t, ContextGlue, "192.0.2.9"), keepAnswers) {
			t.Error("not stored over an entry keep lets go")
		}
		if got := setUnlessAddr(rc); got != "192.0.2.9" {
			t.Errorf("address %q, want 192.0.2.9", got)
		}
	})
}

// The decision and the write are one step: an answer stored by one writer is
// never overwritten by glue that another writer stores with SetUnless, however
// the two interleave. Run with -race as well.
func TestSetUnlessDoesNotOverwriteAnAnswerStoredMeanwhile(t *testing.T) {
	keepAnswers := func(stored CachedRRset) bool { return stored.Context == ContextAnswer }
	for i := 0; i < 200; i++ {
		rc := NewRRsetCache(log.New(io.Discard, "", 0), false, false)
		rc.Set("ns.example.", dns.TypeA, setUnlessEntry(t, ContextGlue, "192.0.2.5"))
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			rc.Set("ns.example.", dns.TypeA, setUnlessEntry(t, ContextAnswer, "192.0.2.1"))
		}()
		go func() {
			defer wg.Done()
			rc.SetUnless("ns.example.", dns.TypeA, setUnlessEntry(t, ContextGlue, "192.0.2.9"), keepAnswers)
		}()
		wg.Wait()
		// Whichever ran first, the answer is what the cache ends with: glue
		// before it is overwritten by it, glue after it is refused.
		if got := setUnlessAddr(rc); got != "192.0.2.1" {
			t.Fatalf("round %d: address %q, want the answer's 192.0.2.1", i, got)
		}
	}
}
