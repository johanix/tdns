/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"context"
	"sync"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A reload that adds a stub stores the stub's servers and then publishes the
// table that names it. A flush that ran in between asked the table whether the
// zone was a stub, got no, and deleted the servers the reload had just stored
// (CodeRabbit on #833). The stub then never took effect, and the next reload
// left it alone, its configuration unchanged. The zone starts each round with
// a server map learned from a referral, which the stub replaces, and a flush
// runs over and over for as long as the reload does. Once both are done, the
// servers in the cache must be the stub's.
func TestReloadAddingAStubRacesAFlush(t *testing.T) {
	imr := newReloadTestImr(t)
	imr.attachCacheHooks() // as start-up does
	rr := mustRR(t, stubFlushChild+" 3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")
	cacheSomething := func() {
		// Something to flush in the zone, so the flush drops server maps.
		imr.Cache.Set(stubFlushChild, dns.TypeDNSKEY, &cache.CachedRRset{Name: stubFlushChild, RRtype: dns.TypeDNSKEY,
			Context: cache.ContextAnswer, RRset: &core.RRset{Name: stubFlushChild, RRtype: dns.TypeDNSKEY, RRs: []dns.RR{rr}}})
	}
	stubNS := cache.ServerKey("ns." + stubFlushChild)
	for i := 0; i < 10000; i++ {
		learned := imr.Cache.GetOrCreateAuthServer("learned.example.")
		if err := imr.Cache.AddServers(stubFlushChild, map[string]*cache.AuthServer{"learned.example.": learned}); err != nil {
			t.Fatalf("AddServers: %v", err)
		}
		cacheSomething()

		stop, running := make(chan struct{}), make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; ; n++ {
				if n == 1 {
					close(running)
				}
				select {
				case <-stop:
					return
				default:
				}
				cacheSomething()
				if _, err := imr.Cache.FlushDomain(stubFlushParent, false); err != nil {
					t.Errorf("FlushDomain: %v", err)
					return
				}
			}
		}()
		<-running
		_, err := imr.ReloadZones([]ImrStubConf{stubConf(stubFlushChild, "ns."+stubFlushChild, "192.0.2.53")}, nil)
		close(stop)
		wg.Wait()
		if err != nil {
			t.Fatalf("ReloadZones: %v", err)
		}

		if m, ok := imr.Cache.ServerMap.Get(stubFlushChild); !ok || m[stubNS] == nil {
			t.Fatalf("round %d: a flush racing the reload that added the stub deleted the stub's servers", i)
		}
		// Remove the stub again for the next round.
		if _, err := imr.ReloadZones(nil, nil); err != nil {
			t.Fatalf("ReloadZones: %v", err)
		}
	}
}
