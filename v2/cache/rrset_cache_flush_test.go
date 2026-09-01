/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cache

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// keepStructural is what separates "flush common" from "flush all", and it
// reaches the cache from the CLI and now over the management API too. It had
// no test.
func TestFlushDomainKeepStructural(t *testing.T) {
	mk := func(t *testing.T) *RRsetCacheT {
		t.Helper()
		c := NewRRsetCache(log.New(io.Discard, "", 0), false, false)
		put := func(name string, rrtype uint16, rrs ...string) {
			t.Helper()
			set := &core.RRset{Name: name, RRtype: rrtype}
			for _, s := range rrs {
				rr, err := dns.NewRR(s)
				if err != nil {
					t.Fatalf("bad test record %q: %v", s, err)
				}
				set.RRs = append(set.RRs, rr)
			}
			c.Set(name, rrtype, &CachedRRset{
				Name: name, RRtype: rrtype, RRset: set,
				Expiration: time.Now().Add(time.Hour),
			})
		}

		// A delegation, its nameserver's address, and ordinary data below it.
		put("example.", dns.TypeNS, "example. 3600 IN NS ns1.example.")
		put("ns1.example.", dns.TypeA, "ns1.example. 3600 IN A 192.0.2.1")
		put("www.example.", dns.TypeA, "www.example. 300 IN A 192.0.2.9")
		put("mail.example.", dns.TypeMX, "mail.example. 300 IN MX 10 mx.example.")
		return c
	}

	t.Run("keepStructural=false removes everything below the domain", func(t *testing.T) {
		c := mk(t)
		removed, err := c.FlushDomain("example.", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if removed != 4 {
			t.Errorf("removed %d, want all 4", removed)
		}
		if c.Get("example.", dns.TypeNS) != nil {
			t.Error("the NS survived a full flush")
		}
	})

	t.Run("keepStructural=true keeps the delegation and its glue", func(t *testing.T) {
		c := mk(t)
		removed, err := c.FlushDomain("example.", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if c.Get("example.", dns.TypeNS) == nil {
			t.Error("the NS was flushed; that is what keepStructural exists to prevent")
		}
		if c.Get("ns1.example.", dns.TypeA) == nil {
			t.Error("the nameserver's address was flushed, so the kept NS is unusable")
		}
		if c.Get("www.example.", dns.TypeA) != nil {
			t.Error("ordinary data survived; nothing would have been flushed at all")
		}
		if c.Get("mail.example.", dns.TypeMX) != nil {
			t.Error("ordinary data survived")
		}
		if removed != 2 {
			t.Errorf("removed %d, want 2 (www and mail, not the NS or its glue)", removed)
		}
	})

	t.Run("the root is refused", func(t *testing.T) {
		c := mk(t)
		if _, err := c.FlushDomain(".", false); err == nil {
			t.Error("flushing the root must be refused")
		}
	})
}
