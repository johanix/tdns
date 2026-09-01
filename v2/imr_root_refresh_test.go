/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// rootNSCache builds a cache holding a root NS RRset with the given TTL.
//
// TTL, not an Expiration: RRsetCacheT.Set always recomputes Expiration from the
// RRset's minimum TTL, so setting the field directly is silently ignored.
func rootNSCache(t *testing.T, ttl uint32) *cache.RRsetCacheT {
	t.Helper()
	c := cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	rr := &dns.NS{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
		Ns:  "a.root.",
	}
	c.Set(".", dns.TypeNS, &cache.CachedRRset{
		Name:   ".",
		RRtype: dns.TypeNS,
		RRset:  &core.RRset{Name: ".", RRtype: dns.TypeNS, RRs: []dns.RR{rr}},
	})
	return c
}

// The status must describe the cache NOW, not the boot-time priming event.
//
// "primed via hints+fetch at 08:00:28" stayed true for nearly three hours
// while the resolver could not resolve anything it had not already cached.
// That line is about the past; this one is about whether an iteration can be
// started at all.
func TestRootNSStatusReportsThePresent(t *testing.T) {
	t.Run("present, with its expiry", func(t *testing.T) {
		imr := &Imr{Cache: rootNSCache(t, 600)}

		present, expires, count := imr.RootNSStatus()
		if !present {
			t.Fatal("a live root NS was reported absent")
		}
		if count != 1 {
			t.Errorf("count = %d, want 1", count)
		}
		if left := time.Until(expires); left <= 0 || left > 600*time.Second {
			t.Errorf("expires in %s, want a positive value no more than the 600s TTL", left)
		}
	})

	// The failure state: the RRset has aged out. Nothing can start an
	// iteration, and the status has to say so rather than report the boot-time
	// priming and look healthy.
	t.Run("expired reads as absent", func(t *testing.T) {
		// TTL 0: Set stamps Expiration at time.Now(), so it is already in
		// the past by the time anything reads it.
		imr := &Imr{Cache: rootNSCache(t, 0)}

		if present, _, _ := imr.RootNSStatus(); present {
			t.Error("an expired root NS was reported present; that is exactly" +
				" the reassurance that hid this failure")
		}
	})

	t.Run("no cache at all", func(t *testing.T) {
		imr := &Imr{}
		if present, _, _ := imr.RootNSStatus(); present {
			t.Error("reported present with no cache")
		}
	})
}

// The refresher must wake up BEFORE expiry, not after: refreshing against the
// live roots is only possible while they are still there. Once the RRset is
// gone the only route left is the hints file, which is the cold-start path we
// are trying not to depend on.
func TestRefreshLeadIsBeforeExpiry(t *testing.T) {
	if rootRefreshLead <= 0 {
		t.Fatal("the lead must be positive, or the refresh runs after expiry")
	}
	if rootRefreshRetry >= rootRefreshLead {
		t.Errorf("retry (%s) >= lead (%s): a single failure would leave no"+
			" time for another attempt before the RRset expires",
			rootRefreshRetry, rootRefreshLead)
	}
}
