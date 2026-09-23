/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #694: when this server changes a child's delegation in its own zone, its own
// resolver must stop validating the child against what it cached before: the
// denial of a DS that now exists, the keys from before a roll, the zone state.
func TestChangedDelegationDropsTheResolversView(t *testing.T) {
	const parent, child, other = "parent.example.", "kid.parent.example.", "other.parent.example."
	rrcache := cache.NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)
	saved := Globals.ImrEngine
	Globals.ImrEngine = &Imr{Cache: rrcache}
	defer func() { Globals.ImrEngine = saved }()

	soa := &core.RRset{Name: parent, Class: dns.ClassINET, RRtype: dns.TypeSOA,
		RRs: []dns.RR{mustRR(t, parent+" 900 IN SOA ns."+parent+" h."+parent+" 1 1800 900 604800 900")}}
	for _, name := range []string{child, other} {
		// The pre-DS denial, cached the way handleNegative caches it.
		rrcache.Set(name, dns.TypeDS, &cache.CachedRRset{Name: name, RRtype: dns.TypeDS, RRset: soa,
			Context: cache.ContextNoErrNoAns, State: cache.ValidationStateSecure, Expiration: time.Now().Add(15 * time.Minute)})
		rrcache.Set(name, dns.TypeDNSKEY, &cache.CachedRRset{Name: name, RRtype: dns.TypeDNSKEY, Context: cache.ContextAnswer,
			RRset: &core.RRset{Name: name, Class: dns.ClassINET, RRtype: dns.TypeDNSKEY,
				RRs: []dns.RR{mustRR(t, name+" 3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")}}})
		rrcache.ZoneMap.Set(name, &cache.Zone{ZoneName: name, State: cache.ValidationStateIndeterminate})
	}

	// The parent adds the child's DS, and changes its own apex NS in the same update.
	invalidateImrDelegations(parent, []dns.RR{
		mustRR(t, child+" 3600 IN DS 12345 15 2 8BE06F4F1E2DE81BD1A9D0A29C7C79C3E43D83C1C1A6E1E6CA0A77F6CD8D0B0E"),
		mustRR(t, parent+" 3600 IN NS ns2."+parent),
	})

	if rrcache.Get(child, dns.TypeDS) != nil {
		t.Error("the child's pre-DS denial is still cached after its DS was added")
	}
	if rrcache.Get(child, dns.TypeDNSKEY) != nil {
		t.Error("the child's old DNSKEY RRset is still cached after its delegation changed")
	}
	if _, ok := rrcache.ZoneMap.Get(child); ok {
		t.Error("the child's zone state is still held after its delegation changed")
	}
	// Nothing else is touched: not a sibling, not the parent itself.
	if rrcache.Get(other, dns.TypeDS) == nil || rrcache.Get(other, dns.TypeDNSKEY) == nil {
		t.Error("a sibling's cache entries went with the changed child's")
	}
}
