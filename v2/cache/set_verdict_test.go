/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// SetVerdict stores a verdict on the entry it was reached for, without
// touching its expiry, and on no other: an entry that another query replaced
// while the verdict was being reached keeps its own.
func TestSetVerdictOnlyOnTheJudgedEntry(t *testing.T) {
	rrcache := negCache(t)
	denial := func() *CachedRRset {
		soa := soaFor(t, secZone)
		return &CachedRRset{Name: secWWW, RRtype: dns.TypeA, Rcode: uint8(dns.RcodeNameError), Context: ContextNXDOMAIN,
			State: ValidationStateIndeterminate, RRset: &core.RRset{Name: secZone, Class: dns.ClassINET, RRtype: dns.TypeSOA, RRs: []dns.RR{soa}}}
	}

	rrcache.Set(secWWW, dns.TypeA, denial())
	judged := rrcache.Get(secWWW, dns.TypeA)
	if !rrcache.SetVerdict(judged, ValidationStateSecure, 0, "") {
		t.Fatal("the entry judged is still cached, and the verdict was not stored")
	}
	if c := rrcache.Get(secWWW, dns.TypeA); c == nil || c.State != ValidationStateSecure || !c.Expiration.Equal(judged.Expiration) {
		t.Errorf("after the verdict: %+v, want Secure with the same expiry", c)
	}

	rrcache.Set(secWWW, dns.TypeA, denial())
	judged = rrcache.Get(secWWW, dns.TypeA)
	answer := &CachedRRset{Name: secWWW, RRtype: dns.TypeA, Context: ContextAnswer, State: ValidationStateIndeterminate,
		RRset: &core.RRset{Name: secWWW, Class: dns.ClassINET, RRtype: dns.TypeA, RRs: []dns.RR{rrFrom(t, secWWW+" 300 IN A 192.0.2.1")}}}
	rrcache.Set(secWWW, dns.TypeA, answer)
	if rrcache.SetVerdict(judged, ValidationStateSecure, 0, "") {
		t.Error("the entry was replaced, and the verdict was stored anyway")
	}
	if c := rrcache.Get(secWWW, dns.TypeA); c == nil || c.Context != ContextAnswer || c.State != ValidationStateIndeterminate {
		t.Errorf("the replacing entry: %+v, want it as it was set (an answer, Indeterminate)", c)
	}
}
