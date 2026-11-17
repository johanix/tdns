/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"strings"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// A zone with a DNSKEY trust anchor is validated with the anchor's keys, and
// its DS is not asked for. The resolver used to look up the DS first and fetch
// it when it was not cached: a question to the parent side that the anchor
// makes unnecessary. Deckard's val_nsec3_* scenarios anchor example. with a
// DNSKEY and script no answer to it, so they failed on an unscripted query.
//
// An anchor that validates no key still leaves the zone to its DS: the data
// is SERVFAIL, as before.
func TestADNSKEYTrustAnchorNeedsNoDS(t *testing.T) {
	const www = "www." + fwdSecParent
	for _, c := range []struct {
		name    string
		anchor  func(ksk *fwdSecKey) *dns.DNSKEY
		outcome string
		askDS   bool
	}{
		{"the anchor's key signs the DNSKEY RRset",
			func(ksk *fwdSecKey) *dns.DNSKEY { return ksk.dnskey }, outcomeSecure, false},
		{"the anchor matches no key",
			func(*fwdSecKey) *dns.DNSKEY { return newFwdSecKey(t, fwdSecParent).dnskey }, outcomeServfail, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The anchor signs the DNSKEY RRset, another key the data, so the
			// data's key has to come from a DNSKEY RRset the anchor validates.
			ksk, zsk := newFwdSecKey(t, fwdSecParent), newFwdSecKey(t, fwdSecParent)
			logr := &upstreamLog{}
			addr, port := startLoggedSignedForwardUpstream(t, map[string]*dns.Msg{
				www + " A":               {Answer: zsk.sign(t, fwdSecRR(t, www+" 300 IN A 192.0.2.7"))},
				fwdSecParent + " DNSKEY": {Answer: ksk.sign(t, dns.Copy(ksk.dnskey), dns.Copy(zsk.dnskey))},
			}, logr)

			imr := newForwardTestImr(t, []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}})
			imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
			imr.DnskeyCache = imr.Cache.DnskeyCache
			if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
				t.Fatalf("PrimeFromHintsOnly: %v", err)
			}
			imr.addDirectDNSKEYTrustAnchors(map[string][]*dns.DNSKEY{fwdSecParent: {c.anchor(ksk)}})

			for i := 1; i <= 2; i++ {
				if got := outcome(t, imr, www, dns.TypeA); got != c.outcome {
					t.Fatalf("question %d: %s, want %s", i, got, c.outcome)
				}
			}
			var asked bool
			logr.mu.Lock()
			for _, q := range logr.queries {
				if q.Qtype == dns.TypeDS && strings.EqualFold(q.Qname, fwdSecParent) {
					asked = true
				}
			}
			logr.mu.Unlock()
			if asked != c.askDS {
				t.Errorf("the DS of %s was asked for: %v, want %v", fwdSecParent, asked, c.askDS)
			}
		})
	}
}
