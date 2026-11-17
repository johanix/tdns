/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"io"
	"log"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Under a policy that requires DNSSEC, the scanner validates a child's glue
// address with the authority section it came with: an address synthesized
// from a wildcard validates with the proof that its name does not exist, and
// not without it.
func TestScannerValidatesWildcardGlueWithItsProof(t *testing.T) {
	prevGlobal := Globals.ImrEngine
	t.Cleanup(func() { Globals.ImrEngine = prevGlobal })

	const zone = "wcglue.example."
	const host = "ns1.w." + zone
	s := newZoneSigner(t, zone)
	imr := verdictImr(t, false)
	imr.Cache.DnskeyCache.Set(zone, s.key.KeyTag(), &cache.CachedDnskeyRRset{Name: zone, Keyid: s.key.KeyTag(),
		TrustAnchor: true, State: cache.ValidationStateSecure, Dnskey: *s.key, Expiration: time.Now().Add(time.Hour)})
	imr.Cache.ZoneMap.Set(zone, &cache.Zone{ZoneName: zone, State: cache.ValidationStateSecure})
	conf := &Config{}
	conf.Internal.ImrReady = NewImrReadiness()
	conf.publishImr(imr)

	answer := wildcardSigned(t, s, "*.w."+zone+" 300 IN A 192.0.2.53", host)
	glue := &core.RRset{Name: host, Class: dns.ClassINET, RRtype: dns.TypeA, RRs: answer[:1], RRSIGs: answer[1:]}
	proof := authorityRRsets(s.sign(t, mustRR(t, "a.w."+zone+" 300 IN NSEC zz.w."+zone+" A RRSIG NSEC")))
	ns := &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: []dns.RR{mustRR(t, zone+" 300 IN NS "+host)}}

	for _, c := range []struct {
		name      string
		authority []*core.RRset
		ok        bool
	}{
		{"with the proof", proof, true},
		{"without it", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sc := NewScanner(nil, false, false)
			sc.conf = conf
			sc.queryChild = func(context.Context, string, uint16, *core.RRset) (*core.RRset, []*core.RRset, bool, error) {
				return glue, c.authority, true, nil
			}
			fetch := sc.securedChildRRsetFetcher(trustStrict(), zone, ns, log.New(io.Discard, "", 0))
			rrs, inSync, err := fetch(context.Background(), host, dns.TypeA)
			if c.ok && (err != nil || !inSync || len(rrs) != 1) {
				t.Errorf("%v, in sync %v, err %v; want the address", rrs, inSync, err)
			}
			if !c.ok && !isScanRefusal(err) {
				t.Errorf("%v, err %v; want a refusal", rrs, err)
			}
		})
	}
}
