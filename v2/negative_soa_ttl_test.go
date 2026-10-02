/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The SOA in a negative answer carries the zone's negative TTL, the smaller
 * of the SOA's own TTL and its MINIMUM (RFC 2308 section 3), and so do the
 * signatures over it and the NSEC records that prove the denial (RFC 9077).
 * A resolver holds a denial for the TTL of the SOA it arrived with; serving
 * the SOA's own TTL let an hour-long SOA stretch a one-minute MINIMUM (#699).
 */
package tdns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// negTTLZone has an SOA TTL of an hour and a MINIMUM of a minute, the shape of
// an auto zone. b.ttl.example. is an empty non-terminal and insecure.ttl.example.
// an unsigned delegation.
const negTTLZone = `ttl.example.	3600	IN	SOA	ns.ttl.example. hostmaster.ttl.example. 1 7200 1800 604800 60
ttl.example.	3600	IN	NS	ns.ttl.example.
ns.ttl.example.	3600	IN	A	192.0.2.1
a.b.ttl.example.	3600	IN	A	192.0.2.2
insecure.ttl.example.	3600	IN	NS	ns.insecure.ttl.example.
ns.insecure.ttl.example.	3600	IN	A	192.0.2.3
`

// soaIn returns the SOA in a section, or nil.
func soaIn(rrs []dns.RR) *dns.SOA {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

// soaSigsIn returns the signatures over the SOA in a section.
func soaSigsIn(rrs []dns.RR) []*dns.RRSIG {
	var out []*dns.RRSIG
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeSOA {
			out = append(out, sig)
		}
	}
	return out
}

func TestNegativeTTL(t *testing.T) {
	for _, tc := range []struct {
		ttl, minimum, want uint32
	}{
		{3600, 60, 60},
		{30, 60, 30},
		{60, 60, 60},
	} {
		soa := &dns.SOA{Hdr: dns.RR_Header{Ttl: tc.ttl}, Minttl: tc.minimum}
		if got := negativeTTL(soa); got != tc.want {
			t.Errorf("negativeTTL(TTL %d, MINIMUM %d) = %d, want %d", tc.ttl, tc.minimum, got, tc.want)
		}
	}
}

// Every negative path of an unsigned zone serves the SOA with the negative
// TTL, with or without DO, while an SOA query gets the record's own TTL and
// the stored SOA keeps it.
func TestDenialSOACarriesTheNegativeTTL(t *testing.T) {
	cases := []struct {
		qname string
		qtype uint16
		rcode int
	}{
		{"nope.ttl.example.", dns.TypeA, dns.RcodeNameError},
		{"ns.ttl.example.", dns.TypeTXT, dns.RcodeSuccess},      // NODATA
		{"b.ttl.example.", dns.TypeA, dns.RcodeSuccess},         // an empty non-terminal
		{"insecure.ttl.example.", dns.TypeDS, dns.RcodeSuccess}, // an unsigned delegation
		{"ns.ttl.example.", dns.TypeDS, dns.RcodeSuccess},       // DS at an ordinary name
		{"nope.ttl.example.", dns.TypeDS, dns.RcodeNameError},   // DS at a name that does not exist
		{"ttl.example.", dns.TypeDS, dns.RcodeSuccess},          // DS at the apex, parent not hosted
	}
	for _, zc := range []struct {
		name    string
		soaTTL  uint32
		wantTTL uint32
	}{
		{"SOA TTL above MINIMUM", 3600, 60},
		{"SOA TTL below MINIMUM", 30, 30},
	} {
		t.Run(zc.name, func(t *testing.T) {
			text := strings.Replace(negTTLZone, "ttl.example.\t3600\tIN\tSOA", fmt.Sprintf("ttl.example.\t%d\tIN\tSOA", zc.soaTTL), 1)
			zd := testSnapshotZone(t, "ttl.example.", text)
			for _, tc := range cases {
				for _, do := range []bool{false, true} {
					m := respondWith(t, zd, tc.qname, tc.qtype, do)
					if m.Rcode != tc.rcode {
						t.Errorf("%s %s (DO %v): rcode %s, want %s", tc.qname, dns.TypeToString[tc.qtype], do,
							dns.RcodeToString[m.Rcode], dns.RcodeToString[tc.rcode])
						continue
					}
					soa := soaIn(m.Ns)
					if soa == nil {
						t.Errorf("%s %s (DO %v): no SOA in AUTHORITY", tc.qname, dns.TypeToString[tc.qtype], do)
						continue
					}
					if soa.Hdr.Ttl != zc.wantTTL {
						t.Errorf("%s %s (DO %v): SOA TTL %d, want %d", tc.qname, dns.TypeToString[tc.qtype], do,
							soa.Hdr.Ttl, zc.wantTTL)
					}
				}
			}

			m := respondWith(t, zd, "ttl.example.", dns.TypeSOA, false)
			if soa := soaIn(m.Answer); soa == nil || soa.Hdr.Ttl != zc.soaTTL {
				t.Errorf("SOA query: answer %v, want the SOA with its own TTL %d", m.Answer, zc.soaTTL)
			}
			stored := getRRsetFrom(zd.publishedSnapshot(), "ttl.example.", dns.TypeSOA)
			if len(stored.RRs) == 0 || stored.RRs[0].Header().Ttl != zc.soaTTL {
				t.Errorf("the stored SOA changed: %v", stored.RRs)
			}
		})
	}
}

// In a signed zone the signatures over the SOA go out with its lowered TTL
// and still verify, and the NSEC records proving the denial carry the same
// TTL; the stored SOA and its signatures keep theirs. Both kinds of proof: the
// stored chain and the compact denial synthesized per response.
func TestSignedDenialSOAAndNSECCarryTheNegativeTTL(t *testing.T) {
	for _, zc := range []struct {
		name    string
		soaTTL  uint32
		wantTTL uint32 // denialZone's MINIMUM is 300
	}{
		{"SOA TTL above MINIMUM", 3600, 300},
		{"SOA TTL below MINIMUM", 120, 120},
	} {
		for _, blackLies := range []bool{false, true} {
			proof := "chain"
			if blackLies {
				proof = "compact"
			}
			t.Run(zc.name+", "+proof, func(t *testing.T) {
				text := strings.Replace(denialZone, "example.\t3600\tIN\tSOA", fmt.Sprintf("example.\t%d\tIN\tSOA", zc.soaTTL), 1)
				zd, kdb := signedTestZone(t, "example.", text, blackLies)
				var keys []*dns.DNSKEY
				for _, rr := range getRRsetFrom(zd.publishedSnapshot(), "example.", dns.TypeDNSKEY).RRs {
					keys = append(keys, rr.(*dns.DNSKEY))
				}
				for _, q := range []struct {
					qname string
					qtype uint16
				}{
					{"nope.example.", dns.TypeA},
					{"www.example.", dns.TypeTXT},
					{"ent.example.", dns.TypeA},
				} {
					m := denialAsk(t, zd, kdb, q.qname, q.qtype, false)
					what := q.qname + " " + dns.TypeToString[q.qtype]
					soa := soaIn(m.Ns)
					if soa == nil {
						t.Errorf("%s: no SOA in AUTHORITY", what)
						continue
					}
					if soa.Hdr.Ttl != zc.wantTTL {
						t.Errorf("%s: SOA TTL %d, want %d", what, soa.Hdr.Ttl, zc.wantTTL)
					}
					sigs := soaSigsIn(m.Ns)
					if len(sigs) == 0 {
						t.Errorf("%s: no signature over the SOA", what)
					}
					for _, sig := range sigs {
						if sig.Hdr.Ttl != zc.wantTTL {
							t.Errorf("%s: RRSIG over the SOA has TTL %d, want %d", what, sig.Hdr.Ttl, zc.wantTTL)
						}
					}
					nsecs := nsecsIn(m.Ns)
					if len(nsecs) == 0 {
						t.Errorf("%s: no NSEC in AUTHORITY", what)
					}
					for _, nsec := range nsecs {
						if nsec.Hdr.Ttl != zc.wantTTL {
							t.Errorf("%s: NSEC %s has TTL %d, want %d", what, nsec.Hdr.Name, nsec.Hdr.Ttl, zc.wantTTL)
						}
					}
					verifySection(t, m.Ns, keys)
				}

				stored := getRRsetFrom(zd.publishedSnapshot(), "example.", dns.TypeSOA)
				want := zc.soaTTL
				if len(stored.RRs) == 0 || stored.RRs[0].Header().Ttl != want {
					t.Errorf("the stored SOA changed: %v", stored.RRs)
				}
				for _, sig := range stored.RRSIGs {
					if sig.Header().Ttl != want {
						t.Errorf("a stored signature over the SOA changed its TTL to %d, want %d", sig.Header().Ttl, want)
					}
				}
			})
		}
	}
}
