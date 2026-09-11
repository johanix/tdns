/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A negative answer's proof is signed at query time: the denial NSEC is
 * synthesized per response. When a zone that must be signed cannot sign it,
 * the answer is SERVFAIL -- the same fail-closed rule the positive path
 * follows -- not an unsigned proof a validator cannot authenticate.
 */
package tdns

import (
	"context"
	"testing"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const negProofZone = `neg.example.	3600	IN	SOA	ns.neg.example. hostmaster.neg.example. 1 7200 1800 604800 7200
neg.example.	3600	IN	NS	ns.neg.example.
ns.neg.example.	3600	IN	A	192.0.2.1
a.b.neg.example.	3600	IN	A	192.0.2.2
insecure.neg.example.	3600	IN	NS	ns.insecure.neg.example.
ns.insecure.neg.example.	3600	IN	A	192.0.2.3
`

const negProofChildZone = `kid.example.	3600	IN	SOA	ns.kid.example. hostmaster.kid.example. 1 7200 1800 604800 7200
kid.example.	3600	IN	NS	ns.kid.example.
ns.kid.example.	3600	IN	A	192.0.2.4
`

// respondWith drives the zone's QueryResponder with no KeyDB. For a zone that
// must be signed, that makes every ephemeral signature fail; for an unsigned
// zone it must make no difference.
func respondWith(t *testing.T, zd *ZoneData, qname string, qtype uint16, do bool) *dns.Msg {
	t.Helper()
	r := new(dns.Msg)
	r.SetQuestion(qname, qtype)
	r.SetEdns0(4096, do)
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(r)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	cw := &captureWriter{}
	_ = zd.QueryResponder(context.Background(), cw, r, qname, qtype, msgo, nil, nil)
	if cw.got == nil {
		t.Fatalf("%s %s: no response written", qname, dns.TypeToString[qtype])
	}
	return cw.got
}

// Every path that synthesizes a denial, in a zone that must be signed and
// cannot be.
func TestUnsignableDenialIsServfail(t *testing.T) {
	zd := testSnapshotZone(t, "neg.example.", negProofZone)
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	kid := testSnapshotZone(t, "kid.example.", negProofChildZone)
	kid.Options = map[ZoneOption]bool{OptOnlineSigning: true}

	cases := []struct {
		name  string
		zd    *ZoneData
		qname string
		qtype uint16
		noDO  int // the rcode without DO, when no signature is attempted
	}{
		{"NXDOMAIN", zd, "nope.neg.example.", dns.TypeA, dns.RcodeNameError},
		{"NODATA", zd, "ns.neg.example.", dns.TypeTXT, dns.RcodeSuccess},
		{"empty non-terminal", zd, "b.neg.example.", dns.TypeA, dns.RcodeSuccess},
		{"DS at an insecure delegation", zd, "insecure.neg.example.", dns.TypeDS, dns.RcodeSuccess},
		{"DS for an in-zone name", zd, "ns.neg.example.", dns.TypeDS, dns.RcodeSuccess},
		{"DS at a child-only apex", kid, "kid.example.", dns.TypeDS, dns.RcodeSuccess},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if m := respondWith(t, c.zd, c.qname, c.qtype, false); m.Rcode != c.noDO {
				t.Fatalf("without DO: rcode %s, want %s", dns.RcodeToString[m.Rcode], dns.RcodeToString[c.noDO])
			}
			m := respondWith(t, c.zd, c.qname, c.qtype, true)
			if m.Rcode != dns.RcodeServerFailure {
				t.Errorf("with DO: rcode %s and authority %v; want SERVFAIL, the denial could not be signed",
					dns.RcodeToString[m.Rcode], m.Ns)
			}
			if len(m.Answer) != 0 || len(m.Ns) != 0 {
				t.Errorf("SERVFAIL carries answer %v authority %v; want neither", m.Answer, m.Ns)
			}
		})
	}
}

// An unsigned zone needs no keys. With no KeyDB it answers a DO query as it
// would without DO -- positive answers and denials alike -- rather than
// failing for want of keys it would never use.
func TestUnsignedZoneWithoutKeyDBAnswersDO(t *testing.T) {
	zd := testSnapshotZone(t, "neg.example.", negProofZone)

	if m := respondWith(t, zd, "ns.neg.example.", dns.TypeA, true); m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
		t.Errorf("positive answer: rcode %s answer %v; want the A record", dns.RcodeToString[m.Rcode], m.Answer)
	}
	if m := respondWith(t, zd, "nope.neg.example.", dns.TypeA, true); m.Rcode == dns.RcodeServerFailure {
		t.Errorf("denial: SERVFAIL for an unsigned zone")
	}
}
