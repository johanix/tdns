/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A CNAME must not reach past a zone cut.
 *
 * A parent zone holds data below its delegations that it is not authoritative
 * for: glue, and anything left under a name after it was delegated. RFC 1034
 * section 4.3.2 walks the label tree before it looks at the node, so a name at
 * or below a cut gets a referral, never an answer. The CNAME chase has to walk
 * the same way: a target below a cut in the zone it lands in is the child's to
 * answer for, and the chase stops there with the CNAME alone, as it does for a
 * target outside every hosted zone.
 */

package tdns

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// occParentZone delegates sub.example. without hosting it, so ns.sub.example.
// is glue and old.sub.example. is occluded: data the parent holds and must
// not serve. hosted.example. is delegated AND hosted, and answers for itself.
const occParentZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
sub.example.	3600	IN	NS	ns.sub.example.
ns.sub.example.	3600	IN	A	192.0.2.1
old.sub.example.	3600	IN	CNAME	www.example.
hosted.example.	3600	IN	NS	ns.hosted.example.
ns.hosted.example.	3600	IN	A	192.0.2.2
alias.example.	3600	IN	CNAME	www.example.
glue.example.	3600	IN	CNAME	ns.sub.example.
cut.example.	3600	IN	CNAME	sub.example.
occ.example.	3600	IN	CNAME	old.sub.example.
tohosted.example.	3600	IN	CNAME	www.hosted.example.
`

const occHostedZone = `hosted.example.	3600	IN	SOA	ns.hosted.example. hostmaster.hosted.example. 1 7200 1800 604800 7200
hosted.example.	3600	IN	NS	ns.hosted.example.
ns.hosted.example.	3600	IN	A	192.0.2.2
www.hosted.example.	3600	IN	A	192.0.2.20
`

// occOtherZone is an unrelated hosted zone whose CNAMEs cross into example.
const occOtherZone = `other.	3600	IN	SOA	ns.other. hostmaster.other. 1 7200 1800 604800 7200
other.	3600	IN	NS	ns.other.
ns.other.	3600	IN	A	10.1.0.1
www.other.	3600	IN	CNAME	www.example.
glue.other.	3600	IN	CNAME	ns.sub.example.
`

// occSection renders a section as "owner TYPE rdata" lines in wire order,
// leaving out OPT and RRSIG.
func occSection(rrs []dns.RR) []string {
	out := []string{}
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT || h.Rrtype == dns.TypeRRSIG {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s %s", core.CanonicalizeName(h.Name),
			dns.TypeToString[h.Rrtype], strings.TrimPrefix(rr.String(), h.String())))
	}
	return out
}

func occAsk(t *testing.T, kdb *KeyDB, qname string, qtype uint16, do bool) *dns.Msg {
	t.Helper()
	zd := FindZone(qname)
	if zd == nil {
		t.Fatalf("no hosted zone for %s", qname)
	}
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	req.SetEdns0(4096, do)
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	rw := &fakeRW{}
	if err := zd.QueryResponder(context.Background(), rw, req, qname, qtype, msgo, kdb, nil); err != nil {
		t.Fatalf("QueryResponder(%s): %v", qname, err)
	}
	if rw.written == nil {
		t.Fatalf("no response written for %s", qname)
	}
	return rw.written
}

func TestCNAMEChaseStopsAtZoneCut(t *testing.T) {
	kdb := newTestKeyDB(t)
	testSnapshotZone(t, "example.", occParentZone)
	testSnapshotZone(t, "hosted.example.", occHostedZone)
	testSnapshotZone(t, "other.", occOtherZone)

	for _, tc := range []struct {
		what   string
		qname  string
		qtype  uint16
		answer []string
	}{
		// The target is glue. The parent's A for it is a hint for reaching
		// the child, not an answer anyone may be given.
		{"target is glue", "glue.example.", dns.TypeA, []string{
			"glue.example. CNAME ns.sub.example.",
		}},
		{"target is glue, chased from another zone", "glue.other.", dns.TypeA, []string{
			"glue.other. CNAME ns.sub.example.",
		}},
		// The target is the delegation point. The NS RRset there is the
		// parent's copy of the child's; the child's apex NS is authoritative.
		{"target is the delegation point", "cut.example.", dns.TypeNS, []string{
			"cut.example. CNAME sub.example.",
		}},
		// The target is an occluded CNAME. The chase follows it no further,
		// so what it points at is never reached either.
		{"target is an occluded CNAME", "occ.example.", dns.TypeA, []string{
			"occ.example. CNAME old.sub.example.",
		}},

		// Targets the server IS authoritative for are still chased.
		{"in-zone target", "alias.example.", dns.TypeA, []string{
			"alias.example. CNAME www.example.",
			"www.example. A 10.0.0.3",
		}},
		{"target in another hosted zone", "www.other.", dns.TypeA, []string{
			"www.other. CNAME www.example.",
			"www.example. A 10.0.0.3",
		}},
		// Below a cut in example., but hosted.example. is hosted too and
		// FindZone lands there, where the name is authoritative.
		{"target in a co-hosted child", "tohosted.example.", dns.TypeA, []string{
			"tohosted.example. CNAME www.hosted.example.",
			"www.hosted.example. A 192.0.2.20",
		}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			m := occAsk(t, kdb, tc.qname, tc.qtype, false)
			if m.Rcode != dns.RcodeSuccess {
				t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
			}
			if !m.Authoritative {
				t.Error("AA not set; the CNAME itself is authoritative data")
			}
			if got := occSection(m.Answer); !reflect.DeepEqual(got, tc.answer) {
				t.Errorf("%s %s ANSWER:\n  got  %q\n  want %q",
					tc.qname, dns.TypeToString[tc.qtype], got, tc.answer)
			}
		})
	}
}

// In a signed parent the same chase was a SERVFAIL under DO: nothing below a
// cut is signed (RFC 4035 §2.2), so the chase met glue with no RRSIG in a zone
// that must be signed, and gave up on the whole response.
func TestCNAMEChaseToGlueInASignedZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testZone(t, "example.", occParentZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity: PolicySigValidity{
			Default: 30 * 86400, DNSKEY: 30 * 86400, DS: 30 * 86400,
		},
	}
	zd.InstallInitialSnapshot()
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}

	m := occAsk(t, kdb, "glue.example.", dns.TypeA, true)
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	want := []string{"glue.example. CNAME ns.sub.example."}
	if got := occSection(m.Answer); !reflect.DeepEqual(got, want) {
		t.Errorf("ANSWER:\n  got  %q\n  want %q", got, want)
	}
	signed := false
	for _, rr := range m.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeCNAME {
			signed = true
		}
	}
	if !signed {
		t.Error("no RRSIG over the CNAME in a signed zone under DO")
	}
}
