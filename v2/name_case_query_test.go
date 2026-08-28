/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The authoritative query path, asked the same question in different cases.
 *
 * DNS names are case-insensitive, so the ONLY thing that may differ between a
 * query for www.example. and one for WWW.EXAMPLE. is the spelling in the
 * question section. Same rcode, same records, same section they land in. This
 * is a differential test rather than a list of expected answers on purpose: it
 * needs no opinion about what the right answer is, only that the spelling did
 * not change it, so it keeps working as the query path grows.
 */
package tdns

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Deliberately covers the shapes that take different branches through
// QueryResponder: apex, ordinary name, a child delegation with glue, a
// wildcard, a CNAME, and a name that does not exist at all.
const caseQueryZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
example.	3600	IN	MX	10 mail.example.
ns.example.	3600	IN	A	10.0.0.1
mail.example.	3600	IN	A	10.0.0.2
www.example.	3600	IN	A	10.0.0.3
www.example.	3600	IN	AAAA	2001:db8::3
alias.example.	3600	IN	CNAME	www.example.
*.wild.example.	3600	IN	A	10.0.0.9
child.example.	3600	IN	NS	ns1.child.example.
ns1.child.example.	3600	IN	A	10.0.0.10
`

// spellings returns the same name written several ways: as given, all upper,
// only the left-hand labels upper, and only the zone-name part upper. The last
// two matter separately -- a bug in the in-zone or delegation walk shows up on
// one and not the other, which is exactly how the referral bug hid.
func spellings(name string) []string {
	labels := dns.SplitDomainName(name)
	if len(labels) == 0 {
		return []string{name}
	}
	leftUpper := make([]string, len(labels))
	zoneUpper := make([]string, len(labels))
	for i, l := range labels {
		leftUpper[i], zoneUpper[i] = l, l
		if i == 0 {
			leftUpper[i] = strings.ToUpper(l)
		} else {
			zoneUpper[i] = strings.ToUpper(l)
		}
	}
	return []string{
		name,
		strings.ToUpper(name),
		strings.Join(leftUpper, ".") + ".",
		strings.Join(zoneUpper, ".") + ".",
	}
}

// responseShape renders a response as something two spellings can be compared
// by: rcode, flags, and the records in each section with owner names folded.
// Owner-name SPELLING is excluded deliberately -- the server answers from
// stored records, so an answer carries the zone's spelling rather than the
// query's, and that is not what this test is about.
func responseShape(m *dns.Msg) string {
	if m == nil {
		return "<no response written>"
	}
	section := func(rrs []dns.RR) []string {
		out := make([]string, 0, len(rrs))
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			h := rr.Header()
			out = append(out, fmt.Sprintf("%s %s %s",
				core.CanonicalizeName(h.Name), dns.TypeToString[h.Rrtype],
				core.CanonicalizeName(strings.TrimPrefix(rr.String(), h.String()))))
		}
		sort.Strings(out)
		return out
	}
	return fmt.Sprintf("rcode=%s aa=%v\n  ANSWER: %v\n  AUTHORITY: %v\n  ADDITIONAL: %v",
		dns.RcodeToString[m.Rcode], m.Authoritative,
		section(m.Answer), section(m.Ns), section(m.Extra))
}

func TestQueryPathIgnoresCase(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testSnapshotZone(t, "example.", caseQueryZone)
	registerZones(t, zd)
	ctx := context.Background()

	ask := func(t *testing.T, qname string, qtype uint16) *dns.Msg {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion(qname, qtype)
		msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
		}
		// A remote address so the transfer path reaches its own ACL rather than
		// tripping over a nil peer: AXFR/IXFR are part of what must not depend
		// on spelling, and REFUSED-by-ACL is a perfectly good shared outcome.
		rw := &fakeRW{remote: udpAddr("127.0.0.1")}
		if err := zd.QueryResponder(ctx, rw, req, qname, qtype, msgo, kdb, nil); err != nil {
			t.Fatalf("QueryResponder(%q): %v", qname, err)
		}
		return rw.written
	}

	for _, tc := range []struct {
		what  string
		qname string
		qtype uint16
	}{
		{"apex SOA", "example.", dns.TypeSOA},
		{"apex NS", "example.", dns.TypeNS},
		{"apex MX", "example.", dns.TypeMX},
		{"ordinary name", "www.example.", dns.TypeA},
		{"ordinary name, other type", "www.example.", dns.TypeAAAA},
		{"NODATA", "www.example.", dns.TypeMX},
		{"NXDOMAIN", "nothere.example.", dns.TypeA},
		{"CNAME", "alias.example.", dns.TypeA},
		{"wildcard", "anything.wild.example.", dns.TypeA},
		{"delegation referral", "host.child.example.", dns.TypeA},
		{"delegation name itself", "child.example.", dns.TypeNS},
		// DS is trapped at the top of QueryResponder and answered from the
		// nearest hosted ancestor, so it exercises the delegation walk on a
		// different path from the referral above.
		{"DS at a delegation", "child.example.", dns.TypeDS},
		{"DS for an ordinary in-zone name", "www.example.", dns.TypeDS},
		{"DS at the apex", "example.", dns.TypeDS},
		// AXFR/IXFR are dispatched by a separate apex test further down
		// QueryResponder, which answered NOTAUTH for a mis-cased apex -- a
		// secondary that upcased its request simply got no zone.
		{"AXFR at the apex", "example.", dns.TypeAXFR},
		{"IXFR at the apex", "example.", dns.TypeIXFR},
	} {
		t.Run(tc.what, func(t *testing.T) {
			want := responseShape(ask(t, tc.qname, tc.qtype))

			for _, spelling := range spellings(tc.qname) {
				if spelling == tc.qname {
					continue
				}
				got := responseShape(ask(t, spelling, tc.qtype))
				if got != want {
					t.Errorf("%s asked as %q answers differently than as %q\n\ngot:\n  %s\n\nwant:\n  %s",
						dns.TypeToString[tc.qtype], spelling, tc.qname, got, want)
				}
			}
		})
	}
}
