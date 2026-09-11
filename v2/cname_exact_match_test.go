/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

const cnameChainZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
alias.example.	3600	IN	CNAME	www.example.
chain.example.	3600	IN	CNAME	alias.example.
`

// RFC 1034 section 4.3.2 step 3a follows a CNAME only when QTYPE does not
// match it. A query for the CNAME itself, or for ANY, is an exact match and
// the CNAME is the whole answer. The chase ran for both: asked for
// chain.example. CNAME, the server also answered with alias.example.'s CNAME,
// and asked for ANY it walked every CNAME in the chain.
func TestCNAMEQueryIsNotChased(t *testing.T) {
	kdb := newTestKeyDB(t)
	testSnapshotZone(t, "example.", cnameChainZone)

	for _, tc := range []struct {
		what   string
		qname  string
		qtype  uint16
		answer []string
	}{
		{"CNAME at a CNAME that points at a CNAME", "chain.example.", dns.TypeCNAME, []string{
			"chain.example. CNAME alias.example.",
		}},
		{"ANY at a CNAME that points at a CNAME", "chain.example.", dns.TypeANY, []string{
			"chain.example. CNAME alias.example.",
		}},
		{"CNAME at a CNAME that points at an address", "alias.example.", dns.TypeCNAME, []string{
			"alias.example. CNAME www.example.",
		}},
		// Any other type is still chased to the end of the chain.
		{"A through the chain", "chain.example.", dns.TypeA, []string{
			"chain.example. CNAME alias.example.",
			"alias.example. CNAME www.example.",
			"www.example. A 10.0.0.3",
		}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			m := occAsk(t, kdb, tc.qname, tc.qtype, false)
			if m.Rcode != dns.RcodeSuccess {
				t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
			}
			if !m.Authoritative {
				t.Error("AA not set")
			}
			if got := occSection(m.Answer); !reflect.DeepEqual(got, tc.answer) {
				t.Errorf("%s %s ANSWER:\n  got  %q\n  want %q",
					tc.qname, dns.TypeToString[tc.qtype], got, tc.answer)
			}
		})
	}
}
