/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

// A CNAME loop is the same loop whatever case its names are written in. The
// chase recorded the names it had visited as written: the query's spelling
// and each CNAME's target as the zone spells it. A loop whose spellings
// differed went round once more than it should have, and the answer carried
// its first CNAME twice.
func TestCNAMELoopIgnoresCase(t *testing.T) {
	kdb := newTestKeyDB(t)
	testSnapshotZone(t, "example.", `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
a.example.	3600	IN	CNAME	b.example.
b.example.	3600	IN	CNAME	a.example.
c.example.	3600	IN	CNAME	D.example.
d.example.	3600	IN	CNAME	C.example.
`)

	for _, tc := range []struct {
		what   string
		qname  string
		answer []string
	}{
		{"targets in another case", "c.example.", []string{
			"c.example. CNAME D.example.",
			"d.example. CNAME C.example.",
		}},
		{"query in another case", "A.EXAMPLE.", []string{
			"a.example. CNAME b.example.",
			"b.example. CNAME a.example.",
		}},
		{"all in one case", "a.example.", []string{
			"a.example. CNAME b.example.",
			"b.example. CNAME a.example.",
		}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			m := occAsk(t, kdb, tc.qname, dns.TypeA, false)
			if got := occSection(m.Answer); !reflect.DeepEqual(got, tc.answer) {
				t.Errorf("%s A ANSWER:\n  got  %q\n  want %q", tc.qname, got, tc.answer)
			}
		})
	}
}
