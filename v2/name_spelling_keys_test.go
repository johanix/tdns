/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * One name, one key, however its octets are written.
 *
 * A name in presentation form can spell one octet several ways: a as a, \a or
 * \097; 0xff as a raw byte or \255; a dot inside a label as \. or \046. The
 * zone parser hands names over as the zone file wrote them and miekg writes
 * names unpacked from the wire its own way, so the owner map's key has to be
 * the same for every spelling, or a name the zone holds answers NXDOMAIN to a
 * query that spells it differently.
 */

package tdns

import (
	"bytes"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// \065 is A, which folds to a; c\xff is a raw octet the wire spells \255; and
// www.a\.b.example. hangs below a label with a dot in it.
const spellingZone = "example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200\n" +
	"example. 3600 IN NS ns.example.\n" +
	"ns.example. 3600 IN A 10.0.0.1\n" +
	`\065.example. 3600 IN A 10.0.0.2` + "\n" +
	"a.example. 3600 IN AAAA 2001:db8::2\n" +
	`b\255.example. 3600 IN A 10.0.0.3` + "\n" +
	"c\xff.example. 3600 IN A 10.0.0.4\n" +
	`www.a\.b.example. 3600 IN A 10.0.0.5` + "\n"

func TestOwnerKeyIsTheSameForEverySpelling(t *testing.T) {
	zd := testSnapshotZone(t, "example.", spellingZone)
	snap := zd.publishedSnapshot()

	for _, group := range [][]string{
		{"a.example.", "A.example.", `\065.example.`, `\097.example.`, `\a.example.`, `\A.example.`},
		{`b\255.example.`, "b\xff.example.", `\098\255.example.`, `B\255.example.`},
		{`c\255.example.`, "c\xff.example.", `\099\255.example.`},
	} {
		want := getOwnerFrom(snap, group[0])
		if want == nil {
			t.Errorf("getOwnerFrom(%q) = nil: the zone holds that name", group[0])
			continue
		}
		for _, spelling := range group[1:] {
			if got := getOwnerFrom(snap, spelling); got != want {
				t.Errorf("getOwnerFrom(%q) = %v, want the owner %q finds", spelling, got, group[0])
			}
			if !nameExistsFrom(snap, spelling) {
				t.Errorf("nameExistsFrom(%q) = false", spelling)
			}
		}
	}

	// \065.example. and a.example. are one name written twice in the zone file,
	// so they are one owner holding both RRsets.
	if od := getOwnerFrom(snap, "a.example."); od != nil {
		if _, ok := od.RRtypes.Get(dns.TypeA); !ok {
			t.Error("a.example. lost the A record the zone file wrote at \\065.example.")
		}
		if _, ok := od.RRtypes.Get(dns.TypeAAAA); !ok {
			t.Error("a.example. lost its AAAA record")
		}
	}
	for name := range snap.Data {
		if dup := getOwnerFrom(snap, name); dup != snap.Data[name] {
			t.Errorf("owner key %q does not reach its own owner", name)
		}
	}

	// www.a\.b.example. makes a\.b.example. an empty non-terminal, which is
	// found by either spelling of the dot in its label.
	for _, spelling := range []string{`a\.b.example.`, `a\046b.example.`} {
		if !isEmptyNonTerminal(snap, spelling) {
			t.Errorf("isEmptyNonTerminal(%q) = false: www.a\\.b.example. hangs below it", spelling)
		}
	}
}

// The owner map's key and the canonical sort key read escapes by one rule, so
// two names share an owner exactly when they share a place in the NSEC chain.
func TestOwnerKeyAgreesWithCanonicalSortKey(t *testing.T) {
	names := []string{
		"a.example.", "A.example.", `\065.example.`, `\097.example.`, `\a.example.`,
		"b.example.", `b\255.example.`, "b\xff.example.", `B\255.example.`,
		`a\.b.example.`, `a\046b.example.`, "a.b.example.", `a\\b.example.`, `a\092b.example.`,
		`\000.example.`, "\x00.example.", "*.example.", `\042.example.`,
		"_dns.example.", `\_dns.example.`, "K.example.", `\226\132\170.example.`,
	}
	for _, a := range names {
		for _, b := range names {
			byKey := core.CanonicalizeName(a) == core.CanonicalizeName(b)
			bySort := bytes.Equal(canonicalSortKey(a), canonicalSortKey(b))
			if byKey != bySort {
				t.Errorf("%q and %q: same owner key %v, same sort key %v", a, b, byKey, bySort)
			}
		}
	}
}

// End to end: a query arrives spelled as miekg unpacks it, and finds the name
// whichever way the zone file wrote it.
func TestQueryFindsANameTheZoneFileSpelledDifferently(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testSnapshotZone(t, "example.", spellingZone)

	for _, qname := range []string{"A.example.", "a.example.", `c\255.example.`, `b\255.example.`} {
		t.Run(qname, func(t *testing.T) {
			m := entAsk(t, zd, kdb, qname, dns.TypeA, false, false)
			if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
				t.Errorf("rcode %s with %d answers, want NOERROR and the A record the zone holds",
					dns.RcodeToString[m.Rcode], len(m.Answer))
			}
		})
	}
}
