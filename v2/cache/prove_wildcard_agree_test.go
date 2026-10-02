/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ProveWildcardAnswer is the reading WildcardAnswerProof makes of the records
// that validate. On the same records, the chain walk (which checks signatures
// with the zone's keys and hands ProveWildcardAnswer what verified) and the
// resolver come to the same verdict (RFC 4035 section 5.3.4, RFC 5155 section
// 8.8). A record of the zone whose signature fails decides the resolver's
// verdict before any proof is read, and the walk's as well (chase.go): such
// cases are not compared here.
func TestProveWildcardAnswerAgrees(t *testing.T) {
	const labels = 3 // *.w.sec.example.
	nsec := func(text string) func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset {
		return func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, soaFor(t, secZone)), signedNSEC(t, k, text)}
		}
	}
	nsec3 := func(name string, flags uint8, iterations uint16) func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset {
		return func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, synthNSEC3(secZone, name, true, flags, iterations, ""))}
		}
	}
	cases := []struct {
		name      string
		qname     string
		authority func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset
		want      ValidationState
		ede       uint16
	}{
		{"NSEC, the proof holds", wcQname, nsec(wcCover), ValidationStateSecure, 0},
		{"NSEC, no proof", wcQname, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, soaFor(t, secZone))}
		}, ValidationStateBogus, 0},
		{"NSEC proving a longer closest encloser", wcQname, nsec(wcNC + " 300 IN NSEC zz.w." + secZone + " A RRSIG NSEC"), ValidationStateBogus, 0},
		{"NSEC whose next name is below qname", wcNC, nsec("x.w." + secZone + " 300 IN NSEC a." + wcNC + " A RRSIG NSEC"), ValidationStateBogus, 0},
		{"NSEC at an ancestor with DNAME", wcQname, nsec("w." + secZone + " 300 IN NSEC zz.w." + secZone + " DNAME RRSIG NSEC"), ValidationStateBogus, 0},
		{"NSEC at an ancestor with NS and no SOA", wcQname, nsec("w." + secZone + " 300 IN NSEC zz.w." + secZone + " NS RRSIG NSEC"), ValidationStateBogus, 0},
		{"NSEC at an ancestor that is neither", wcQname, nsec("w." + secZone + " 300 IN NSEC zz.w." + secZone + " TXT RRSIG NSEC"), ValidationStateSecure, 0},
		{"NSEC that does not cover qname", wcQname, nsec("b.w." + secZone + " 300 IN NSEC c.w." + secZone + " A RRSIG NSEC"), ValidationStateBogus, 0},
		{"NSEC owned by qname", wcQname, nsec(wcQname + " 300 IN NSEC zz.w." + secZone + " A RRSIG NSEC"), ValidationStateBogus, 0},
		{"NSEC signed by the zone above", wcQname, func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) []*core.RRset {
			above := newZoneKey(t, rrcache, "example.", true)
			rrcache.ZoneMap.Set("example.", &Zone{ZoneName: "example.", State: ValidationStateSecure})
			return []*core.RRset{above.sign(t, rrFrom(t, wcCover))}
		}, ValidationStateBogus, 0},
		{"NSEC3, the next closer name covered", wcQname, nsec3(wcNC, 0, 0), ValidationStateSecure, 0},
		{"NSEC3 through Opt-Out", wcQname, nsec3(wcNC, 1, 0), ValidationStateInsecure, 0},
		{"NSEC3 over the iteration limit", wcQname, nsec3(wcNC, 0, DefaultNSEC3MaxIterations+1), ValidationStateInsecure, edeUnsupportedNSEC3Iterations},
		{"NSEC3 not covering the next closer name", wcQname, nsec3(wcQname, 0, 0), ValidationStateBogus, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			sets := c.authority(t, rrcache, k)
			rState, rEDE := rrcache.WildcardAnswerProof(context.Background(), secZone, c.qname, labels, sets, nil)
			nsecs, nsec3s := zoneRecords(t, rrcache, secZone, sets)
			wState, wEDE := ProveWildcardAnswer(secZone, c.qname, labels, nsecs, nsec3s)
			if wState != c.want || wEDE != c.ede {
				t.Errorf("ProveWildcardAnswer: %s EDE %d, want %s EDE %d", ValidationStateToString[wState], wEDE,
					ValidationStateToString[c.want], c.ede)
			}
			if wState != rState || wEDE != rEDE {
				t.Errorf("ProveWildcardAnswer %s EDE %d, WildcardAnswerProof %s EDE %d",
					ValidationStateToString[wState], wEDE, ValidationStateToString[rState], rEDE)
			}
		})
	}
}

// ExpansionSignature is the rule ValidateAnswer splits signatures by.
func TestExpansionSignature(t *testing.T) {
	for _, c := range []struct {
		owner  string
		labels uint8
		want   bool
	}{
		{wcQname, 3, true},         // a.z.w.sec.example. from *.w.sec.example.
		{wcQname, 5, false},        // over the owner itself
		{wcWild, 3, false},         // the wildcard asked for by name
		{"x." + secZone, 0, true},  // from *. at the root
		{"*." + secZone, 2, false}, // the leading * is not counted
	} {
		sig := &dns.RRSIG{Labels: c.labels}
		if got := ExpansionSignature(sig, c.owner); got != c.want {
			t.Errorf("%s, Labels %d: %v, want %v", c.owner, c.labels, got, c.want)
		}
	}
}
