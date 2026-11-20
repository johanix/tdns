/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/miekg/dns"
)

// The authority NS RRset on a positive answer (issue #1154): left out when the
// answer already is the apex NS RRset, with the glue still in ADDITIONAL, and
// unchanged on every other positive answer.

const authNSZoneText = `example.	3600	IN	SOA	ns1.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
example.	3600	IN	NS	ns.example.net.
example.	3600	IN	A	10.0.0.10
ns1.example.	3600	IN	A	10.0.0.1
ns1.example.	3600	IN	AAAA	2001:db8::1
www.example.	3600	IN	A	10.0.0.2
apexalias.example.	3600	IN	CNAME	example.
`

var (
	authNSApexNS = []string{"example. NS", "example. NS"}
	authNSGlue   = []string{"ns1.example. A", "ns1.example. AAAA"}
)

// authNSSignedZone hosts authNSZoneText inline-signed and returns the KeyDB to
// query it with.
func authNSSignedZone(t *testing.T) *KeyDB {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := testZone(t, "example.", authNSZoneText)
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
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	return kdb
}

// authNSCount counts the entries of the rendered sections equal to s.
func authNSCount(m *dns.Msg, s string) int {
	n := 0
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, got := range qtRender(sec) {
			if got == s {
				n++
			}
		}
	}
	return n
}

func authNSCheckSections(t *testing.T, m *dns.Msg, answer, authority, additional []string) {
	t.Helper()
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if got := qtRender(m.Answer); answer != nil && !reflect.DeepEqual(got, answer) {
		t.Errorf("ANSWER = %q, want %q", got, answer)
	}
	if got := qtRender(m.Ns); !reflect.DeepEqual(got, authority) {
		t.Errorf("AUTHORITY = %q, want %q", got, authority)
	}
	if got := qtRender(m.Extra); !reflect.DeepEqual(got, additional) {
		t.Errorf("ADDITIONAL = %q, want %q", got, additional)
	}
}

// An unsigned zone, without DO: the apex NS RRset goes out once, in ANSWER,
// when it is the answer, and in AUTHORITY on every other positive answer.
func TestAuthorityNSNotRepeatedWhenAnswer(t *testing.T) {
	kdb := newTestKeyDB(t)
	testSnapshotZone(t, "example.", authNSZoneText)

	for _, tc := range []struct {
		what       string
		allowAny   bool
		qname      string
		qtype      uint16
		answer     []string
		authority  []string
		additional []string
	}{
		{"NS at the apex", false, "example.", dns.TypeNS,
			authNSApexNS, []string{}, authNSGlue},
		{"ANY at the apex, every RRset", true, "example.", dns.TypeANY,
			[]string{"example. A", "example. NS", "example. NS", "example. SOA"}, []string{}, authNSGlue},
		{"NS through a CNAME to the apex", false, "apexalias.example.", dns.TypeNS,
			append([]string{"apexalias.example. CNAME"}, authNSApexNS...), []string{}, authNSGlue},

		// Not the apex NS RRset in the answer: unchanged.
		{"A below the apex", false, "www.example.", dns.TypeA,
			[]string{"www.example. A"}, authNSApexNS, authNSGlue},
		{"A at the apex", false, "example.", dns.TypeA,
			[]string{"example. A"}, authNSApexNS, authNSGlue},
		{"SOA at the apex", false, "example.", dns.TypeSOA,
			[]string{"example. SOA"}, authNSApexNS, authNSGlue},
		{"ANY at the apex, one RRset", false, "example.", dns.TypeANY,
			[]string{"example. A"}, authNSApexNS, authNSGlue},
		{"A through a CNAME to the apex", false, "apexalias.example.", dns.TypeA,
			[]string{"apexalias.example. CNAME", "example. A"}, authNSApexNS, authNSGlue},
	} {
		t.Run(tc.what, func(t *testing.T) {
			opts := map[AuthOption]string{}
			if tc.allowAny {
				opts[AuthOptAllowAnyQueries] = "true"
			}
			kdb.SetOptions(opts)
			m := occAsk(t, kdb, tc.qname, tc.qtype, false)
			authNSCheckSections(t, m, tc.answer, tc.authority, tc.additional)
		})
	}
}

// A signed zone under DO: the apex NS RRset and its signature go out once.
// The glue keeps its signatures.
func TestAuthorityNSNotRepeatedWhenAnswerSigned(t *testing.T) {
	kdb := authNSSignedZone(t)
	signedGlue := []string{"ns1.example. A", "ns1.example. AAAA", "ns1.example. RRSIG A", "ns1.example. RRSIG AAAA"}
	signedApexNS := slices.Concat(authNSApexNS, []string{"example. RRSIG NS"})

	t.Run("NS at the apex", func(t *testing.T) {
		m := occAsk(t, kdb, "example.", dns.TypeNS, true)
		authNSCheckSections(t, m, signedApexNS, []string{}, signedGlue)
	})

	t.Run("NS at the apex, without DO", func(t *testing.T) {
		m := occAsk(t, kdb, "example.", dns.TypeNS, false)
		authNSCheckSections(t, m, authNSApexNS, []string{}, authNSGlue)
	})

	t.Run("ANY at the apex, every RRset", func(t *testing.T) {
		kdb.SetOptions(map[AuthOption]string{AuthOptAllowAnyQueries: "true"})
		defer kdb.SetOptions(map[AuthOption]string{})
		m := occAsk(t, kdb, "example.", dns.TypeANY, true)
		// The full ANSWER is every apex RRset with its signatures; what
		// matters is that the NS RRset and its signature are in it once.
		authNSCheckSections(t, m, nil, []string{}, signedGlue)
		if n := authNSCount(m, "example. NS"); n != 2 {
			t.Errorf("%d NS records in the response, want 2", n)
		}
		if n := authNSCount(m, "example. RRSIG NS"); n != 1 {
			t.Errorf("%d RRSIGs over the NS RRset in the response, want 1", n)
		}
	})

	t.Run("A below the apex keeps the authority NS RRset", func(t *testing.T) {
		m := occAsk(t, kdb, "www.example.", dns.TypeA, true)
		authNSCheckSections(t, m, []string{"www.example. A", "www.example. RRSIG A"}, signedApexNS, signedGlue)
	})
}

// minimal-responses leaves out the authority NS RRset and the glue on every
// positive answer, the apex NS answer included, as before.
func TestAuthorityNSMinimalResponses(t *testing.T) {
	kdb := newTestKeyDB(t)
	testSnapshotZone(t, "example.", authNSZoneText)
	kdb.SetOptions(map[AuthOption]string{AuthOptMinimalResponses: "true"})

	for _, tc := range []struct {
		what   string
		qname  string
		qtype  uint16
		answer []string
	}{
		{"NS at the apex", "example.", dns.TypeNS, authNSApexNS},
		{"A below the apex", "www.example.", dns.TypeA, []string{"www.example. A"}},
		{"A at the apex", "example.", dns.TypeA, []string{"example. A"}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			m := occAsk(t, kdb, tc.qname, tc.qtype, false)
			authNSCheckSections(t, m, tc.answer, []string{}, []string{})
		})
	}
}
