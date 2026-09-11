/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

// y.blocked.example. is an empty non-terminal: it owns nothing, but
// x.y.blocked.example. lives beneath it.
const encloserZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
*.wild.example.	3600	IN	A	10.0.0.9
*.cn.example.	3600	IN	CNAME	www.example.
*.blocked.example.	3600	IN	A	10.0.0.8
x.y.blocked.example.	3600	IN	A	10.0.0.7
`

// The wildcard that answers for a name that does not exist sits at the name's
// closest encloser, its nearest ancestor that does exist (RFC 4592 section
// 3.3.1), however many labels up that is. The lookup only ever tried the
// immediate parent, so *.wild.example. answered a.wild.example. and left
// a.b.wild.example. NXDOMAIN.
func TestWildcardAtTheClosestEncloser(t *testing.T) {
	kdb := newTestKeyDB(t)
	testSnapshotZone(t, "example.", encloserZone)

	for _, tc := range []struct {
		what   string
		qname  string
		rcode  int
		answer []string
	}{
		{"one label below", "a.wild.example.", dns.RcodeSuccess, []string{
			"a.wild.example. A 10.0.0.9",
		}},
		{"two labels below", "a.b.wild.example.", dns.RcodeSuccess, []string{
			"a.b.wild.example. A 10.0.0.9",
		}},
		{"three labels below", "a.b.c.wild.example.", dns.RcodeSuccess, []string{
			"a.b.c.wild.example. A 10.0.0.9",
		}},
		{"a CNAME, two labels below", "a.b.cn.example.", dns.RcodeSuccess, []string{
			"a.b.cn.example. CNAME www.example.",
			"www.example. A 10.0.0.3",
		}},
		// The closest encloser here is the empty non-terminal
		// y.blocked.example., which exists, so only *.y.blocked.example.
		// could answer. *.blocked.example. is further up and must not.
		{"an empty non-terminal is the closest encloser", "a.y.blocked.example.", dns.RcodeNameError, []string{}},
		// The closest encloser is the apex, and there is no *.example.
		{"no wildcard at the closest encloser", "a.b.nowild.example.", dns.RcodeNameError, []string{}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			m := occAsk(t, kdb, tc.qname, dns.TypeA, false)
			if m.Rcode != tc.rcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[m.Rcode], dns.RcodeToString[tc.rcode])
			}
			if got := occSection(m.Answer); !reflect.DeepEqual(got, tc.answer) {
				t.Errorf("%s A ANSWER:\n  got  %q\n  want %q", tc.qname, got, tc.answer)
			}
		})
	}
}

// Signed, the expansion is served with the wildcard's RRSIG, whose Labels
// field counts the labels of *.wild.example. without the asterisk. A validator
// keeps that many labels of a.b.wild.example. and prefixes "*." to rebuild the
// owner that was signed (RFC 4035 section 5.3.2), so an expansion of any depth
// verifies against the one signature.
func TestSignedWildcardAtTheClosestEncloserValidates(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testZone(t, "example.", encloserZone)
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

	m := occAsk(t, kdb, "a.b.wild.example.", dns.TypeA, true)
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	var a []dns.RR
	var sig *dns.RRSIG
	for _, rr := range m.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			a = append(a, rr)
		case *dns.RRSIG:
			if rr.TypeCovered == dns.TypeA {
				sig = rr
			}
		}
	}
	if len(a) == 0 || sig == nil {
		t.Fatalf("ANSWER lacks the A or its RRSIG: %v", m.Answer)
	}
	if a[0].Header().Name != "a.b.wild.example." || sig.Hdr.Name != "a.b.wild.example." {
		t.Errorf("owners = %s (A), %s (RRSIG), want a.b.wild.example. for both",
			a[0].Header().Name, sig.Hdr.Name)
	}

	keys := getRRsetFrom(zd.publishedSnapshot(), "example.", dns.TypeDNSKEY)
	if keys == nil {
		t.Fatal("no DNSKEY RRset at the apex")
	}
	for _, rr := range keys.RRs {
		if k, ok := rr.(*dns.DNSKEY); ok && k.KeyTag() == sig.KeyTag {
			if err := sig.Verify(k, a); err != nil {
				t.Errorf("RRSIG over the two-label expansion does not verify: %v", err)
			}
			return
		}
	}
	t.Errorf("no DNSKEY with key tag %d at the apex", sig.KeyTag)
}

// The walk itself, with the two shapes the query tests do not reach: an owner
// node that holds no records and has nothing beneath it, which does not exist
// and so is walked past, and the root zone, where the root is the closest
// encloser above every label.
func TestWildcardSourceFrom(t *testing.T) {
	zd := testSnapshotZone(t, "example.", encloserZone)
	base := zd.publishedSnapshot()
	if base == nil {
		t.Fatal("no published snapshot")
	}
	data := map[string]*OwnerData{}
	for k, v := range base.Data {
		data[k] = v
	}
	data["vestigial.example."] = NewOwnerData("vestigial.example.")
	snap := zd.buildSnapshotLocked(base.Serial, data, nil)

	for _, tc := range []struct{ qname, want string }{
		{"a.wild.example.", "*.wild.example."},
		{"a.b.c.wild.example.", "*.wild.example."},
		{"a.www.example.", "*.www.example."},
		{"a.y.blocked.example.", "*.y.blocked.example."},
		{"a.b.nowild.example.", "*.example."},
		{"a.vestigial.example.", "*.example."},
		{"A.B.WILD.EXAMPLE.", "*.WILD.EXAMPLE."},
	} {
		if got := wildcardSourceFrom(snap, "example.", tc.qname); got != tc.want {
			t.Errorf("wildcardSourceFrom(%s) = %s, want %s", tc.qname, got, tc.want)
		}
	}

	root := testSnapshotZone(t, ".", `.	3600	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400
.	3600	IN	NS	a.root-servers.net.
`)
	for _, qname := range []string{"a.", "a.b.", "a.b.c."} {
		if got := wildcardSourceFrom(root.publishedSnapshot(), ".", qname); got != "*." {
			t.Errorf("wildcardSourceFrom(%s) in the root zone = %s, want *.", qname, got)
		}
	}
}
