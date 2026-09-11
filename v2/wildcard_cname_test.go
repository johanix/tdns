/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

const wildCNAMEZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
*.wild.example.	3600	IN	CNAME	www.example.
`

// A record synthesised from a wildcard is owned by the name that was asked,
// "and not the node with the "*" label" (RFC 1034 section 4.3.2 step 3c). A
// CNAME at a wildcard was not: handleCNAMEChain was handed the wildcard owner
// and served the stored record as it stood, so foo.wild.example. got
// *.wild.example. CNAME www.example., which a resolver discards as no answer
// to its question. The exact-match arm has always rewritten the owner.
func TestWildcardCNAMEIsOwnedByTheQueryName(t *testing.T) {
	kdb := newTestKeyDB(t)
	testSnapshotZone(t, "example.", wildCNAMEZone)

	for _, tc := range []struct {
		what   string
		qtype  uint16
		answer []string
	}{
		{"chased", dns.TypeA, []string{
			"foo.wild.example. CNAME www.example.",
			"www.example. A 10.0.0.3",
		}},
		{"asked for the CNAME", dns.TypeCNAME, []string{
			"foo.wild.example. CNAME www.example.",
		}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			m := occAsk(t, kdb, "foo.wild.example.", tc.qtype, false)
			if m.Rcode != dns.RcodeSuccess {
				t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
			}
			if got := occSection(m.Answer); !reflect.DeepEqual(got, tc.answer) {
				t.Errorf("foo.wild.example. %s ANSWER:\n  got  %q\n  want %q",
					dns.TypeToString[tc.qtype], got, tc.answer)
			}
		})
	}
}

// Under DO the RRSIG is re-owned with the CNAME and still validates. Its
// Labels field is the wildcard's, so a validator rebuilds *.wild.example. from
// foo.wild.example. (RFC 4035 section 5.3.2) and checks the signature the zone
// made. Verify also insists that the RRSIG and the RRset share an owner, so
// renaming one without the other fails here too.
func TestSignedWildcardCNAMEValidates(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testZone(t, "example.", wildCNAMEZone)
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

	m := occAsk(t, kdb, "foo.wild.example.", dns.TypeA, true)
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	var cname *dns.CNAME
	var sig *dns.RRSIG
	for _, rr := range m.Answer {
		switch rr := rr.(type) {
		case *dns.CNAME:
			cname = rr
		case *dns.RRSIG:
			if rr.TypeCovered == dns.TypeCNAME {
				sig = rr
			}
		}
	}
	if cname == nil || sig == nil {
		t.Fatalf("ANSWER lacks the CNAME or its RRSIG: %v", m.Answer)
	}
	if cname.Hdr.Name != "foo.wild.example." {
		t.Errorf("CNAME owner = %s, want foo.wild.example.", cname.Hdr.Name)
	}
	if sig.Hdr.Name != "foo.wild.example." {
		t.Errorf("RRSIG owner = %s, want foo.wild.example.", sig.Hdr.Name)
	}

	keys := getRRsetFrom(zd.publishedSnapshot(), "example.", dns.TypeDNSKEY)
	if keys == nil {
		t.Fatal("no DNSKEY RRset at the apex")
	}
	for _, rr := range keys.RRs {
		if k, ok := rr.(*dns.DNSKEY); ok && k.KeyTag() == sig.KeyTag {
			if err := sig.Verify(k, []dns.RR{cname}); err != nil {
				t.Errorf("RRSIG over the synthesised CNAME does not verify: %v", err)
			}
			return
		}
	}
	t.Errorf("no DNSKEY with key tag %d at the apex", sig.KeyTag)
}
