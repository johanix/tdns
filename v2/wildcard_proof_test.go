/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// a.wild.example. and x.a.wild.example. sit just before the names the
// synthesised cover is built around, and m.wild.example. just after, so a
// cover that reached too far would take one of them in.
const proofZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
*.wild.example.	3600	IN	A	10.0.0.9
a.wild.example.	3600	IN	A	10.0.0.10
x.a.wild.example.	3600	IN	A	10.0.0.11
m.wild.example.	3600	IN	A	10.0.0.12
*.cn.example.	3600	IN	CNAME	www.example.
`

// testWireCompare is canonical order (RFC 4034 section 6.1) worked out apart
// from the code under test: pack both names, fold A-Z, compare the labels
// from the right, and let a name that runs out of labels first sort first.
func testWireCompare(t *testing.T, a, b string) int {
	t.Helper()
	labels := func(n string) [][]byte {
		buf := make([]byte, 256)
		if _, err := dns.PackDomainName(dns.Fqdn(n), buf, 0, nil, false); err != nil {
			t.Fatalf("PackDomainName(%q): %v", n, err)
		}
		var out [][]byte
		for i := 0; buf[i] != 0; i += 1 + int(buf[i]) {
			l := append([]byte(nil), buf[i+1:i+1+int(buf[i])]...)
			for j, c := range l {
				if c >= 'A' && c <= 'Z' {
					l[j] = c + 32
				}
			}
			out = append(out, l)
		}
		return out
	}
	al, bl := labels(a), labels(b)
	for i, j := len(al)-1, len(bl)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := bytes.Compare(al[i], bl[j]); c != 0 {
			return c
		}
	}
	return len(al) - len(bl)
}

// unboundProvesWildcard is Unbound's val_nsec_proves_positive_wildcard: the
// NSEC must prove qname does not exist, and the closest encloser it implies
// -- the longer of what its owner and its next name share with qname -- must
// be the wildcard's.
func unboundProvesWildcard(t *testing.T, nsec *dns.NSEC, qname, ce string) bool {
	t.Helper()
	owner, next := nsec.Hdr.Name, nsec.NextDomain
	if testWireCompare(t, owner, qname) == 0 {
		return false // proves qname exists
	}
	if dns.IsSubDomain(owner, qname) {
		has := map[uint16]bool{}
		for _, typ := range nsec.TypeBitMap {
			has[typ] = true
		}
		if has[dns.TypeDNAME] || (has[dns.TypeNS] && !has[dns.TypeSOA]) {
			return false
		}
	}
	strictlyBelow := func(child, parent string) bool {
		return dns.IsSubDomain(parent, child) && testWireCompare(t, child, parent) != 0
	}
	switch c := testWireCompare(t, owner, next); {
	case c == 0:
		if !strictlyBelow(qname, next) {
			return false
		}
	case c > 0: // the last NSEC, whose next name is the apex
		if !(testWireCompare(t, owner, qname) < 0 && strictlyBelow(qname, next)) {
			return false
		}
	default:
		if !(testWireCompare(t, owner, qname) < 0 && testWireCompare(t, qname, next) < 0) {
			return false
		}
	}
	shared := dns.CompareDomainName(owner, qname)
	if n := dns.CompareDomainName(next, qname); n > shared {
		shared = n
	}
	return shared == dns.CountLabel(ce)
}

func signedProofZone(t *testing.T, blackLies bool) (*ZoneData, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := testZone(t, "example.", proofZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true, OptBlackLies: blackLies}
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
	return zd, kdb
}

// A signed wildcard answer carries the NSEC that proves the query name does
// not exist (RFC 4035 section 3.1.3.3); without one a validator rejects it
// (section 5.3.4). A zone with a chain proves it with the chain's own record.
// A black-lies zone has none, and gets a cover synthesised for the next
// closer name that hides no name the zone holds.
func TestSignedWildcardAnswerCarriesProof(t *testing.T) {
	for _, mode := range []struct {
		name      string
		blackLies bool
	}{{"chain", false}, {"black-lies", true}} {
		t.Run(mode.name, func(t *testing.T) {
			zd, kdb := signedProofZone(t, mode.blackLies)
			snap := zd.publishedSnapshot()
			keys := getRRsetFrom(snap, "example.", dns.TypeDNSKEY)
			if keys == nil {
				t.Fatal("no DNSKEY RRset at the apex")
			}

			for _, tc := range []struct{ qname, ce string }{
				{"b.wild.example.", "wild.example."},
				{"q.r.wild.example.", "wild.example."},
				{"z.wild.example.", "wild.example."},
				{"a.b.cn.example.", "cn.example."}, // a wildcard CNAME, through handleCNAMEChain
			} {
				t.Run(tc.qname, func(t *testing.T) {
					m := occAsk(t, kdb, tc.qname, dns.TypeA, true)
					if m.Rcode != dns.RcodeSuccess {
						t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
					}
					var nsecs []*dns.NSEC
					for _, rr := range m.Ns {
						if n, ok := rr.(*dns.NSEC); ok {
							nsecs = append(nsecs, n)
						}
					}
					if len(nsecs) != 1 {
						t.Fatalf("AUTHORITY has %d NSEC records, want the one proof: %v", len(nsecs), m.Ns)
					}
					nsec := nsecs[0]
					if !unboundProvesWildcard(t, nsec, tc.qname, tc.ce) {
						t.Errorf("%s does not prove %s under *.%s", nsec, tc.qname, tc.ce)
					}

					verified := false
					for _, rr := range m.Ns {
						sig, ok := rr.(*dns.RRSIG)
						if !ok || sig.TypeCovered != dns.TypeNSEC || !strings.EqualFold(sig.Hdr.Name, nsec.Hdr.Name) {
							continue
						}
						for _, k := range keys.RRs {
							if dk, ok := k.(*dns.DNSKEY); ok && dk.KeyTag() == sig.KeyTag {
								if err := sig.Verify(dk, []dns.RR{nsec}); err != nil {
									t.Errorf("RRSIG over the proof does not verify: %v", err)
								}
								verified = true
							}
						}
					}
					if !verified {
						t.Errorf("no RRSIG over the proof %s", nsec.Hdr.Name)
					}

					stored := getOwnerFrom(snap, nsec.Hdr.Name)
					if !mode.blackLies {
						if stored == nil || len(stored.NSEC.RRs) == 0 || stored.NSEC.RRs[0].String() != nsec.String() {
							t.Errorf("proof %s is not the chain's own record", nsec)
						}
						return
					}
					if stored != nil || isEmptyNonTerminal(snap, nsec.Hdr.Name) {
						t.Errorf("synthesised owner %s is a name the zone holds", nsec.Hdr.Name)
					}
					names := []string{}
					for name := range snap.Data {
						names = append(names, name)
					}
					for name := range snap.ents {
						names = append(names, name)
					}
					for _, name := range names {
						if testWireCompare(t, nsec.Hdr.Name, name) < 0 && testWireCompare(t, name, nsec.NextDomain) < 0 {
							t.Errorf("the cover %s -> %s hides %s, which exists", nsec.Hdr.Name, nsec.NextDomain, name)
						}
					}
				})
			}

			// A name the zone holds is no wildcard answer and gets no proof.
			m := occAsk(t, kdb, "m.wild.example.", dns.TypeA, true)
			for _, rr := range m.Ns {
				if _, ok := rr.(*dns.NSEC); ok {
					t.Errorf("NSEC in the answer for a name that exists: %v", m.Ns)
				}
			}
		})
	}
}

// An unsigned zone serves its wildcard answers with no proof to go with them.
func TestUnsignedWildcardAnswerHasNoProof(t *testing.T) {
	kdb := newTestKeyDB(t)
	testSnapshotZone(t, "example.", proofZone)
	for _, qname := range []string{"b.wild.example.", "a.b.cn.example."} {
		m := occAsk(t, kdb, qname, dns.TypeA, true)
		if m.Rcode != dns.RcodeSuccess {
			t.Errorf("%s: rcode = %s, want NOERROR", qname, dns.RcodeToString[m.Rcode])
		}
		for _, rr := range m.Ns {
			if _, ok := rr.(*dns.NSEC); ok {
				t.Errorf("%s: NSEC in an unsigned zone's answer: %v", qname, m.Ns)
			}
		}
	}
}

// The synthesised cover for next closer names chosen to reach the edges: the
// octet A-Z folding skips over, a label that is only \000 or ends in one, a
// label already 63 octets long, one that cannot be followed at all, and a name
// so long the owner's padding has to stop short.
func TestCoverNextCloser(t *testing.T) {
	zd := testSnapshotZone(t, "example.", proofZone)
	snap := zd.publishedSnapshot()
	long := strings.Repeat("c", 63)
	longCE := long + "." + long + "." + long + ".example."

	for _, tc := range []struct {
		what, qname, ce string
		none            bool
	}{
		{"an ordinary label", "b.wild.example.", "wild.example.", false},
		{"below the next closer name", "q.r.wild.example.", "wild.example.", false},
		{"a digit", "0.wild.example.", "wild.example.", false},
		{"upper case in the query", "B.WILD.EXAMPLE.", "wild.example.", false},
		{"'[', just above the letters folding skips", "\\091.wild.example.", "wild.example.", false},
		{"a label ending in \\000", "b\\000.wild.example.", "wild.example.", false},
		{"a label that is only \\000", "\\000.wild.example.", "wild.example.", false},
		{"a 63-octet label", strings.Repeat("a", 63) + ".wild.example.", "wild.example.", false},
		{"a 63-octet label of \\255", strings.Repeat("\\255", 63) + ".wild.example.", "wild.example.", true},
		{"a name near 255 octets", "b." + longCE, longCE, false},
	} {
		t.Run(tc.what, func(t *testing.T) {
			nsec := coverNextCloser(snap, tc.qname, tc.ce, 3600)
			if tc.none {
				if nsec != nil {
					t.Fatalf("got %s, want none", nsec)
				}
				return
			}
			if nsec == nil {
				t.Fatal("no cover")
			}
			nc := nextCloserName(tc.qname, tc.ce)
			if testWireCompare(t, nsec.Hdr.Name, nc) >= 0 {
				t.Errorf("owner %s does not sort before %s", nsec.Hdr.Name, nc)
			}
			if testWireCompare(t, "zz."+nc, nsec.NextDomain) >= 0 || testWireCompare(t, nc, nsec.NextDomain) >= 0 {
				t.Errorf("next %s does not follow %s and its subtree", nsec.NextDomain, nc)
			}
			if !unboundProvesWildcard(t, nsec, tc.qname, tc.ce) {
				t.Errorf("%s does not prove %s under *.%s", nsec, tc.qname, tc.ce)
			}
			for _, name := range []string{nsec.Hdr.Name, nsec.NextDomain} {
				if _, ok := dns.IsDomainName(name); !ok {
					t.Errorf("%q is not a domain name", name)
				}
			}
			if tc.qname == "\\000.wild.example." {
				// Nothing sorts between wild.example. and \000.wild.example.,
				// so the owner is wild.example. itself: an ENT, which owns
				// nothing but RRSIG and NSEC.
				if !strings.EqualFold(nsec.Hdr.Name, "wild.example.") || len(nsec.TypeBitMap) != 2 {
					t.Errorf("got %s, want owner wild.example. with RRSIG NSEC only", nsec)
				}
			}
		})
	}
}

// A closest encloser that is not a proper ancestor of the query name has no
// next closer name, and gets no cover rather than a panic.
func TestCoverNextCloserNeedsAProperAncestor(t *testing.T) {
	zd := testSnapshotZone(t, "example.", proofZone)
	for _, tc := range []struct{ qname, ce string }{
		{"wild.example.", "wild.example."},
		{"b.wild.example.", "other.example."},
		{"example.", "b.wild.example."},
	} {
		if nsec := coverNextCloser(zd.publishedSnapshot(), tc.qname, tc.ce, 3600); nsec != nil {
			t.Errorf("coverNextCloser(%s, %s) = %s, want none", tc.qname, tc.ce, nsec)
		}
	}
}
