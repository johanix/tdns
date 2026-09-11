/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// Two KEYs, 32 octets each: bytes 0x00-0x1f and 0x20-0x3f.
const (
	lookupWildKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	lookupHostKey = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
)

// y.blocked.example. is an empty non-terminal.
const lookupWildZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
*.wild.example.	3600	IN	TXT	"wild"
*.blocked.example.	3600	IN	TXT	"blocked"
x.y.blocked.example.	3600	IN	TXT	"x"
*.keys.example.	3600	IN	KEY	512 3 15 ` + lookupWildKey + `
host.keys.example.	3600	IN	KEY	512 3 15 ` + lookupHostKey + `
`

// LookupRRset answers from the wildcard at the closest encloser, as
// QueryResponder does, and not from one at the immediate parent. An empty
// non-terminal exists, so no wildcard answers for it.
func TestLookupRRsetWildcard(t *testing.T) {
	zd := testZone(t, "example.", lookupWildZone)

	for _, tc := range []struct {
		what  string
		qname string
		found bool
	}{
		{"one label below the wildcard", "a.wild.example.", true},
		{"two labels below the wildcard", "a.b.wild.example.", true},
		{"an empty non-terminal under a wildcard", "y.blocked.example.", false},
		{"below an empty non-terminal", "a.y.blocked.example.", false},
	} {
		t.Run(tc.what, func(t *testing.T) {
			rrset, err := zd.LookupRRset(tc.qname, dns.TypeTXT, false)
			if err != nil {
				t.Fatalf("LookupRRset(%s): %v", tc.qname, err)
			}
			found := rrset != nil && len(rrset.RRs) > 0
			if found != tc.found {
				t.Fatalf("LookupRRset(%s) found = %v, want %v: %v", tc.qname, found, tc.found, rrset)
			}
			if found && rrset.RRs[0].Header().Name != tc.qname {
				t.Errorf("owner = %s, want %s", rrset.RRs[0].Header().Name, tc.qname)
			}
		})
	}
}

// A SIG(0) signer's KEY is the one published at the signer's name. A wildcard
// KEY is not a key for every name beneath it, and finding a signer's key
// through one let a *.parent KEY authenticate any signer under the parent.
func TestSig0KeyDiscoveryIgnoresWildcards(t *testing.T) {
	zd := testZone(t, "example.", lookupWildZone)

	keyTag := func(owner, b64 string) uint16 {
		rr, err := dns.NewRR(owner + " 3600 IN KEY 512 3 15 " + b64)
		if err != nil {
			t.Fatalf("NewRR: %v", err)
		}
		return rr.(*dns.KEY).KeyTag()
	}

	if k, err := zd.FindSig0KeyViaDNS("other.keys.example.", keyTag("other.keys.example.", lookupWildKey)); err == nil && k != nil {
		t.Errorf("found a key for other.keys.example. through *.keys.example.: %+v", k)
	}
	k, err := zd.FindSig0KeyViaDNS("host.keys.example.", keyTag("host.keys.example.", lookupHostKey))
	if err != nil || k == nil {
		t.Fatalf("no key for host.keys.example., which publishes its own: key %v, err %v", k, err)
	}
	if k.Name != "host.keys.example." {
		t.Errorf("key name = %s, want host.keys.example.", k.Name)
	}
}
