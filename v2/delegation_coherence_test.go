package tdns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const cohChild = "child.example."

// cohKey builds a KSK and the DS that matches it.
func cohKey(t *testing.T, pub string) (*dns.DNSKEY, *dns.DS) {
	t.Helper()
	dk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: cohChild, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: pub,
	}
	ds := dk.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("ToDS returned nil")
	}
	return dk, ds
}

func addDS(ds *dns.DS) dns.RR {
	c := dns.Copy(ds)
	c.Header().Class = dns.ClassINET
	return c
}

func delDSRRset() dns.RR {
	return &dns.DS{Hdr: dns.RR_Header{Name: cohChild, Rrtype: dns.TypeDS, Class: dns.ClassANY}}
}

func delOneDS(ds *dns.DS) dns.RR {
	c := dns.Copy(ds)
	c.Header().Class = dns.ClassNONE
	return c
}

func fetcherFor(keys ...*dns.DNSKEY) dnskeyFetcher {
	return func(string) ([]dns.RR, error) {
		var out []dns.RR
		for _, k := range keys {
			out = append(out, k)
		}
		return out, nil
	}
}

// An update that says nothing about DS must not be checked at all -- and must
// not trigger a DNSKEY lookup. NS and glue changes cannot break the chain of
// trust, and making them depend on the child being reachable would be a new
// failure mode for the common case.
func TestCoherenceIgnoresUpdatesThatDoNotTouchDS(t *testing.T) {
	_, ds := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")
	ns, err := dns.NewRR(cohChild + " 3600 IN NS ns1." + cohChild)
	if err != nil {
		t.Fatal(err)
	}

	called := false
	fetch := func(string) ([]dns.RR, error) {
		called = true
		return nil, fmt.Errorf("should not have been called")
	}

	if err := CheckDelegationCoherence(cohChild, []dns.RR{ds}, []dns.RR{ns}, fetch); err != nil {
		t.Fatalf("an NS-only update was refused: %v", err)
	}
	if called {
		t.Error("an NS-only update triggered a DNSKEY lookup")
	}
}

// Clearing the DS is legitimate: it is what going insecure means, and it leaves
// the child working rather than bogus.
func TestCoherenceAllowsClearingTheDS(t *testing.T) {
	_, ds := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")

	called := false
	fetch := func(string) ([]dns.RR, error) {
		called = true
		return nil, nil
	}
	if err := CheckDelegationCoherence(cohChild, []dns.RR{ds}, []dns.RR{delDSRRset()}, fetch); err != nil {
		t.Fatalf("clearing the DS was refused: %v", err)
	}
	if called {
		t.Error("clearing the DS triggered a DNSKEY lookup; going insecure needs no key to match")
	}
}

// The multi-DS rollover: a DS is added for a key whose DNSKEY is not published
// yet, alongside the DS for the live key. This MUST be allowed -- it is the
// procedure the rollover engine implements, and a rule of "every DS must match
// a published key" would reject it.
func TestCoherenceAllowsAPrePublishedDS(t *testing.T) {
	liveKey, liveDS := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")
	_, incomingDS := cohKey(t, "1G+3r1iVxr1l3jWgTnKEWXDNQSa8iiRWS/5Hi1ECTE1=")

	err := CheckDelegationCoherence(cohChild,
		[]dns.RR{liveDS},
		[]dns.RR{addDS(incomingDS)},
		fetcherFor(liveKey))
	if err != nil {
		t.Fatalf("a pre-published DS alongside the live one was refused: %v", err)
	}
}

// The rollover driven from the wrong end: the live key's DS is replaced by one
// for a key that is not published. Nothing then validates.
func TestCoherenceRefusesADSSetMatchingNoPublishedKey(t *testing.T) {
	liveKey, liveDS := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")
	_, unpublishedDS := cohKey(t, "1G+3r1iVxr1l3jWgTnKEWXDNQSa8iiRWS/5Hi1ECTE1=")

	err := CheckDelegationCoherence(cohChild,
		[]dns.RR{liveDS},
		[]dns.RR{delOneDS(liveDS), addDS(unpublishedDS)},
		fetcherFor(liveKey))
	if err == nil {
		t.Fatal("a DS set matching no published key was accepted; the child would be bogus")
	}
	if !strings.Contains(err.Error(), "matches none") {
		t.Errorf("unexpected refusal reason: %v", err)
	}
}

// Bootstrapping from insecure: the first DS must match a published key, and
// does.
func TestCoherenceAllowsBootstrappingWithAMatchingDS(t *testing.T) {
	key, ds := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")

	if err := CheckDelegationCoherence(cohChild, nil, []dns.RR{addDS(ds)}, fetcherFor(key)); err != nil {
		t.Fatalf("bootstrapping with a matching DS was refused: %v", err)
	}
}

// Fail closed. Accepting on a lookup failure would make the check a formality
// that anything can bypass by being unreachable at the right moment.
func TestCoherenceRefusesWhenTheDNSKEYLookupFails(t *testing.T) {
	_, ds := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")

	fetch := func(string) ([]dns.RR, error) { return nil, fmt.Errorf("no route to host") }
	err := CheckDelegationCoherence(cohChild, nil, []dns.RR{addDS(ds)}, fetch)
	if err == nil {
		t.Fatal("a DS change was accepted despite the DNSKEY lookup failing")
	}
	if !strings.Contains(err.Error(), "DNSKEY lookup failed") {
		t.Errorf("unexpected refusal reason: %v", err)
	}
}

// A ZSK must not satisfy the rule: a DS that hashes a non-SEP key is not a
// usable entry point.
func TestCoherenceIgnoresNonSEPKeys(t *testing.T) {
	dk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: cohChild, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256, // ZONE, no SEP
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=",
	}
	ds := dk.ToDS(dns.SHA256)

	err := CheckDelegationCoherence(cohChild, nil, []dns.RR{addDS(ds)}, fetcherFor(dk))
	if err == nil {
		t.Fatal("a DS hashing a ZSK was accepted as an entry point")
	}
}

// Deleting the whole name (ClassANY/TypeANY) takes the DS with it.
func TestCoherenceTreatsDeleteAllAsClearingTheDS(t *testing.T) {
	_, ds := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")
	delAll := &dns.ANY{Hdr: dns.RR_Header{Name: cohChild, Rrtype: dns.TypeANY, Class: dns.ClassANY}}

	result, touched := dsAfterActions(cohChild, []dns.RR{ds}, []dns.RR{delAll})
	if !touched {
		t.Fatal("delete-all was not recognised as touching the DS")
	}
	if len(result) != 0 {
		t.Errorf("delete-all left %d DS records", len(result))
	}
}

// childNameFromUpdate does label arithmetic, which is easy to get subtly wrong
// and produces a plausible-looking name when it does.
func TestChildNameFromUpdate(t *testing.T) {
	mk := func(names ...string) *dns.Msg {
		m := new(dns.Msg)
		m.SetUpdate("example.")
		for _, n := range names {
			m.Ns = append(m.Ns, &dns.NS{
				Hdr: dns.RR_Header{Name: n, Rrtype: dns.TypeNS, Class: dns.ClassINET},
				Ns:  "ns1." + n,
			})
		}
		return m
	}

	tests := []struct {
		name  string
		names []string
		want  string
	}{
		{"apex of the child", []string{"child.example."}, "child.example."},
		{"glue under the child", []string{"ns1.child.example."}, "child.example."},
		{"deeper name still maps to the delegation", []string{"a.b.child.example."}, "child.example."},
		{"child apex and its glue together", []string{"child.example.", "ns1.child.example."}, "child.example."},
		{"records at the parent apex are not a delegation", []string{"example."}, ""},
		{"names outside the parent are ignored", []string{"child.other."}, ""},
		{"no records", nil, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := childNameFromUpdate("example.", mk(tc.names...))
			if got != tc.want {
				t.Errorf("childNameFromUpdate = %q, want %q", got, tc.want)
			}
		})
	}
}
