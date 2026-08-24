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

// The delegation an update is about is the owner of its DS records -- no label
// arithmetic, so a multi-label child works by construction. The earlier version
// trimmed names to one label below the apex, which silently skipped the check
// for foo.bar.example. of example.: an authorised principal could publish a
// bogus DS there and the parent would take it.
func TestChildrenWithDSChanges(t *testing.T) {
	ds := func(owner string, class uint16) dns.RR {
		return &dns.DS{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeDS, Class: class}}
	}
	ns := func(owner string) dns.RR {
		return &dns.NS{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1." + owner}
	}
	anyDel := func(owner string) dns.RR {
		return &dns.ANY{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeANY, Class: dns.ClassANY}}
	}

	tests := []struct {
		name    string
		actions []dns.RR
		want    []string
	}{
		{"single-label child", []dns.RR{ds("child.example.", dns.ClassINET)}, []string{"child.example."}},
		{"multi-label child", []dns.RR{ds("foo.bar.example.", dns.ClassINET)}, []string{"foo.bar.example."}},
		{"DS delete counts", []dns.RR{ds("child.example.", dns.ClassANY)}, []string{"child.example."}},
		{"delete-all takes the DS with it", []dns.RR{anyDel("child.example.")}, []string{"child.example."}},
		{"NS-only touches no DS", []dns.RR{ns("child.example.")}, nil},
		{"records at the apex are not a delegation", []dns.RR{ds("example.", dns.ClassINET)}, nil},
		{"names outside the parent are ignored", []dns.RR{ds("child.other.", dns.ClassINET)}, nil},
		{
			"two children in one update",
			[]dns.RR{ds("a.example.", dns.ClassINET), ds("b.example.", dns.ClassANY)},
			[]string{"a.example.", "b.example."},
		},
		{
			"the same child twice is listed once",
			[]dns.RR{ds("child.example.", dns.ClassANY), ds("child.example.", dns.ClassINET)},
			[]string{"child.example."},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := childrenWithDSChanges("example.", tc.actions)
			if len(got) != len(tc.want) {
				t.Fatalf("children = %v, want %v", got, tc.want)
			}
			for i := range got {
				if !strings.EqualFold(got[i], tc.want[i]) {
					t.Errorf("children[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// A request that mentions DS but leaves the set unchanged must not be refused,
// and must not make an unrelated NS edit depend on the child being reachable.
func TestCoherenceIgnoresANoOpDSChange(t *testing.T) {
	_, ds := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")

	called := false
	fetch := func(string) ([]dns.RR, error) {
		called = true
		return nil, fmt.Errorf("should not have been called")
	}

	// Re-adding the DS that is already published changes nothing.
	if err := CheckDelegationCoherence(cohChild, []dns.RR{ds}, []dns.RR{addDS(ds)}, fetch); err != nil {
		t.Fatalf("a no-op DS re-add was refused: %v", err)
	}
	if called {
		t.Error("a no-op DS change triggered a DNSKEY lookup")
	}
}

// An unvalidated DNSKEY answer must not bless a DS. The whole point of the
// check is to stop the parent publishing something nothing can validate, and an
// attacker-supplied key set would otherwise certify exactly that.
func TestCoherenceRefusesAnUnvalidatedDNSKEYAnswer(t *testing.T) {
	key, ds := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")

	// The fetcher itself reports the failure, as imrDnskeyFetcher does for an
	// unvalidated response.
	fetch := func(string) ([]dns.RR, error) {
		return nil, fmt.Errorf("DNSKEY RRset for %s did not DNSSEC-validate", cohChild)
	}
	if err := CheckDelegationCoherence(cohChild, nil, []dns.RR{addDS(ds)}, fetch); err == nil {
		t.Fatal("a DS was accepted on the strength of an unvalidated DNSKEY answer")
	}
	// Sanity: the same DS with a validated answer is fine.
	if err := CheckDelegationCoherence(cohChild, nil, []dns.RR{addDS(ds)}, fetcherFor(key)); err != nil {
		t.Fatalf("a validated matching DS was refused: %v", err)
	}
}

// SEP is advisory and validators ignore it, so a DS hashing a flags-256 CSK is
// a usable entry point and must not be refused.
func TestCoherenceAcceptsAZoneBitCSK(t *testing.T) {
	csk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: cohChild, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256, // ZONE, no SEP
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=",
	}
	ds := csk.ToDS(dns.SHA256)

	if err := CheckDelegationCoherence(cohChild, nil, []dns.RR{addDS(ds)}, fetcherFor(csk)); err != nil {
		t.Fatalf("a DS hashing a ZONE-bit CSK was refused: %v", err)
	}
}
