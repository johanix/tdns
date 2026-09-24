package tdns

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #637: the scanner applies the delegation policy bound to the parent zone.
// ProcessCSYNCNotify and ProcessCDSNotify run end to end; only the network is
// replaced (Scanner.queryChild, Scanner.validateRRset), except in
// TestScannerValidatesChildDataWithTheImrValidator, which uses the real one.

// trustNet is what a child's nameservers serve, and what the validator
// concludes about each RRset, keyed "name/TYPE".
type trustNet struct {
	served    map[string][]dns.RR
	verdict   map[string]cache.ValidationState // absent: insecure
	validated []string                         // keys handed to the validator

	// laterVerdict and laterDisagree apply from the second validation or
	// query of a key on: what differs between the start and the end SOA.
	laterVerdict  map[string]cache.ValidationState
	laterDisagree map[string]bool
	queried       map[string]int

	// disagree: the nameservers do not agree on the key, from the first
	// query on.
	disagree map[string]bool
}

func trustKey(name string, qtype uint16) string { return name + "/" + dns.TypeToString[qtype] }

func (n *trustNet) query(_ context.Context, qname string, qtype uint16, _ *core.RRset) (*core.RRset, bool, error) {
	k := trustKey(qname, qtype)
	if n.queried == nil {
		n.queried = map[string]int{}
	}
	n.queried[k]++
	// Data nobody serves comes back the way queryAllNSAndCompare reports every
	// nameserver answering that there is none: an empty RRset, in sync.
	inSync := !n.disagree[k] && !(n.queried[k] > 1 && n.laterDisagree[k])
	return &core.RRset{Name: qname, Class: dns.ClassINET, RRtype: qtype, RRs: n.served[k]}, inSync, nil
}

func (n *trustNet) validate(_ context.Context, rrset *core.RRset) (cache.ValidationState, error) {
	k := trustKey(rrset.Name, rrset.RRtype)
	seen := n.validations(k)
	n.validated = append(n.validated, k)
	if v, ok := n.laterVerdict[k]; ok && seen > 0 {
		return v, nil
	}
	if v, ok := n.verdict[k]; ok {
		return v, nil
	}
	return cache.ValidationStateInsecure, nil
}

func (n *trustNet) validations(key string) int {
	count := 0
	for _, k := range n.validated {
		if k == key {
			count++
		}
	}
	return count
}

func (n *trustNet) set(state cache.ValidationState, keys ...string) {
	for _, k := range keys {
		n.verdict[k] = state
	}
}

type trustBackend struct {
	data map[string]map[uint16][]dns.RR
}

func (b *trustBackend) ApplyChildUpdate(string, UpdateRequest) error { return nil }
func (b *trustBackend) GetDelegationData(string, string) (map[string]map[uint16][]dns.RR, error) {
	return b.data, nil
}
func (b *trustBackend) ListChildren(string) ([]string, error) { return nil, nil }
func (b *trustBackend) Name() string                          { return "trust-test" }

func trustStrict() DelegationPolicy {
	return DelegationPolicy{Name: "strict", Mechanisms: []string{"at-apex", "at-ns"}, RequireDnssec: true}
}

func trustLax() DelegationPolicy {
	return DelegationPolicy{Name: "lax", Mechanisms: []string{"at-apex"}}
}

// trustParent: example. delegates child to the given nameservers (default
// ns1.<child>, in bailiwick with A glue, and ns.provider.net.) under pol. The
// delegation backend holds the same delegation.
func trustParent(t *testing.T, child string, pol DelegationPolicy, nameservers ...string) *ZoneData {
	t.Helper()
	ns1 := "ns1." + child
	if len(nameservers) == 0 {
		nameservers = []string{ns1, "ns.provider.net."}
	}
	var nsRRs []dns.RR
	for _, ns := range nameservers {
		nsRRs = append(nsRRs, mustRR(t, child+" 3600 IN NS "+ns))
	}
	glue := rrs(t, ns1+" 3600 IN A 192.0.2.1")
	zd := newMapZone("example.", Primary, map[string][]dns.RR{
		"example.": {
			mustRR(t, "example. 3600 IN SOA ns.example. h.example. 1 3600 600 604800 300"),
			mustRR(t, "example. 3600 IN NS ns.example."),
		},
		child: nsRRs,
		ns1:   glue,
	})
	zd.DelegationPolicy = &pol
	zd.DelegationBackend = &trustBackend{data: map[string]map[uint16][]dns.RR{
		child: {dns.TypeNS: nsRRs},
		ns1:   {dns.TypeA: glue},
	}}
	return zd
}

func trustScanner(n *trustNet) *Scanner {
	sc := NewScanner(nil, false, false)
	quiet := log.New(io.Discard, "", 0)
	sc.Log["CDS"], sc.Log["CSYNC"] = quiet, quiet
	sc.queryChild = n.query
	sc.validateRRset = n.validate
	return sc
}

// csyncMove: the child replaces ns.provider.net. with ns2.provider.net. and
// keeps ns1.<child> and its address.
func csyncMove(t *testing.T, child string) *trustNet {
	t.Helper()
	ns1 := "ns1." + child
	return &trustNet{
		served: map[string][]dns.RR{
			trustKey(child, dns.TypeSOA):   rrs(t, child+" 3600 IN SOA "+ns1+" h."+child+" 7 3600 600 604800 300"),
			trustKey(child, dns.TypeCSYNC): rrs(t, child+" 3600 IN CSYNC 7 1 A NS AAAA"),
			trustKey(child, dns.TypeNS):    rrs(t, child+" 3600 IN NS "+ns1, child+" 3600 IN NS ns2.provider.net."),
			trustKey(ns1, dns.TypeA):       rrs(t, ns1+" 3600 IN A 192.0.2.1"),
		},
		verdict: map[string]cache.ValidationState{},
	}
}

func runCSYNC(t *testing.T, sc *Scanner, zd *ZoneData, child string) ScanTupleResponse {
	t.Helper()
	t.Cleanup(func() { forgetCsyncProcessed(child) })
	ch := make(chan ScanTupleResponse, 1)
	sc.ProcessCSYNCNotify(context.Background(), ScanTuple{Zone: child}, zd, ScanCSYNC, nil, ch)
	return <-ch
}

func runCDS(t *testing.T, sc *Scanner, zd *ZoneData, child string, currentDS []dns.RR) ScanTupleResponse {
	t.Helper()
	tuple := ScanTuple{Zone: child}
	if len(currentDS) > 0 {
		tuple.CurrentData.DS = &core.RRset{Name: child, RRtype: dns.TypeDS, RRs: currentDS}
	}
	ch := make(chan ScanTupleResponse, 1)
	sc.ProcessCDSNotify(context.Background(), tuple, zd, ScanCDS, nil, ch)
	return <-ch
}

func assertRefused(t *testing.T, resp ScanTupleResponse, wantReason string) {
	t.Helper()
	if resp.Validation != ScanRefused || !resp.Error {
		t.Fatalf("validation %q, error %v (%s); want refused", resp.Validation, resp.Error, resp.ErrorMsg)
	}
	if !strings.Contains(resp.ValidationReason, wantReason) {
		t.Errorf("reason %q does not say %q", resp.ValidationReason, wantReason)
	}
	if n := len(resp.DSAdds) + len(resp.DSRemoves) + len(resp.NSAdds) + len(resp.NSRemoves) + len(resp.GlueAdds) + len(resp.GlueRemoves); n > 0 {
		t.Errorf("a refused scan carries %d changes", n)
	}
	if scanResponseChangesDelegation(resp) {
		t.Error("a refused scan would be applied")
	}
}

// The case that found #637: a parent whose policy requires DNSSEC, an
// unsigned child, and an NS change applied through NOTIFY(CSYNC). Every RRset
// the change rests on has to validate, and no-dnssec-validation in
// scanner.options does not change that.
func TestScanCSYNCUnderRequireDnssecRefusesDataThatIsNotSecure(t *testing.T) {
	for i, tc := range []struct {
		name    string
		prepare func(n *trustNet, child string)
		options []string
		want    string
	}{
		{name: "an unsigned child", want: "SOA is insecure"},
		{name: "no-dnssec-validation does not override the policy", options: []string{"no-dnssec-validation"}, want: "SOA is insecure"},
		{name: "the CSYNC is not secure", want: "CSYNC is insecure", prepare: func(n *trustNet, c string) {
			n.set(cache.ValidationStateSecure, trustKey(c, dns.TypeSOA))
		}},
		{name: "the NS RRset is not secure", want: "NS is insecure", prepare: func(n *trustNet, c string) {
			n.set(cache.ValidationStateSecure, trustKey(c, dns.TypeSOA), trustKey(c, dns.TypeCSYNC))
		}},
		{name: "glue for a kept nameserver is bogus", want: "A is bogus", prepare: func(n *trustNet, c string) {
			n.set(cache.ValidationStateSecure, trustKey(c, dns.TypeSOA), trustKey(c, dns.TypeCSYNC), trustKey(c, dns.TypeNS))
			n.set(cache.ValidationStateBogus, trustKey("ns1."+c, dns.TypeA))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := fmt.Sprintf("refused%d.example.", i)
			n := csyncMove(t, child)
			if tc.prepare != nil {
				tc.prepare(n, child)
			}
			sc := trustScanner(n)
			sc.Options = tc.options

			resp := runCSYNC(t, sc, trustParent(t, child, trustStrict()), child)

			assertRefused(t, resp, tc.want)
			if !strings.Contains(resp.ValidationReason, `"strict"`) {
				t.Errorf("reason %q does not name the policy", resp.ValidationReason)
			}
			if _, marked := csyncProcessedSerial(child); marked {
				t.Error("a refused CSYNC was recorded as processed, so it would never be retried")
			}
		})
	}
}

func TestScanCSYNCUnderRequireDnssecAppliesSecureData(t *testing.T) {
	const child = "secure.example."
	n := csyncMove(t, child)
	n.set(cache.ValidationStateSecure, trustKey(child, dns.TypeSOA), trustKey(child, dns.TypeCSYNC),
		trustKey(child, dns.TypeNS), trustKey("ns1."+child, dns.TypeA))

	resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustStrict()), child)

	if resp.Error || resp.Validation != ScanValidated {
		t.Fatalf("validation %q, error %q; want validated", resp.Validation, resp.ErrorMsg)
	}
	if got := names(resp.NSAdds); len(got) != 1 || !strings.Contains(got[0], "ns2.provider.net.") {
		t.Errorf("NS adds %v, want ns2.provider.net.", got)
	}
	if got := names(resp.NSRemoves); len(got) != 1 || !strings.Contains(got[0], "ns.provider.net.") {
		t.Errorf("NS removes %v, want ns.provider.net.", got)
	}
	if !scanResponseChangesDelegation(resp) {
		t.Error("a validated change would not be applied")
	}
	if got := n.validations(trustKey(child, dns.TypeSOA)); got != 2 {
		t.Errorf("the SOA was validated %d time(s), want 2: the start and the end SOA", got)
	}
}

// The end SOA goes through the same fetch as the start SOA. An end serial that
// does not validate, or that the nameservers disagree on, could hide a change
// made during the analysis, so it stops the CSYNC before anything is recorded.
func TestScanCSYNCEndSOAIsValidatedAndAgreedOn(t *testing.T) {
	for i, tc := range []struct {
		name    string
		prepare func(n *trustNet, soa string)
		refused bool
		want    string
	}{
		{name: "the end SOA is bogus", refused: true, want: "SOA is bogus", prepare: func(n *trustNet, soa string) {
			n.laterVerdict = map[string]cache.ValidationState{soa: cache.ValidationStateBogus}
		}},
		{name: "the nameservers disagree on the end SOA", want: "not in sync for end SOA", prepare: func(n *trustNet, soa string) {
			n.laterDisagree = map[string]bool{soa: true}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := fmt.Sprintf("endsoa%d.example.", i)
			n := csyncMove(t, child)
			soa := trustKey(child, dns.TypeSOA)
			n.set(cache.ValidationStateSecure, soa, trustKey(child, dns.TypeCSYNC),
				trustKey(child, dns.TypeNS), trustKey("ns1."+child, dns.TypeA))
			tc.prepare(n, soa)

			resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustStrict()), child)

			if tc.refused {
				assertRefused(t, resp, tc.want)
			} else {
				if !resp.Error || !strings.Contains(resp.ErrorMsg, tc.want) {
					t.Fatalf("error %v %q; want an error saying %q", resp.Error, resp.ErrorMsg, tc.want)
				}
				if scanResponseChangesDelegation(resp) {
					t.Error("a CSYNC stopped at the end SOA would be applied")
				}
			}
			if _, marked := csyncProcessedSerial(child); marked {
				t.Error("a CSYNC stopped at the end SOA was recorded as processed")
			}
		})
	}
}

func TestScanCSYNCWithoutRequireDnssecIsAppliedAndSaysUnvalidated(t *testing.T) {
	const child = "lax.example."
	n := csyncMove(t, child)

	resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

	if resp.Error || resp.Validation != ScanUnvalidated {
		t.Fatalf("validation %q, error %q; want unvalidated", resp.Validation, resp.ErrorMsg)
	}
	if !strings.Contains(resp.ValidationReason, `"lax" does not require DNSSEC`) {
		t.Errorf("reason %q does not say why nothing was validated", resp.ValidationReason)
	}
	if len(resp.NSAdds) != 1 || !scanResponseChangesDelegation(resp) {
		t.Errorf("NS adds %v, applied %v; want the change applied", names(resp.NSAdds), scanResponseChangesDelegation(resp))
	}
	if len(n.validated) != 0 {
		t.Errorf("validated %v under a policy that does not require it", n.validated)
	}
}

func TestScanCDSFollowsTheDelegationPolicy(t *testing.T) {
	const oldDigest = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	atNSOnly := DelegationPolicy{Name: "ns-only", Mechanisms: []string{"at-ns"}, RequireDnssec: true}
	atApexStrict := DelegationPolicy{Name: "apex-strict", Mechanisms: []string{"at-apex"}, RequireDnssec: true}
	lockedDown := DelegationPolicy{Name: "locked", Mechanisms: []string{}, RequireDnssec: true}

	for i, tc := range []struct {
		name          string
		pol           DelegationPolicy
		inBailiwick   bool // the child's only nameserver is ns1.<child>
		hasDS         bool
		cdsVerdict    cache.ValidationState
		options       []string
		atApexChecks  int
		want          ScanValidation
		wantReason    string
		wantValidated int
	}{
		{name: "with a DS, strict: a bogus CDS changes nothing", pol: trustStrict(), hasDS: true,
			cdsVerdict: cache.ValidationStateBogus, want: ScanRefused, wantReason: "CDS is bogus", wantValidated: 1},
		{name: "with a DS, strict: an insecure CDS changes nothing", pol: trustStrict(), hasDS: true,
			want: ScanRefused, wantReason: "CDS is insecure", wantValidated: 1},
		{name: "with a DS, strict: a secure CDS is applied", pol: trustStrict(), hasDS: true,
			cdsVerdict: cache.ValidationStateSecure, want: ScanValidated, wantReason: "through the child's DS", wantValidated: 2},
		// With a DS the chain exists, so the CDS is validated whatever the
		// policy's require-dnssec says.
		{name: "with a DS, lax: a bogus CDS changes nothing", pol: trustLax(), hasDS: true,
			cdsVerdict: cache.ValidationStateBogus, want: ScanRefused, wantReason: "has a DS, so its CDS must validate", wantValidated: 1},
		{name: "with a DS, lax: an insecure CDS changes nothing", pol: trustLax(), hasDS: true,
			want: ScanRefused, wantReason: "CDS is insecure", wantValidated: 1},
		{name: "with a DS, lax: a secure CDS is applied, validated", pol: trustLax(), hasDS: true,
			cdsVerdict: cache.ValidationStateSecure, want: ScanValidated, wantReason: "through the child's DS", wantValidated: 2},
		{name: "bootstrap under at-ns only: at-apex in scanner.options is not taken", pol: atNSOnly, inBailiwick: true,
			cdsVerdict: cache.ValidationStateSecure, options: []string{"at-apex", "no-dnssec-validation"},
			want: ScanRefused, wantReason: "no bootstrap mechanism"},
		{name: "bootstrap under at-ns: no signaling names can be asked", pol: atNSOnly,
			want: ScanRefused, wantReason: "RFC 9615"},
		{name: "bootstrap at-apex, strict: an insecure CDS is refused", pol: atApexStrict,
			want: ScanRefused, wantReason: "CDS is insecure", wantValidated: 1},
		{name: "bootstrap at-apex, strict: a secure CDS is applied", pol: atApexStrict,
			cdsVerdict: cache.ValidationStateSecure, want: ScanValidated, wantReason: "at the child's apex", wantValidated: 1},
		{name: "bootstrap at-apex, lax, one check", pol: trustLax(), atApexChecks: 1,
			want: ScanUnvalidated, wantReason: "RFC 8078"},
		{name: "bootstrap at-apex, lax: checks > 1 is refused, not ignored", pol: trustLax(), atApexChecks: 3,
			want: ScanRefused, wantReason: "at-apex.checks is 3"},
		{name: "bootstrap under a policy with no mechanisms", pol: lockedDown,
			cdsVerdict: cache.ValidationStateSecure, want: ScanRefused, wantReason: "no bootstrap mechanism"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := fmt.Sprintf("cds%d.example.", i)
			var zd *ZoneData
			if tc.inBailiwick {
				zd = trustParent(t, child, tc.pol, "ns1."+child)
			} else {
				zd = trustParent(t, child, tc.pol)
			}
			n := &trustNet{served: map[string][]dns.RR{}, verdict: map[string]cache.ValidationState{}}
			serveKeyAndCDS(t, n, child)
			n.set(cache.ValidationStateSecure, trustKey(child, dns.TypeDNSKEY))
			if tc.cdsVerdict != 0 {
				n.set(tc.cdsVerdict, trustKey(child, dns.TypeCDS))
			}
			sc := trustScanner(n)
			sc.Options = tc.options
			sc.AtApexChecks = tc.atApexChecks
			var currentDS []dns.RR
			if tc.hasDS {
				currentDS = rrs(t, child+" 3600 IN DS 1111 13 2 "+oldDigest)
			}

			resp := runCDS(t, sc, zd, child, currentDS)

			if tc.want == ScanRefused {
				assertRefused(t, resp, tc.wantReason)
			} else {
				if resp.Error || resp.Validation != tc.want {
					t.Fatalf("validation %q, error %q; want %q", resp.Validation, resp.ErrorMsg, tc.want)
				}
				if !strings.Contains(resp.ValidationReason, tc.wantReason) {
					t.Errorf("reason %q does not say %q", resp.ValidationReason, tc.wantReason)
				}
				if len(resp.DSAdds) != 1 || !scanResponseChangesDelegation(resp) {
					t.Errorf("DS adds %v, applied %v; want the new DS applied", names(resp.DSAdds), scanResponseChangesDelegation(resp))
				}
			}
			if len(n.validated) != tc.wantValidated {
				t.Errorf("validator asked about %v, want %d call(s)", n.validated, tc.wantValidated)
			}
		})
	}
}

// serveKeyAndCDS makes n serve a new DNSKEY for child and a CDS naming it, and
// returns both.
func serveKeyAndCDS(t *testing.T, n *trustNet, child string) (*dns.DNSKEY, *dns.CDS) {
	t.Helper()
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: child, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	if _, err := key.Generate(256); err != nil {
		t.Fatalf("generating a key for %s: %v", child, err)
	}
	cds := key.ToDS(dns.SHA256).ToCDS()
	n.served[trustKey(child, dns.TypeDNSKEY)] = []dns.RR{key}
	n.served[trustKey(child, dns.TypeCDS)] = []dns.RR{cds}
	return key, cds
}

// A CDS that passes the trust gate can still name no key the child publishes: a
// typo in a digest, or a key not published yet. Applied, its DS would make the
// child's whole zone bogus. The scan refuses it by the rule a DS change by
// UPDATE meets (CheckDelegationCoherence).
func TestScanCDSMustLeadToAKeyTheChildPublishes(t *testing.T) {
	const oldDigest = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	for i, tc := range []struct {
		name       string
		hasDS      bool
		prepare    func(t *testing.T, n *trustNet, child string)
		wantReason string // empty: applied
	}{
		{name: "with a DS: a CDS for the published key is applied", hasDS: true},
		{name: "with a DS: a CDS for a key not published is refused", hasDS: true,
			prepare: func(t *testing.T, n *trustNet, child string) {
				other := &trustNet{served: map[string][]dns.RR{}}
				key, _ := serveKeyAndCDS(t, other, child)
				n.served[trustKey(child, dns.TypeDNSKEY)] = []dns.RR{key}
			},
			wantReason: "matches none of the 1 DNSKEY(s)"},
		{name: "with a DS: no DNSKEY published is refused", hasDS: true,
			prepare: func(t *testing.T, n *trustNet, child string) {
				delete(n.served, trustKey(child, dns.TypeDNSKEY))
			},
			wantReason: "publishes no DNSKEY RRset"},
		{name: "with a DS: a DNSKEY RRset that does not validate is refused", hasDS: true,
			prepare: func(t *testing.T, n *trustNet, child string) {
				n.set(cache.ValidationStateInsecure, trustKey(child, dns.TypeDNSKEY))
			},
			wantReason: "did not DNSSEC-validate"},
		{name: "with a DS: one CDS record for a published key is enough", hasDS: true,
			prepare: func(t *testing.T, n *trustNet, child string) {
				n.served[trustKey(child, dns.TypeCDS)] = append(n.served[trustKey(child, dns.TypeCDS)],
					mustRR(t, child+" 3600 IN CDS 4444 13 2 "+strings.Repeat("ab", 32)))
			}},
		{name: "first DS: an unvalidated DNSKEY RRset with the key is enough"},
		{name: "first DS: a CDS for a key not published is refused",
			prepare: func(t *testing.T, n *trustNet, child string) {
				other := &trustNet{served: map[string][]dns.RR{}}
				key, _ := serveKeyAndCDS(t, other, child)
				n.served[trustKey(child, dns.TypeDNSKEY)] = []dns.RR{key}
			},
			wantReason: "matches none of the 1 DNSKEY(s)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := fmt.Sprintf("cdskey%d.example.", i)
			zd := trustParent(t, child, trustLax())
			n := &trustNet{served: map[string][]dns.RR{}, verdict: map[string]cache.ValidationState{}}
			serveKeyAndCDS(t, n, child)
			n.set(cache.ValidationStateSecure, trustKey(child, dns.TypeCDS), trustKey(child, dns.TypeDNSKEY))
			if tc.prepare != nil {
				tc.prepare(t, n, child)
			}
			sc := trustScanner(n)
			var currentDS []dns.RR
			if tc.hasDS {
				currentDS = rrs(t, child+" 3600 IN DS 1111 13 2 "+oldDigest)
			}

			resp := runCDS(t, sc, zd, child, currentDS)

			if tc.wantReason != "" {
				assertRefused(t, resp, tc.wantReason)
				return
			}
			if resp.Error || !scanResponseChangesDelegation(resp) {
				t.Fatalf("error %q, applied %v; want the DS change applied", resp.ErrorMsg, scanResponseChangesDelegation(resp))
			}
		})
	}
}

// RFC 8078's removal sentinel for a child with no DS asks for no change. It is
// settled before the trust gate, so a strict parent does not report a refusal
// of a no-op on every NOTIFY.
func TestScanCDSRemovalSentinelWithoutDSIsANoOp(t *testing.T) {
	const child = "sentinel.example."
	n := &trustNet{
		served:  map[string][]dns.RR{trustKey(child, dns.TypeCDS): rrs(t, child+" 3600 IN CDS 0 0 0 00")},
		verdict: map[string]cache.ValidationState{},
	}

	resp := runCDS(t, trustScanner(n), trustParent(t, child, trustStrict()), child, nil)

	if resp.Error || resp.DataChanged || resp.Validation != "" {
		t.Errorf("error %q, changed %v, validation %q; want a quiet no-op", resp.ErrorMsg, resp.DataChanged, resp.Validation)
	}
	if len(n.validated) != 0 {
		t.Errorf("validated %v for a no-op", n.validated)
	}
}

func TestScanResponseChangesDelegationOnlyAfterATrustDecision(t *testing.T) {
	ns := rrs(t, "c.example. 3600 IN NS ns.example.")
	for _, tc := range []struct {
		name string
		resp ScanTupleResponse
		want bool
	}{
		{"validated change", ScanTupleResponse{DataChanged: true, NSAdds: ns, Validation: ScanValidated}, true},
		{"unvalidated change", ScanTupleResponse{DataChanged: true, NSAdds: ns, Validation: ScanUnvalidated}, true},
		{"refused", ScanTupleResponse{DataChanged: true, NSAdds: ns, Validation: ScanRefused}, false},
		{"no trust decision recorded", ScanTupleResponse{DataChanged: true, NSAdds: ns}, false},
		{"an error", ScanTupleResponse{DataChanged: true, NSAdds: ns, Validation: ScanValidated, Error: true}, false},
		{"validated, nothing to change", ScanTupleResponse{DataChanged: true, Validation: ScanValidated}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanResponseChangesDelegation(tc.resp); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// The production validator, not the stub: validateChildData hands the child's
// RRset to the IMR's cache, which must say Secure for a correctly signed RRset
// and something else for the same RRset without its signature.
func TestScannerValidatesChildDataWithTheImrValidator(t *testing.T) {
	prevGlobal := Globals.ImrEngine
	t.Cleanup(func() { Globals.ImrEngine = prevGlobal })

	imr := newTestImr(t)
	conf := &Config{}
	conf.Internal.ImrReady = NewImrReadiness()
	conf.publishImr(imr)
	sc := NewScanner(nil, false, false)
	sc.conf = conf

	const zone = "signed.example."
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	imr.Cache.DnskeyCache.Set(zone, key.KeyTag(), &cache.CachedDnskeyRRset{
		Name: zone, Keyid: key.KeyTag(), State: cache.ValidationStateSecure, TrustAnchor: true,
		Dnskey: *key, Expiration: time.Now().Add(time.Hour),
	})

	ns := rrs(t, zone+" 3600 IN NS ns1."+zone, zone+" 3600 IN NS ns.provider.net.")
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeNS,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(zone)),
		OrigTtl:     3600,
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  zone,
	}
	if err := sig.Sign(priv.(crypto.Signer), ns); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	signed := &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: ns, RRSIGs: []dns.RR{sig}}
	if err := sc.requireSecure(ctx, signed, trustStrict()); err != nil {
		t.Fatalf("a correctly signed RRset was refused: %v", err)
	}

	unsigned := &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: ns}
	if err := sc.requireSecure(ctx, unsigned, trustStrict()); !isScanRefusal(err) {
		t.Fatalf("the same RRset without its signature was not refused: %v", err)
	}
}
