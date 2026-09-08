/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"fmt"

	"github.com/johanix/tdns/v2/debug/peer"
	"github.com/miekg/dns"
)

// Section 0, following tests/ixfr-interop's README: prove the oracle
// discriminates BEFORE anything relies on it.
//
// Every verdict this family reaches is a comparison that passes when two things
// agree. If a comparator cannot report a difference, every PASS above it is
// worthless and the run looks its cleanest exactly when it is most broken. So
// each comparator is handed a planted difference at startup and is required to
// object. A failure here is a setup error (exit 2), not a violation: the
// instrument is broken, and nothing it says about the SUT means anything.
//
// The unit tests in v2/debug/peer make the same checks. This is the runtime
// counterpart, and it is not redundant with them: it runs against the binary
// the operator actually invoked.

const section0Checks = 5

func section0() error {
	zone := "section0.test."
	base, err := buildSeedZone(zone, 100)
	if err != nil {
		return err
	}

	// 1. Identical content must compare equal, or every round fails for nothing.
	if d := peer.CompareContent(base, base.Clone()); !d.Equal() {
		return fmt.Errorf("the content comparator reports a zone as differing from itself: %s", d)
	}

	// 2. A planted content difference must be reported.
	altered := base.Clone()
	altered.Add(mustSection0RR("planted.section0.test. 3600 IN A 10.255.255.255"))
	if d := peer.CompareContent(base, altered); d.Equal() {
		return fmt.Errorf("the content comparator cannot see an added record, so N4 would pass vacuously")
	}

	// 3. A serial difference alone must NOT be reported: the SUT rewrites the
	//    serial by design, and a comparator that objected would fail every round.
	bumped := base.Clone()
	if err := bumped.SetSerial(101); err != nil {
		return err
	}
	if d := peer.CompareContent(base, bumped); !d.Equal() {
		return fmt.Errorf("the content comparator objects to a rewritten SOA serial, which is expected behaviour: %s", d)
	}

	// 4. A delta compared against the wrong change must be reported.
	rr := mustSection0RR("delta.section0.test. 3600 IN A 10.0.0.1")
	other := mustSection0RR("other.section0.test. 3600 IN A 10.0.0.2")
	good := peer.CompareDelta(
		peer.Change{Label: "s0", Add: []dns.RR{rr}},
		[]peer.Delta{{From: 100, To: 101, Added: []dns.RR{rr}}})
	if !good.Equal() {
		return fmt.Errorf("the delta comparator rejects a delta that matches its change: %s", good)
	}
	bad := peer.CompareDelta(
		peer.Change{Label: "s0", Add: []dns.RR{rr}},
		[]peer.Delta{{From: 100, To: 101, Added: []dns.RR{other}}})
	if bad.Equal() {
		return fmt.Errorf("the delta comparator cannot see a delta carrying the wrong record, so N5 would pass vacuously")
	}

	// 5. A missing signature must be reported.
	signed, err := section0SignedZone(zone)
	if err != nil {
		return err
	}
	if rep := peer.CheckSigning(signed); !rep.FullySigned() {
		return fmt.Errorf("the signing checker objects to a correctly signed zone: %s", rep)
	}
	stripped := signed.Clone()
	for _, r := range stripped.RRs() {
		if r.Header().Rrtype == dns.TypeRRSIG {
			stripped.Remove(r)
			break
		}
	}
	if rep := peer.CheckSigning(stripped); rep.FullySigned() {
		return fmt.Errorf("the signing checker cannot see a removed RRSIG, so N3 and N6 would pass vacuously")
	}
	return nil
}

// section0SignedZone is a minimal correctly signed zone: apex plus one host,
// a DNSKEY, an RRSIG on every authoritative RRset, and a two-name NSEC chain.
func section0SignedZone(zone string) (*peer.Zone, error) {
	const key = "section0.test. 3600 IN DNSKEY 257 3 15 kRBqRMzUZ6PJyDXkkyOJXHZTRlAvNRTOZUqbXkMDBHo="
	k, err := dns.NewRR(key)
	if err != nil {
		return nil, err
	}
	tag := k.(*dns.DNSKEY).KeyTag()

	sig := func(owner string, covered uint16) string {
		return fmt.Sprintf("%s 3600 IN RRSIG %s 15 %d 3600 20260930000000 20260901000000 %d %s c2lnbmF0dXJl",
			owner, dns.TypeToString[covered], dns.CountLabel(owner), tag, zone)
	}
	lines := []string{
		fmt.Sprintf("%s 3600 IN SOA ns.%s hostmaster.%s 100 7200 1800 604800 3600", zone, zone, zone),
		fmt.Sprintf("%s 3600 IN NS ns.%s", zone, zone),
		fmt.Sprintf("ns.%s 3600 IN A 127.0.0.1", zone),
		key,
		fmt.Sprintf("%s 3600 IN NSEC ns.%s NS SOA RRSIG NSEC DNSKEY", zone, zone),
		fmt.Sprintf("ns.%s 3600 IN NSEC %s A RRSIG NSEC", zone, zone),
		sig(zone, dns.TypeSOA), sig(zone, dns.TypeNS), sig(zone, dns.TypeDNSKEY), sig(zone, dns.TypeNSEC),
		sig("ns."+zone, dns.TypeA), sig("ns."+zone, dns.TypeNSEC),
	}
	var rrs []dns.RR
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			return nil, fmt.Errorf("section 0 fixture %q: %w", l, err)
		}
		rrs = append(rrs, rr)
	}
	return peer.ZoneFromRRs(zone, rrs), nil
}

func mustSection0RR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		// Unreachable: these are literals in this file.
		panic(fmt.Sprintf("section 0 fixture %q: %v", s, err))
	}
	return rr
}
