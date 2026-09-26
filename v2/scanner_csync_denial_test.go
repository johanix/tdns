/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"crypto"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #779: under a delegation policy that requires DNSSEC, a CSYNC removes a glue
// type the child no longer serves once the proof of its absence validates.
// Glue whose absence cannot be proven stays, and is named in the scan result
// instead of being skipped in silence.

// AuthQueryEngine keeps the authority section of an authoritative NODATA, the
// proof that there is no such RRset, and keeps none for an answer with data.
func TestAuthQueryEngineKeepsTheProofOfANodata(t *testing.T) {
	sc := NewScanner(startAuthQueryEngine(t), false, false)
	const name = "ns1.child.example."
	soa := "child.example. 300 IN SOA ns1.child.example. h.child.example. 7 3600 600 604800 300"
	nsec := name + " 300 IN NSEC ns2.child.example. AAAA RRSIG NSEC"
	sig := name + " 300 IN RRSIG NSEC 13 3 300 20300101000000 20200101000000 12345 child.example. AAAA"

	rrset, proof, err := sc.authQueryWithDenial(name, testAuthServerWithAuthority(t, true, nil, []string{soa, nsec, sig}), dns.TypeA, "tcp")
	if err != nil || rrset == nil || len(rrset.RRs) != 0 {
		t.Fatalf("authoritative NODATA: %v, %v; want an empty RRset", rrset, err)
	}
	if len(proof) != 2 {
		t.Fatalf("proof has %d RRsets, want the SOA and the NSEC: %v", len(proof), proof)
	}
	if proof[0].RRtype != dns.TypeSOA || len(proof[0].RRs) != 1 {
		t.Errorf("first proof RRset %s with %d RR(s), want the SOA", dns.TypeToString[proof[0].RRtype], len(proof[0].RRs))
	}
	if proof[1].RRtype != dns.TypeNSEC || len(proof[1].RRs) != 1 || len(proof[1].RRSIGs) != 1 {
		t.Errorf("second proof RRset %s with %d RR(s) and %d RRSIG(s), want the NSEC with its RRSIG",
			dns.TypeToString[proof[1].RRtype], len(proof[1].RRs), len(proof[1].RRSIGs))
	}

	a := name + " 300 IN A 192.0.2.1"
	_, proof, err = sc.authQueryWithDenial(name, testAuthServerWithAuthority(t, true, []string{a}, []string{soa}), dns.TypeA, "tcp")
	if err != nil || len(proof) != 0 {
		t.Errorf("an answer with data: proof %v, err %v; want no proof", proof, err)
	}
}

// Each RRset of the proof gets the RRSIGs that cover it, wherever they sit in
// the section, in the order each owner and type first appears.
func TestAuthorityRRsetsGroupsTheProof(t *testing.T) {
	const zone = "child.example."
	const ns1 = "ns1." + zone
	in := []dns.RR{
		mustRR(t, ns1+" 300 IN RRSIG NSEC 13 3 300 20300101000000 20200101000000 12345 "+zone+" AAAA"),
		mustRR(t, zone+" 300 IN SOA "+ns1+" h."+zone+" 7 3600 600 604800 300"),
		nil,
		mustRR(t, ns1+" 300 IN NSEC ns2."+zone+" AAAA RRSIG NSEC"),
		mustRR(t, zone+" 300 IN RRSIG SOA 13 2 300 20300101000000 20200101000000 12345 "+zone+" AAAA"),
	}
	got := authorityRRsets(in)
	if len(got) != 2 {
		t.Fatalf("got %d RRsets, want 2: %v", len(got), got)
	}
	nsec, soa := got[0], got[1]
	if nsec.Name != ns1 || nsec.RRtype != dns.TypeNSEC || len(nsec.RRs) != 1 || len(nsec.RRSIGs) != 1 {
		t.Errorf("first RRset %s %s with %d RR(s) and %d RRSIG(s), want %s NSEC with one of each",
			nsec.Name, dns.TypeToString[nsec.RRtype], len(nsec.RRs), len(nsec.RRSIGs), ns1)
	}
	if soa.Name != zone || soa.RRtype != dns.TypeSOA || len(soa.RRs) != 1 || len(soa.RRSIGs) != 1 {
		t.Errorf("second RRset %s %s with %d RR(s) and %d RRSIG(s), want %s SOA with one of each",
			soa.Name, dns.TypeToString[soa.RRtype], len(soa.RRs), len(soa.RRSIGs), zone)
	}
}

// csyncDropA: the child keeps ns1.<child> in its NS set, and serves an AAAA for
// it but no A. The parent's delegation holds that AAAA, and the A the child
// dropped when parentHoldsA is set. Everything the child serves validates.
func csyncDropA(t *testing.T, child string, parentHoldsA bool) (*ZoneData, *trustNet) {
	t.Helper()
	ns1 := "ns1." + child
	zd := trustParent(t, child, trustStrict())
	glue := zd.DelegationBackend.(*trustBackend).data[ns1]
	glue[dns.TypeAAAA] = rrs(t, ns1+" 3600 IN AAAA 2001:db8::1")
	if !parentHoldsA {
		delete(glue, dns.TypeA)
	}
	n := &trustNet{
		served: map[string][]dns.RR{
			trustKey(child, dns.TypeSOA):   rrs(t, child+" 3600 IN SOA "+ns1+" h."+child+" 7 3600 600 604800 300"),
			trustKey(child, dns.TypeCSYNC): rrs(t, child+" 3600 IN CSYNC 7 3 A NS AAAA"),
			trustKey(child, dns.TypeNS):    rrs(t, child+" 3600 IN NS "+ns1, child+" 3600 IN NS ns.provider.net."),
			trustKey(ns1, dns.TypeAAAA):    rrs(t, ns1+" 3600 IN AAAA 2001:db8::1"),
		},
		verdict: map[string]cache.ValidationState{},
		denial:  map[string]cache.ValidationState{},
		zone:    child,
	}
	n.set(cache.ValidationStateSecure, trustKey(child, dns.TypeSOA), trustKey(child, dns.TypeCSYNC),
		trustKey(child, dns.TypeNS), trustKey(ns1, dns.TypeAAAA))
	return zd, n
}

// The case in #779: the child drops the A of a nameserver it keeps, and the
// NSEC at that name proves it gone. The parent removes that A glue.
func TestScanCSYNCRemovesGlueWhoseAbsenceIsProven(t *testing.T) {
	const child = "dropa.example."
	ns1 := "ns1." + child
	zd, n := csyncDropA(t, child, true)
	n.denial[trustKey(ns1, dns.TypeA)] = cache.ValidationStateSecure

	resp := runCSYNC(t, trustScanner(n), zd, child)
	if resp.Error || resp.Validation != ScanValidated {
		t.Fatalf("error %v (%s), validation %q; want a validated scan", resp.Error, resp.ErrorMsg, resp.Validation)
	}
	if len(resp.GlueRemoves) != 1 || resp.GlueRemoves[0].String() != mustRR(t, ns1+" 3600 IN A 192.0.2.1").String() {
		t.Errorf("glue removes %v, want the A of %s", resp.GlueRemoves, ns1)
	}
	if n := len(resp.GlueAdds) + len(resp.NSAdds) + len(resp.NSRemoves); n != 0 {
		t.Errorf("%d other change(s), want none", n)
	}
	if !scanResponseChangesDelegation(resp) {
		t.Error("the removal would not be applied")
	}
	if len(resp.GlueSkipped) != 0 {
		t.Errorf("glue skipped: %v; want none", resp.GlueSkipped)
	}
	if !slices.Contains(n.denialsJudged, trustKey(ns1, dns.TypeA)) {
		t.Errorf("the proof for %s A was never validated (judged: %v)", ns1, n.denialsJudged)
	}
	if want := "the child's proof that it no longer serves " + ns1 + " A"; !strings.Contains(resp.ValidationReason, want) {
		t.Errorf("reason %q does not say %q", resp.ValidationReason, want)
	}
}

// An absence whose proof does not validate Secure changes nothing, whatever the
// verdict, and the scan names the glue it kept and why. A Bogus proof is not a
// refusal either: see proveAbsent.
func TestScanCSYNCKeepsGlueWhoseAbsenceIsNotProven(t *testing.T) {
	for i, tc := range []struct {
		name    string
		verdict cache.ValidationState // zero: the NODATA comes with no proof
		why     string
	}{
		{"an NSEC3 proof, which the validator does not verify yet", cache.ValidationStateIndeterminate, "indeterminate"},
		{"a proof that fails validation", cache.ValidationStateBogus, "bogus"},
		{"no proof at all", 0, "no proof"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := []string{"nsec3.example.", "bogus.example.", "noproof.example."}[i]
			ns1 := "ns1." + child
			zd, n := csyncDropA(t, child, true)
			if tc.verdict != 0 {
				n.denial[trustKey(ns1, dns.TypeA)] = tc.verdict
			}

			resp := runCSYNC(t, trustScanner(n), zd, child)
			if resp.Error || resp.Validation != ScanValidated {
				t.Fatalf("error %v (%s), validation %q; want the scan to go through", resp.Error, resp.ErrorMsg, resp.Validation)
			}
			if resp.DataChanged || len(resp.GlueRemoves) != 0 {
				t.Errorf("changed %v, glue removes %v; want the A kept", resp.DataChanged, resp.GlueRemoves)
			}
			if len(resp.GlueSkipped) != 1 {
				t.Fatalf("glue skipped %v, want the A of %s", resp.GlueSkipped, ns1)
			}
			if s := resp.GlueSkipped[0]; !strings.HasPrefix(s, ns1+" A: ") || !strings.Contains(s, tc.why) {
				t.Errorf("glue skipped %q, want it to name %s A and say %q", s, ns1, tc.why)
			}
			// Nothing was removed on a proof, so the reason claims none (F2).
			if strings.Contains(resp.ValidationReason, "no longer serves") {
				t.Errorf("reason %q claims a proven absence, and none was", resp.ValidationReason)
			}
		})
	}
}

// Glue the parent does not hold cannot be stale. A nameserver with only an
// AAAA, in a CSYNC that lists A, would otherwise be named on every poll round
// of a child whose NODATA answers the validator cannot judge.
func TestScanCSYNCDoesNotReportAnAbsenceThereIsNoGlueFor(t *testing.T) {
	const child = "aaaaonly.example."
	zd, n := csyncDropA(t, child, false)

	resp := runCSYNC(t, trustScanner(n), zd, child)
	if resp.Error || resp.DataChanged {
		t.Fatalf("error %v (%s), changed %v; want no change", resp.Error, resp.ErrorMsg, resp.DataChanged)
	}
	if len(resp.GlueSkipped) != 0 {
		t.Errorf("glue skipped %v, want none: the parent holds no A for it", resp.GlueSkipped)
	}
}

// Nameservers that disagree on a glue RRset were skipped in silence too.
func TestScanCSYNCReportsGlueTheNameserversDisagreeOn(t *testing.T) {
	const child = "disagree.example."
	ns1 := "ns1." + child
	zd, n := csyncDropA(t, child, false)
	n.disagree = map[string]bool{trustKey(ns1, dns.TypeAAAA): true}

	resp := runCSYNC(t, trustScanner(n), zd, child)
	if resp.Error {
		t.Fatalf("error %s", resp.ErrorMsg)
	}
	if len(resp.GlueSkipped) != 1 || !strings.HasPrefix(resp.GlueSkipped[0], ns1+" AAAA: ") {
		t.Errorf("glue skipped %v, want the AAAA of %s", resp.GlueSkipped, ns1)
	}
}

// The scan result line names skipped glue, and is at Info then even without a
// change: the scan log that says more is off by default.
func TestScanResultNamesSkippedGlueAtInfo(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	parent := &ZoneData{ZoneName: "example."}
	infoLines := func() []string {
		var out []string
		for _, l := range strings.Split(buf.String(), "\n") {
			if strings.Contains(l, "level=INFO") && strings.Contains(l, "scan result") {
				out = append(out, l)
			}
		}
		return out
	}

	logScanResult(parent, ScanCSYNC, ScanTupleResponse{Qname: "child.example.", Validation: ScanValidated})
	if got := infoLines(); len(got) != 0 {
		t.Errorf("no change and nothing skipped is logged at Info: %v", got)
	}

	const skipped = "ns1.child.example. A: no ns1.child.example. A served, and the proof that there is none is indeterminate"
	logScanResult(parent, ScanCSYNC, ScanTupleResponse{Qname: "child.example.", Validation: ScanValidated, GlueSkipped: []string{skipped}})
	got := infoLines()
	if len(got) != 1 {
		t.Fatalf("%d Info scan result line(s) for skipped glue, want 1:\n%s", len(got), buf.String())
	}
	if !strings.Contains(got[0], "glue-skipped=") || !strings.Contains(got[0], "ns1.child.example. A:") {
		t.Errorf("the line does not name the skipped glue: %s", got[0])
	}
}

// validatorScanner is a scanner with a real IMR that holds a trust anchor for
// each of zones. sign signs an RRset with the named zone's key, so a test can
// hand proveAbsent proofs that the IMR's own validator judges.
func validatorScanner(t *testing.T, zones ...string) (*Scanner, *Imr, func(zone string, set []dns.RR) dns.RR) {
	t.Helper()
	prevGlobal := Globals.ImrEngine
	t.Cleanup(func() { Globals.ImrEngine = prevGlobal })

	imr := newTestImr(t)
	conf := &Config{}
	conf.Internal.ImrReady = NewImrReadiness()
	conf.publishImr(imr)
	sc := NewScanner(nil, false, false)
	sc.conf = conf

	type zoneKey struct {
		key  *dns.DNSKEY
		priv crypto.Signer
	}
	keys := map[string]zoneKey{}
	for _, zone := range zones {
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
		keys[zone] = zoneKey{key, priv.(crypto.Signer)}
	}
	sign := func(zone string, set []dns.RR) dns.RR {
		t.Helper()
		zk := keys[zone]
		h := set[0].Header()
		sig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
			TypeCovered: h.Rrtype,
			Algorithm:   zk.key.Algorithm,
			Labels:      uint8(dns.CountLabel(h.Name)),
			OrigTtl:     h.Ttl,
			Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
			Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
			KeyTag:      zk.key.KeyTag(),
			SignerName:  zone,
		}
		if err := sig.Sign(zk.priv, set); err != nil {
			t.Fatal(err)
		}
		return sig
	}
	return sc, imr, sign
}

// signedSet is set followed by its RRSIG from zone's key.
func signedSet(sign func(string, []dns.RR) dns.RR, zone string, set []dns.RR) []dns.RR {
	return append(append([]dns.RR{}, set...), sign(zone, set))
}

// The IMR's own validator. An NSEC at the nameserver's name whose bitmap lacks
// the type proves it gone. The same NSEC does not prove a type it lists gone,
// and without its signature it proves nothing.
func TestProveAbsentWithTheImrValidator(t *testing.T) {
	const zone = "signed.example."
	const ns1 = "ns1." + zone
	sc, _, sign := validatorScanner(t, zone)

	soa := rrs(t, zone+" 300 IN SOA "+ns1+" h."+zone+" 7 3600 600 604800 300")
	nsec := rrs(t, ns1+" 300 IN NSEC "+zone+" AAAA RRSIG NSEC")
	signed := append(signedSet(sign, zone, soa), signedSet(sign, zone, nsec)...)
	unsigned := append(append([]dns.RR{}, soa...), nsec...)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sc.proveAbsent(ctx, zone, ns1, dns.TypeA, authorityRRsets(signed)); err != nil {
		t.Errorf("A, absent from a signed NSEC at %s: %v; want it proven", ns1, err)
	}
	for _, tc := range []struct {
		name  string
		qtype uint16
		proof []*core.RRset
	}{
		{"a type the NSEC lists", dns.TypeAAAA, authorityRRsets(signed)},
		{"the NSEC without its signature", dns.TypeA, authorityRRsets(unsigned)},
		{"no proof", dns.TypeA, nil},
	} {
		if err := sc.proveAbsent(ctx, zone, ns1, tc.qtype, tc.proof); !isAbsenceNotProven(err) {
			t.Errorf("%s: %v; want the absence not proven", tc.name, err)
		}
	}
}

// Review F1. The parent's own NSEC at the zone cut covers every name below it,
// the wildcard included, and it validates wherever the parent is trusted --
// which, for the scanner, is always: the parent is the zone it runs for. A
// child nameserver that answers NODATA with the parent's SOA and cut NSEC must
// not get live glue removed. Nor may an unsigned NSEC at the nameserver name
// placed beside them.
func TestProveAbsentRefusesTheParentsCutNSEC(t *testing.T) {
	const parent = "example."
	const child = "child." + parent
	const ns1 = "ns1." + child
	sc, imr, sign := validatorScanner(t, parent)

	soa := rrs(t, parent+" 300 IN SOA ns."+parent+" h."+parent+" 1 3600 600 604800 300")
	cut := rrs(t, child+" 300 IN NSEC other."+parent+" NS DS RRSIG NSEC")
	replay := append(signedSet(sign, parent, soa), signedSet(sign, parent, cut)...)
	planted := append(append([]dns.RR{}, replay...), rrs(t, ns1+" 300 IN NSEC ns2."+child+" AAAA RRSIG NSEC")...)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// What makes this a hole, and what childNodataProof is there for: the
	// validator itself calls the replay Secure (#784). Pinned, so the guard
	// below keeps testing the case it exists for.
	state, _, verr := imr.Cache.ValidateNegativeResponse(ctx, ns1, dns.TypeA, dns.RcodeSuccess,
		authorityRRsets(replay), imr.IterativeDNSQueryFetcher())
	if state != cache.ValidationStateSecure || verr != nil {
		t.Errorf("the validator no longer calls the parent's cut NSEC a Secure denial of %s A (%s, err %v): if #784 is fixed, make this require that it refuses it",
			ns1, cache.ValidationStateToString[state], verr)
	}

	for _, tc := range []struct {
		name  string
		proof []dns.RR
	}{
		{"the parent's SOA and cut NSEC", replay},
		{"the same, with an unsigned NSEC at the nameserver name", planted},
	} {
		if err := sc.proveAbsent(ctx, child, ns1, dns.TypeA, authorityRRsets(tc.proof)); !isAbsenceNotProven(err) {
			t.Errorf("%s: %v; want the absence not proven", tc.name, err)
		}
	}
}
