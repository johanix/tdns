/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// DS and DNSKEY questions at a name that owns a CNAME (#875), on the doubles of
// #717 (startSigChainDouble). A client's question follows the CNAME as any
// other type does. The resolver's own question is answered by the CNAME: there
// is no DS and no DNSKEY at the name. Either way the link's server is asked
// once, and the link is what the cache holds.

// A client's DS question at a CNAME owner is answered with the chain: every
// link, then the DS at its end, with their RRSIGs and AD. Each DS question
// reaches the server once, the second answer coming from the cache.
func TestClientDSAtACNAMEOwnerFollowsTheChain(t *testing.T) {
	imr, d := sigChainImr(t)
	want := []string{"s1.sigchain.example. CNAME", "s2.sigchain.example. CNAME", "s3.sigchain.example. DS"}
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "s1."+sigChainZone, dns.TypeDS)
		if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) {
			t.Fatalf("%s: rcode %s, answer %v; want NOERROR with %v", path, dns.RcodeToString[m.Rcode], answerOrder(m), want)
		}
		if !m.AuthenticatedData {
			t.Errorf("%s: AD not set on a chain whose every part is signed", path)
		}
		if n := answerSigCount(m); n != 3 {
			t.Errorf("%s: %d RRSIGs in the answer, want 3 (two CNAMEs and the DS)", path, n)
		}
	}
	for _, name := range []string{"s1.", "s2.", "s3."} {
		if n := d.count(name+sigChainZone, dns.TypeDS); n != 1 {
			t.Errorf("%s%s DS was asked %d times, want 1", name, sigChainZone, n)
		}
	}
}

// A client's DNSKEY question at a CNAME owner follows the chain too: to the
// DNSKEY at the zone apex, or to the NODATA at a name that has none.
func TestClientDNSKEYAtACNAMEOwnerFollowsTheChain(t *testing.T) {
	imr, _ := sigChainImr(t)
	want := []string{"top.sigchain.example. CNAME", "sigchain.example. DNSKEY"}
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "top."+sigChainZone, dns.TypeDNSKEY)
		if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) {
			t.Fatalf("top DNSKEY, %s: rcode %s, answer %v; want NOERROR with %v", path, dns.RcodeToString[m.Rcode], answerOrder(m), want)
		}
		if !m.AuthenticatedData {
			t.Errorf("top DNSKEY, %s: AD not set on a chain whose every part is signed", path)
		}
	}

	want = []string{"s1.sigchain.example. CNAME", "s2.sigchain.example. CNAME"}
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "s1."+sigChainZone, dns.TypeDNSKEY)
		if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) {
			t.Fatalf("s1 DNSKEY, %s: rcode %s, answer %v; want NOERROR with %v", path, dns.RcodeToString[m.Rcode], answerOrder(m), want)
		}
		var nsec bool
		for _, rr := range m.Ns {
			if n, ok := rr.(*dns.NSEC); ok && core.EqualNames(n.Hdr.Name, "s3."+sigChainZone) {
				nsec = true
			}
		}
		if !nsec {
			t.Errorf("s1 DNSKEY, %s: AUTHORITY %v lacks s3's NSEC", path, m.Ns)
		}
	}
}

// The shape of www.sidn.nl DS: the CNAME points at the apex of a signed child,
// and the child's servers put their own NODATA for the child's DS beside it.
// The DS at the chain's end is the parent's, validated with the parent's key;
// the child's denial is not what is served.
func TestClientDSAtACNAMEIntoASignedChild(t *testing.T) {
	imr, d := sigChainImr(t)
	kid := "kid." + sigChainZone
	want := []string{"www." + kid + " CNAME", kid + " DS"}
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "www."+kid, dns.TypeDS)
		if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) {
			t.Fatalf("%s: rcode %s, answer %v; want NOERROR with %v", path, dns.RcodeToString[m.Rcode], answerOrder(m), want)
		}
		if !m.AuthenticatedData {
			t.Errorf("%s: AD not set; the link is signed by the child and the DS by the parent", path)
		}
		for _, rr := range m.Ns {
			if rr.Header().Rrtype == dns.TypeNSEC {
				t.Errorf("%s: AUTHORITY carries %v: the child's denial of its own DS", path, rr)
			}
		}
	}
	if n := d.count(kid, dns.TypeDS); n != 1 {
		t.Errorf("%s DS was asked %d times, want 1", kid, n)
	}
}

// A chain into an unsigned zone ends in that zone's NODATA for the DS: served,
// without AD.
func TestClientDSAtACNAMEIntoAnUnsignedZone(t *testing.T) {
	imr, _ := sigChainImr(t)
	want := []string{"out.sigchain.example. CNAME"}
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "out."+sigChainZone, dns.TypeDS)
		if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) {
			t.Fatalf("%s: rcode %s, answer %v; want NOERROR with %v", path, dns.RcodeToString[m.Rcode], answerOrder(m), want)
		}
		if m.AuthenticatedData {
			t.Errorf("%s: AD set on a chain that ends in an unsigned zone", path)
		}
	}
}

// A link whose RRSIG was stripped fails a client's DS question as it fails an
// A question.
func TestClientDSAtAStrippedLinkIsBogus(t *testing.T) {
	imr, _ := sigChainImr(t)
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "bad."+sigChainZone, dns.TypeDS)
		if m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 {
			t.Fatalf("%s: rcode %s with %d answer RRs; want SERVFAIL", path, dns.RcodeToString[m.Rcode], len(m.Answer))
		}
		if got := edeOf(m); got != edns0.EDEDNSSECBogus {
			t.Errorf("%s: EDE %d, want %d (DNSSEC Bogus)", path, got, edns0.EDEDNSSECBogus)
		}
	}
}

// The other types follow as they did before #875.
func TestOtherTypesAtACNAMEOwnerStillFollow(t *testing.T) {
	imr, _ := sigChainImr(t)
	want := []string{"s1.sigchain.example. CNAME", "s2.sigchain.example. CNAME"}
	for _, qtype := range []uint16{dns.TypeSOA, dns.TypeNS} {
		m, _ := askChain(t, imr, "s1."+sigChainZone, qtype)
		if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) || !m.AuthenticatedData {
			t.Errorf("s1 %s: rcode %s, answer %v, AD %v; want NOERROR with %v and AD",
				dns.TypeToString[qtype], dns.RcodeToString[m.Rcode], answerOrder(m), m.AuthenticatedData, want)
		}
	}
	m, _ := askChain(t, imr, "s1."+sigChainZone, dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || !answerHas(m, "s3."+sigChainZone, dns.TypeA) {
		t.Errorf("s1 A: rcode %s, answer %v; want NOERROR with s3's A", dns.RcodeToString[m.Rcode], answerOrder(m))
	}
}

// The resolver's own DS and DNSKEY questions at a CNAME owner are answered by
// the CNAME: no RRset, NOERROR, NODATA, no error. The server is asked once, the
// CNAME is not followed, and the next question is answered from the link,
// which is cached with its verdict.
func TestOwnQuestionAtACNAMEOwnerIsAnsweredByTheLink(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeDS, dns.TypeDNSKEY} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			imr, d := sigChainImr(t)
			s1 := "s1." + sigChainZone
			_, servers, _ := imr.Cache.FindClosestKnownZoneFor(s1, qtype)
			for _, ask := range []string{"first", "second"} {
				rrset, rcode, cctx, _, err := imr.IterativeDNSQuery(context.Background(), s1, qtype, servers, false, edns0.PrivacyNone)
				if err != nil || rcode != dns.RcodeSuccess || cctx != cache.ContextNoErrNoAns || (rrset != nil && len(rrset.RRs) > 0) {
					t.Fatalf("%s ask: rrset %v, rcode %s, context %s, err %v; want no RRset, NOERROR, NODATA and no error",
						ask, rrset, dns.RcodeToString[rcode], cache.CacheContextToString[cctx], err)
				}
			}
			if n := d.count(s1, qtype); n != 1 {
				t.Errorf("s1 %s was asked %d times, want 1", dns.TypeToString[qtype], n)
			}
			for _, name := range []string{"s2.", "s3."} {
				if n := d.count(name+sigChainZone, qtype); n != 0 {
					t.Errorf("%s%s %s was asked %d times: the CNAME was followed", name, sigChainZone, dns.TypeToString[qtype], n)
				}
			}
			link := imr.Cache.Get(s1, dns.TypeCNAME)
			if link == nil || link.State != cache.ValidationStateSecure {
				t.Errorf("s1's link is not cached as Secure: %+v", link)
			}
			if c := imr.Cache.Get(s1, qtype); c != nil {
				t.Errorf("an entry was cached under <s1, %s>: %+v", dns.TypeToString[qtype], c)
			}
		})
	}
}

// The #717 recursion. Validating the unsigned link at bad asks for the DS at
// bad, whose answer is the link again. That question is answered without being
// asked, the client's A question fails at once, and the own question is not
// followed to s3 either.
func TestValidatingAnUnsignedLinkDoesNotAskForItsDS(t *testing.T) {
	imr, d := sigChainImr(t)
	m, took := askChain(t, imr, "bad."+sigChainZone, dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("bad A: rcode %s, want SERVFAIL", dns.RcodeToString[m.Rcode])
	}
	if took > 2*time.Second {
		t.Errorf("bad A took %v", took)
	}
	for _, name := range []string{"bad.", "s3."} {
		if n := d.count(name+sigChainZone, dns.TypeDS); n != 0 {
			t.Errorf("%s%s DS was asked %d times, want 0", name, sigChainZone, n)
		}
	}
}

// A link whose RRSIG names the link's owner as its signer has the validator ask
// for the DNSKEY there, whose answer is the link again. That question is
// answered without being asked, and the answer fails at once.
func TestALinkSignedByItsOwnOwnerTerminates(t *testing.T) {
	imr, d := sigChainImr(t)
	m, took := askChain(t, imr, "self."+sigChainZone, dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure || m.AuthenticatedData {
		t.Errorf("self A: rcode %s, AD %v; want SERVFAIL", dns.RcodeToString[m.Rcode], m.AuthenticatedData)
	}
	if took > 2*time.Second {
		t.Errorf("self A took %v", took)
	}
	if n := d.count("self."+sigChainZone, dns.TypeDNSKEY); n != 0 {
		t.Errorf("self DNSKEY was asked %d times, want 0", n)
	}
}

// ImrQuery, as the embedded users ask it, asks as the resolver does: a DS or
// DNSKEY at a CNAME owner is "none there", with the CNAME's verdict.
func TestImrQueryAtACNAMEOwnerIsNoData(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeDS, dns.TypeDNSKEY} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			imr, _ := sigChainImr(t)
			resp, err := imr.ImrQuery(context.Background(), "s1."+sigChainZone, qtype, dns.ClassINET, nil)
			if err != nil || resp == nil {
				t.Fatalf("ImrQuery: %v, %v", resp, err)
			}
			if resp.RRset != nil || resp.Denial != cache.ContextNoErrNoAns || resp.ValidationState != cache.ValidationStateSecure {
				t.Errorf("RRset %v, denial %s, state %s; want none, NODATA, secure",
					resp.RRset, cache.CacheContextToString[resp.Denial], cache.ValidationStateToString[resp.ValidationState])
			}
		})
	}
}

// The API's "imr query" (imr-resolve) asks as a DNS client does: a DS or
// DNSKEY question at a CNAME owner follows the CNAME, as it does for dig, and
// the records that come back are those at the chain's end.
func TestAPIimrResolveFollowsACNAMEForDSAndDNSKEY(t *testing.T) {
	for _, c := range []struct {
		qname, owner string
		qtype        uint16
	}{
		{"s1." + sigChainZone, "s3." + sigChainZone, dns.TypeDS},
		{"top." + sigChainZone, sigChainZone, dns.TypeDNSKEY},
	} {
		t.Run(dns.TypeToString[c.qtype], func(t *testing.T) {
			imr, _ := sigChainImr(t)
			saved := Globals.ImrEngine
			Globals.ImrEngine = imr
			t.Cleanup(func() { Globals.ImrEngine = saved })

			body, _ := json.Marshal(ImrMgmtPost{Command: "imr-resolve",
				Data: map[string]interface{}{"qname": c.qname, "qtype": dns.TypeToString[c.qtype]}})
			rec := httptest.NewRecorder()
			(&Config{}).APIimr()(rec, httptest.NewRequest(http.MethodPost, "/imr", bytes.NewReader(body)))
			var resp ImrMgmtResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decoding response: %v (%s)", err, rec.Body.String())
			}
			if resp.Error {
				t.Fatalf("imr-resolve failed: %s", resp.ErrorMsg)
			}
			data, _ := resp.Data.(map[string]interface{})
			records, _ := data["records"].([]interface{})
			if len(records) == 0 {
				t.Fatalf("%s %s: no records (%v); want the %s at %s", c.qname, dns.TypeToString[c.qtype], data,
					dns.TypeToString[c.qtype], c.owner)
			}
			for _, r := range records {
				rr := mustRR(t, r.(string))
				if rr.Header().Rrtype != c.qtype || !core.EqualNames(rr.Header().Name, c.owner) {
					t.Errorf("%s %s: record %v; want the %s at %s", c.qname, dns.TypeToString[c.qtype], rr,
						dns.TypeToString[c.qtype], c.owner)
				}
			}
			if got, want := data["state"], cache.ValidationStateToString[cache.ValidationStateSecure]; got != want {
				t.Errorf("state %v, want %q", got, want)
			}
		})
	}
}

// The "imr query" in tdns-imr's own shell sends its question on RecursorCh
// with AsClient set, and is answered as the API's "imr query" is: through the
// CNAME. Without AsClient, as the embedded users ask, a DS or DNSKEY at a
// CNAME owner is "none there".
func TestRecursorRequestAsClientFollowsACNAME(t *testing.T) {
	for _, c := range []struct {
		qname, owner string
		qtype        uint16
	}{
		{"s1." + sigChainZone, "s3." + sigChainZone, dns.TypeDS},
		{"top." + sigChainZone, sigChainZone, dns.TypeDNSKEY},
	} {
		for _, asClient := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/AsClient=%v", dns.TypeToString[c.qtype], asClient), func(t *testing.T) {
				imr, _ := sigChainImr(t)
				ch := make(chan ImrResponse, 1)
				imr.handleRecursorRequest(context.Background(), ImrRequest{Qname: c.qname, Qtype: c.qtype,
					Qclass: dns.ClassINET, ResponseCh: ch, AsClient: asClient})
				var r ImrResponse
				select {
				case r = <-ch:
				default:
					t.Fatal("no response")
				}
				if !asClient {
					if r.RRset != nil || r.Denial != cache.ContextNoErrNoAns {
						t.Errorf("RRset %v, denial %s; want none, NODATA", r.RRset, cache.CacheContextToString[r.Denial])
					}
					return
				}
				if r.RRset == nil || len(r.RRset.RRs) == 0 {
					t.Fatalf("no records (%+v); want the %s at %s", r, dns.TypeToString[c.qtype], c.owner)
				}
				for _, rr := range r.RRset.RRs {
					if rr.Header().Rrtype != c.qtype || !core.EqualNames(rr.Header().Name, c.owner) {
						t.Errorf("record %v; want the %s at %s", rr, dns.TypeToString[c.qtype], c.owner)
					}
				}
				if r.ValidationState != cache.ValidationStateSecure {
					t.Errorf("state %s, want secure", cache.ValidationStateToString[r.ValidationState])
				}
			})
		}
	}
}

// Who follows, and for whom a CNAME is the answer.
func TestFollowsCNAMEByOrigin(t *testing.T) {
	bg := context.Background()
	client := withClientQuery(bg)
	origins := []struct {
		name   string
		ctx    context.Context
		client bool
	}{
		{"client", client, true},
		{"own lookup inside a client query", withOwnTraffic(client), false},
		{"unmarked", bg, false},
	}
	for _, o := range origins {
		for _, c := range []struct {
			qtype   uint16
			follows bool // for a client
			denies  bool // for the resolver itself
		}{
			{dns.TypeDS, true, true},
			{dns.TypeDNSKEY, true, true},
			{dns.TypeA, true, false},
			{dns.TypeSOA, true, false},
			{dns.TypeCNAME, false, false},
			{dns.TypeNSEC, false, false},
		} {
			follows := c.follows && (o.client || (c.qtype != dns.TypeDS && c.qtype != dns.TypeDNSKEY))
			denies := c.denies && !o.client
			if got := followsCNAME(o.ctx, c.qtype); got != follows {
				t.Errorf("%s, %s: followsCNAME %v, want %v", o.name, dns.TypeToString[c.qtype], got, follows)
			}
			if got := cnameDeniesType(o.ctx, c.qtype); got != denies {
				t.Errorf("%s, %s: cnameDeniesType %v, want %v", o.name, dns.TypeToString[c.qtype], got, denies)
			}
		}
	}
}

// What ImrQuery's lookups run as. A caller that marked its context
// asClientQuery (the API's "imr query") gets a client's lookup, counted as
// client traffic; any other caller the resolver's own. An ImrQuery nested
// inside the first is the resolver's own again.
func TestImrQueryContextByCaller(t *testing.T) {
	bg := context.Background()
	asClient := imrQueryContext(asClientQuery(bg))
	if !isClientQuery(asClient) || trafficClass(asClient, edns0.PrivacyNone) != cache.ClassNone {
		t.Errorf("asked as a client: client %v, class %v; want a client's lookup without PRIVACY",
			isClientQuery(asClient), trafficClass(asClient, edns0.PrivacyNone))
	}
	if nested := imrQueryContext(asClient); isClientQuery(nested) {
		t.Error("an ImrQuery nested inside a client's: a client's lookup, want the resolver's own")
	}
	for name, ctx := range map[string]context.Context{"unmarked": bg, "inside a client query": withClientQuery(bg)} {
		if got := imrQueryContext(ctx); isClientQuery(got) || trafficClass(got, edns0.PrivacyNone) != cache.ClassInternal {
			t.Errorf("%s: a client's lookup, want the resolver's own", name)
		}
	}
}

// The resolver's own DS question at a CNAME synthesized from a wildcard: the
// link is validated with the proof that came with it in the authority section,
// as any link is (#874), and cached Secure with that proof. The question is
// NODATA, as at any CNAME owner.
func TestOwnDSQuestionAtAWildcardCNAMEKeepsItsProof(t *testing.T) {
	imr := wildcardImr(t)
	qname := "x.c." + wcnZone
	_, servers, _ := imr.Cache.FindClosestKnownZoneFor(qname, dns.TypeDS)
	rrset, rcode, cctx, _, err := imr.IterativeDNSQuery(context.Background(), qname, dns.TypeDS, servers, false, edns0.PrivacyNone)
	if err != nil || rcode != dns.RcodeSuccess || cctx != cache.ContextNoErrNoAns || (rrset != nil && len(rrset.RRs) > 0) {
		t.Fatalf("rrset %v, rcode %s, context %s, err %v; want no RRset, NOERROR, NODATA and no error",
			rrset, dns.RcodeToString[rcode], cache.CacheContextToString[cctx], err)
	}
	link := imr.Cache.Peek(qname, dns.TypeCNAME)
	if link == nil || link.State != cache.ValidationStateSecure || len(link.WildcardProof) == 0 {
		t.Errorf("the link is not cached Secure with its proof: %+v", link)
	}
}
