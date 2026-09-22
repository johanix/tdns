/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"strconv"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Forward first (#722; docs/2026-09-22-forwarding-and-priming.md, S1). Every
// path that picks servers for a question has to decide whether the question is
// forwarded before it looks for a cached zone cut: a forwarded question needs
// no servers, so "no cut, no servers" is normal for it. Seven paths looked for
// the cut first, fell back to the root's servers, and gave up without them.
//
// Each test below runs one of those paths with "." forwarded and no root server
// map, which is where a forwarding resolver is whenever the root NS it holds
// has expired: the upstream's copy counts down, and every few minutes it is
// gone for a while. Nothing is primed, and no hints are seeded.

// rootForward is a forward of "." to the upstream at addr:port.
func rootForward(addr string, port uint16) []ImrForwardConf {
	return []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}}
}

// requireNoRootServerMap fails the test unless the resolver holds no server
// map at all, for the root or for any other zone.
func requireNoRootServerMap(t *testing.T, imr *Imr) {
	t.Helper()
	if zones := imr.Cache.ServerMap.Keys(); len(zones) != 0 {
		t.Fatalf("test setup: server maps are cached for %v", zones)
	}
}

// requireAsked fails the test unless the upstream was asked <qname, qtype>.
func requireAsked(t *testing.T, logr *upstreamLog, qname string, qtype uint16) {
	t.Helper()
	if len(logr.find(qname, qtype)) == 0 {
		t.Errorf("the upstream was never asked %s %s", qname, dns.TypeToString[qtype])
	}
}

// signedRootForward is a resolver forwarding "." to a double of a validating
// recursive upstream that serves sec.example., signed, and kid.sec.example.,
// signed and delegated from it (fwdSecParent, fwdSecKid). The resolver has its
// own DNSKEY cache, and holds no servers.
type signedRootForward struct {
	imr         *Imr
	logr        *upstreamLog
	parent, kid *fwdSecKey
}

// newSignedRootForward starts the upstream with the answers answers returns,
// for the keys it is given, and a resolver forwarding "." to it.
func newSignedRootForward(t *testing.T, answers func(parent, kid *fwdSecKey) map[string]*dns.Msg) *signedRootForward {
	t.Helper()
	parent, kid := newFwdSecKey(t, fwdSecParent), newFwdSecKey(t, fwdSecKid)
	logr := &upstreamLog{}
	addr, port := startLoggedSignedForwardUpstream(t, answers(parent, kid), logr)
	imr := newForwardTestImr(t, rootForward(addr, port))
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache
	requireNoRootServerMap(t, imr)
	return &signedRootForward{imr: imr, logr: logr, parent: parent, kid: kid}
}

// anchor loads trust anchors from the configuration, as start-up does before
// anything is fetched (loadConfiguredTrustAnchors).
func (s *signedRootForward) anchor(t *testing.T, set func(ic *ImrEngineConf)) {
	t.Helper()
	conf := &Config{}
	set(&conf.Imr)
	s.imr.loadConfiguredTrustAnchors(conf)
}

// anchorParentDNSKEY configures the parent's key as a DNSKEY trust anchor.
func (s *signedRootForward) anchorParentDNSKEY(t *testing.T) {
	t.Helper()
	s.anchor(t, func(ic *ImrEngineConf) { ic.TrustAnchorDNSKEY = s.parent.dnskey.String() })
	if z, ok := s.imr.Cache.ZoneMap.Get(fwdSecParent); !ok || z.GetState() != cache.ValidationStateSecure {
		t.Fatalf("test setup: %s is not Secure after loading its trust anchor", fwdSecParent)
	}
}

// signedRRset is the section rrs (records followed by their RRSIG, as sign
// returns them) as one RRset.
func signedRRset(rrs []dns.RR) *core.RRset {
	rrset := &core.RRset{Name: rrs[0].Header().Name, Class: dns.ClassINET, RRtype: rrs[0].Header().Rrtype}
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			rrset.RRSIGs = append(rrset.RRSIGs, rr)
			continue
		}
		rrset.RRs = append(rrset.RRs, rr)
	}
	return rrset
}

// Gate: imrQuery. It looked for the closest cached cut, found no servers, and
// went to resolve the cut's nameservers -- which needs the cut's NS RRset. With
// the root NS gone that failed with `no nameservers for zone ""` before the
// forward was consulted. (From #723.)
func TestImrQueryForwardsWithoutARootServerMap(t *testing.T) {
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()

	imr := newForwardTestImr(t, rootForward(addr, port))
	requireNoRootServerMap(t, imr)

	resp, err := imr.ImrQuery(context.Background(), "www.fwd.example.", dns.TypeA, dns.ClassINET, nil)
	if err != nil {
		t.Fatalf("ImrQuery: %v", err)
	}
	if resp.RRset == nil || len(resp.RRset.RRs) != 1 {
		t.Fatalf("no answer: %+v", resp)
	}
	requireAsked(t, logr, "www.fwd.example.", dns.TypeA)
}

// Gate: ImrResponder. The same path as imrQuery's, and the client got a
// SERVFAIL.
func TestImrResponderForwardsWithoutARootServerMap(t *testing.T) {
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()

	imr := newForwardTestImr(t, rootForward(addr, port))
	requireNoRootServerMap(t, imr)

	r := new(dns.Msg)
	r.SetQuestion("www.fwd.example.", dns.TypeA)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, "www.fwd.example.", dns.TypeA, &edns0.MsgOptions{RD: true})
	if cw.got == nil {
		t.Fatal("nothing written")
	}
	if cw.got.Rcode != dns.RcodeSuccess || len(cw.got.Answer) != 1 {
		t.Fatalf("rcode %s with %d answer RRs; want NOERROR with the answer",
			dns.RcodeToString[cw.got.Rcode], len(cw.got.Answer))
	}
	requireAsked(t, logr, "www.fwd.example.", dns.TypeA)
}

// Gate: DefaultRRsetFetcher, which answered "no servers for" a forwarded name.
func TestDefaultRRsetFetcherForwardsWithoutARootServerMap(t *testing.T) {
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()

	imr := newForwardTestImr(t, rootForward(addr, port))
	requireNoRootServerMap(t, imr)

	rrset, err := imr.DefaultRRsetFetcher(context.Background(), "www.fwd.example.", dns.TypeA)
	if err != nil {
		t.Fatalf("DefaultRRsetFetcher: %v", err)
	}
	if rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("no answer: %v", rrset)
	}
	requireAsked(t, logr, "www.fwd.example.", dns.TypeA)
}

// Gate: DefaultDNSKEYFetcher, the same.
func TestDefaultDNSKEYFetcherForwardsWithoutARootServerMap(t *testing.T) {
	s := newSignedRootForward(t, func(parent, _ *fwdSecKey) map[string]*dns.Msg {
		return map[string]*dns.Msg{
			fwdSecParent + " DNSKEY": {Answer: parent.sign(t, dns.Copy(parent.dnskey))},
		}
	})
	s.anchorParentDNSKEY(t)

	rrset, err := s.imr.DefaultDNSKEYFetcher(context.Background(), fwdSecParent)
	if err != nil {
		t.Fatalf("DefaultDNSKEYFetcher: %v", err)
	}
	if rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("no DNSKEY RRset: %v", rrset)
	}
	requireAsked(t, s.logr, fwdSecParent, dns.TypeDNSKEY)
}

// Gate: the validator's fetch of a signer's DNSKEY RRset (ValidateRRset). With
// no servers for the signer's zone it never fetched, and data signed by a zone
// anchored by a DS was Indeterminate.
func TestValidatorFetchesASignersDNSKEYThroughTheForward(t *testing.T) {
	s := newSignedRootForward(t, func(parent, _ *fwdSecKey) map[string]*dns.Msg {
		return map[string]*dns.Msg{
			fwdSecParent + " DNSKEY": {Answer: parent.sign(t, dns.Copy(parent.dnskey))},
		}
	})
	// A DS-form anchor: the DS is known, the key has to be fetched.
	s.anchor(t, func(ic *ImrEngineConf) { ic.TrustAnchorDS = s.parent.dnskey.ToDS(dns.SHA256).String() })

	www := signedRRset(s.parent.sign(t, fwdSecRR(t, "www."+fwdSecParent+" 300 IN A 192.0.2.8")))
	vstate, err := s.imr.Cache.ValidateRRset(context.Background(), www, s.imr.IterativeDNSQueryFetcher())
	if err != nil {
		t.Fatalf("ValidateRRset: %v", err)
	}
	if vstate != cache.ValidationStateSecure {
		t.Errorf("www.%s A validated %s, want secure", fwdSecParent, cache.ValidationStateToString[vstate])
	}
	requireAsked(t, s.logr, fwdSecParent, dns.TypeDNSKEY)
}

// Gate: the validator's fetch of a zone's DS (backfillDS). With no servers for
// the parent it never fetched, and a signed child of an anchored zone was
// Indeterminate.
func TestValidatorFetchesADSThroughTheForward(t *testing.T) {
	s := newSignedRootForward(t, func(parent, kid *fwdSecKey) map[string]*dns.Msg {
		return map[string]*dns.Msg{
			fwdSecKid + " DS": {Answer: parent.sign(t, kid.dnskey.ToDS(dns.SHA256))},
		}
	})
	s.anchorParentDNSKEY(t)

	keys := signedRRset(s.kid.sign(t, dns.Copy(s.kid.dnskey)))
	vstate, err := s.imr.Cache.ValidateDNSKEYs(context.Background(), keys, s.imr.IterativeDNSQueryFetcher())
	if err != nil {
		t.Fatalf("ValidateDNSKEYs: %v", err)
	}
	if vstate != cache.ValidationStateSecure {
		t.Errorf("%s DNSKEY validated %s, want secure", fwdSecKid, cache.ValidationStateToString[vstate])
	}
	requireAsked(t, s.logr, fwdSecKid, dns.TypeDS)
}

// Gate: the parent side's evidence for unsigned data below a Secure zone
// (delegationEvidence). With no servers for the parent it asked nothing, and
// data from an insecure delegation of an anchored zone was Bogus.
func TestUnsignedDataAsksForItsDelegationThroughTheForward(t *testing.T) {
	s := newSignedRootForward(t, func(parent, _ *fwdSecKey) map[string]*dns.Msg {
		soa := fwdSecRR(t, fwdSecParent+" 300 IN SOA ns."+fwdSecParent+" hostmaster."+fwdSecParent+" 1 7200 1800 604800 300")
		nsec := fwdSecRR(t, fwdSecKid+" 300 IN NSEC zzz."+fwdSecParent+" NS RRSIG NSEC")
		return map[string]*dns.Msg{
			fwdSecKid + " DS": {Ns: append(parent.sign(t, soa), parent.sign(t, nsec)...)},
		}
	})
	s.anchorParentDNSKEY(t)

	www := &core.RRset{Name: fwdSecWWW, Class: dns.ClassINET, RRtype: dns.TypeA,
		RRs: []dns.RR{fwdSecRR(t, fwdSecWWW+" 300 IN A 192.0.2.9")}}
	vstate, err := s.imr.Cache.ValidateRRset(context.Background(), www, s.imr.IterativeDNSQueryFetcher())
	if err != nil {
		t.Fatalf("ValidateRRset: %v", err)
	}
	if vstate != cache.ValidationStateInsecure {
		t.Errorf("unsigned %s A validated %s, want insecure", fwdSecWWW, cache.ValidationStateToString[vstate])
	}
	requireAsked(t, s.logr, fwdSecKid, dns.TypeDS)
}

// Gate: trust-anchor set-up, which fetches the anchored zone's DNSKEY RRset.
// It wanted the zone's servers or the root's, and without them start-up
// failed: `no known servers for "." to fetch DNSKEY`. The upstream does not
// answer the ". NS" that set-up asks next, which is not fatal.
func TestTrustAnchorDNSKEYIsFetchedThroughTheForward(t *testing.T) {
	root := newFwdSecKey(t, ".")
	logr := &upstreamLog{}
	addr, port := startLoggedSignedForwardUpstream(t, map[string]*dns.Msg{
		". DNSKEY": {Answer: root.sign(t, dns.Copy(root.dnskey))},
	}, logr)
	imr := newForwardTestImr(t, rootForward(addr, port))
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache
	requireNoRootServerMap(t, imr)

	conf := &Config{}
	conf.Imr.TrustAnchorDNSKEY = root.dnskey.String()
	imr.loadConfiguredTrustAnchors(conf)
	if err := imr.initializeImrTrustAnchors(context.Background(), conf); err != nil {
		t.Fatalf("initializeImrTrustAnchors: %v", err)
	}
	if crr := imr.Cache.Get(".", dns.TypeDNSKEY); crr == nil || crr.State != cache.ValidationStateSecure {
		t.Errorf(". DNSKEY is not cached Secure: %+v", crr)
	}
	requireAsked(t, logr, ".", dns.TypeDNSKEY)
}

// The cache's Forwarded hook answers as the resolver decides: a name under a
// forward zone is forwarded, a name under a more specific stub zone is not, a
// name outside a forward zone below the root is not, and with no forward zones
// nothing is.
func TestCacheForwardedHookFollowsTheZoneTable(t *testing.T) {
	imr := newForwardTestImr(t, rootForward("192.0.2.53", 53))
	imr.setZoneTable(imr.ForwardZones(), []string{"stub.example."}, nil)
	for _, c := range []struct {
		qname string
		qtype uint16
		want  bool
	}{
		{"www.example.", dns.TypeA, true},
		{"example.", dns.TypeDNSKEY, true},
		{"www.stub.example.", dns.TypeA, false},
		{"stub.example.", dns.TypeDNSKEY, false},
	} {
		if got := imr.Cache.Forwarded(c.qname, c.qtype); got != c.want {
			t.Errorf("Forwarded(%s, %s) = %v, want %v", c.qname, dns.TypeToString[c.qtype], got, c.want)
		}
	}

	// Only fwd.example. forwarded, and nothing cached: its names go out with
	// no servers, and every other name is iterated, with no servers to ask.
	sub := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.53", Port: 53}}},
	})
	if !sub.Cache.Forwarded("www.fwd.example.", dns.TypeA) {
		t.Error("a name under the forward zone is not forwarded")
	}
	if servers, ok := sub.Cache.ServersFor("www.fwd.example.", dns.TypeA); !ok || len(servers) != 0 {
		t.Errorf("ServersFor(www.fwd.example.) = %d servers, %v; want none, and forwarded", len(servers), ok)
	}
	if sub.Cache.Forwarded("www.example.", dns.TypeA) {
		t.Error("a name outside the forward zone is forwarded")
	}
	if _, ok := sub.Cache.ServersFor("www.example.", dns.TypeA); ok {
		t.Error("ServersFor(www.example.) has something to ask, with nothing cached")
	}
	if _, _, forwarded, _ := sub.serversForQuestion("www.example.", dns.TypeA); forwarded {
		t.Error("serversForQuestion forwards a name outside the forward zone")
	}

	none := newForwardTestImr(t, nil)
	if none.Cache.Forwarded("www.example.", dns.TypeA) {
		t.Error("forwarded with no forward zones")
	}
}

// A path that finds a question forwarded sends it with no servers, and the
// forward hook in IterativeDNSQuery decides again. A reload that removes the
// forward in between left the question with neither, and the query failed with
// nothing tried (CodeRabbit on #726). It is iterated instead, from the closest
// cached zone cut, as it would be if it were asked after the reload.
func TestAQuestionWhoseForwardWasRemovedIsIterated(t *testing.T) {
	const zone, qname = "example.", "www.example."
	a := fwdSecRR(t, qname+" 300 IN A 192.0.2.10")
	for _, c := range []struct {
		name string
		pick func(imr *Imr) (map[string]*cache.AuthServer, bool)
	}{
		{"the fetchers (ServersFor)", func(imr *Imr) (map[string]*cache.AuthServer, bool) {
			return imr.Cache.ServersFor(qname, dns.TypeA)
		}},
		{"imrQuery and ImrResponder (serversForQuestion)", func(imr *Imr) (map[string]*cache.AuthServer, bool) {
			_, servers, forwarded, _ := imr.serversForQuestion(qname, dns.TypeA)
			return servers, forwarded
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			port, stop := startAnswerDouble(t, zone, dns.TypeA, []dns.RR{a})
			defer stop()
			imr := newForwardTestImr(t, rootForward("192.0.2.53", 53))
			p := strconv.Itoa(port)
			imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
			imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
			// The cut the question falls back to, which it passes over while
			// "." is forwarded.
			if err := imr.Cache.AddStub(zone, []cache.AuthServer{
				{Name: "ns." + zone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
			}); err != nil {
				t.Fatalf("AddStub: %v", err)
			}

			servers, forwarded := c.pick(imr)
			if !forwarded || len(servers) != 0 {
				t.Fatalf("test setup: before the reload, %d servers and forwarded %v; want none, forwarded", len(servers), forwarded)
			}
			imr.setZoneTable(nil, nil, nil) // the reload: no forward zones

			rrset, _, _, _, err := imr.IterativeDNSQuery(context.Background(), qname, dns.TypeA, servers, false, edns0.PrivacyNone)
			if err != nil {
				t.Fatalf("IterativeDNSQuery after the forward was removed: %v", err)
			}
			if rrset == nil || len(rrset.RRs) != 1 {
				t.Fatalf("no answer from the cut: %v", rrset)
			}
		})
	}
}
