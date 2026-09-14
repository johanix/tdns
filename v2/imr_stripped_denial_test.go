/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A denial whose RRSIGs and NSEC records were stripped, from a signed zone at or
 * below one the resolver holds as Secure, is bogus -- and a bogus denial is
 * SERVFAIL, not a name gone.
 */
package tdns

import (
	"context"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const (
	denParent  = "denparent.example."
	denKid     = "kid." + denParent
	denKidNope = "nope." + denKid // no such name
	denKidWWW  = "www." + denKid  // an A and nothing else
	denNope    = "nope." + denParent
)

// denialDelegation is how denParent delegates denKid.
type denialDelegation int

const (
	delegatedWithDS   denialDelegation = iota // the child is signed, and the parent publishes its DS
	delegatedByNSEC                           // the child is unsigned: the parent's NSEC at the cut has NS and no DS
	delegatedByOptOut                         // the child is unsigned: the parent is NSEC3-signed, the cut in an Opt-Out span
)

type denialSetup struct {
	delegation denialDelegation
	stripped   bool // a signed child's denials reach the resolver as their SOA alone
}

// newDenialImr is a resolver holding denParent as Secure under a trust anchor,
// reaching it through a stub on 127.0.0.1. The same server serves denKid, so the
// resolver never sees a referral and has no ZoneMap entry for the child. The
// parent's own denial, of denNope, always arrives as its SOA alone.
func newDenialImr(t *testing.T, s denialSetup) *Imr {
	t.Helper()
	parent, kid := newRefKey(t, denParent), newRefKey(t, denKid)
	parentSOA := mustRR(t, denParent+" 300 IN SOA ns."+denParent+" hostmaster."+denParent+" 1 7200 1800 604800 300")
	kidSOA := mustRR(t, denKid+" 300 IN SOA ns."+denKid+" hostmaster."+denKid+" 1 7200 1800 604800 300")
	signedParentSOA := parent.sign(t, parentSOA)

	// The parent side's answer to the DS question at the cut.
	var dsAnswer, dsDenial []dns.RR
	switch s.delegation {
	case delegatedWithDS:
		ds := kid.key.ToDS(dns.SHA256)
		ds.Hdr.Ttl = 300
		dsAnswer = parent.sign(t, ds)
	case delegatedByNSEC:
		dsDenial = slices.Concat(signedParentSOA, parent.sign(t, mustRR(t, denKid+" 300 IN NSEC "+denParent+" NS RRSIG NSEC")))
	case delegatedByOptOut:
		dsDenial = slices.Concat(signedParentSOA,
			parent.sign(t, refNSEC3(denParent, denParent, false, 0, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM)),
			parent.sign(t, refNSEC3(denParent, denKid, true, 1, dns.TypeA, dns.TypeRRSIG)))
	}

	kidNX, kidNoData, kidDNSKEY := []dns.RR{kidSOA}, []dns.RR{kidSOA}, []dns.RR(nil)
	if s.delegation == delegatedWithDS {
		kidDNSKEY = kid.sign(t, kid.key)
		if !s.stripped {
			kidNX = slices.Concat(kid.sign(t, kidSOA), kid.sign(t, mustRR(t, denKid+" 300 IN NSEC "+denKidWWW+" SOA NS RRSIG NSEC DNSKEY")))
			kidNoData = slices.Concat(kid.sign(t, kidSOA), kid.sign(t, mustRR(t, denKidWWW+" 300 IN NSEC "+denKid+" A RRSIG NSEC")))
		}
	}

	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		switch name := dns.CanonicalName(q.Name); {
		case q.Qtype == dns.TypeDS && name == denKid:
			m.Answer = append(m.Answer, dsAnswer...)
			m.Ns = append(m.Ns, dsDenial...)
		case q.Qtype == dns.TypeDNSKEY && name == denKid && kidDNSKEY != nil:
			m.Answer = append(m.Answer, kidDNSKEY...)
		case name == denKidNope:
			m.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, kidNX...)
		case dns.IsSubDomain(denKid, name):
			m.Ns = append(m.Ns, kidNoData...)
		case name == denNope:
			m.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, parentSOA)
		default:
			m.Ns = append(m.Ns, signedParentSOA...)
		}
		_ = w.WriteMsg(m)
	})

	imr := verdictImr(t, true)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	if err := imr.Cache.AddStub(denParent, []cache.AuthServer{
		{Name: "ns." + denParent, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.Cache.DnskeyCache.Set(denParent, parent.key.KeyTag(), &cache.CachedDnskeyRRset{Name: denParent,
		Keyid: parent.key.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure, Dnskey: *parent.key,
		Expiration: time.Now().Add(time.Hour)})
	imr.Cache.ZoneMap.Set(denParent, &cache.Zone{ZoneName: denParent, State: cache.ValidationStateSecure})
	return imr
}

func askDenialImr(t *testing.T, imr *Imr, qname string, qtype uint16, q verdictQuery) *dns.Msg {
	t.Helper()
	r, opts := q.msgFor(qname, qtype)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, qtype, opts)
	if cw.got == nil {
		t.Fatalf("%s %s: responder wrote nothing", qname, dns.TypeToString[qtype])
	}
	return cw.got
}

// wantBogusDenial fails the test unless m is a SERVFAIL carrying EDE 6.
func wantBogusDenial(t *testing.T, via string, m *dns.Msg) {
	t.Helper()
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("%s: rcode %s; a stripped denial from a signed zone must be SERVFAIL", via, dns.RcodeToString[m.Rcode])
	} else if got := edeOf(m); got != edns0.EDEDNSSECBogus {
		t.Errorf("%s: EDE %d, want %d (DNSSEC Bogus)", via, got, edns0.EDEDNSSECBogus)
	}
}

// THE DEFECT. denKid is signed and its parent, held Secure, publishes its DS,
// but the resolver has no ZoneMap entry for the child. A denial from it with its
// RRSIGs and NSEC stripped on the path validated Insecure -- only a zone with an
// entry of its own held Secure made a stripped denial Bogus -- and the name was
// gone for every client, fresh and from the cache.
func TestAStrippedDenialFromASignedChildIsNotServed(t *testing.T) {
	denials := []struct {
		name  string
		qname string
		qtype uint16
		rcode int
	}{
		{"NXDOMAIN", denKidNope, dns.TypeA, dns.RcodeNameError},
		{"NODATA", denKidWWW, dns.TypeTXT, dns.RcodeSuccess},
	}
	for _, d := range denials {
		for flags, q := range map[string]verdictQuery{"DO": {do: true}, "no DO": {}} {
			t.Run(d.name+"/"+flags, func(t *testing.T) {
				imr := newDenialImr(t, denialSetup{stripped: true})
				for _, via := range []string{"fresh", "cached"} {
					wantBogusDenial(t, via, askDenialImr(t, imr, d.qname, d.qtype, q))
				}
				if state := zoneStateOf(imr, denKid); state == "insecure" {
					t.Errorf("child zone is %s", state)
				}
				// CD asks for the records, to validate them itself.
				if m := askDenialImr(t, imr, d.qname, d.qtype, verdictQuery{do: true, cd: true}); m.Rcode != d.rcode || m.AuthenticatedData {
					t.Errorf("CD: rcode %s, AD %v; want %s without AD", dns.RcodeToString[m.Rcode], m.AuthenticatedData, dns.RcodeToString[d.rcode])
				}
			})
		}
	}
}

// A zone the resolver holds as Secure itself: its stripped denial was found
// Bogus, and served all the same, because nothing that serves a denial read the
// verdict.
func TestABogusDenialIsNotServed(t *testing.T) {
	imr := newDenialImr(t, denialSetup{stripped: true})
	for _, via := range []string{"fresh", "cached"} {
		wantBogusDenial(t, via, askDenialImr(t, imr, denNope, dns.TypeA, verdictQuery{do: true}))
	}
}

// Behind a referral: a child entered as Secure, and one the referral did not
// enter because the DS question for it went unanswered, have their stripped
// denials refused the same way.
func TestAStrippedDenialBehindAReferralIsNotServed(t *testing.T) {
	paths := []struct {
		name string
		path func(z *referralZones) referralPath
	}{
		{"DS in the referral", func(z *referralZones) referralPath { return referralPath{referral: z.ds, dsAnswer: z.ds} }},
		{"DS stripped, DS question unanswered", func(*referralZones) referralPath { return referralPath{} }},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			imr, _ := newReferralImr(t, referralSetup{strippedDenials: true, path: p.path})
			for _, via := range []string{"fresh", "cached"} {
				wantBogusDenial(t, via, askDenialImr(t, imr, refKidWWW, dns.TypeTXT, verdictQuery{do: true}))
			}
			if state := zoneStateOf(imr, refKid); state == "insecure" {
				t.Errorf("child zone is %s", state)
			}
		})
	}
}

// The chain the attack breaks, intact: the child's denials validate and carry AD.
func TestGenuineDenialsFromASignedChildAreSecure(t *testing.T) {
	imr := newDenialImr(t, denialSetup{})
	for _, d := range []struct {
		qname string
		qtype uint16
		rcode int
	}{{denKidNope, dns.TypeA, dns.RcodeNameError}, {denKidWWW, dns.TypeTXT, dns.RcodeSuccess}} {
		for _, via := range []string{"fresh", "cached"} {
			if m := askDenialImr(t, imr, d.qname, d.qtype, verdictQuery{do: true}); m.Rcode != d.rcode || !m.AuthenticatedData {
				t.Errorf("%s %s, %s: rcode %s, AD %v; want %s with AD", d.qname, dns.TypeToString[d.qtype], via,
					dns.RcodeToString[m.Rcode], m.AuthenticatedData, dns.RcodeToString[d.rcode])
			}
		}
	}
}

// What the fix must keep. A child its secure parent proves insecure -- by an NSEC
// at the cut or an NSEC3 Opt-Out span, found through the DS question or carried
// in a referral -- has its unsigned denials served, without AD. So does a child
// on a resolver with no trust anchor.
func TestAnUnsignedChildsDenialIsServed(t *testing.T) {
	referral := func(s referralSetup) func(t *testing.T) *Imr {
		return func(t *testing.T) *Imr {
			imr, _ := newReferralImr(t, s)
			return imr
		}
	}
	cases := []struct {
		name  string
		imr   func(t *testing.T) *Imr
		qname string
		qtype uint16
		rcode int
		zone  string
		want  string
	}{
		{"same servers, NSEC at the cut", func(t *testing.T) *Imr { return newDenialImr(t, denialSetup{delegation: delegatedByNSEC}) },
			denKidNope, dns.TypeA, dns.RcodeNameError, denKid, "insecure"},
		{"same servers, NSEC3 Opt-Out span", func(t *testing.T) *Imr { return newDenialImr(t, denialSetup{delegation: delegatedByOptOut}) },
			denKidWWW, dns.TypeTXT, dns.RcodeSuccess, denKid, "insecure"},
		{"referral with an NSEC", referral(referralSetup{unsignedKid: true,
			path: func(z *referralZones) referralPath { return referralPath{referral: z.nsec} }}),
			refKidWWW, dns.TypeTXT, dns.RcodeSuccess, refKid, "insecure"},
		{"referral with an NSEC3 Opt-Out span", referral(referralSetup{unsignedKid: true,
			path: func(z *referralZones) referralPath { return referralPath{referral: z.optOut} }}),
			refKidWWW, dns.TypeTXT, dns.RcodeSuccess, refKid, "insecure"},
		{"no trust anchor", referral(referralSetup{parent: cache.ValidationStateIndeterminate, unanchored: true, unsignedKid: true}),
			refKidWWW, dns.TypeTXT, dns.RcodeSuccess, refKid, "indeterminate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imr := c.imr(t)
			for _, via := range []string{"fresh", "cached"} {
				if m := askDenialImr(t, imr, c.qname, c.qtype, verdictQuery{do: true}); m.Rcode != c.rcode || m.AuthenticatedData {
					t.Errorf("%s: rcode %s, AD %v; want %s without AD", via, dns.RcodeToString[m.Rcode], m.AuthenticatedData, dns.RcodeToString[c.rcode])
				}
			}
			if state := zoneStateOf(imr, c.zone); state != c.want {
				t.Errorf("child zone is %s, want %s", state, c.want)
			}
		})
	}
}
