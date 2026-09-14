/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A referral without a DS makes the child Insecure only when the parent proves
 * that there is no DS (RFC 4035 section 5.2, RFC 6840 section 4.4).
 */
package tdns

import (
	"context"
	"crypto"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	refParent = "refparent.example."
	refKid    = "kid." + refParent
	refKidNS  = "ns." + refKid
	refKidWWW  = "www." + refKid
	refKidMail = "mail." + refKid // always served without its RRSIG
)

// refKey is a zone key whose signatures validate for real.
type refKey struct {
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newRefKey(t *testing.T, zone string) *refKey {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	p, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return &refKey{key: k, priv: p.(crypto.Signer)}
}

// sign returns rrs followed by their RRSIG.
func (k *refKey) sign(t *testing.T, rrs ...dns.RR) []dns.RR {
	t.Helper()
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: k.key.KeyTag(), SignerName: k.key.Hdr.Name,
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(k.priv, rrs); err != nil {
		t.Fatal(err)
	}
	return append(append([]dns.RR{}, rrs...), sig)
}

const refHashDigits = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

// refHashStep is the base32hex hash one step after h, or before it for a
// negative step.
func refHashStep(h string, step int) string {
	b := []byte(h)
	for i := len(b) - 1; i >= 0; i-- {
		switch j := strings.IndexByte(refHashDigits, b[i]) + step; {
		case j >= len(refHashDigits):
			b[i] = refHashDigits[0]
		case j < 0:
			b[i] = refHashDigits[len(refHashDigits)-1]
		default:
			b[i] = refHashDigits[j]
			return string(b)
		}
	}
	return string(b)
}

// refNSEC3 is an NSEC3 in refParent matching name, or, with cover, covering it
// with an interval that holds its hash and no other.
func refNSEC3(name string, cover bool, flags uint8, types ...uint16) *dns.NSEC3 {
	h := dns.HashName(name, dns.SHA1, 0, "")
	owner := h
	if cover {
		owner = refHashStep(h, -1)
	}
	return &dns.NSEC3{Hdr: dns.RR_Header{Name: owner + "." + refParent, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash: dns.SHA1, Flags: flags, HashLength: 20, NextDomain: refHashStep(h, 1), TypeBitMap: types}
}

// referralZones is the signed material the parent's side can deliver. It is
// made in the test's goroutine before the doubles start, so nothing signs on a
// server goroutine.
type referralZones struct {
	ds        []dns.RR // refKid's DS and its RRSIG
	dsAltered []dns.RR // the DS changed on the path, its RRSIG kept
	nsec      []dns.RR // the NSEC at the cut: NS, and no DS
	optOut    []dns.RR // an NSEC3 closest encloser proof for refKid, its covering NSEC3 with Opt-Out
	apexNSEC3 []dns.RR // the apex NSEC3 alone, which proves nothing about refKid
	soa       []dns.RR
}

// referralPath is what the parent's side of the path delivers: what the
// referral to refKid carries beside the NS, and the answer and authority
// sections for the DS question at refKid. With both empty the question gets a
// response with nothing in it.
type referralPath struct {
	referral, dsAnswer, dsDenial []dns.RR
}

// kidAnswer is how the child's A RRset for refKidWWW reaches the resolver.
type kidAnswer int

const (
	kidGenuine  kidAnswer = iota // signed, as the child serves it
	kidStripped                  // the RRSIG stripped on the path, or an unsigned child's own answer
	kidTampered                  // the address changed on the path, the genuine RRSIG kept
)

type referralSetup struct {
	parent      cache.ValidationState // refParent's state in ZoneMap; Secure, under a trust anchor, when zero
	unanchored  bool                  // the resolver holds no trust anchor at all
	unsignedKid bool
	answer      kidAnswer
	path        func(z *referralZones) referralPath
}

// startRefDouble serves handler on ip:port (port 0 picks one) until the test ends.
func startRefDouble(t *testing.T, ip net.IP, port int, handler dns.HandlerFunc) int {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		t.Skipf("cannot listen on %s port %d: %v", ip, port, err)
	}
	started := make(chan struct{})
	served := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() { served <- srv.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-served:
		t.Fatalf("auth double on %s failed to serve: %v", ip, err)
	case <-time.After(2 * time.Second):
		t.Fatal("auth double did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("auth double on %s shutdown: %v", ip, err)
		}
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Errorf("auth double on %s: serve goroutine did not exit", ip)
		}
	})
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// newReferralImr is a resolver reaching refParent through a stub on 127.0.0.1.
// The parent delegates refKid to ns.kid on ::1, on the same port, and what its
// side delivers is s.path. The child is signed with a key whose DS the parent
// publishes, unless s.unsignedKid. The counter records the DS questions the
// parent's side received.
func newReferralImr(t *testing.T, s referralSetup) (*Imr, *atomic.Int32) {
	t.Helper()
	parent, kid := newRefKey(t, refParent), newRefKey(t, refKid)

	ds := kid.key.ToDS(dns.SHA256)
	ds.Hdr.Ttl = 300
	altered := dns.Copy(ds).(*dns.DS)
	altered.KeyTag++
	z := &referralZones{
		ds:        parent.sign(t, ds),
		nsec:      parent.sign(t, mustRR(t, refKid+" 300 IN NSEC zzz."+refParent+" NS RRSIG NSEC")),
		apexNSEC3: parent.sign(t, refNSEC3(refParent, false, 0, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM)),
		soa:       parent.sign(t, mustRR(t, refParent+" 300 IN SOA ns."+refParent+" hostmaster."+refParent+" 1 7200 1800 604800 300")),
	}
	z.dsAltered = []dns.RR{altered, z.ds[1]}
	z.optOut = slices.Concat(z.apexNSEC3, parent.sign(t, refNSEC3(refKid, true, 1, dns.TypeA, dns.TypeRRSIG)))
	var path referralPath
	if s.path != nil {
		path = s.path(z)
	}

	kidSOA := mustRR(t, refKid+" 300 IN SOA "+refKidNS+" hostmaster."+refKid+" 1 7200 1800 604800 300")
	real := mustRR(t, refKidWWW+" 300 IN A 192.0.2.80")
	mail := mustRR(t, refKidMail+" 300 IN A 192.0.2.81")
	www, kidDNSKEY, kidNoData := []dns.RR{real}, []dns.RR(nil), []dns.RR{kidSOA}
	if !s.unsignedKid {
		signedA := kid.sign(t, real)
		switch s.answer {
		case kidGenuine:
			www = signedA
		case kidTampered:
			www = []dns.RR{mustRR(t, refKidWWW+" 300 IN A 192.0.2.66"), signedA[1]}
		}
		kidDNSKEY, kidNoData = kid.sign(t, kid.key), kid.sign(t, kidSOA)
	}
	delegation := mustRR(t, refKid+" 300 IN NS "+refKidNS)
	glue := mustRR(t, refKidNS+" 300 IN AAAA ::1")

	var dsQuestions atomic.Int32
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		name := dns.CanonicalName(q.Name)
		switch {
		case q.Qtype == dns.TypeDS && name == refKid:
			dsQuestions.Add(1)
			m.Answer = append(m.Answer, path.dsAnswer...)
			if len(path.dsAnswer) == 0 {
				m.Ns = append(m.Ns, path.dsDenial...)
			}
		case dns.IsSubDomain(refKid, name):
			m.Authoritative = false
			m.Ns = append(append(m.Ns, delegation), path.referral...)
			m.Extra = append(m.Extra, glue)
		default:
			m.Ns = append(m.Ns, z.soa...)
		}
		_ = w.WriteMsg(m)
	})
	startRefDouble(t, net.IPv6loopback, port, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		name := dns.CanonicalName(q.Name)
		switch {
		case q.Qtype == dns.TypeDNSKEY && name == refKid && kidDNSKEY != nil:
			m.Answer = append(m.Answer, kidDNSKEY...)
		case q.Qtype == dns.TypeA && name == refKidWWW:
			m.Answer = append(m.Answer, www...)
		case q.Qtype == dns.TypeA && name == refKidMail:
			m.Answer = append(m.Answer, mail)
		default:
			m.Ns = append(m.Ns, kidNoData...)
		}
		_ = w.WriteMsg(m)
	})

	imr := verdictImr(t, !s.unanchored)
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	if err := imr.Cache.AddStub(refParent, []cache.AuthServer{
		{Name: "ns." + refParent, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	state := s.parent
	if state == 0 {
		state = cache.ValidationStateSecure
		imr.Cache.DnskeyCache.Set(refParent, parent.key.KeyTag(), &cache.CachedDnskeyRRset{Name: refParent,
			Keyid: parent.key.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure, Dnskey: *parent.key,
			Expiration: time.Now().Add(time.Hour)})
	}
	imr.Cache.ZoneMap.Set(refParent, &cache.Zone{ZoneName: refParent, State: state})
	return imr, &dsQuestions
}

func askReferralImr(t *testing.T, imr *Imr, qname string) *dns.Msg {
	t.Helper()
	r, opts := verdictQuery{do: true}.msgFor(qname, dns.TypeA)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, dns.TypeA, opts)
	if cw.got == nil {
		t.Fatalf("%s: responder wrote nothing", qname)
	}
	return cw.got
}

func zoneStateOf(imr *Imr, zone string) string {
	if z, ok := imr.Cache.ZoneMap.Get(zone); ok {
		return cache.ValidationStateToString[z.GetState()]
	}
	return "absent"
}

// THE DEFECT. The parent is held Secure and publishes a DS for the child, and
// the referral reached the resolver with no DS that validates. With a trust
// anchor loaded, handleReferral entered the child as Insecure when the DS was
// gone and as Indeterminate when it did not validate, and from then on the
// child's answers were served: tampered ones, since a signer zone held Insecure
// is never checked, and stripped ones, since unsigned data from a zone held
// Insecure or Indeterminate is.
func TestAReferralWithoutAValidDSDoesNotLetTheChildsAnswersThrough(t *testing.T) {
	paths := []struct {
		name string
		path func(z *referralZones) referralPath
	}{
		{"DS stripped", func(z *referralZones) referralPath { return referralPath{dsAnswer: z.ds} }},
		{"DS stripped, and its RRSIG from the DS answer", func(z *referralZones) referralPath { return referralPath{dsAnswer: z.ds[:1]} }},
		{"DS stripped, DS question unanswered", func(*referralZones) referralPath { return referralPath{} }},
		{"DS altered", func(z *referralZones) referralPath { return referralPath{referral: z.dsAltered, dsAnswer: z.ds} }},
		{"DS RRSIG stripped", func(z *referralZones) referralPath { return referralPath{referral: z.ds[:1], dsAnswer: z.ds} }},
		{"DS replaced by an NSEC3 proving nothing", func(z *referralZones) referralPath {
			return referralPath{referral: z.apexNSEC3, dsAnswer: z.ds}
		}},
	}
	answers := []struct {
		name   string
		answer kidAnswer
	}{{"tampered", kidTampered}, {"stripped", kidStripped}}
	for _, p := range paths {
		for _, a := range answers {
			t.Run(p.name+"/"+a.name, func(t *testing.T) {
				imr, _ := newReferralImr(t, referralSetup{answer: a.answer, path: p.path})
				for _, via := range []string{"fresh", "cached"} {
					m := askReferralImr(t, imr, refKidWWW)
					if state := zoneStateOf(imr, refKid); state == "insecure" {
						t.Errorf("%s: child zone is %s", via, state)
					}
					if m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 {
						t.Errorf("%s: rcode %s with answer %v; a %s answer from a signed child must be SERVFAIL",
							via, dns.RcodeToString[m.Rcode], m.Answer, a.name)
					} else if edeOf(m) == 0 {
						t.Errorf("%s: SERVFAIL without an EDE", via)
					}
				}
				// Whatever that left in ZoneMap -- the validator enters the child
				// as Indeterminate, or with its DS's state, when it cannot anchor
				// the child's keys -- a stripped answer for another name in the
				// child is refused as well.
				if m := askReferralImr(t, imr, refKidMail); m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 {
					t.Errorf("then %s: rcode %s with answer %v; want SERVFAIL", refKidMail, dns.RcodeToString[m.Rcode], m.Answer)
				}
			})
		}
	}
}

// The chain the attacks break, intact: the DS in the referral makes the child
// Secure and its answer is served with AD.
func TestAReferralWithADSMakesTheChildSecure(t *testing.T) {
	imr, _ := newReferralImr(t, referralSetup{answer: kidGenuine, path: func(z *referralZones) referralPath {
		return referralPath{referral: z.ds, dsAnswer: z.ds}
	}})
	m := askReferralImr(t, imr, refKidWWW)
	if state := zoneStateOf(imr, refKid); state != "secure" {
		t.Errorf("child zone is %s, want secure", state)
	}
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 || !m.AuthenticatedData {
		t.Errorf("rcode %s, AD %v, answer %v; want NOERROR with AD", dns.RcodeToString[m.Rcode], m.AuthenticatedData, m.Answer)
	}
}

// What the fix must keep: an unsigned child of a secure parent, proven so, is
// Insecure and its data is served without AD. The proof may come in the
// referral, as an NSEC or the NSEC3 way, or only in the answer to the DS
// question, which is asked only then.
func TestAProvenInsecureDelegationIsServed(t *testing.T) {
	cases := []struct {
		name string
		path func(z *referralZones) referralPath
		asks bool
	}{
		{"NSEC in the referral", func(z *referralZones) referralPath { return referralPath{referral: z.nsec} }, false},
		{"NSEC3 Opt-Out span in the referral", func(z *referralZones) referralPath { return referralPath{referral: z.optOut} }, false},
		{"NSEC in the DS answer", func(z *referralZones) referralPath {
			return referralPath{dsDenial: slices.Concat(z.soa, z.nsec)}
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imr, asked := newReferralImr(t, referralSetup{unsignedKid: true, path: c.path})
			for _, via := range []string{"fresh", "cached"} {
				m := askReferralImr(t, imr, refKidWWW)
				if state := zoneStateOf(imr, refKid); state != "insecure" {
					t.Errorf("%s: child zone is %s, want insecure", via, state)
				}
				if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
					t.Fatalf("%s: rcode %s with %d answer RRs; data in a proven insecure child must be served",
						via, dns.RcodeToString[m.Rcode], len(m.Answer))
				}
				if m.AuthenticatedData {
					t.Errorf("%s: AD set on data from an insecure child", via)
				}
			}
			if n := asked.Load(); (n > 0) != c.asks {
				t.Errorf("%d DS question(s) asked of the parent", n)
			}
		})
	}
}

// Below a parent with no chain of trust -- one held Insecure, or on a resolver
// with no trust anchor -- the child takes the parent's state, as it did before,
// and no DS is asked for.
func TestAReferralBelowAnUnvalidatedParentAsksNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup referralSetup
		want  string
	}{
		{"insecure parent", referralSetup{parent: cache.ValidationStateInsecure, unsignedKid: true}, "insecure"},
		{"no trust anchor", referralSetup{parent: cache.ValidationStateIndeterminate, unanchored: true, unsignedKid: true}, "indeterminate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imr, asked := newReferralImr(t, c.setup)
			m := askReferralImr(t, imr, refKidWWW)
			if state := zoneStateOf(imr, refKid); state != c.want {
				t.Errorf("child zone is %s, want %s", state, c.want)
			}
			if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 || m.AuthenticatedData {
				t.Errorf("rcode %s, AD %v, answer %v; want NOERROR without AD", dns.RcodeToString[m.Rcode], m.AuthenticatedData, m.Answer)
			}
			if n := asked.Load(); n != 0 {
				t.Errorf("%d DS question(s) asked of the parent", n)
			}
		})
	}
}
