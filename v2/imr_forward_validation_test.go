/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A forwarding IMR that validates for itself (no trust-ad) sees no referrals:
// the DS of a zone is asked for on its own, by the validator, and a zone the
// parent delegates without a DS is known only by the parent's denial of it.
// These tests run that through the IMR's own forwarding, validation and
// responder, against a double of a validating recursive upstream that serves
// sec.example., signed, which the IMR holds a trust anchor for, and
// kid.sec.example., signed, delegated from it with or without a DS.
const (
	fwdSecParent = "sec.example."
	fwdSecKid    = "kid.sec.example."
	fwdSecWWW    = "www.kid.sec.example."
)

type fwdSecKey struct {
	dnskey *dns.DNSKEY
	priv   crypto.Signer
}

func newFwdSecKey(t *testing.T, zone string) *fwdSecKey {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	p, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return &fwdSecKey{dnskey: k, priv: p.(crypto.Signer)}
}

// sign returns rrs followed by their RRSIG, as a message section carries them.
func (k *fwdSecKey) sign(t *testing.T, rrs ...dns.RR) []dns.RR {
	t.Helper()
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: k.dnskey.KeyTag(), SignerName: k.dnskey.Hdr.Name,
		Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(k.priv, rrs); err != nil {
		t.Fatal(err)
	}
	return append(append([]dns.RR{}, rrs...), sig)
}

func fwdSecRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

// startSignedForwardUpstream serves the answers in sections, keyed by
// "qname qtype", with RA set, and SERVFAIL to anything else. The records are
// built before the server starts: the handler runs outside the test goroutine.
func startSignedForwardUpstream(t *testing.T, answers map[string]*dns.Msg) (string, uint16) {
	t.Helper()
	return startLoggedSignedForwardUpstream(t, answers, nil)
}

// startLoggedSignedForwardUpstream is startSignedForwardUpstream that also
// records every question it is asked in logr, when logr is not nil.
func startLoggedSignedForwardUpstream(t *testing.T, answers map[string]*dns.Msg, logr *upstreamLog) (string, uint16) {
	t.Helper()
	h := func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if logr != nil {
			logr.add(upstreamQuery{Qname: q.Name, Qtype: q.Qtype, RD: r.RecursionDesired, CD: r.CheckingDisabled})
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		if a, ok := answers[strings.ToLower(q.Name)+" "+dns.TypeToString[q.Qtype]]; ok {
			m.Answer, m.Ns = a.Answer, a.Ns
		} else {
			m.Rcode = dns.RcodeServerFailure
		}
		_ = w.WriteMsg(m)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := splitHostPort(t, pc.LocalAddr().String())
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(h), NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test upstream did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	return host, port
}

// #702: through a forwarding IMR, a signed zone with no DS in its signed parent
// was SERVFAIL, whether the parent denies the DS with NSEC or with NSEC3. It is
// Insecure: NOERROR without AD, on the first question and every one after, and
// whichever of its names is asked first. A zone with a DS stays Secure.
func TestForwardValidatesASignedZoneWithNoDSAsInsecure(t *testing.T) {
	cases := []struct {
		name   string
		ds     func(t *testing.T, parent, kid *fwdSecKey) *dns.Msg
		secure bool
	}{
		{"NSEC denial of the DS", func(t *testing.T, parent, _ *fwdSecKey) *dns.Msg {
			return &dns.Msg{Ns: parent.sign(t, fwdSecRR(t, fwdSecKid+" 300 IN NSEC zzz."+fwdSecParent+" NS RRSIG NSEC"))}
		}, false},
		{"NSEC3 denial of the DS", func(t *testing.T, parent, _ *fwdSecKey) *dns.Msg {
			nsec3 := &dns.NSEC3{Hdr: dns.RR_Header{Name: dns.HashName(fwdSecKid, dns.SHA1, 0, "") + "." + fwdSecParent,
				Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
				Hash: dns.SHA1, HashLength: 20, NextDomain: dns.HashName("zzz."+fwdSecParent, dns.SHA1, 0, ""),
				TypeBitMap: []uint16{dns.TypeNS}}
			return &dns.Msg{Ns: parent.sign(t, nsec3)}
		}, false},
		{"a DS", func(t *testing.T, parent, kid *fwdSecKey) *dns.Msg {
			return &dns.Msg{Answer: parent.sign(t, kid.dnskey.ToDS(dns.SHA256))}
		}, true},
	}
	for _, c := range cases {
		for _, first := range []struct {
			qname string
			qtype uint16
		}{{fwdSecWWW, dns.TypeA}, {fwdSecKid, dns.TypeDNSKEY}} {
			t.Run(c.name+"/"+dns.TypeToString[first.qtype]+" first", func(t *testing.T) {
				parent, kid := newFwdSecKey(t, fwdSecParent), newFwdSecKey(t, fwdSecKid)
				ds := c.ds(t, parent, kid)
				if len(ds.Answer) == 0 {
					ds.Ns = append(parent.sign(t, fwdSecRR(t, fwdSecParent+" 300 IN SOA ns."+fwdSecParent+" hostmaster."+fwdSecParent+" 1 7200 1800 604800 300")), ds.Ns...)
				}
				addr, port := startSignedForwardUpstream(t, map[string]*dns.Msg{
					fwdSecWWW + " A":         {Answer: kid.sign(t, fwdSecRR(t, fwdSecWWW+" 300 IN A 192.0.2.7"))},
					fwdSecKid + " DNSKEY":    {Answer: kid.sign(t, dns.Copy(kid.dnskey))},
					fwdSecKid + " DS":        ds,
					fwdSecParent + " DNSKEY": {Answer: parent.sign(t, dns.Copy(parent.dnskey))},
				})

				imr := newForwardTestImr(t, []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}})
				imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
				if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
					t.Fatalf("PrimeFromHintsOnly: %v", err)
				}
				imr.Cache.DnskeyCache.Set(fwdSecParent, parent.dnskey.KeyTag(), &cache.CachedDnskeyRRset{
					Name: fwdSecParent, Keyid: parent.dnskey.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure,
					Dnskey: *parent.dnskey, Expiration: time.Now().Add(time.Hour)})
				imr.Cache.ZoneMap.Set(fwdSecParent, &cache.Zone{ZoneName: fwdSecParent, State: cache.ValidationStateSecure})

				for i := 1; i <= 2; i++ {
					r := new(dns.Msg)
					r.SetQuestion(first.qname, first.qtype)
					r.SetEdns0(4096, true)
					cw := &captureWriter{}
					imr.ImrResponder(context.Background(), cw, r, first.qname, first.qtype, &edns0.MsgOptions{RD: true, DO: true})
					if cw.got == nil {
						t.Fatalf("question %d: nothing written", i)
					}
					if cw.got.Rcode != dns.RcodeSuccess || len(cw.got.Answer) == 0 {
						t.Fatalf("question %d: rcode %s, %d answer RRs, EDE %d; want NOERROR with an answer",
							i, dns.RcodeToString[cw.got.Rcode], len(cw.got.Answer), edeOf(cw.got))
					}
					if cw.got.AuthenticatedData != c.secure {
						t.Errorf("question %d: AD=%v, want %v", i, cw.got.AuthenticatedData, c.secure)
					}
				}
				want := cache.ValidationStateInsecure
				if c.secure {
					want = cache.ValidationStateSecure
				}
				if z, ok := imr.Cache.ZoneMap.Get(fwdSecKid); !ok || z.GetState() != want {
					t.Errorf("zone %s is not in ZoneMap as %s", fwdSecKid, cache.ValidationStateToString[want])
				}
			})
		}
	}
}
