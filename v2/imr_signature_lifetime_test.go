/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Through the resolver, on a 2010 data clock: an authenticated answer or
 * denial is served and cached no longer than the signatures that
 * authenticated it allow (RFC 4035 section 5.3.3), and asked for again once
 * they no longer do.
 */
package tdns

import (
	"context"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const (
	ltZone  = "lt.example."  // signed with NSEC
	lt3Zone = "lt3.example." // signed with NSEC3
)

// newLifetimeImr is a resolver forwarding "." to a double that serves
// ltZone and lt3Zone, each a trust anchor. The answers are made on the data
// clock: the zones' keys and SOAs are signed for a week, and what each case
// is about as the case says.
func newLifetimeImr(t *testing.T) (*Imr, *upstreamLog) {
	t.Helper()
	from := faketime2010.Add(-time.Hour)
	week, in60s := faketime2010.Add(7*24*time.Hour), faketime2010.Add(60*time.Second)
	nsec, nsec3 := newFwdSecKey(t, ltZone), newFwdSecKey(t, lt3Zone)
	soa := func(zone string) dns.RR {
		return fwdSecRR(t, zone+" 3600 IN SOA ns."+zone+" h."+zone+" 1 7200 1800 604800 3600")
	}
	served := func(rrs []dns.RR, ttl uint32) []dns.RR { // records served with ttl, signed at their own
		out := make([]dns.RR, len(rrs))
		for i, rr := range rrs {
			out[i] = dns.Copy(rr)
			if _, isSig := rr.(*dns.RRSIG); !isSig {
				out[i].Header().Ttl = ttl
			}
		}
		return out
	}
	n3 := func(r *dns.NSEC3) dns.RR { r.Hdr.Ttl = 3600; return r }
	cat := func(sets ...[]dns.RR) []dns.RR {
		var out []dns.RR
		for _, s := range sets {
			out = append(out, s...)
		}
		return out
	}
	ltSOA, lt3SOA := nsec.signAt(t, from, week, soa(ltZone)), nsec3.signAt(t, from, week, soa(lt3Zone))
	answers := map[string]*dns.Msg{
		ltZone + " DNSKEY":  {Answer: nsec.signAt(t, from, week, dns.Copy(nsec.dnskey))},
		lt3Zone + " DNSKEY": {Answer: nsec3.signAt(t, from, week, dns.Copy(nsec3.dnskey))},
		// The proofs' signatures expire 60 s on.
		"nx." + ltZone + " A": {MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}, Ns: cat(ltSOA,
			nsec.signAt(t, from, in60s, fwdSecRR(t, ltZone+" 3600 IN NSEC zzz."+ltZone+" SOA NS RRSIG NSEC DNSKEY")))},
		"www." + ltZone + " TXT": {Ns: cat(ltSOA,
			nsec.signAt(t, from, in60s, fwdSecRR(t, "www."+ltZone+" 3600 IN NSEC zzz."+ltZone+" A RRSIG NSEC")))},
		"nx3." + lt3Zone + " A": {MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}, Ns: cat(lt3SOA,
			nsec3.signAt(t, from, in60s, n3(refNSEC3(lt3Zone, lt3Zone, false, 0, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM))),
			nsec3.signAt(t, from, in60s, n3(refNSEC3(lt3Zone, "nx3."+lt3Zone, true, 0))),
			nsec3.signAt(t, from, in60s, n3(refNSEC3(lt3Zone, "*."+lt3Zone, true, 0))))},
		// The answer's signature expires 60 s on.
		"www." + ltZone + " A": {Answer: nsec.signAt(t, from, in60s, fwdSecRR(t, "www."+ltZone+" 3600 IN A 192.0.2.1"))},
		// Signed at a TTL of 300, served with 3600; the signatures last a week.
		"ttl." + ltZone + " A": {Answer: served(nsec.signAt(t, from, week, fwdSecRR(t, "ttl."+ltZone+" 300 IN A 192.0.2.2")), 3600)},
		"nxo." + ltZone + " A": {MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}, Ns: cat(ltSOA,
			served(nsec.signAt(t, from, week, fwdSecRR(t, ltZone+" 300 IN NSEC zzz."+ltZone+" SOA NS RRSIG NSEC DNSKEY")), 3600))},
	}
	logr := &upstreamLog{}
	addr, port := startLoggedSignedForwardUpstream(t, answers, logr)
	imr := newForwardTestImr(t, []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}})
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("PrimeFromHintsOnly: %v", err)
	}
	for _, k := range []*fwdSecKey{nsec, nsec3} {
		zone := k.dnskey.Hdr.Name
		imr.Cache.DnskeyCache.Set(zone, k.dnskey.KeyTag(), &cache.CachedDnskeyRRset{
			Name: zone, Keyid: k.dnskey.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure,
			Dnskey: *k.dnskey, Expiration: cache.Now().Add(30 * 24 * time.Hour)})
		imr.Cache.ZoneMap.Set(zone, &cache.Zone{ZoneName: zone, State: cache.ValidationStateSecure})
	}
	return imr, logr
}

// askLifetime asks imr for <qname, qtype> with DO, as a validating client does.
func askLifetime(t *testing.T, imr *Imr, qname string, qtype uint16) *dns.Msg {
	t.Helper()
	r := new(dns.Msg)
	r.SetQuestion(qname, qtype)
	r.SetEdns0(4096, true)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, qtype, &edns0.MsgOptions{RD: true, DO: true})
	if cw.got == nil {
		t.Fatalf("%s %s: nothing written", qname, dns.TypeToString[qtype])
	}
	return cw.got
}

// servedTTL is the TTL of the answer's first record, or of the SOA in the
// authority section of a denial.
func servedTTL(m *dns.Msg) uint32 {
	if len(m.Answer) > 0 {
		return m.Answer[0].Header().Ttl
	}
	for _, rr := range m.Ns {
		if rr.Header().Rrtype == dns.TypeSOA {
			return rr.Header().Ttl
		}
	}
	return 0
}

func TestAnAuthenticatedEntryIsAskedForAgainOnceItsSignaturesAllowNoMore(t *testing.T) {
	path := startTestDataClock(t, faketime2010)
	imr, logr := newLifetimeImr(t)

	cases := []struct {
		name  string
		qname string
		qtype uint16
		rcode int
		bound uint32 // the most it may be served and cached for, in seconds
	}{
		{"NSEC NXDOMAIN, the proof signed for 60 s", "nx." + ltZone, dns.TypeA, dns.RcodeNameError, 60},
		{"NSEC NODATA, the proof signed for 60 s", "www." + ltZone, dns.TypeTXT, dns.RcodeSuccess, 60},
		{"NSEC3 NXDOMAIN, the proof signed for 60 s", "nx3." + lt3Zone, dns.TypeA, dns.RcodeNameError, 60},
		{"an answer signed for 60 s", "www." + ltZone, dns.TypeA, dns.RcodeSuccess, 60},
		{"an answer with Original TTL 300, served with 3600", "ttl." + ltZone, dns.TypeA, dns.RcodeSuccess, 300},
		{"NXDOMAIN, the proof's Original TTL 300, served with 3600", "nxo." + ltZone, dns.TypeA, dns.RcodeNameError, 300},
	}
	asked := func(qname string, qtype uint16) int { return len(logr.find(qname, qtype)) }
	for _, c := range cases {
		m := askLifetime(t, imr, c.qname, c.qtype)
		if m.Rcode != c.rcode || !m.AuthenticatedData {
			t.Fatalf("%s: rcode %s, AD %v; want %s with AD", c.name, dns.RcodeToString[m.Rcode], m.AuthenticatedData, dns.RcodeToString[c.rcode])
		}
		if ttl := servedTTL(m); ttl > c.bound || ttl+2 < c.bound {
			t.Errorf("%s: served with TTL %d, want about %d", c.name, ttl, c.bound)
		}
		if e := imr.Cache.Peek(c.qname, c.qtype); e == nil || e.Ttl > c.bound {
			t.Errorf("%s: cached %+v, want for at most %d s", c.name, e, c.bound)
		}
		if n := asked(c.qname, c.qtype); n != 1 {
			t.Errorf("%s: asked upstream %d times, want 1", c.name, n)
		}
	}

	// 61 s on, what was signed for 60 s is asked for again, and as the server
	// still sends the signatures that have now expired, it is SERVFAIL. What
	// was capped by its Original TTL is still served from the cache. 301 s on,
	// that is asked for again too, and its signatures still hold.
	writeFaketimeFile(t, path, faketime2010.Add(61*time.Second))
	for _, c := range cases {
		m := askLifetime(t, imr, c.qname, c.qtype)
		want, rcode := 1, c.rcode
		if c.bound == 60 {
			want, rcode = 2, dns.RcodeServerFailure
		}
		if n := asked(c.qname, c.qtype); n != want {
			t.Errorf("%s, 61 s on: asked upstream %d times, want %d", c.name, n, want)
		}
		if m.Rcode != rcode {
			t.Errorf("%s, 61 s on: rcode %s, want %s", c.name, dns.RcodeToString[m.Rcode], dns.RcodeToString[rcode])
		}
	}
	writeFaketimeFile(t, path, faketime2010.Add(301*time.Second))
	for _, c := range cases {
		if c.bound != 300 {
			continue
		}
		m := askLifetime(t, imr, c.qname, c.qtype)
		if n := asked(c.qname, c.qtype); n != 2 {
			t.Errorf("%s, 301 s on: asked upstream %d times, want 2", c.name, n)
		}
		if m.Rcode != c.rcode || !m.AuthenticatedData {
			t.Errorf("%s, 301 s on: rcode %s, AD %v; want %s with AD", c.name, dns.RcodeToString[m.Rcode], m.AuthenticatedData, dns.RcodeToString[c.rcode])
		}
	}
}
