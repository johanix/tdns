/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Data under a trust anchor that does not validate is SERVFAIL, whether or not
// the anchor zone's DNSKEY RRset could be fetched and matched at start-up.

const (
	taRootNS   = "k.root-ta.test."
	taUnsigned = "unsigned.root-ta.test."
)

// signWithin returns rrs followed by an RRSIG valid from inception to
// expiration.
func (k *refKey) signWithin(t *testing.T, inception, expiration time.Time, rrs ...dns.RR) []dns.RR {
	t.Helper()
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: k.key.KeyTag(), SignerName: k.key.Hdr.Name,
		Inception: uint32(inception.Unix()), Expiration: uint32(expiration.Unix())}
	if err := sig.Sign(k.priv, rrs); err != nil {
		t.Fatal(err)
	}
	return append(append([]dns.RR{}, rrs...), sig)
}

// taRoot is what the root's server double serves: the DNSKEY and NS RRsets as
// given, and taUnsigned's A RRset and the root's TXT RRset without RRSIGs.
type taRoot struct {
	dnskey, ns []dns.RR
}

// anchorImr: the DS of anchor's key is the trust anchor for the root, and the
// root's server is a double on 127.0.0.1 serving what it is given. With startup, the
// anchor is processed as at start-up (processTrustAnchorZone), which fails
// when the DNSKEY RRset it is given does not validate against the anchor; without,
// the start-up fetch never got an answer.
func anchorImr(t *testing.T, anchor *refKey, serve taRoot, startup bool) *Imr {
	t.Helper()
	return anchorImrDS(t, anchor.key.ToDS(dns.SHA256), serve, startup)
}

// anchorImrDS is anchorImr with the root's trust anchor given as a DS.
func anchorImrDS(t *testing.T, ds *dns.DS, serve taRoot, startup bool) *Imr {
	t.Helper()
	soa := mustRR(t, ". 300 IN SOA "+taRootNS+" hostmaster.root-ta.test. 1 7200 1800 604800 300")
	unsigned := mustRR(t, taUnsigned+" 300 IN A 192.0.2.53")
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		switch q := r.Question[0]; {
		case q.Name == "." && q.Qtype == dns.TypeDNSKEY:
			m.Answer = append(m.Answer, serve.dnskey...)
		case q.Name == "." && q.Qtype == dns.TypeNS:
			m.Answer = append(m.Answer, serve.ns...)
		case dns.CanonicalName(q.Name) == taUnsigned && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, unsigned)
		case q.Name == "." && q.Qtype == dns.TypeTXT:
			m.Answer = append(m.Answer, mustRR(t, `. 300 IN TXT "unsigned"`))
		default:
			m.Ns = append(m.Ns, soa)
		}
		_ = w.WriteMsg(m)
	})
	imr := verdictImr(t, false)
	imr.DnskeyCache = imr.Cache.DnskeyCache // as InitImrEngine sets it
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	srv := imr.Cache.GetOrCreateAuthServer(taRootNS)
	srv.SetAddrs([]string{"127.0.0.1"})
	imr.Cache.ServerMap.Set(".", map[string]*cache.AuthServer{cache.ServerKey(taRootNS): srv})

	ds.Hdr.Ttl = 3600
	dsByName := map[string][]*dns.DS{".": {ds}}
	imr.seedDSRRsetFromTrustAnchors(".", dsByName["."])
	if startup {
		_ = imr.processTrustAnchorZone(context.Background(), ".", dsByName, nil)
	}
	return imr
}

// rootServing signs the root's DNSKEY RRset (signer's key) and NS RRset with
// signer, within the windows given.
func rootServing(t *testing.T, signer *refKey, dnskeyValid, nsValid bool) taRoot {
	t.Helper()
	now := time.Now()
	window := func(valid bool) (time.Time, time.Time) {
		if valid {
			return now.Add(-time.Hour), now.Add(time.Hour)
		}
		return now.Add(-48 * time.Hour), now.Add(-24 * time.Hour) // expired
	}
	ki, ke := window(dnskeyValid)
	ni, ne := window(nsValid)
	return taRoot{
		dnskey: signer.signWithin(t, ki, ke, signer.key),
		ns:     signer.signWithin(t, ni, ne, mustRR(t, ". 300 IN NS "+taRootNS)),
	}
}

func askType(t *testing.T, imr *Imr, qname string, qtype uint16) *dns.Msg {
	t.Helper()
	r, opts := verdictQuery{do: true}.msgFor(qname, qtype)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, qtype, opts)
	if cw.got == nil {
		t.Fatalf("%s %s: responder wrote nothing", qname, dns.TypeToString[qtype])
	}
	return cw.got
}

func wantServfail(t *testing.T, imr *Imr, got *dns.Msg) {
	t.Helper()
	if got.Rcode != dns.RcodeServerFailure || len(got.Answer) != 0 {
		t.Errorf("got %s, AD=%v, %d answers; want SERVFAIL (root zone state %s):\n%s",
			dns.RcodeToString[got.Rcode], got.AuthenticatedData, len(got.Answer), zoneStateOf(imr, "."), got)
	}
}

// Every signature valid: the control, Secure.
func TestDataUnderATrustAnchorThatValidatesIsSecure(t *testing.T) {
	for _, startup := range []bool{true, false} {
		t.Run("startup="+strconv.FormatBool(startup), func(t *testing.T) {
			root := newRefKey(t, ".")
			imr := anchorImr(t, root, rootServing(t, root, true, true), startup)
			got := askType(t, imr, ".", dns.TypeNS)
			if got.Rcode != dns.RcodeSuccess || len(got.Answer) == 0 || !got.AuthenticatedData {
				t.Errorf("got %s, AD=%v, %d answers; want NOERROR with AD:\n%s",
					dns.RcodeToString[got.Rcode], got.AuthenticatedData, len(got.Answer), got)
			}
		})
	}
}

// Expired signatures, on the NS RRset or on the DNSKEY RRset too. With the
// DNSKEY RRset's expired and no start-up fetch, the NS RRset used to be served
// without AD: the resolver did not count a DS anchor whose keys it had not yet
// matched as an anchor.
func TestExpiredSignaturesUnderATrustAnchorAreServfail(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		dnskeyValid, nsValid bool
	}{
		{"NS signature expired", true, false},
		{"DNSKEY and NS signatures expired", false, false},
	} {
		for _, startup := range []bool{true, false} {
			t.Run(tc.name+"/startup="+strconv.FormatBool(startup), func(t *testing.T) {
				root := newRefKey(t, ".")
				imr := anchorImr(t, root, rootServing(t, root, tc.dnskeyValid, tc.nsValid), startup)
				wantServfail(t, imr, askType(t, imr, ".", dns.TypeNS))
			})
		}
	}
}

// A DNSKEY RRset that does not match the anchor, another key signing it and the
// NS RRset: the NS RRset is SERVFAIL, and so is unsigned data asked for next.
// The root used to be marked Indeterminate by the failed DNSKEY validation, and
// the unsigned data under it was then served.
func TestKeysNotMatchingTheAnchorAreServfail(t *testing.T) {
	for _, startup := range []bool{true, false} {
		t.Run("startup="+strconv.FormatBool(startup), func(t *testing.T) {
			other := newRefKey(t, ".")
			imr := anchorImr(t, newRefKey(t, "."), rootServing(t, other, true, true), startup)
			wantServfail(t, imr, askType(t, imr, ".", dns.TypeNS))
			wantServfail(t, imr, askType(t, imr, taUnsigned, dns.TypeA))
		})
	}
}

// Unsigned data under an anchor whose DNSKEY RRset was never fetched is
// SERVFAIL: the anchor makes the zone Secure from the moment it is loaded.
func TestUnsignedDataUnderAnUnfetchedAnchorIsServfail(t *testing.T) {
	root := newRefKey(t, ".")
	imr := anchorImr(t, root, rootServing(t, root, true, true), false)
	wantServfail(t, imr, askType(t, imr, taUnsigned, dns.TypeA))
}

// Unsigned data at the root's apex, under an anchor that was activated at
// start-up: SERVFAIL. The root was passed over when unsigned data looked for
// the zone it belongs to, and such data was served.
func TestUnsignedRootDataUnderAnActivatedAnchorIsServfail(t *testing.T) {
	root := newRefKey(t, ".")
	imr := anchorImr(t, root, rootServing(t, root, true, true), true)
	wantServfail(t, imr, askType(t, imr, ".", dns.TypeTXT))
}

// Every configured anchor is processed at start-up, and every zone is Secure,
// when the first one fails: here no anchor zone's DNSKEY RRset can be fetched.
// The first failure used to end the loop, and the anchors after it were not
// processed.
func TestEveryTrustAnchorIsProcessedWhenOneFails(t *testing.T) {
	imr := verdictImr(t, false)
	imr.DnskeyCache = imr.Cache.DnskeyCache
	rootDS := newRefKey(t, ".").key.ToDS(dns.SHA256)
	otherDS := newRefKey(t, "anchor2.test.").key.ToDS(dns.SHA256)
	file := t.TempDir() + "/anchors"
	if err := os.WriteFile(file, []byte(otherDS.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Imr.TrustAnchorDS = rootDS.String()
	conf.Imr.TrustAnchorFile = file

	err := imr.initializeImrTrustAnchors(context.Background(), conf)
	if err == nil {
		t.Fatal("want an error: no anchor zone's DNSKEY RRset can be fetched")
	}
	for _, zone := range []string{".", "anchor2.test."} {
		if !strings.Contains(err.Error(), "trust anchor "+zone+":") {
			t.Errorf("error %q does not report the anchor for %s", err, zone)
		}
		if state := zoneStateOf(imr, zone); state != cache.ValidationStateToString[cache.ValidationStateSecure] {
			t.Errorf("%s is %s, want secure", zone, state)
		}
	}
	if !imr.hasTrustAnchors() {
		t.Error("hasTrustAnchors is false with two anchors configured")
	}
}

// Signed data under an anchor whose DNSKEY RRset cannot be fetched at all:
// the signature cannot be checked, and under a trust anchor that is SERVFAIL.
// A DS anchor whose keys had never been matched did not count as an anchor,
// and such data was served.
func TestUnfetchableKeysUnderATrustAnchorAreServfail(t *testing.T) {
	root := newRefKey(t, ".")
	serve := rootServing(t, root, true, true)
	serve.dnskey = nil // the DNSKEY question gets an empty answer
	imr := anchorImr(t, root, serve, false)
	wantServfail(t, imr, askType(t, imr, ".", dns.TypeNS))
}

// expireCached makes the cached <name, qtype> entry expired, as time passing
// would. It writes the entry directly: Set would compute a new expiration.
func expireCached(t *testing.T, imr *Imr, name string, qtype uint16) {
	t.Helper()
	for item := range imr.Cache.RRsets.IterBuffered() {
		if core.EqualNames(item.Val.Name, name) && item.Val.RRtype == qtype {
			expired := item.Val
			expired.Expiration = time.Now().Add(-time.Minute)
			imr.Cache.RRsets.Set(item.Key, expired)
			if imr.Cache.Get(name, qtype) != nil {
				t.Fatalf("precondition: %s %s is still cached", name, dns.TypeToString[qtype])
			}
			return
		}
	}
	t.Fatalf("precondition: no cached %s %s", name, dns.TypeToString[qtype])
}

func wantSecure(t *testing.T, got *dns.Msg) {
	t.Helper()
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) == 0 || !got.AuthenticatedData {
		t.Errorf("got %s, AD=%v, %d answers; want NOERROR with AD:\n%s",
			dns.RcodeToString[got.Rcode], got.AuthenticatedData, len(got.Answer), got)
	}
}

// A flush leaves an anchor whose keys were never matched in force: its zone
// stays Secure, so unsigned data under it is still SERVFAIL, and its signed data
// still validates, from the anchor's DS (FlushAll removes the seeded copy). The
// flushes kept the anchor zones they found through a trust anchor key, which a
// DS anchor does not have until its keys have matched it.
func TestAFlushLeavesATrustAnchorInForce(t *testing.T) {
	for name, flush := range map[string]func(*Imr){
		"FlushAll":       func(imr *Imr) { imr.Cache.FlushAll() },
		"FlushDomain(.)": func(imr *Imr) { _, _ = imr.Cache.FlushDomain(".", false) },
	} {
		t.Run(name, func(t *testing.T) {
			root := newRefKey(t, ".")
			imr := anchorImr(t, root, rootServing(t, root, true, true), false)
			flush(imr)
			if state := zoneStateOf(imr, "."); state != cache.ValidationStateToString[cache.ValidationStateSecure] {
				t.Errorf("after the flush the root is %s, want secure", state)
			}
			wantServfail(t, imr, askType(t, imr, taUnsigned, dns.TypeA))
			wantSecure(t, askType(t, imr, ".", dns.TypeNS))
		})
	}
}

// The DS RRset seeded from a DS anchor expires like any other RRset. The anchor
// does not: signed data under it still validates.
func TestATrustAnchorOutlivesItsSeededDS(t *testing.T) {
	root := newRefKey(t, ".")
	imr := anchorImr(t, root, rootServing(t, root, true, true), false)
	expireCached(t, imr, ".", dns.TypeDS)
	wantSecure(t, askType(t, imr, ".", dns.TypeNS))
}

// A DS anchor for a zone below the root, whose parent publishes no DS for it
// (an island of security). Once the seeded DS had expired, the DS was asked of
// the parent, whose denial made the zone an insecure delegation and undid the
// anchor. The zone's data still validates.
func TestAnIslandAnchorOutlivesItsSeededDS(t *testing.T) {
	const zone, zoneNS = "island.test.", "ns.island.test."
	key := newRefKey(t, zone)
	now := time.Now()
	dnskey := key.signWithin(t, now.Add(-time.Hour), now.Add(time.Hour), key.key)
	ns := key.signWithin(t, now.Add(-time.Hour), now.Add(time.Hour), mustRR(t, zone+" 300 IN NS "+zoneNS))
	parentSOA := mustRR(t, "test. 300 IN SOA ns.test. hostmaster.test. 1 7200 1800 604800 300")
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		switch q := r.Question[0]; {
		case dns.CanonicalName(q.Name) == zone && q.Qtype == dns.TypeDNSKEY:
			m.Answer = append(m.Answer, dnskey...)
		case dns.CanonicalName(q.Name) == zone && q.Qtype == dns.TypeNS:
			m.Answer = append(m.Answer, ns...)
		default: // the parent side: no DS for the island, unsigned
			m.Ns = append(m.Ns, parentSOA)
		}
		_ = w.WriteMsg(m)
	})
	imr := verdictImr(t, false)
	imr.DnskeyCache = imr.Cache.DnskeyCache
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	for z, nsname := range map[string]string{zone: zoneNS, ".": taRootNS} {
		srv := imr.Cache.GetOrCreateAuthServer(nsname)
		srv.SetAddrs([]string{"127.0.0.1"})
		imr.Cache.ServerMap.Set(z, map[string]*cache.AuthServer{cache.ServerKey(nsname): srv})
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})
	ds := key.key.ToDS(dns.SHA256)
	ds.Hdr.Ttl = 3600
	imr.seedDSRRsetFromTrustAnchors(zone, []*dns.DS{ds})
	expireCached(t, imr, zone, dns.TypeDS)

	wantSecure(t, askType(t, imr, zone, dns.TypeNS))
	if state := zoneStateOf(imr, zone); state != cache.ValidationStateToString[cache.ValidationStateSecure] {
		t.Errorf("%s is %s, want secure", zone, state)
	}
}
