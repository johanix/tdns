/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * #636: a zone's Insecure or Indeterminate validation state is revisited, from
 * the config knob to the zone state a referral leaves behind.
 */
package tdns

import (
	"context"
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Through handleReferral, where the issue was seen: a child first delegated
// without a DS is recorded Insecure, and a later referral carrying a DS that
// the secure parent signed makes it Secure, with no restart and no interval to
// wait out in between.
func TestAReferralWithADSMakesAnInsecureZoneSecure(t *testing.T) {
	imr := newReloadTestImr(t)
	imr.Cache.DnskeyCache = cache.NewDnskeyCache()
	const parent, child, ns = "p636r.example.", "c.p636r.example.", "ns.elsewhere.test."

	// A resolver with a trust anchor, and a secure parent whose key it holds.
	imr.Cache.DnskeyCache.Set(".", 1, &cache.CachedDnskeyRRset{Name: ".", Keyid: 1,
		State: cache.ValidationStateSecure, TrustAnchor: true, Expiration: time.Now().Add(time.Hour)})
	pk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: parent, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 256, Protocol: 3, Algorithm: dns.ED25519}
	ppriv, err := pk.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	imr.Cache.DnskeyCache.Set(parent, pk.KeyTag(), &cache.CachedDnskeyRRset{Name: parent, Keyid: pk.KeyTag(),
		State: cache.ValidationStateSecure, Dnskey: *pk, Expiration: time.Now().Add(time.Hour)})
	pz := &cache.Zone{ZoneName: parent}
	pz.SetState(cache.ValidationStateSecure)
	imr.Cache.ZoneMap.Set(parent, pz)

	// The child's DS, as the parent signs it.
	ck := &dns.DNSKEY{Hdr: dns.RR_Header{Name: child, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	if _, err := ck.Generate(256); err != nil {
		t.Fatal(err)
	}
	ds := ck.ToDS(dns.SHA256)
	dsSig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: pk.KeyTag(), SignerName: parent,
		Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := dsSig.Sign(ppriv.(crypto.Signer), []dns.RR{ds}); err != nil {
		t.Fatal(err)
	}
	// Before the DS, the parent's NSEC at the cut proves there is none: a secure
	// parent's referral without a DS makes the child Insecure only with that
	// proof (ReferralChildState).
	nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: child, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "zzz." + parent, TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}}
	nsecSig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: pk.KeyTag(), SignerName: parent,
		Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := nsecSig.Sign(ppriv.(crypto.Signer), []dns.RR{nsec}); err != nil {
		t.Fatal(err)
	}

	// The child's nameserver is out of bailiwick, with its address already
	// cached, so the referral needs neither glue nor a lookup.
	imr.Cache.Set(ns, dns.TypeA, &cache.CachedRRset{Name: ns, RRtype: dns.TypeA, Context: cache.ContextAnswer,
		State: cache.ValidationStateInsecure, RRset: &core.RRset{Name: ns, Class: dns.ClassINET, RRtype: dns.TypeA,
			RRs: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: ns, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A: net.ParseIP("192.0.2.53")}}}})

	// handleReferral records the zone state first and then follows the
	// referral; the cancelled context stops the follow-up.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	refer := func(withDS bool) {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion("www."+child, dns.TypeA)
		m.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: child, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: ns}}
		if withDS {
			m.Ns = append(m.Ns, ds, dsSig)
		} else {
			m.Ns = append(m.Ns, nsec, nsecSig)
		}
		imr.handleReferral(ctx, "www."+child, dns.TypeA, m, false, map[string]bool{}, core.TransportDo53, edns0.PrivacyNone)
	}
	state := func() cache.ValidationState {
		z, ok := imr.Cache.ZoneMap.Get(child)
		if !ok {
			return cache.ValidationStateNone
		}
		return z.GetState()
	}

	refer(false)
	if st := state(); st != cache.ValidationStateInsecure {
		t.Fatalf("after a referral without a DS the child is %s, want insecure", cache.ValidationStateToString[st])
	}
	refer(true)
	if st := state(); st != cache.ValidationStateSecure {
		t.Fatalf("after a referral with a DS signed by the secure parent the child is %s, want secure",
			cache.ValidationStateToString[st])
	}
}

func TestZoneStateRecheckTuningDefault(t *testing.T) {
	var tc ImrTuningConf
	LoadImrTuningDefaults(&tc)
	if tc.ZoneStateRecheck != cache.DefaultZoneStateRecheck {
		t.Errorf("default zone-state-recheck is %s, want %s", tc.ZoneStateRecheck, cache.DefaultZoneStateRecheck)
	}
}

// The key decodes as a duration, and a changed value is reported as needing a
// restart like every other tuning key: the interval is installed once, at init.
func TestZoneStateRecheckDecodesAndNeedsRestart(t *testing.T) {
	boot := ImrEngineConf{}
	imr := runningImr(t, boot)
	conf := writeImrConfig(t, `imrengine:
   tuning:
      zone-state-recheck: 5m
   forward:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
`)
	block, err := conf.reloadImrEngineFromFile()
	if err != nil {
		t.Fatalf("reloadImrEngineFromFile: %v", err)
	}
	if block.Tuning.ZoneStateRecheck != 5*time.Minute {
		t.Fatalf("decoded zone-state-recheck %s, want 5m", block.Tuning.ZoneStateRecheck)
	}

	conf.Internal.ImrEngine = imr
	conf.Imr = boot
	res, err := conf.applyImrEngineReload()
	if err != nil {
		t.Fatalf("applyImrEngineReload: %v", err)
	}
	if len(res.RestartRequired) != 1 || res.RestartRequired[0] != "imrengine.tuning" {
		t.Errorf("RestartRequired = %v, want [imrengine.tuning]", res.RestartRequired)
	}
}

// The join: the interval set in the config is the one the cache runs on.
func TestZoneStateRecheckReachesTheCache(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	savedImr := Globals.ImrEngine
	savedLimits := cache.GetTTLLimits()
	t.Cleanup(func() {
		Globals.ImrEngine = savedImr
		cache.SetTTLLimits(savedLimits)
		cache.SetZoneStateRecheck(0)
	})

	conf := &Config{}
	conf.Imr.Forward = []ImrForwardConf{fwdConf(".", addr, port)}
	conf.Imr.Tuning.ZoneStateRecheck = 5 * time.Minute
	if err := conf.InitImrEngine(context.Background(), true); err != nil {
		t.Fatalf("InitImrEngine: %v", err)
	}
	if got := cache.ZoneStateRecheck(); got != 5*time.Minute {
		t.Errorf("the cache runs on a %s interval, want the configured 5m", got)
	}
}
