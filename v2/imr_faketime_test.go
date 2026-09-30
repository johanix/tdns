/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The test clock (imrengine.testing.faketime), through the resolver: the
// validity of signatures, cache expiry and the TTLs served all follow a
// libfaketime timestamp file, as Deckard writes it.
// docs/2026-09-28-imr-deckard-test-clock-and-switches.md §3.

var faketime2010 = time.Date(2010, 3, 4, 5, 6, 7, 0, time.Local)

// writeFaketimeFile replaces the timestamp file the way Deckard does.
func writeFaketimeFile(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.WriteFile(path+".tmp", []byte("@"+at.Format("2006-01-02 15:04:05")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

// startTestDataClock starts the test clock at at, as the resolver's start does
// for faketime, until the test ends.
func startTestDataClock(t *testing.T, at time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".time")
	writeFaketimeFile(t, path, at)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); cache.SetDataClock(nil) })
	if err := startDataClock(ctx, ImrTestingConf{FaketimeFile: path}); err != nil {
		t.Fatalf("startDataClock: %v", err)
	}
	return path
}

// signAt returns rrs followed by their RRSIG, valid from inception to
// expiration.
func (k *fwdSecKey) signAt(t *testing.T, inception, expiration time.Time, rrs ...dns.RR) []dns.RR {
	t.Helper()
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: k.dnskey.KeyTag(), SignerName: k.dnskey.Hdr.Name,
		Inception: uint32(inception.Unix()), Expiration: uint32(expiration.Unix())}
	if err := sig.Sign(k.priv, rrs); err != nil {
		t.Fatal(err)
	}
	return append(append([]dns.RR{}, rrs...), sig)
}

// newImr2010 is a resolver forwarding "." to a double that serves
// sec.example. and kid.sec.example., signed with signatures valid for the ten
// minutes after faketime2010, with a trust anchor for sec.example.
func newImr2010(t *testing.T) *Imr {
	t.Helper()
	from, until := faketime2010.Add(-time.Hour), faketime2010.Add(10*time.Minute)
	parent, kid := newFwdSecKey(t, fwdSecParent), newFwdSecKey(t, fwdSecKid)
	addr, port := startSignedForwardUpstream(t, map[string]*dns.Msg{
		fwdSecWWW + " A":         {Answer: kid.signAt(t, from, until, fwdSecRR(t, fwdSecWWW+" 3600 IN A 192.0.2.7"))},
		fwdSecKid + " DNSKEY":    {Answer: kid.signAt(t, from, until, dns.Copy(kid.dnskey))},
		fwdSecKid + " DS":        {Answer: parent.signAt(t, from, until, kid.dnskey.ToDS(dns.SHA256))},
		fwdSecParent + " DNSKEY": {Answer: parent.signAt(t, from, until, dns.Copy(parent.dnskey))},
	})
	imr := newForwardTestImr(t, []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}})
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("PrimeFromHintsOnly: %v", err)
	}
	imr.Cache.DnskeyCache.Set(fwdSecParent, parent.dnskey.KeyTag(), &cache.CachedDnskeyRRset{
		Name: fwdSecParent, Keyid: parent.dnskey.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure,
		Dnskey: *parent.dnskey, Expiration: cache.Now().Add(time.Hour)})
	imr.Cache.ZoneMap.Set(fwdSecParent, &cache.Zone{ZoneName: fwdSecParent, State: cache.ValidationStateSecure})
	return imr
}

func askWWW(t *testing.T, imr *Imr) *dns.Msg {
	t.Helper()
	r := new(dns.Msg)
	r.SetQuestion(fwdSecWWW, dns.TypeA)
	r.SetEdns0(4096, true)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, fwdSecWWW, dns.TypeA, &edns0.MsgOptions{RD: true, DO: true})
	if cw.got == nil {
		t.Fatal("nothing written")
	}
	return cw.got
}

// On a clock set to 2010, data signed in 2010 validates, and is served with
// the TTL its signature leaves. Once the clock has moved past the signatures'
// expiry, the cached answer is gone, and the same data, asked again, is bogus.
// On real time it is bogus from the start.
func TestResolverFollowsTheTestClock(t *testing.T) {
	if m := askWWW(t, newImr2010(t)); m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("on real time: rcode %s; want SERVFAIL, the signatures expired in 2010", dns.RcodeToString[m.Rcode])
	}

	path := startTestDataClock(t, faketime2010)
	imr := newImr2010(t)
	m := askWWW(t, imr)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 || !m.AuthenticatedData {
		t.Fatalf("on a 2010 clock: rcode %s, %d answer RRs, AD=%v; want NOERROR, an answer, AD",
			dns.RcodeToString[m.Rcode], len(m.Answer), m.AuthenticatedData)
	}
	if ttl := m.Answer[0].Header().Ttl; ttl > 600 || ttl < 590 {
		t.Errorf("TTL %d; want what the signature leaves, about 600", ttl)
	}
	// Again, from the cache.
	if m := askWWW(t, imr); !m.AuthenticatedData || len(m.Answer) == 0 || m.Answer[0].Header().Ttl > 600 || m.Answer[0].Header().Ttl < 590 {
		t.Errorf("from the cache: AD=%v, %d answer RRs, TTL %d; want AD and about 600",
			m.AuthenticatedData, len(m.Answer), func() uint32 {
				if len(m.Answer) == 0 {
					return 0
				}
				return m.Answer[0].Header().Ttl
			}())
	}

	writeFaketimeFile(t, path, faketime2010.Add(11*time.Minute))
	if c := imr.Cache.Get(fwdSecWWW, dns.TypeA); c != nil {
		t.Errorf("still cached 11 minutes on in data time, expiring %v", c.Expiration)
	}
	if m := askWWW(t, imr); m.Rcode != dns.RcodeServerFailure {
		t.Errorf("after the signatures expired in data time: rcode %s; want SERVFAIL", dns.RcodeToString[m.Rcode])
	}
}

// The test clock needs its file, cannot be combined with a root refresh, and
// implies none. A resolver asked for it without a file does not start.
func TestFaketimeActivation(t *testing.T) {
	t.Cleanup(func() { cache.SetDataClock(nil) })
	t.Setenv("FAKETIME_TIMESTAMP_FILE", "")
	on, off := true, false
	ctx := context.Background()

	for name, tc := range map[string]ImrTestingConf{
		"no file named":             {Faketime: true},
		"a missing file":            {FaketimeFile: filepath.Join(t.TempDir(), "missing")},
		"root-refresh beside it":    {Faketime: true, FaketimeFile: startTestDataClock(t, faketime2010), RootRefresh: &on},
		"root-refresh without file": {Faketime: true, RootRefresh: &on},
	} {
		cache.SetDataClock(nil)
		if err := startDataClock(ctx, tc); err == nil {
			t.Errorf("%s: the clock started", name)
		}
	}

	conf := &Config{}
	conf.Imr.Testing.Faketime = true
	if err := conf.InitImrEngine(ctx, true); err == nil || !strings.Contains(err.Error(), "faketime") {
		t.Errorf("InitImrEngine with faketime and no file: %v; want a faketime error", err)
	}

	if !(ImrTestingConf{Faketime: true}).SkipRootRefresh() || !(ImrTestingConf{RootRefresh: &off}).SkipRootRefresh() ||
		(ImrTestingConf{}).SkipRootRefresh() || (ImrTestingConf{RootRefresh: &on}).SkipRootRefresh() {
		t.Error("the root refresh is off exactly when root-refresh is false or the test clock is on")
	}
}

// Starting the resolver again, after a failed start, keeps the clock running.
func TestFaketimeRestartKeepsTheClock(t *testing.T) {
	path := startTestDataClock(t, faketime2010)
	first := cache.DataClock()
	if err := startDataClock(context.Background(), ImrTestingConf{FaketimeFile: path}); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if cache.DataClock() != first {
		t.Error("a second start replaced the clock")
	}
}

// A changed testing block needs a restart.
func TestTestingChangeNeedsARestart(t *testing.T) {
	boot := ImrEngineConf{}
	cur := ImrEngineConf{}
	cur.Testing.Faketime = true
	if !slices.Contains(imrRestartRequiredKeys(boot, cur), "imrengine.testing") {
		t.Errorf("turning faketime on: restart-required keys %v; want imrengine.testing", imrRestartRequiredKeys(boot, cur))
	}
	off := false
	boot.Testing.RootRefresh, cur.Testing.RootRefresh = &off, new(bool)
	cur.Testing.Faketime = false
	if keys := imrRestartRequiredKeys(boot, cur); slices.Contains(keys, "imrengine.testing") {
		t.Errorf("the same testing block: restart-required keys %v", keys)
	}
}
