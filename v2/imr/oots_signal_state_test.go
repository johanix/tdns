/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	stateZone     = "kid.p.test."
	providerZone  = "provider.example."
	providerOwner = "_dns.ns." + providerZone
)

// stateOnEachPath runs section, an Additional section holding one
// nameserver's SVCB RRset and perhaps RRSIGs, through each path a signal
// arrives by, as signalOnEachPath does, and returns the server each left
// behind. The answer path gets the SVCB records and lookupState, the verdict
// a lookup of _dns.<ns> would have reached. prep, when not nil, readies each
// path's resolver.
func stateOnEachPath(t *testing.T, section []dns.RR, lookupState cache.ValidationState, prep func(*Imr)) map[string]*cache.AuthServer {
	t.Helper()
	ctx := context.Background()
	out := map[string]*cache.AuthServer{}
	fresh := func() *Imr {
		imr := newTestImr(t)
		imr.Quiet = true
		if prep != nil {
			prep(imr)
		}
		return imr
	}

	imr := fresh()
	server := cache.NewAuthServer(pathNS)
	r := new(dns.Msg)
	r.SetQuestion("www."+stateZone, dns.TypeA)
	r.Extra = copyRRs(section)
	imr.parseTransportForServerFromAdditional(ctx, server, r)
	out[cache.SignalViaResponse] = server

	imr = fresh()
	ref := new(dns.Msg)
	ref.SetQuestion("www."+stateZone, dns.TypeA)
	ref.Response = true
	ref.Ns = []dns.RR{mustRR(t, stateZone+" 3600 IN NS "+pathNS)}
	ref.Extra = copyRRs(section)
	nsrrset := &core.RRset{Name: stateZone, Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: ref.Ns}
	if _, err := imr.ParseAdditionalForNSAddrs(ctx, "authority", nsrrset, stateZone, "p.test.",
		map[string]bool{pathNS: true}, ref); err != nil {
		t.Fatalf("ParseAdditionalForNSAddrs: %v", err)
	}
	out[cache.SignalViaReferral] = imr.Cache.GetOrCreateAuthServer(pathNS)

	imr = fresh()
	server = cache.NewAuthServer(pathNS)
	imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})
	imr.applyTransportRRsetFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB,
		RRs: copyRRs(svcbAt(section, pathOwner))}, lookupState)
	out[cache.SignalViaLookup] = server
	return out
}

// selectionSnapshot is what selection uses from a server's signal: the
// received signal (signalSnapshot), the weights with their absence defaults,
// and the transports.
func selectionSnapshot(server *cache.AuthServer) string {
	transports, weights := server.GetTransportSignal()
	var w, tr []string
	for t, v := range weights {
		w = append(w, fmt.Sprintf("%s:%d", core.TransportToString[t], v))
	}
	for _, t := range transports {
		tr = append(tr, core.TransportToString[t])
	}
	sort.Strings(w)
	sort.Strings(tr)
	return fmt.Sprintf("%s sel=%s tr=%s", signalSnapshot(server), strings.Join(w, ","), strings.Join(tr, ","))
}

// signedSection is section with k's RRSIG over the records at each owner in
// owners appended, as tdns-auth injects them for a DO query.
func signedSection(t *testing.T, k *signerTestKey, section []dns.RR, owners ...string) []dns.RR {
	t.Helper()
	out := copyRRs(section)
	for _, owner := range owners {
		rrset := k.sign(t, copyRRs(svcbAt(section, owner))...)
		out = append(out, rrset.RRSIGs...)
	}
	return out
}

// Each path records the state of the RRset a signal was read from: decided in
// place from the RRSIG in the Additional section and the keys the cache holds,
// and taken from the lookup's verdict on the answer path. The state changes
// nothing that is installed: weights, transports and ports are the same as
// for the RRset without an RRSIG (R4).
func TestOOTSSignalStateOnEachPath(t *testing.T) {
	records := []dns.RR{
		mustRR(t, pathOwner+` 3600 IN SVCB 1 . oots="do53:100,doq:20"`),
		mustRR(t, pathOwner+` 3600 IN SVCB 1 . port=1234 oots="dot:10"`),
	}
	dkc := signerTestDnskeyCache(t)
	held := newSignerTestKey(t, stateZone, 256)
	held.holdSecure(dkc)
	stranger := newSignerTestKey(t, stateZone, 256) // the cache does not hold it

	tampered := signedSection(t, held, records, pathOwner)
	tampered[1] = mustRR(t, pathOwner+` 3600 IN SVCB 1 . port=1234 oots="dot:90"`)

	holdInsecure := func(imr *Imr) {
		imr.Cache.ZoneMap.Set(stateZone, &cache.Zone{ZoneName: stateZone, State: cache.ValidationStateInsecure})
	}

	baseline := map[cache.ValidationState]map[string]string{}
	baselineFor := func(lookup cache.ValidationState) map[string]string {
		if b, ok := baseline[lookup]; ok {
			return b
		}
		b := map[string]string{}
		for via, server := range stateOnEachPath(t, records, lookup, nil) {
			b[via] = selectionSnapshot(server)
		}
		baseline[lookup] = b
		return b
	}

	for _, tc := range []struct {
		name       string
		section    []dns.RR
		prep       func(*Imr)
		lookup     cache.ValidationState // the answer path's verdict
		additional cache.ValidationState // what both Additional paths decide in place
	}{
		{"signed, key at hand", signedSection(t, held, records, pathOwner), nil,
			cache.ValidationStateSecure, cache.ValidationStateSecure},
		{"no RRSIG", records, nil,
			cache.ValidationStateInsecure, cache.SignalStateUnknown},
		{"signature does not verify", tampered, nil,
			cache.ValidationStateBogus, cache.ValidationStateBogus},
		{"key not at hand", signedSection(t, stranger, records, pathOwner), nil,
			cache.ValidationStateIndeterminate, cache.SignalStateUnknown},
		{"signer zone held insecure", signedSection(t, held, records, pathOwner), holdInsecure,
			cache.ValidationStateNone, cache.ValidationStateInsecure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := map[string]cache.ValidationState{
				cache.SignalViaResponse: tc.additional,
				cache.SignalViaReferral: tc.additional,
				cache.SignalViaLookup:   cache.SignalState(tc.lookup),
			}
			base := baselineFor(tc.lookup)
			for via, server := range stateOnEachPath(t, tc.section, tc.lookup, tc.prep) {
				rec := server.GetReceivedSignal()
				if rec == nil {
					t.Fatalf("%s: no signal installed", via)
				}
				if rec.Via != via {
					t.Errorf("%s: Via = %q", via, rec.Via)
				}
				wantPath := []cache.SignalHop{{Owner: pathOwner, State: want[via]}}
				if got, w := cache.FormatSignalPath(rec.Path), cache.FormatSignalPath(wantPath); got != w {
					t.Errorf("%s: path %q, want %q", via, got, w)
				}
				if got := rec.PathState(); got != want[via] {
					t.Errorf("%s: PathState %s, want %s", via, cache.SignalStateString(got), cache.SignalStateString(want[via]))
				}
				if via == cache.SignalViaLookup {
					continue // the tampered record changes the weights, not the path
				}
				if tc.name == "signature does not verify" {
					continue
				}
				if got := selectionSnapshot(server); got != base[via] {
					t.Errorf("%s: selection changed:\n got  %s\n want %s", via, got, base[via])
				}
			}
		})
	}
}

// A Bogus RRset is installed just as an unsigned one is: no record with
// TargetName "." needs validation (R4), and R2 keeps those records whatever
// the state of the RRset.
func TestOOTSBogusSignalStillInstalled(t *testing.T) {
	records := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 1 . port=1234 oots="dot:90"`)}
	dkc := signerTestDnskeyCache(t)
	held := newSignerTestKey(t, stateZone, 256)
	held.holdSecure(dkc)
	signed := signedSection(t, held, []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 1 . port=1234 oots="dot:10"`)}, pathOwner)
	bogus := append(copyRRs(records), signed[1:]...) // the RRSIG over dot:10

	want := map[string]string{}
	for via, server := range stateOnEachPath(t, records, cache.ValidationStateBogus, nil) {
		want[via] = selectionSnapshot(server)
	}
	for via, server := range stateOnEachPath(t, bogus, cache.ValidationStateBogus, nil) {
		if got := server.GetReceivedSignal().PathState(); got != cache.ValidationStateBogus {
			t.Errorf("%s: state %s, want bogus", via, cache.SignalStateString(got))
		}
		if got := selectionSnapshot(server); got != want[via] {
			t.Errorf("%s: selection changed:\n got  %s\n want %s", via, got, want[via])
		}
	}
}

// A verdict the cache holds for the same RRs and RRSIGs is reused: the
// verifying lookup's Secure carries over to the same RRset in Additional
// even when the key has since left the DNSKEY cache.
func TestOOTSSignalStateReusesCachedVerdict(t *testing.T) {
	records := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 1 . oots="dot:10"`)}
	signerTestDnskeyCache(t)
	key := newSignerTestKey(t, stateZone, 256) // never held
	section := signedSection(t, key, records, pathOwner)
	rrset := &core.RRset{Name: pathOwner, Class: dns.ClassINET, RRtype: dns.TypeSVCB,
		RRs: copyRRs(svcbAt(section, pathOwner)), RRSIGs: copyRRs(section[1:])}

	imr := newTestImr(t)
	if got := imr.additionalSVCBState(section, pathOwner, svcbAt(section, pathOwner)); got != cache.SignalStateUnknown {
		t.Fatalf("before the lookup: %s, want unknown", cache.SignalStateString(got))
	}
	imr.Cache.Set(pathOwner, dns.TypeSVCB, &cache.CachedRRset{
		Name: pathOwner, RRtype: dns.TypeSVCB, RRset: rrset,
		State: cache.ValidationStateSecure, Expiration: time.Now().Add(time.Hour),
	})
	if got := imr.additionalSVCBState(section, pathOwner, svcbAt(section, pathOwner)); got != cache.ValidationStateSecure {
		t.Errorf("after the lookup: %s, want secure", cache.SignalStateString(got))
	}
}

// An RRset that holds an AliasMode record records the state of every hop on
// its path (R5): the alias RRset at _dns.<ns> and the RRset at each target,
// read from the same Additional section. Nothing is installed from it.
func TestOOTSSignalStateAliasHops(t *testing.T) {
	dkc := signerTestDnskeyCache(t)
	kid := newSignerTestKey(t, stateZone, 256)
	kid.holdSecure(dkc)
	provider := newSignerTestKey(t, providerZone, 256)
	provider.holdSecure(dkc)

	alias := mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)
	target := mustRR(t, providerOwner+` 3600 IN SVCB 1 . oots="dot:50"`)
	sign := func(k *signerTestKey, rr dns.RR) []dns.RR {
		return k.sign(t, dns.Copy(rr)).RRSIGs
	}
	join := func(parts ...[]dns.RR) []dns.RR {
		var out []dns.RR
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	one := func(rr dns.RR) []dns.RR { return []dns.RR{rr} }
	hop := func(owner string, s cache.ValidationState) cache.SignalHop {
		return cache.SignalHop{Owner: owner, State: s}
	}
	secure, unknown, bogus := cache.ValidationStateSecure, cache.SignalStateUnknown, cache.ValidationStateBogus

	// Two hops: _dns.<ns> -> _dns.ns.a.example. -> _dns.ns.b.example.
	aOwner, bOwner := "_dns.ns.a.example.", "_dns.ns.b.example."
	a := newSignerTestKey(t, "a.example.", 256)
	a.holdSecure(dkc)
	b := newSignerTestKey(t, "b.example.", 256)
	b.holdSecure(dkc)
	aliasA := mustRR(t, pathOwner+` 3600 IN SVCB 0 `+aOwner)
	aToB := mustRR(t, aOwner+` 3600 IN SVCB 0 `+bOwner)
	bRec := mustRR(t, bOwner+` 3600 IN SVCB 1 . oots="doq:30"`)
	aBack := mustRR(t, aOwner+` 3600 IN SVCB 0 `+pathOwner)

	// A chain longer than the depth cap: _dns.<ns> -> c1 -> c2 -> c3 -> c4.
	var chain []dns.RR
	prev := pathOwner
	for i := 1; i <= 4; i++ {
		next := fmt.Sprintf("_dns.ns.c%d.example.", i)
		chain = append(chain, mustRR(t, prev+` 3600 IN SVCB 0 `+next))
		prev = next
	}

	for _, tc := range []struct {
		name    string
		section []dns.RR
		want    []cache.SignalHop
		state   cache.ValidationState
	}{
		{"both hops signed", join(one(alias), sign(kid, alias), one(target), sign(provider, target)),
			[]cache.SignalHop{hop(pathOwner, secure), hop(providerOwner, secure)}, secure},
		{"target unsigned", join(one(alias), sign(kid, alias), one(target)),
			[]cache.SignalHop{hop(pathOwner, secure), hop(providerOwner, unknown)}, unknown},
		{"target not in the section", join(one(alias), sign(kid, alias)),
			[]cache.SignalHop{hop(pathOwner, secure), hop(providerOwner, unknown)}, unknown},
		{"alias unsigned", join(one(alias), one(target), sign(provider, target)),
			[]cache.SignalHop{hop(pathOwner, unknown), hop(providerOwner, secure)}, unknown},
		{"target signed by a zone that cannot hold it", join(one(alias), sign(kid, alias), one(target), sign(kid, target)),
			[]cache.SignalHop{hop(pathOwner, secure), hop(providerOwner, bogus)}, bogus},
		{"target bogus", join(one(alias), sign(kid, alias),
			one(mustRR(t, providerOwner+` 3600 IN SVCB 1 . oots="dot:99"`)), sign(provider, target)),
			[]cache.SignalHop{hop(pathOwner, secure), hop(providerOwner, bogus)}, bogus},
		{"two hops", join(one(aliasA), sign(kid, aliasA), one(aToB), sign(a, aToB), one(bRec), sign(b, bRec)),
			[]cache.SignalHop{hop(pathOwner, secure), hop(aOwner, secure), hop(bOwner, secure)}, secure},
		{"a loop ends the path", join(one(aliasA), sign(kid, aliasA), one(aBack), sign(a, aBack)),
			[]cache.SignalHop{hop(pathOwner, secure), hop(aOwner, secure)}, secure},
		{"the depth cap ends the path", chain,
			[]cache.SignalHop{hop(pathOwner, unknown), hop("_dns.ns.c1.example.", unknown),
				hop("_dns.ns.c2.example.", unknown), hop("_dns.ns.c3.example.", unknown)}, unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := newTestImr(t)
			imr.Quiet = true
			set := &svcbSignalSet{}
			for _, rr := range svcbAt(tc.section, pathOwner) {
				set.add(rr.(*dns.SVCB))
			}
			imr.decideAdditionalPath(set, tc.section, cache.SignalViaResponse)
			if got, want := cache.FormatSignalPath(set.path), cache.FormatSignalPath(tc.want); got != want {
				t.Errorf("path\n got  %s\n want %s", got, want)
			}
			if got := cache.SignalPathState(set.path); got != tc.state {
				t.Errorf("path state %s, want %s", cache.SignalStateString(got), cache.SignalStateString(tc.state))
			}
			// The alias delegates the signal to the RRset its path ends at,
			// and its records with TargetName "." are inherited whatever the
			// state (R4). A path that ends nowhere installs nothing.
			wantInstall := !map[string]bool{
				"target not in the section": true, "a loop ends the path": true, "the depth cap ends the path": true,
			}[tc.name]
			if installed, _ := imr.installSVCBSignal(cache.NewAuthServer(pathNS), set); installed != wantInstall {
				t.Errorf("installed %v, want %v", installed, wantInstall)
			}
		})
	}
}

// The lookup of _dns.<ns> does not follow an AliasMode record: its target is a
// hop of unknown state after the alias RRset's own verdict.
func TestOOTSSignalStateLookupAlias(t *testing.T) {
	set := &svcbSignalSet{}
	set.add(mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner).(*dns.SVCB))
	set.decideLookupPath(cache.ValidationStateSecure)
	want := []cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}, {Owner: providerOwner}}
	if got, w := cache.FormatSignalPath(set.path), cache.FormatSignalPath(want); got != w {
		t.Errorf("path %q, want %q", got, w)
	}
	if set.via != cache.SignalViaLookup {
		t.Errorf("via %q", set.via)
	}
}

// An AliasMode set delegates the signal on both Additional paths: the
// server takes the signal of the RRset the alias leads to, with the state of
// every hop. An alias whose target the section does not hold leaves the
// earlier signal alone.
func TestOOTSSignalStateAliasDelegates(t *testing.T) {
	dkc := signerTestDnskeyCache(t)
	kid := newSignerTestKey(t, stateZone, 256)
	kid.holdSecure(dkc)
	provider := newSignerTestKey(t, providerZone, 256)
	provider.holdSecure(dkc)
	earlier := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 1 . port=1234 oots="dot:30"`)}
	alias := mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)
	target := mustRR(t, providerOwner+` 3600 IN SVCB 1 . oots="doq:50"`)
	aliasOnly := []dns.RR{alias, kid.sign(t, dns.Copy(alias)).RRSIGs[0]}
	section := append(copyRRs(aliasOnly), target, provider.sign(t, dns.Copy(target)).RRSIGs[0])
	const want = "oots w=doq:50 p= sel=do53-tcp:100,do53:100,doh:0,doq:50,dot:0 tr=do53,doh,doq,dot " + pathOwner + " secure -> " + providerOwner + " secure"
	snapshot := func(server *cache.AuthServer) string {
		return selectionSnapshot(server) + " " + cache.FormatSignalPath(server.GetReceivedSignal().Path)
	}

	ctx := context.Background()
	imr := newTestImr(t)
	imr.Quiet = true
	server := cache.NewAuthServer(pathNS)
	r := new(dns.Msg)
	r.SetQuestion("www."+stateZone, dns.TypeA)
	r.Extra = copyRRs(earlier)
	imr.parseTransportForServerFromAdditional(ctx, server, r)
	before := snapshot(server)
	r.Extra = copyRRs(aliasOnly)
	imr.parseTransportForServerFromAdditional(ctx, server, r)
	if got := snapshot(server); got != before {
		t.Errorf("response path, an alias to a target not in the section:\n got  %s\n want %s", got, before)
	}
	r.Extra = copyRRs(section)
	imr.parseTransportForServerFromAdditional(ctx, server, r)
	if got := snapshot(server); got != want {
		t.Errorf("response path, through the alias:\n got  %s\n want %s", got, want)
	}

	imr = newTestImr(t)
	imr.Quiet = true
	nsrrset := &core.RRset{Name: stateZone, Class: dns.ClassINET, RRtype: dns.TypeNS,
		RRs: []dns.RR{mustRR(t, stateZone+" 3600 IN NS "+pathNS)}}
	ref := new(dns.Msg)
	ref.SetQuestion("www."+stateZone, dns.TypeA)
	ref.Response = true
	ref.Ns = nsrrset.RRs
	ref.Extra = copyRRs(section)
	if _, err := imr.ParseAdditionalForNSAddrs(ctx, "authority", nsrrset, stateZone, "p.test.",
		map[string]bool{pathNS: true}, ref); err != nil {
		t.Fatalf("ParseAdditionalForNSAddrs: %v", err)
	}
	if got := snapshot(imr.Cache.GetOrCreateAuthServer(pathNS)); got != want {
		t.Errorf("referral path, through the alias (target outside the referring zone):\n got  %s\n want %s", got, want)
	}
}

// A signal that did not come from an SVCB RRset has no Via and no path.
func TestOOTSSignalStateTSYNCHasNoPath(t *testing.T) {
	server := cache.NewAuthServer(pathNS)
	imr := newTestImr(t)
	if !imr.applyTransportSignalToServer(server, "dot:30") {
		t.Fatal("TSYNC string not applied")
	}
	rec := server.GetReceivedSignal()
	if rec.Via != "" || rec.Path != nil {
		t.Errorf("TSYNC signal: Via %q, path %v", rec.Via, rec.Path)
	}
	if got := rec.PathState(); got != cache.SignalStateUnknown {
		t.Errorf("TSYNC signal: state %s", cache.SignalStateString(got))
	}
}
