/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"slices"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The validation state of a transport signal on each path it arrives by
// (cache/signal_state.go): every RRset a signal is read from gets the state of
// that RRset. Nothing is decided by it here. A record the resolver acts on has
// TargetName ".", which needs no validation (R4 of
// docs/2026-11-14-transport-signal-alternative-endpoint.md); the state is
// stored with the signal, logged, and shown by "imr dump", for the step that
// honours a TargetName only when the whole path is Secure (R1, R5).

// maxSignalAliasDepth is how many AliasMode hops a path follows from
// _dns.<ns>: three, as tdns-auth chases them when it injects a signal
// (docs/2026-10-04-transport-signal-publication-and-serving.md, section 4).
const maxSignalAliasDepth = 3

// aliasTargetOf is the target of the AliasMode record in rrs, "" when there is
// none or it is "." (the service is not available, RFC 9460 section 2.5.1).
// RFC 9460 section 2.4.2 lets an RRset hold one AliasMode record. Should it
// hold more, the lowest target is taken, so that the path does not depend on
// the order the records arrived in.
func aliasTargetOf(rrs []dns.RR) string {
	target := ""
	for _, rr := range rrs {
		svcb, ok := rr.(*dns.SVCB)
		if !ok || svcb.Priority != 0 || svcb.Target == "." || svcb.Target == "" {
			continue
		}
		if target == "" || core.CanonicalizeName(svcb.Target) < core.CanonicalizeName(target) {
			target = svcb.Target
		}
	}
	return target
}

// svcbAt is the SVCB records in section whose owner is owner.
func svcbAt(section []dns.RR, owner string) []dns.RR {
	var out []dns.RR
	for _, rr := range section {
		if svcb, ok := rr.(*dns.SVCB); ok && core.EqualNames(svcb.Hdr.Name, owner) {
			out = append(out, svcb)
		}
	}
	return out
}

// additionalSVCBState decides in place the state of the SVCB RRset rrs at
// owner, with the RRSIGs in section that cover it (RRsetCacheT.SignalRRsetState).
// The RRset is a copy: a verdict caps the TTLs of what it validates, and the
// records belong to the message.
func (imr *Imr) additionalSVCBState(section []dns.RR, owner string, rrs []dns.RR) cache.ValidationState {
	if imr == nil || imr.Cache == nil || len(rrs) == 0 {
		return cache.SignalStateUnknown
	}
	rrset := &core.RRset{Name: dns.Fqdn(owner), Class: dns.ClassINET, RRtype: dns.TypeSVCB}
	for _, rr := range rrs {
		rrset.RRs = append(rrset.RRs, dns.Copy(rr))
	}
	for _, rr := range section {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeSVCB && core.EqualNames(sig.Hdr.Name, owner) {
			rrset.RRSIGs = append(rrset.RRSIGs, dns.Copy(sig))
		}
	}
	return imr.Cache.SignalRRsetState(rrset)
}

// decideAdditionalPath records where set arrived and the state of each RRset
// on its path, decided in place from the Additional section it came in: the
// set's own RRset at _dns.<ns>, then, when it holds an AliasMode record, the
// RRset at each target (R5), to maxSignalAliasDepth hops. The RRset the path
// ends at, when it holds no AliasMode record, becomes set.final: the signal
// the alias delegates to, installed for the nameserver with the whole path
// (installSVCBSignal).
//
// A hop is read from anywhere in the section, not only within the referring
// zone. A server that can send the alias at _dns.<ns> can send ServiceMode
// records there just as well, so a target outside its zone gives it nothing
// more, and a TargetName at the end is honoured only on a Secure path.
//
// A target the section does not hold is a hop of unknown state, and the set
// then waits for the lookup of _dns.<ns>, which follows the alias. So is a hop
// whose RRset came without an RRSIG, or whose keys the cache does not hold
// yet. A loop, or a path longer than the cap, installs nothing.
func (imr *Imr) decideAdditionalPath(set *svcbSignalSet, section []dns.RR, via string) {
	if set == nil || len(set.rrs) == 0 {
		return
	}
	set.via = via
	set.path = []cache.SignalHop{{Owner: set.owner, State: imr.additionalSVCBState(section, set.owner, set.rrs)}}
	seen := map[string]bool{core.CanonicalizeName(set.owner): true}
	target := aliasTargetOf(set.rrs)
	for depth := 0; target != "" && depth < maxSignalAliasDepth; depth++ {
		key := core.CanonicalizeName(target)
		if seen[key] {
			return
		}
		seen[key] = true
		rrs := svcbAt(section, target)
		set.path = append(set.path, cache.SignalHop{Owner: target, State: imr.additionalSVCBState(section, target, rrs)})
		if len(rrs) == 0 {
			set.awaitsLookup = true
			return
		}
		if !hasAliasMode(rrs) {
			set.final = finalSignalSet(rrs, set.via, set.path)
			return
		}
		target = aliasTargetOf(rrs)
	}
}

// decideLookupPath records the state of a set read from the answer to a
// lookup of _dns.<ns>, which the lookup has validated (vstate). An AliasMode
// record's target is a hop of unknown state until followLookupAlias reads it.
func (set *svcbSignalSet) decideLookupPath(vstate cache.ValidationState) {
	if set == nil || len(set.rrs) == 0 {
		return
	}
	set.via = cache.SignalViaLookup
	set.path = []cache.SignalHop{{Owner: set.owner, State: cache.SignalState(vstate)}}
	if target := aliasTargetOf(set.rrs); target != "" {
		set.path = append(set.path, cache.SignalHop{Owner: target, State: cache.SignalStateUnknown})
	}
}

// hasAliasMode reports whether rrs holds an AliasMode record.
func hasAliasMode(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if svcb, ok := rr.(*dns.SVCB); ok && svcb.Priority == 0 {
			return true
		}
	}
	return false
}

// finalSignalSet is the set an alias path ends at, rrs, read with the whole
// path: its records with a target are honoured only when every hop is Secure
// (R5), and those with TargetName "." are inherited whatever the state (R4).
func finalSignalSet(rrs []dns.RR, via string, path []cache.SignalHop) *svcbSignalSet {
	final := &svcbSignalSet{}
	for _, rr := range rrs {
		if svcb, ok := rr.(*dns.SVCB); ok {
			final.add(svcb)
		}
	}
	final.via = via
	final.path = path
	return final
}

// followLookupAlias follows the AliasMode record of set, read from the answer
// to a lookup of _dns.<ns>, through the signals the cache holds: each hop's
// RRset and the verdict the lookup that brought it reached. It replaces the
// set's path with the hops read, and sets set.final when the path ends at an
// RRset with no AliasMode record. A hop the cache does not hold is looked up
// off the query path (lookupSignalAliasHop); when that lookup ends, the
// alias is followed again. A loop, a denial, or a path longer than the cap
// installs nothing.
func (imr *Imr) followLookupAlias(set *svcbSignalSet) {
	if set == nil || !set.alias || len(set.path) == 0 || imr.Cache == nil {
		return
	}
	set.path = set.path[:1]
	seen := map[string]bool{core.CanonicalizeName(set.owner): true}
	target := aliasTargetOf(set.rrs)
	for depth := 0; target != "" && depth < maxSignalAliasDepth; depth++ {
		key := core.CanonicalizeName(target)
		if seen[key] {
			return
		}
		seen[key] = true
		cached := imr.Cache.Get(target, dns.TypeSVCB)
		if cached == nil || cached.Context != cache.ContextAnswer || cached.RRset == nil || len(cached.RRset.RRs) == 0 {
			set.path = append(set.path, cache.SignalHop{Owner: target, State: cache.SignalStateUnknown})
			if cached == nil {
				imr.lookupSignalAliasHop(set.owner, target)
			}
			return
		}
		rrs := cached.RRset.RRs
		set.path = append(set.path, cache.SignalHop{Owner: target, State: cache.SignalState(cached.State)})
		if !hasAliasMode(rrs) {
			set.final = finalSignalSet(rrs, set.via, set.path)
			return
		}
		target = aliasTargetOf(rrs)
	}
}

// signalAliasHopLookupHook, when set, stands in for the ImrQuery of an alias
// hop: tests set it, so that no lookup leaves the process. It is to leave the
// answer in the cache, as a lookup does.
var signalAliasHopLookupHook func(imr *Imr, target string) (*ImrResponse, error)

// lookupSignalAliasHop looks up the SVCB RRset at target, a hop on the alias
// path of the signal at owner, off the query path, and then follows owner's
// alias again from the cache. The transport-signal tracker runs one lookup
// per target, as it does for _dns.<ns>; without one (a resolver that does no
// discovery) nothing is looked up.
func (imr *Imr) lookupSignalAliasHop(owner, target string) {
	if !imr.TransportSignalDiscovery.Begin(target) {
		return
	}
	lookup := func(imr *Imr, target string) (*ImrResponse, error) {
		ctx, cancel := detachedContext(5 * time.Second)
		defer cancel()
		return imr.ImrQuery(ctx, target, dns.TypeSVCB, dns.ClassINET, nil)
	}
	if signalAliasHopLookupHook != nil {
		lookup = signalAliasHopLookupHook
	}
	go func() {
		resp, err := lookup(imr, target)
		if !imr.Quiet {
			lgDns.Debug("transport signal: alias hop looked up", "owner", owner, "target", target, "err", err)
		}
		imr.settleSignalAliasHop(target, resp, err)
		if c := imr.Cache.Get(owner, dns.TypeSVCB); c != nil && c.Context == cache.ContextAnswer && c.RRset != nil {
			imr.applyTransportRRsetFromAnswer(owner, c.RRset, c.State)
		}
	}()
}

// settleSignalAliasHop records how the lookup of an alias hop ended, as
// settleTransportSignalLookup does for _dns.<ns>: the hop is always an SVCB.
func (imr *Imr) settleSignalAliasHop(target string, resp *ImrResponse, err error) {
	switch {
	case err == nil && resp != nil && resp.RRset != nil && resp.RRset.RRtype == dns.TypeSVCB && len(resp.RRset.RRs) > 0:
		imr.TransportSignalDiscovery.Succeed(target)
	case err == nil && resp != nil && resp.Denial != 0:
		imr.TransportSignalDiscovery.Reset(target)
	default:
		imr.TransportSignalDiscovery.Fail(target, err)
	}
}

// pathCopy is set's path for one ReceivedSignal: the answer path installs one
// set on every server of that name.
func (set *svcbSignalSet) pathCopy() []cache.SignalHop {
	if set == nil || set.path == nil {
		return nil
	}
	return slices.Clone(set.path)
}
