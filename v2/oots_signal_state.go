/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"slices"

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
// RRset at each target (R5). A hop is read from anywhere in the section, not
// only within the referring zone, since only its state is recorded and a
// signature makes that independent of who sent it. A target the section does
// not hold is a hop of unknown state; so is one whose RRset came without an
// RRSIG, or whose keys the cache does not hold yet. A loop ends the path.
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
			break
		}
		seen[key] = true
		rrs := svcbAt(section, target)
		set.path = append(set.path, cache.SignalHop{Owner: target, State: imr.additionalSVCBState(section, target, rrs)})
		target = aliasTargetOf(rrs)
	}
}

// decideLookupPath records the state of a set read from the answer to a
// lookup of _dns.<ns>, which the lookup has validated (vstate). The lookup
// does not follow an AliasMode record, so a target is a hop of unknown state.
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

// pathCopy is set's path for one ReceivedSignal: the answer path installs one
// set on every server of that name.
func (set *svcbSignalSet) pathCopy() []cache.SignalHop {
	if set == nil || set.path == nil {
		return nil
	}
	return slices.Clone(set.path)
}
