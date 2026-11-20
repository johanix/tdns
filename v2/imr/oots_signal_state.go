/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
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

// aliasWalk is how followLookupAlias reads an alias path. Its zero value
// reads every hop from the cache as it stands, and looks up a hop the cache
// does not hold.
type aliasWalk struct {
	// cacheOnly reads the path through the cache and looks no hop up. It is
	// for an answer that came in an alias hop's own lookup (aliasWalkFor): the
	// walk of each owner waiting for that lookup decides what is looked up
	// next, within its own maxSignalAliasDepth. A hop's answer that walked on
	// by itself would start a count of its own, and a chain of AliasMode
	// records at _dns. owners would drive lookups one after another without
	// end.
	cacheOnly bool
	// fresh is the hop whose lookup has just ended, for the walk that follows
	// the owners waiting for it (refollowAliasOwner). That hop is read as the
	// lookup left it, an entry that expired less than freshChainGrace ago
	// included, as a query reads the chain it has just resolved (chainEntry):
	// a record with TTL 0 is stored already expired, and is still the answer
	// to that lookup. Every other hop, and every hop of every other walk, is
	// read from the cache as it stands: an entry that has expired is not
	// there.
	fresh string
}

// hopGrace is the grace walk reads target with (chainEntry).
func (imr *Imr) hopGrace(walk aliasWalk, target string) time.Duration {
	if walk.fresh != "" && core.EqualNames(walk.fresh, target) {
		return imr.freshChainGrace()
	}
	return 0
}

// signalAliasHopLookupKey marks the context of an alias hop's lookup
// (lookupSignalAliasHop), and of everything that lookup asks on the way.
type signalAliasHopLookupKey struct{}

// withSignalAliasHopLookup marks ctx as an alias hop's lookup's.
func withSignalAliasHopLookup(ctx context.Context) context.Context {
	return context.WithValue(ctx, signalAliasHopLookupKey{}, true)
}

// aliasWalkFor is how a signal read from the answer to a query made on ctx
// follows its alias: through the cache only when the query is, or is part
// of, an alias hop's lookup.
func aliasWalkFor(ctx context.Context) aliasWalk {
	if ctx == nil {
		return aliasWalk{}
	}
	in, _ := ctx.Value(signalAliasHopLookupKey{}).(bool)
	return aliasWalk{cacheOnly: in}
}

// testHookAliasHopMissed, when set, runs in followLookupAlias between a hop's
// miss in the cache and the start of its lookup. A test ends another lookup
// of the hop there, in the window a real one can end in.
var testHookAliasHopMissed func(target string)

// followLookupAlias follows the AliasMode record of set, read from the answer
// to a lookup of _dns.<ns>, through the signals the cache holds: each hop's
// RRset and the verdict the lookup that brought it reached. It replaces the
// set's path with the hops read, and sets set.final when the path ends at an
// RRset with no AliasMode record. A hop the cache does not hold is looked up
// off the query path (lookupSignalAliasHop), unless walk is cacheOnly; when
// that lookup finds it, the alias is followed again. A loop, a denial, or a
// path longer than the cap installs nothing. With transport signals turned
// off no alias is followed: nothing is installed through one, and no hop is
// looked up.
func (imr *Imr) followLookupAlias(set *svcbSignalSet, walk aliasWalk) {
	if set == nil || !set.alias || len(set.path) == 0 || imr.Cache == nil {
		return
	}
	if imr.Options[OptUseTransportSignals] == "false" {
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
		grace := imr.hopGrace(walk, target)
		rrs, state, held := imr.cachedSignalHop(target, grace)
		if len(rrs) == 0 && !held && !walk.cacheOnly {
			if testHookAliasHopMissed != nil {
				testHookAliasHopMissed(target)
			}
			if imr.lookupSignalAliasHop(set.owner, target) == hopCoolingDown {
				// The hop's last lookup ended less than signalAliasHopRetry
				// ago, perhaps between the miss and the join, too late to
				// follow this owner again. Whatever it found is in the
				// cache by now.
				rrs, state, held = imr.cachedSignalHop(target, grace)
			}
		}
		if len(rrs) == 0 {
			set.path = append(set.path, cache.SignalHop{Owner: target, State: cache.SignalStateUnknown})
			return
		}
		set.path = append(set.path, cache.SignalHop{Owner: target, State: state})
		if !hasAliasMode(rrs) {
			set.final = finalSignalSet(rrs, set.via, set.path)
			return
		}
		target = aliasTargetOf(rrs)
	}
}

// cachedSignalHop reads the SVCB RRset at target, a hop on an alias path, from
// the cache, with the state it is held in. A target that is a CNAME is read
// through its chain, as a lookup of <target, SVCB> follows it and caches it
// link by link (chainAt): the RRset at the chain's end, in the weakest state
// of the links and that RRset, since every record that leads to a signal is a
// hop that must be Secure for a target to be honoured (R5). Every entry is
// read with grace (chainEntry): 0, the cache as it stands, but for the hop
// whose lookup has just ended (aliasWalk.fresh). held reports that the cache
// holds an answer for target, a denial included, so that there is nothing to
// look up.
func (imr *Imr) cachedSignalHop(target string, grace time.Duration) (rrs []dns.RR, state cache.ValidationState, held bool) {
	if c := imr.chainEntry(target, dns.TypeSVCB, edns0.PrivacyNone, grace); c != nil {
		if c.Context == cache.ContextAnswer && c.RRset != nil && len(c.RRset.RRs) > 0 {
			return c.RRset.RRs, cache.SignalState(c.State), true
		}
		return nil, cache.SignalStateUnknown, true
	}
	links, final, _, err := imr.chainAt(target, dns.TypeSVCB, edns0.PrivacyNone, grace)
	if err != nil || final == nil || len(links) == 0 {
		return nil, cache.SignalStateUnknown, false
	}
	if final.Context != cache.ContextAnswer || final.RRset == nil || len(final.RRset.RRs) == 0 {
		return nil, cache.SignalStateUnknown, true
	}
	hops := make([]cache.SignalHop, 0, len(links)+1)
	for _, l := range links {
		hops = append(hops, cache.SignalHop{Owner: l.Name, State: cache.SignalState(l.State)})
	}
	hops = append(hops, cache.SignalHop{Owner: final.Name, State: cache.SignalState(final.State)})
	return final.RRset.RRs, cache.SignalPathState(hops), true
}

// signalAliasHopRetry is how long an alias hop waits after its lookup has
// ended, however it ended, before it is looked up again. It bounds the
// lookups of a hop the cache cannot hold (a TTL of 0) to one per period, and
// lets a hop whose cached RRset has expired be looked up again after it.
const signalAliasHopRetry = 30 * time.Second

// aliasHopTracker runs one lookup at a time of each alias hop, and holds the
// owners waiting for it: many nameservers' aliases may lead to one provider's
// signal, and each is to be followed again when it is found. Its zero value
// is ready for use.
type aliasHopTracker struct {
	mu      sync.Mutex
	waiting map[string]map[string]string // target -> owners waiting (canonical -> as given); present while a lookup is in flight
	next    map[string]time.Time         // target -> when it may be looked up again
	retry   time.Duration                // signalAliasHopRetry when zero; tests set it
	// running counts the lookups in flight, each until the owners that
	// waited for it have been followed again. A lookup those walks start is
	// counted before the one that started it ends, so a Wait returns once
	// the chain of lookups has ended (tests).
	running sync.WaitGroup
}

// hopLookup is what became of a call for an alias hop's lookup
// (lookupSignalAliasHop).
type hopLookup int

const (
	hopNoLookup    hopLookup = iota // the resolver does no discovery: nothing is looked up
	hopStarted                      // the caller is to start the lookup; owner waits for it
	hopJoined                       // a lookup is in flight; owner waits for it
	hopCoolingDown                  // target was looked up less than signalAliasHopRetry ago; owner does not wait
)

// join enters owner among those waiting for target's lookup, and reports
// whether the caller is to start that lookup (hopStarted). When a lookup is
// in flight, owner waits for it (hopJoined). When target was looked up less
// than signalAliasHopRetry ago, owner is not entered (hopCoolingDown): no
// lookup is coming, and what the last one found is in the cache.
func (tr *aliasHopTracker) join(target, owner string, now time.Time) hopLookup {
	key := core.CanonicalizeName(target)
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if w, ok := tr.waiting[key]; ok {
		w[core.CanonicalizeName(owner)] = owner
		return hopJoined
	}
	if now.Before(tr.next[key]) {
		return hopCoolingDown
	}
	for k, at := range tr.next {
		if !now.Before(at) {
			delete(tr.next, k)
		}
	}
	if tr.waiting == nil {
		tr.waiting = map[string]map[string]string{}
	}
	tr.waiting[key] = map[string]string{core.CanonicalizeName(owner): owner}
	return hopStarted
}

// done ends target's lookup. It returns the owners that waited for it, and
// target is not looked up again for signalAliasHopRetry.
func (tr *aliasHopTracker) done(target string, now time.Time) []string {
	key := core.CanonicalizeName(target)
	tr.mu.Lock()
	defer tr.mu.Unlock()
	owners := make([]string, 0, len(tr.waiting[key]))
	for _, owner := range tr.waiting[key] {
		owners = append(owners, owner)
	}
	delete(tr.waiting, key)
	if tr.next == nil {
		tr.next = map[string]time.Time{}
	}
	retry := tr.retry
	if retry == 0 {
		retry = signalAliasHopRetry
	}
	tr.next[key] = now.Add(retry)
	sort.Strings(owners)
	return owners
}

// signalAliasHopLookupHook, when set, stands in for the Query of an alias
// hop: tests set it, so that no lookup leaves the process. It is to leave the
// answer in the cache, as a lookup does, and ctx is the lookup's
// (withSignalAliasHopLookup).
var signalAliasHopLookupHook func(ctx context.Context, imr *Imr, target string) (*Response, error)

// lookupSignalAliasHop looks up the SVCB RRset at target, a hop on the alias
// path of the signal at owner, off the query path, and reports what became of
// the call. One lookup of a target runs at a time, and every owner whose alias
// reached it meanwhile waits for it (aliasHopTracker); when it finds the hop,
// each of them is followed again from the cache (refollowAliasOwner). A
// resolver that does no discovery looks nothing up.
//
// The lookup's context is marked (withSignalAliasHopLookup), so that the
// signal in its answer follows its own alias through the cache only
// (aliasWalkFor): the next hop is for the waiting owners' walks to look up,
// each within its maxSignalAliasDepth.
func (imr *Imr) lookupSignalAliasHop(owner, target string) hopLookup {
	if imr.TransportSignalDiscovery == nil {
		return hopNoLookup
	}
	if joined := imr.signalAliasHops.join(target, owner, time.Now()); joined != hopStarted {
		return joined
	}
	lookup := func(ctx context.Context, imr *Imr, target string) (*Response, error) {
		return imr.imrQuery(ctx, target, dns.TypeSVCB, dns.ClassINET, false)
	}
	if signalAliasHopLookupHook != nil {
		lookup = signalAliasHopLookupHook
	}
	imr.signalAliasHops.running.Add(1)
	go func() {
		defer imr.signalAliasHops.running.Done()
		ctx, cancel := detachedContext(5 * time.Second)
		defer cancel()
		resp, err := lookup(withSignalAliasHopLookup(ctx), imr, target)
		owners := imr.signalAliasHops.done(target, time.Now())
		imr.lgDns().Debug("transport signal: alias hop looked up", "target", target, "owners", owners, "err", err)
		if !signalAliasHopFound(resp, err) {
			return
		}
		for _, owner := range owners {
			imr.refollowAliasOwner(aliasWalk{fresh: target}, owner)
		}
	}()
	return hopStarted
}

// maxSignalRefollows bounds how often refollowAliasOwner installs again
// because the owner's RRset was replaced under it.
const maxSignalRefollows = 3

// testHookAliasRefollowRead, when set, runs in refollowAliasOwner between
// reading the owner's RRset and installing from it. A test replaces the RRset
// there, in the window a newer answer can arrive in.
var testHookAliasRefollowRead func(owner string)

// refollowAliasOwner follows owner's alias again from the cache, with walk,
// and installs what it leads to on each server of that name
// (applyTransportRRsetWalk). It is for an owner whose alias waited for a hop's
// lookup that has found the hop, and for one whose cached alias the verify
// lookup stops at (launchTransportSignalQuery).
//
// It follows the RRset the cache holds at owner, and only while that holds an
// AliasMode record: an answer that replaced it with ServiceMode records
// installed them itself. An answer can also replace it between the read and
// the install, and install first, so the RRset is read again after the
// install. If it is no longer the one followed, the one there now is
// installed again, after this install, at most maxSignalRefollows times.
//
// Two races are left, and in both the older RRset's signal stays installed
// until a later install on that server replaces it:
//   - An answer that replaces the RRset between the last read and the last
//     install is overwritten by the older one. That takes more than
//     maxSignalRefollows replacements of one owner's RRset during one
//     refollow. A lock would close the window, but it would be held across
//     the install, which runs honouredRecords.
//   - No install withdraws a signal, on any path. An answer whose RRset
//     installs none, such as an AliasMode record that leads to no signal,
//     leaves in place the older RRset's signal that this refollow installed,
//     and one replacement between the first read and the first install is
//     enough. The same two answers leave that state with no refollow at all
//     when the older one is installed first. Closing it takes an install
//     that withdraws, which changes every install path.
func (imr *Imr) refollowAliasOwner(walk aliasWalk, owner string) {
	if imr.Cache == nil {
		return
	}
	c := imr.Cache.Get(owner, dns.TypeSVCB)
	if c == nil || c.Context != cache.ContextAnswer || c.RRset == nil || !hasAliasMode(c.RRset.RRs) {
		return
	}
	if testHookAliasRefollowRead != nil {
		testHookAliasRefollowRead(owner)
	}
	imr.applyTransportRRsetWalk(walk, owner, c.RRset, c.State)
	for range maxSignalRefollows {
		now := imr.Cache.Get(owner, dns.TypeSVCB)
		if now == nil || now.Context != cache.ContextAnswer || now.RRset == nil || (now.RRset == c.RRset && now.State == c.State) {
			return
		}
		c = now
		imr.applyTransportRRsetWalk(walk, owner, c.RRset, c.State)
	}
}

// signalAliasHopFound reports whether the lookup of an alias hop found an SVCB
// RRset, and so whether the owners waiting for it are worth following again.
// After a denial or a failure they are not: the cache has nothing new to lead
// them to. Once signalAliasHopRetry has passed, the next query that brings an
// owner's RRset follows it again, and so does the verify lookup of an owner
// whose alias the cache holds (launchTransportSignalQuery).
func signalAliasHopFound(resp *Response, err error) bool {
	return err == nil && resp != nil && resp.RRset != nil && resp.RRset.RRtype == dns.TypeSVCB && len(resp.RRset.RRs) > 0
}

// pathCopy is set's path for one ReceivedSignal: the answer path installs one
// set on every server of that name.
func (set *svcbSignalSet) pathCopy() []cache.SignalHop {
	if set == nil || set.path == nil {
		return nil
	}
	return slices.Clone(set.path)
}
