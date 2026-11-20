/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The endpoint model (docs/2026-11-14-transport-signal-alternative-endpoint.md,
// sections 2-4). A signal record whose TargetName is not "." sends the
// transports it names to that name, at its port or theirs. Such a record is
// honoured only when its whole path validated Secure (R1, R5); one that did
// not is ignored whole (R2), with a debug line and a counter. The target's
// addresses are looked up off the query path and never through a redirected
// endpoint; until they are known the transport uses its default endpoint.
// When every address of an endpoint is backed off or lame for the zone, an
// encrypted transport's attempt fails without a dial, and the query goes on
// to its next tuple. udp and tcp fall back to the nameserver's own address on
// port 53 instead: the one endpoint the delegation guarantees (section 3), and
// the last resort candidateTransports keeps. Backoff, RTT and the zone's
// lameness are all kept under the address and port an attempt dials, so a
// lame endpoint holds back only itself. A target is a server of its own
// (endpointTarget): the server backoff and RTT of the attempts sent to it are
// kept on its instance, not on the nameserver that redirected them.

// honouredRecords is recs without the records whose target the set's path does
// not allow: all of them unless the path validated Secure (R1, R5). Their
// records with TargetName "." stay, whatever the state (R2, R4). Each record
// ignored is logged and counted on server. One ignored while the path was
// undecided marks the set as waiting for the verifying lookup. A record left
// whose port is on the bad-port list goes to the nameserver itself on the
// default port (withoutBadPorts).
func (imr *Imr) honouredRecords(server *cache.AuthServer, set *svcbSignalSet, recs []ootsRecord) []ootsRecord {
	state := cache.SignalPathState(set.path)
	if state == cache.ValidationStateSecure {
		return imr.withoutBadPorts(server, recs)
	}
	out := make([]ootsRecord, 0, len(recs))
	ignored := 0
	for _, rec := range recs {
		if rec.target == "" {
			out = append(out, rec)
			continue
		}
		ignored++
		if !imr.Quiet {
			lgDns.Debug("transport signal: a redirect ignored for want of validation",
				"servername", server.Name, "target", rec.target, "port", rec.port, "transports", MarshalTransport(rec.raw),
				"state", cache.SignalStateString(state), "via", set.via, "path", cache.FormatSignalPath(set.path))
		}
	}
	if ignored > 0 {
		server.AddIgnoredRedirects(ignored)
		if state == cache.SignalStateUnknown {
			set.awaitsLookup = true
		}
	}
	return imr.withoutBadPorts(server, out)
}

// defaultEndpointsKey marks a context whose queries go to every server's
// default endpoints: the lookups of an endpoint's addresses. A target may be
// served by the very nameserver whose transport is redirected to it, so those
// lookups go to the nameserver's name on its default ports (section 3).
type defaultEndpointsKey struct{}

func withDefaultEndpoints(ctx context.Context) context.Context {
	return context.WithValue(ctx, defaultEndpointsKey{}, true)
}

func defaultEndpointsOnly(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	only, _ := ctx.Value(defaultEndpointsKey{}).(bool)
	return only
}

// endpointDial is where one attempt goes.
type endpointDial struct {
	// server is the instance the attempt goes to: the nameserver itself, or
	// the target's own instance (endpointTarget) when the signal sent the
	// transport to a target. Its server backoff, RTT and counters are kept
	// on that instance.
	server   *cache.AuthServer
	addr     string // the address dialed, a bare IP
	port     uint16 // the port dialed; 0 for the transport's default
	redirect bool   // the address is a target's, not the server's own
	// keyPort is the port backoff, RTT and the zone's lameness are kept
	// under: the port dialed, at the server's own address and at a target's
	// alike (AddrXport).
	keyPort uint16
}

// dialAddr is d as passed to Exchange: the address, with the port joined on
// unless it is the transport's default.
func (d endpointDial) dialAddr() string {
	return cache.JoinDialAddr(d.addr, d.port)
}

// fallsBackToPort53 reports whether t, when its signalled endpoint is not
// usable, is sent to the nameserver's own address on port 53: udp and tcp,
// for which the delegation guarantees that endpoint (the design, section 3).
func fallsBackToPort53(t core.Transport) bool {
	return t == core.TransportDo53 || t == core.TransportDo53TCP
}

// errEndpointUnavailable is an attempt not made: every address of the
// transport's endpoint is backed off, or none may be used.
type errEndpointUnavailable struct {
	server, target string
	transport      core.Transport
}

func (e errEndpointUnavailable) Error() string {
	return fmt.Sprintf("%s: no usable address of the %s endpoint at %s", e.server, core.TransportToString[e.transport], e.target)
}

// errEndpointSuspectFamily is an attempt not made: the address it would dial
// is of a family held suspect that selection reserved no probe for
// (suspectWithoutProbe).
type errEndpointSuspectFamily struct {
	server, target string
	transport      core.Transport
}

func (e errEndpointSuspectFamily) Error() string {
	return fmt.Sprintf("%s: the %s endpoint at %s is of a suspect address family, with no probe reserved", e.server, core.TransportToString[e.transport], e.target)
}

// errEndpointTried is an attempt not made: an extra pass's tuple would dial
// an endpoint the pass before tried (attemptSelection).
type errEndpointTried struct {
	server, target string
	transport      core.Transport
}

func (e errEndpointTried) Error() string {
	return fmt.Sprintf("%s: the %s endpoint at %s was tried in the pass before", e.server, core.TransportToString[e.transport], e.target)
}

// endpointFor is where an attempt for transport t at the server's own address
// addr goes, for a query to zone (nil when none is known). At the server's
// own name it is addr, at the endpoint's port. At a target it is the best
// usable address of the target, once those are known; until then the default
// endpoint, addr at the usual port, and the lookup of the target's addresses
// is started; it is started again when one family of them is due
// (endpointFamily.due), and the other's are used meanwhile. A udp or tcp endpoint with no usable
// address (fallsBackToPort53) gives way to addr on port 53. A context marked
// withDefaultEndpoints always gets the default endpoint. Forced TCP asks for Do53TCP, so it goes to the
// tcp endpoint or port 53, never to the udp one.
func (imr *Imr) endpointFor(ctx context.Context, server *cache.AuthServer, zone *cache.Zone, addr string, t core.Transport) (endpointDial, error) {
	if defaultEndpointsOnly(ctx) {
		return endpointDial{server: server, addr: addr}, nil
	}
	return imr.resolveEndpoint(server, zone, addr, t, true)
}

// resolveEndpoint is endpointFor's choice for a context not marked
// withDefaultEndpoints. lookup says whether a target whose addresses are not
// known, or one of whose families is due (endpointFamily.due), is looked up:
// not for the stub probe, which only reports. An address
// is usable when neither the backoff of the instance it belongs to nor the
// zone's lameness holds it at the endpoint's port (endpointUsable). A
// target's addresses belong to the target's own instance, never to the
// nameserver's: the target is another server.
//
// A port the signal gave explicitly that is the client's own default for t
// is the default endpoint's socket, and is kept under 0 like it: a signal
// that names port 853 for DoT, or 53 for udp, shares the backoff and RTT of
// one that leaves the port out.
func (imr *Imr) resolveEndpoint(server *cache.AuthServer, zone *cache.Zone, addr string, t core.Transport, lookup bool) (endpointDial, error) {
	own := endpointDial{server: server, addr: addr}
	ep := server.GetTransportEndpoint(t)
	if ep.Port != 0 && ep.Port == imr.clientDefaultPort(t) {
		ep.Port = 0
	}
	if ep.Target == "" {
		if ep.Port != 0 && fallsBackToPort53(t) && !endpointUsable(server, zone, addr, ep.Port, t) {
			return own, nil
		}
		return endpointDial{server: server, addr: addr, port: ep.Port, keyPort: ep.Port}, nil
	}
	target, addrs, known, stale := imr.endpointAddrs.get(ep.Target, time.Now())
	if lookup && (!known || stale) {
		imr.startEndpointLookup(ep.Target)
	}
	if !known {
		return own, nil
	}
	pick := imr.chooseEndpointAddr(target, zone, addrs, ep.Port, t)
	if pick == "" {
		if fallsBackToPort53(t) {
			return own, nil
		}
		return endpointDial{}, errEndpointUnavailable{server: server.Name, target: ep.Target, transport: t}
	}
	return endpointDial{server: target, addr: pick, port: ep.Port, redirect: true, keyPort: ep.Port}, nil
}

// attemptKey is the endpoint an attempt for t at the server's own address
// addr would dial for a query to zone (endpointFor): the instance, address
// and port its backoff, RTT and lameness are kept under. lookup says whether
// a target whose addresses are not known is looked up, as endpointFor does:
// selection does, so that a default endpoint in backoff, which keeps the
// tuple from being tried, does not keep the target from being found either.
// ok is false when no attempt would be made.
func (imr *Imr) attemptKey(ctx context.Context, server *cache.AuthServer, zone *cache.Zone, addr string, t core.Transport, lookup bool) (endpointDial, bool) {
	if defaultEndpointsOnly(ctx) {
		return endpointDial{server: server, addr: addr}, true
	}
	d, err := imr.resolveEndpoint(server, zone, addr, t, lookup)
	if err != nil {
		return endpointDial{}, false
	}
	return d, true
}

// tupleRTT is the RTT of what an attempt for tup would dial (attemptKey),
// as the instance dialed keeps it.
func (imr *Imr) tupleRTT(ctx context.Context, zone *cache.Zone, tup ServerAddrXportTuple) (time.Duration, bool) {
	d, ok := imr.attemptKey(ctx, tup.Server, zone, tup.Addr, tup.Transport, false)
	if !ok {
		return 0, false
	}
	return d.server.GetEndpointAddrRTT(d.addr, d.keyPort, tup.Transport)
}

// endpointUsable reports whether an attempt for t may dial addr at port:
// neither the backoff of server, the instance the address belongs to, nor
// the zone's lameness holds it there. A nil zone has no lameness.
func endpointUsable(server *cache.AuthServer, zone *cache.Zone, addr string, port uint16, t core.Transport) bool {
	return server.IsEndpointAddrAvailable(addr, port, t) && zone.IsZoneEndpointAvailable(addr, port, t)
}

// standardPorts is each transport's port for a client that does not say
// which it dials (clientDefaultPort).
var standardPorts = map[core.Transport]uint16{
	core.TransportDo53:    53,
	core.TransportDo53TCP: 53,
	core.TransportDoT:     853,
	core.TransportDoQ:     853,
	core.TransportDoH:     443,
}

// clientDefaultPort is the port the client for t dials when it is given a
// bare address: its own configured port, or the standard one for a client
// that does not say (a test's stand-in).
func (imr *Imr) clientDefaultPort(t core.Transport) uint16 {
	if imr.Cache != nil {
		if c, ok := imr.Cache.DNSClient[t].(*core.DNSClient); ok && c != nil {
			if p, err := strconv.ParseUint(c.Port, 10, 16); err == nil && p != 0 {
				return uint16(p)
			}
		}
	}
	return standardPorts[t]
}

// chooseEndpointAddr picks among a target's addresses as prioritizeServers
// does among a server's own: never one on this host unless
// allow-loopback-nameservers is set, never one of an address family not in
// use, never one in the target's backoff or lame for zone at this port and
// transport; of the rest the lowest RTT the target holds, an address with no
// sample counting as unprobedRTTSentinel. An address of a family held suspect
// is picked only when no other is left: selection then lets the tuple through
// as that family's recovery probe (ShouldProbe), as it does a nameserver's own
// address, and tryServer dials it only for a tuple selection decided on that
// family. "" when none is left.
func (imr *Imr) chooseEndpointAddr(target *cache.AuthServer, zone *cache.Zone, addrs []string, port uint16, t core.Transport) string {
	allowHostLocal := imr.allowHostLocalServers()
	type cand struct {
		addr    string
		rtt     time.Duration
		suspect bool
	}
	var cands []cand
	for _, a := range addrs {
		if !allowHostLocal && hostLocalAddr(a) {
			continue
		}
		if !target.AllowsAddrFamily(a) {
			continue
		}
		if !endpointUsable(target, zone, a, port, t) {
			continue
		}
		rtt, ok := target.GetEndpointAddrRTT(a, port, t)
		if !ok {
			rtt = unprobedRTTSentinel
		}
		cands = append(cands, cand{a, rtt, imr.FamilyTracker.IsSuspect(cache.FamilyOf(a))})
	}
	if len(cands) == 0 {
		return ""
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].suspect != cands[j].suspect {
			return !cands[i].suspect
		}
		return cands[i].rtt < cands[j].rtt
	})
	return cands[0].addr
}

// endpointAddrRetry is how long a target whose addresses could not be found
// waits before it is looked up again.
const endpointAddrRetry = 30 * time.Second

// endpointTargetIdle is how long a target's instance is kept once its
// addresses have run out and nothing has asked for them: as long as a server
// backoff or an RTT sample on it can stay in force, so that dropping it
// forgets nothing that still counts.
func endpointTargetIdle() time.Duration {
	p := cache.GetBackoffPolicy()
	d := max(p.MaxFailure, p.RoutingFailure, p.LameDelegation)
	return d + time.Duration(float64(d)*p.JitterFraction)
}

// endpointAddr is one address of a target, and when the record it came from
// runs out: the form addresses are handed to the tracker in by finish, set
// and the test hook (answersOf).
type endpointAddr struct {
	addr   string
	expire time.Time
}

// endpointFamilies is the families of a target's addresses. Each is looked
// up, runs out and fails apart from the other.
var endpointFamilies = [...]cache.AddressFamily{cache.FamilyV4, cache.FamilyV6}

// endpointFamily is what a target holds for one address family. A family is
// in one of three states:
//
//   - answered: its last query answered with addresses, live until expire.
//     Once they have run out it is looked up again, and the other family's
//     addresses are used meanwhile.
//   - denied: its last query answered that it has none (no addrs, retryAt
//     zero). It is looked up again along with the other family, never on its
//     own.
//   - failed: its last query got no answer to go by (retryAt set). It keeps
//     the addresses an earlier answer gave it, used while they are live, and
//     is looked up again at retryAt, whether or not it holds any.
//
// Only an answer, addresses or a denial, replaces what a family holds.
type endpointFamily struct {
	addrs   []string
	expire  time.Time // when addrs run out
	retryAt time.Time // when a failed family is looked up again; zero once answered
}

// live is f's addresses, unless they have run out at now.
func (f *endpointFamily) live(now time.Time) []string {
	if f == nil || !now.Before(f.expire) {
		return nil
	}
	return f.addrs
}

// due reports whether f is to be looked up again at now: it failed and its
// retry time has come, or it was answered with addresses that have run out.
func (f *endpointFamily) due(now time.Time) bool {
	if f == nil {
		return false
	}
	if !f.retryAt.IsZero() {
		return !now.Before(f.retryAt)
	}
	return len(f.addrs) > 0 && !now.Before(f.expire)
}

// familyLookup is how the query of one family of a target's addresses came
// out: addresses live until expire, none (a denial), or failed, when it got
// no answer to go by.
type familyLookup struct {
	family cache.AddressFamily
	addrs  []string
	expire time.Time
	failed bool
}

func (r familyLookup) String() string {
	switch {
	case r.failed:
		return fmt.Sprintf("v%d failed", r.family)
	case len(r.addrs) == 0:
		return fmt.Sprintf("v%d none", r.family)
	}
	return fmt.Sprintf("v%d %v until %s", r.family, r.addrs, r.expire.Format(time.RFC3339))
}

// answersOf is found as a lookup's outcome in every family: each family
// answered with its addresses in found, live until the first of them runs
// out, and denied when found has none of it. No address at all is a lookup
// that failed in both.
func answersOf(found []endpointAddr) []familyLookup {
	out := make([]familyLookup, 0, len(endpointFamilies))
	for _, fam := range endpointFamilies {
		r := familyLookup{family: fam, failed: len(found) == 0}
		for _, a := range found {
			if cache.FamilyOf(a.addr) != fam {
				continue
			}
			r.addrs = append(r.addrs, a.addr)
			if r.expire.IsZero() || a.expire.Before(r.expire) {
				r.expire = a.expire
			}
		}
		out = append(out, r)
	}
	return out
}

// endpointTarget is a redirect target: a ServiceMode record's TargetName
// other than ".", most likely another auth server than the nameserver whose
// signal names it. It has an AuthServer instance of its own, which carries
// only the addresses of the target's lookup and never a signal, and on which
// the server backoff, RTT and counters of every attempt sent to the target
// are kept, whichever nameserver redirected it. The instance is in neither
// AuthServerMap nor any zone's ServerMap, so nothing that installs a signal
// by name reaches it, and a nameserver of the same name keeps its own.
type endpointTarget struct {
	server *cache.AuthServer
	fams   map[cache.AddressFamily]*endpointFamily
	used   time.Time // when the addresses were last asked for while live
}

// liveAddrs is the addresses in fams that have not run out at now, and when
// the last of them does.
func liveAddrs(fams map[cache.AddressFamily]*endpointFamily, now time.Time) ([]string, time.Time) {
	var out []string
	var latest time.Time
	for _, fam := range endpointFamilies {
		f := fams[fam]
		if addrs := f.live(now); len(addrs) > 0 {
			out = append(out, addrs...)
			if f.expire.After(latest) {
				latest = f.expire
			}
		}
	}
	return out, latest
}

// live is e's addresses that have not run out at now.
func (e *endpointTarget) live(now time.Time) []string {
	addrs, _ := liveAddrs(e.fams, now)
	return addrs
}

// due reports whether a family of e is to be looked up again at now
// (endpointFamily.due).
func (e *endpointTarget) due(now time.Time) bool {
	for _, fam := range endpointFamilies {
		if e.fams[fam].due(now) {
			return true
		}
	}
	return false
}

// endpointAddrTracker holds the redirect targets (endpointTarget) by
// canonical name, and the lookups of their addresses in flight. Its zero
// value is ready for use.
type endpointAddrTracker struct {
	mu      sync.Mutex
	entries map[string]*endpointTarget
	pending map[string]chan struct{}
	retry   map[string]time.Time
	ended   map[string]uint64 // the stamp of each target's last lookup to end (lookupState)
	stamps  uint64            // the last stamp given
}

// get returns target's instance and its addresses that are live, and whether
// any is. stale is true when one of its families is due to be looked up
// again (endpointFamily.due) while the target has live addresses: the lookup
// is started (resolveEndpoint), and the live addresses are used meanwhile.
func (tr *endpointAddrTracker) get(target string, now time.Time) (srv *cache.AuthServer, addrs []string, known, stale bool) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	e, ok := tr.entries[core.CanonicalizeName(target)]
	if !ok {
		return nil, nil, false, false
	}
	addrs = e.live(now)
	if len(addrs) == 0 {
		return nil, nil, false, false
	}
	e.used = now
	return e.server, addrs, true, e.due(now)
}

// begin claims the lookup of target, and returns the families it is to
// query: every family but one that failed and whose retry time is still to
// come, so that the refresh of one family does not retry the other early.
// ok is false when a lookup is in flight, when the last one left the target
// without a live address less than endpointAddrRetry ago and no family of it
// is due (endpointFamily.due), when no family is left to query, or when the
// target has live addresses and no family is due: the caller read it stale
// before another lookup refreshed it. A family that is due is looked up
// although a later lookup of the other family, denied, left the target
// without a live address a moment ago.
func (tr *endpointAddrTracker) begin(target string, now time.Time) (fams []cache.AddressFamily, ok bool) {
	key := core.CanonicalizeName(target)
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.pending[key] != nil {
		return nil, false
	}
	e := tr.entries[key]
	due := e != nil && e.due(now)
	if now.Before(tr.retry[key]) && !due {
		return nil, false
	}
	if e != nil && len(e.live(now)) > 0 && !due {
		return nil, false
	}
	for _, fam := range endpointFamilies {
		if e != nil {
			if f := e.fams[fam]; f != nil && now.Before(f.retryAt) {
				continue
			}
		}
		fams = append(fams, fam)
	}
	if len(fams) == 0 {
		return nil, false
	}
	if tr.pending == nil {
		tr.pending = map[string]chan struct{}{}
	}
	tr.pending[key] = make(chan struct{})
	return fams, true
}

// inflight returns a channel that is closed when the running lookup of
// target ends, or nil when none is running.
func (tr *endpointAddrTracker) inflight(target string) <-chan struct{} {
	_, ch := tr.lookupState(target)
	return ch
}

// lookupState returns the stamp of the last lookup of target to end, 0 when
// the tracker holds none, and a channel that is closed when the running one
// ends, nil when none is running. Each lookup that ends gets a stamp no other
// has had, so that one ending between two readings always shows.
func (tr *endpointAddrTracker) lookupState(target string) (ended uint64, running <-chan struct{}) {
	key := core.CanonicalizeName(target)
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if ch := tr.pending[key]; ch != nil {
		running = ch
	}
	return tr.ended[key], running
}

// finish ends the lookup of target with the addresses found, in the form
// answersOf reads: a family with none is denied, and none at all is a lookup
// that failed (finishLookup).
func (tr *endpointAddrTracker) finish(target string, found []endpointAddr, now time.Time, newServer func(string) *cache.AuthServer) {
	tr.finishLookup(target, answersOf(found), now, newServer)
}

// finishLookup ends the lookup of target with each family's outcome
// (results), applied to that family alone (endpointFamily): an answer
// replaces what the family holds, addresses or a denial; a family that
// failed, or whose addresses have already run out at now, keeps what it holds
// and is looked up again after endpointAddrRetry. A family not in results is
// left as it is. A target left with no live address is held back from
// another lookup for endpointAddrRetry. The first lookup that leaves live
// addresses creates the target's instance with newServer (nil: a plain
// AuthServer); later ones give it their addresses, and its backoff and RTT
// carry on. Retry marks that have run out are dropped, and so are the targets
// whose addresses ran out and that no one has asked for for
// endpointTargetIdle, so the tracker holds only the targets that are live,
// waiting, or still have state that counts.
func (tr *endpointAddrTracker) finishLookup(target string, results []familyLookup, now time.Time, newServer func(string) *cache.AuthServer) {
	key := core.CanonicalizeName(target)
	idle := endpointTargetIdle()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if ch := tr.pending[key]; ch != nil {
		close(ch)
		delete(tr.pending, key)
	}
	for k, e := range tr.entries {
		if len(e.live(now)) == 0 && now.Sub(e.used) >= idle {
			delete(tr.entries, k)
		}
	}
	for k, at := range tr.retry {
		if !now.Before(at) {
			delete(tr.retry, k)
		}
	}
	for k := range tr.ended {
		if tr.entries[k] == nil && tr.pending[k] == nil && tr.retry[k].IsZero() {
			delete(tr.ended, k)
		}
	}
	if tr.ended == nil {
		tr.ended = map[string]uint64{}
	}
	tr.stamps++
	tr.ended[key] = tr.stamps
	e := tr.entries[key]
	fams := map[cache.AddressFamily]*endpointFamily{}
	if e != nil {
		fams = e.fams
	}
	for _, r := range results {
		f := fams[r.family]
		if f == nil {
			f = &endpointFamily{}
			fams[r.family] = f
		}
		if r.failed || (len(r.addrs) > 0 && !now.Before(r.expire)) {
			f.retryAt = now.Add(endpointAddrRetry)
			continue
		}
		*f = endpointFamily{addrs: r.addrs, expire: r.expire}
	}
	addrs, latest := liveAddrs(fams, now)
	if len(addrs) == 0 {
		if tr.retry == nil {
			tr.retry = map[string]time.Time{}
		}
		tr.retry[key] = now.Add(endpointAddrRetry)
		if e != nil {
			e.server.SetAddrs(nil)
		}
		return
	}
	delete(tr.retry, key)
	if e == nil {
		var srv *cache.AuthServer
		if newServer != nil {
			srv = newServer(key)
		} else if srv = cache.NewAuthServer(key); srv != nil {
			srv.ForceSetSrc("target")
		}
		if srv == nil {
			return
		}
		if tr.entries == nil {
			tr.entries = map[string]*endpointTarget{}
		}
		e = &endpointTarget{server: srv, fams: fams}
		tr.entries[key] = e
	}
	e.used = now
	e.server.SetAddrs(addrs)
	e.server.SetExpire(latest)
}

// set records target's addresses directly, live until expire.
func (tr *endpointAddrTracker) set(target string, addrs []string, expire time.Time) {
	tr.finish(target, sameExpiry(addrs, expire), time.Now(), nil)
}

// servers returns the targets' instances, by name.
func (tr *endpointAddrTracker) servers() []*cache.AuthServer {
	tr.mu.Lock()
	out := make([]*cache.AuthServer, 0, len(tr.entries))
	for _, e := range tr.entries {
		out = append(out, e.server)
	}
	tr.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RedirectTargetServers returns the instances of the redirect targets the
// resolver holds, by name: the servers transport signals sent a transport
// to, apart from every nameserver (endpointTarget). Status output lists them
// on lines of their own.
func (imr *Imr) RedirectTargetServers() []*cache.AuthServer {
	if imr == nil {
		return nil
	}
	return imr.endpointAddrs.servers()
}

// sameExpiry is addrs, each live until expire.
func sameExpiry(addrs []string, expire time.Time) []endpointAddr {
	out := make([]endpointAddr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, endpointAddr{addr: a, expire: expire})
	}
	return out
}

// endpointAddrLookupHook, when set, stands in for lookupEndpointAddrs: tests
// set it, so that no lookup leaves the process. Its addresses all run out at
// the time it returns, and it is read as finish reads addresses (answersOf):
// a family with none is denied, and none at all is a lookup that failed. Of
// that, only the families the lookup queries count (onlyFamilies).
var endpointAddrLookupHook func(imr *Imr, target string) ([]string, time.Time)

// onlyFamilies is the outcomes in results of the families in fams.
func onlyFamilies(results []familyLookup, fams []cache.AddressFamily) []familyLookup {
	out := make([]familyLookup, 0, len(results))
	for _, r := range results {
		if slices.Contains(fams, r.family) {
			out = append(out, r)
		}
	}
	return out
}

// startEndpointLookup looks up target's addresses off the query path, the
// families begin says are to be queried, unless a lookup is in flight or
// failed a moment ago, or no family is due.
func (imr *Imr) startEndpointLookup(target string) {
	if imr.Cache == nil {
		return
	}
	fams, ok := imr.endpointAddrs.begin(target, time.Now())
	if !ok {
		return
	}
	lookup := (*Imr).lookupEndpointAddrs
	if hook := endpointAddrLookupHook; hook != nil {
		lookup = func(imr *Imr, target string, fams []cache.AddressFamily) []familyLookup {
			return onlyFamilies(answersOf(sameExpiry(hook(imr, target))), fams)
		}
	}
	go func() {
		results := lookup(imr, target, fams)
		imr.endpointAddrs.finishLookup(target, results, time.Now(), imr.Cache.NewTargetAuthServer)
		if !imr.Quiet {
			lgDns.Debug("transport signal: endpoint addresses", "target", target, "results", fmt.Sprint(results))
		}
	}()
}

// lookupEndpointAddrs looks up the families of target's addresses in fams, A
// and AAAA, CNAMEs followed, as for any nameserver name, through the servers'
// default endpoints, and returns each family's outcome (familyLookup). An answer held Bogus is not used;
// Insecure is, as a nameserver's address is (section 4). Each family's
// addresses run out when the first of the records that led to them does, the
// links of a CNAME chain included (addrsExpiry): the two families apart, so
// that one that runs out during the other's lookup does not take the other
// with it. A family failed when its query got no answer to go by: an error,
// a Bogus answer or denial, or addresses whose expiry is not known. A denial
// is an answer: the family has no addresses.
func (imr *Imr) lookupEndpointAddrs(target string, fams []cache.AddressFamily) []familyLookup {
	ctx, cancel := detachedContext(5 * time.Second)
	defer cancel()
	ctx = withDefaultEndpoints(ctx)
	var out []familyLookup
	for _, qtype := range imr.Cache.AddressTypes() {
		r := familyLookup{family: cache.FamilyV4}
		if qtype == dns.TypeAAAA {
			r.family = cache.FamilyV6
		}
		if !slices.Contains(fams, r.family) {
			continue
		}
		resp, err := imr.ImrQuery(ctx, target, qtype, dns.ClassINET, nil)
		switch {
		case err != nil || resp == nil || resp.ValidationState == cache.ValidationStateBogus:
			r.failed = true
		case resp.RRset == nil:
			r.failed = resp.Denial == 0
		default:
			r.addrs, r.expire = imr.endpointAddrsOf(target, qtype, resp, time.Now())
			r.failed = len(r.addrs) == 0
		}
		out = append(out, r)
	}
	return out
}

// endpointAddrsOf returns the addresses resp carries for <target, qtype> and
// when they run out (addrsExpiry). It returns none when that is already past,
// or not known, as for an answer reached through a CNAME chain the lookup
// carried no expiry for: an address is kept only while every record that led
// to it is.
func (imr *Imr) endpointAddrsOf(target string, qtype uint16, resp *ImrResponse, now time.Time) ([]string, time.Time) {
	var addrs []string
	for _, rr := range resp.RRset.RRs {
		switch a := rr.(type) {
		case *dns.A:
			addrs = append(addrs, a.A.String())
		case *dns.AAAA:
			addrs = append(addrs, a.AAAA.String())
		}
	}
	if len(addrs) == 0 {
		return nil, time.Time{}
	}
	exp := imr.addrsExpiry(target, qtype, resp)
	if !now.Before(exp) {
		return nil, time.Time{}
	}
	return addrs, exp
}

// addrsExpiry is when the addresses resp carries for <target, qtype> run out:
// the expiration of the cache entry that holds them, or their TTL from now
// when that is not known, and, when a CNAME chain led to them, no later than
// its first link to run out (ImrResponse.ChainExpiration): a link that changes
// may lead elsewhere. The lookup carries the chain's expiry with its answer,
// so a link that changed or left the cache since does not count. The zero
// time when the chain's expiry is not known.
//
// A response reached through a chain carries no Expiration: the addresses are
// not cached under the question. Their entry is read under the chain's last
// name instead, and counts only while it holds the RRset resp carries, as
// lookupEntry judges an entry; one stored since is another lookup's.
func (imr *Imr) addrsExpiry(target string, qtype uint16, resp *ImrResponse) time.Time {
	chained := !core.EqualNames(resp.RRset.Name, target)
	exp := resp.Expiration
	if exp.IsZero() && chained {
		if e := imr.Cache.Peek(resp.RRset.Name, qtype); e != nil && e.RRset == resp.RRset {
			exp = e.Expiration
		}
	}
	if exp.IsZero() {
		exp = time.Now().Add(cache.GetMinTTL(resp.RRset.RRs))
	}
	if chained {
		if link := resp.ChainExpiration; link.Before(exp) {
			exp = link
		}
	}
	return exp
}

// redirectTargetName is the name of the target d goes to, "" when it goes to
// the server's own address.
func redirectTargetName(d endpointDial) string {
	if !d.redirect || d.server == nil {
		return ""
	}
	return d.server.Name
}

// targetLookupWatch follows the lookups of the targets that the servers in
// serverMap with an address selection may query (mayQueryAddr) send a
// transport to, a transport a query for qname at privacy may use
// (candidateTransports): a strict query never waits for the target of a udp
// endpoint, which it cannot dial, nor any query for one reached only through
// a nameserver on this host that it may not query. Each call
// returns the lookups running then, a channel per target closed when its
// lookup ends, and whether a lookup of one of the targets has ended since the
// call before (endpointAddrTracker.lookupState). The first call reads where
// things stand.
func (imr *Imr) targetLookupWatch(serverMap map[string]*cache.AuthServer, qname string, privacy edns0.PrivacyLevel) func() (running map[string]<-chan struct{}, ended bool) {
	last := map[string]uint64{}
	allowHostLocal := imr.allowHostLocalServers()
	return func() (map[string]<-chan struct{}, bool) {
		running := map[string]<-chan struct{}{}
		ended := false
		seen := map[string]bool{}
		for _, server := range serverMap {
			if server == nil || !slices.ContainsFunc(server.GetAddrs(), func(a string) bool { return mayQueryAddr(server, a, allowHostLocal) }) {
				continue
			}
			for _, t := range candidateTransports(server, qname, privacy) {
				ep := server.GetTransportEndpoint(t)
				if ep.Target == "" {
					continue
				}
				key := core.CanonicalizeName(ep.Target)
				if seen[key] {
					continue
				}
				seen[key] = true
				stamp, ch := imr.endpointAddrs.lookupState(key)
				if stamp != last[key] {
					ended = true
					last[key] = stamp
				}
				if ch != nil {
					running[key] = ch
				}
			}
		}
		return running, ended
	}
}

// awaitTargetLookups waits for the target lookups in running until ready
// says a tuple is usable, no lookup it waits for is running, or ctx is done,
// and reports what ready says then. ready is asked when a lookup ends, and
// not before: the caller has just asked, and each asking selects, which may
// reserve a suspect family's probe. Whichever lookup ends first is looked at
// first. After each asking, watch (targetLookupWatch) gives the lookups
// running then, which the wait takes on, as one that ready itself started for
// a target whose retry mark had run out; when a lookup ended meanwhile, ready
// is asked again. A lookup is bounded by its own deadline
// (lookupEndpointAddrs), so the wait is too.
func awaitTargetLookups(ctx context.Context, running map[string]<-chan struct{}, watch func() (map[string]<-chan struct{}, bool), ready func() bool) bool {
	if len(running) == 0 {
		return ready()
	}
	ended := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	waiting := map[<-chan struct{}]bool{}
	left := 0
	add := func(lookups map[string]<-chan struct{}) {
		for _, ch := range lookups {
			if waiting[ch] {
				continue
			}
			waiting[ch] = true
			left++
			go func() {
				select {
				case <-ch:
					select {
					case ended <- struct{}{}:
					case <-stop:
					}
				case <-stop:
				}
			}()
		}
	}
	take := func() bool {
		lookups, endedSince := watch()
		add(lookups)
		return endedSince
	}
	add(running)
	for left > 0 {
		select {
		case <-ended:
			left--
		case <-ctx.Done():
			return ready()
		}
		take()
		for {
			if ready() {
				return true
			}
			if !take() {
				break
			}
		}
	}
	return false
}
