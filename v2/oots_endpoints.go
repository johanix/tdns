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

// endpointFor is where an attempt for transport t at the server's own address
// addr goes, for a query to zone (nil when none is known). At the server's
// own name it is addr, at the endpoint's port. At a target it is the best
// usable address of the target, once those are known; until then the default
// endpoint, addr at the usual port, and the lookup of the target's addresses
// is started; it is started again when one family of them has run out, and
// the other's are used meanwhile. A udp or tcp endpoint with no usable
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
// known, or one of whose families has run out, is looked up: not for the stub
// probe, which only reports. An address
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
// use or held suspect, never one in the target's backoff or lame for zone at
// this port and transport; of the rest the lowest RTT the target holds, an
// address with no sample counting as unprobedRTTSentinel. "" when none is
// left.
func (imr *Imr) chooseEndpointAddr(target *cache.AuthServer, zone *cache.Zone, addrs []string, port uint16, t core.Transport) string {
	allowHostLocal := imr.allowHostLocalServers()
	type cand struct {
		addr string
		rtt  time.Duration
	}
	var cands []cand
	for _, a := range addrs {
		if !allowHostLocal && hostLocalAddr(a) {
			continue
		}
		if !target.AllowsAddrFamily(a) {
			continue
		}
		if imr.FamilyTracker != nil && imr.FamilyTracker.IsSuspect(cache.FamilyOf(a)) {
			continue
		}
		if !endpointUsable(target, zone, a, port, t) {
			continue
		}
		rtt, ok := target.GetEndpointAddrRTT(a, port, t)
		if !ok {
			rtt = unprobedRTTSentinel
		}
		cands = append(cands, cand{a, rtt})
	}
	if len(cands) == 0 {
		return ""
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].rtt < cands[j].rtt })
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
// runs out. A target's A and AAAA are looked up apart, and each family runs
// out on its own.
type endpointAddr struct {
	addr   string
	expire time.Time
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
	addrs  []endpointAddr
	used   time.Time // when the addresses were last asked for while live
}

// live is e's addresses that have not run out at now.
func (e *endpointTarget) live(now time.Time) []string {
	var out []string
	for _, a := range e.addrs {
		if now.Before(a.expire) {
			out = append(out, a.addr)
		}
	}
	return out
}

// endpointAddrTracker holds the redirect targets (endpointTarget) by
// canonical name, and the lookups of their addresses in flight. Its zero
// value is ready for use.
type endpointAddrTracker struct {
	mu      sync.Mutex
	entries map[string]*endpointTarget
	pending map[string]chan struct{}
	retry   map[string]time.Time
}

// get returns target's instance and its addresses that are live, and whether
// any is. stale is true when some address the last lookup found has run out
// while others are live: A and AAAA run out apart, and a family that has run
// out is looked up again (resolveEndpoint) while the other's addresses are
// used.
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
	return e.server, addrs, true, len(addrs) < len(e.addrs)
}

// begin claims the lookup of target: false when one is in flight, or the last
// one failed less than endpointAddrRetry ago.
func (tr *endpointAddrTracker) begin(target string, now time.Time) bool {
	key := core.CanonicalizeName(target)
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.pending[key] != nil || now.Before(tr.retry[key]) {
		return false
	}
	if tr.pending == nil {
		tr.pending = map[string]chan struct{}{}
	}
	tr.pending[key] = make(chan struct{})
	return true
}

// inflight returns a channel that is closed when the running lookup of
// target ends, or nil when none is running.
func (tr *endpointAddrTracker) inflight(target string) <-chan struct{} {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if ch := tr.pending[core.CanonicalizeName(target)]; ch != nil {
		return ch
	}
	return nil
}

// finish ends the lookup of target with the addresses found, every family
// answered (finishLookup).
func (tr *endpointAddrTracker) finish(target string, found []endpointAddr, now time.Time, newServer func(string) *cache.AuthServer) {
	tr.finishLookup(target, found, nil, now, newServer)
}

// finishLookup ends the lookup of target with the addresses found. Those that
// have already run out at now are left out, each family by its own expiry,
// and none left is a failure, retried after endpointAddrRetry. A family whose
// query failed (failed) keeps the addresses held for it: those still live
// stay usable, and those that have run out keep the family stale, so it is
// looked up again, after endpointAddrRetry. Only an answer replaces a
// family's addresses. The first success
// creates the target's instance with newServer (nil: a plain AuthServer);
// later ones give it their addresses, and its backoff and RTT carry on.
// Retry marks that have run out are dropped, and so are the targets whose
// addresses ran out and that no one has asked for for endpointTargetIdle, so
// the tracker holds only the targets that are live, waiting, or still have
// state that counts.
func (tr *endpointAddrTracker) finishLookup(target string, found []endpointAddr, failed []cache.AddressFamily, now time.Time, newServer func(string) *cache.AuthServer) {
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
	var live []endpointAddr
	for _, a := range found {
		if now.Before(a.expire) {
			live = append(live, a)
		}
	}
	if len(live) == 0 {
		if tr.retry == nil {
			tr.retry = map[string]time.Time{}
		}
		tr.retry[key] = now.Add(endpointAddrRetry)
		return
	}
	e := tr.entries[key]
	kept := false
	if e != nil && len(failed) > 0 {
		for _, a := range e.addrs {
			if slices.Contains(failed, cache.FamilyOf(a.addr)) {
				live = append(live, a)
				kept = true
			}
		}
	}
	var addrs []string
	var latest time.Time
	for _, a := range live {
		if !now.Before(a.expire) {
			continue
		}
		addrs = append(addrs, a.addr)
		if a.expire.After(latest) {
			latest = a.expire
		}
	}
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
		e = &endpointTarget{server: srv}
		tr.entries[key] = e
	}
	e.addrs = live
	e.used = now
	e.server.SetAddrs(addrs)
	e.server.SetExpire(latest)
	if kept {
		if tr.retry == nil {
			tr.retry = map[string]time.Time{}
		}
		tr.retry[key] = now.Add(endpointAddrRetry)
	} else {
		delete(tr.retry, key)
	}
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
// the time it returns.
var endpointAddrLookupHook func(imr *Imr, target string) ([]string, time.Time)

// startEndpointLookup looks up target's addresses off the query path, unless
// a lookup is in flight or failed a moment ago.
func (imr *Imr) startEndpointLookup(target string) {
	if imr.Cache == nil || !imr.endpointAddrs.begin(target, time.Now()) {
		return
	}
	lookup := (*Imr).lookupEndpointAddrs
	if hook := endpointAddrLookupHook; hook != nil {
		lookup = func(imr *Imr, target string) ([]endpointAddr, []cache.AddressFamily) {
			return sameExpiry(hook(imr, target)), nil
		}
	}
	go func() {
		found, failed := lookup(imr, target)
		imr.endpointAddrs.finishLookup(target, found, failed, time.Now(), imr.Cache.NewTargetAuthServer)
		if !imr.Quiet {
			lgDns.Debug("transport signal: endpoint addresses", "target", target, "addrs", found, "failed", failed)
		}
	}()
}

// lookupEndpointAddrs looks up target's A and AAAA, CNAMEs followed, as for
// any nameserver name, through the servers' default endpoints. An answer held
// Bogus is not used; Insecure is, as a nameserver's address is (section 4).
// Each address runs out when the first of the records that led to it does,
// the links of a CNAME chain included (addrsExpiry): the two families apart,
// so that one that runs out during the other's lookup does not take the
// other with it. failed is the families whose query got no answer to go by:
// an error, a Bogus answer or denial, or addresses whose expiry is not known.
// A denial is an answer: the family has no addresses.
func (imr *Imr) lookupEndpointAddrs(target string) (found []endpointAddr, failed []cache.AddressFamily) {
	ctx, cancel := detachedContext(5 * time.Second)
	defer cancel()
	ctx = withDefaultEndpoints(ctx)
	for _, qtype := range imr.Cache.AddressTypes() {
		fam := cache.FamilyV4
		if qtype == dns.TypeAAAA {
			fam = cache.FamilyV6
		}
		resp, err := imr.ImrQuery(ctx, target, qtype, dns.ClassINET, nil)
		if err != nil || resp == nil || resp.ValidationState == cache.ValidationStateBogus {
			failed = append(failed, fam)
			continue
		}
		if resp.RRset == nil {
			if resp.Denial == 0 {
				failed = append(failed, fam)
			}
			continue
		}
		addrs, exp := imr.endpointAddrsOf(target, qtype, resp, time.Now())
		if len(addrs) == 0 {
			failed = append(failed, fam)
			continue
		}
		found = append(found, sameExpiry(addrs, exp)...)
	}
	return found, failed
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

// runningTargetLookups returns, for the servers in serverMap that have an
// address, the running lookups of the targets their signals send a transport
// to: a channel per target, closed when its lookup ends.
func (imr *Imr) runningTargetLookups(serverMap map[string]*cache.AuthServer) map[string]<-chan struct{} {
	out := map[string]<-chan struct{}{}
	for _, server := range serverMap {
		if server == nil || len(server.GetAddrs()) == 0 {
			continue
		}
		for _, ep := range server.GetTransportEndpoints() {
			if ep.Target == "" {
				continue
			}
			key := core.CanonicalizeName(ep.Target)
			if _, ok := out[key]; ok {
				continue
			}
			if ch := imr.endpointAddrs.inflight(key); ch != nil {
				out[key] = ch
			}
		}
	}
	return out
}

// awaitTargetLookups waits for the target lookups in running
// (runningTargetLookups) until ready says a tuple is usable, every lookup
// has ended, or ctx is done, and reports what ready says then. ready is
// asked once per lookup that ends, and not before: the caller has just
// asked, and each asking selects, which may reserve a suspect family's
// probe. Whichever lookup ends first is looked at first. A lookup is bounded
// by its own deadline (lookupEndpointAddrs), so the wait is too.
func awaitTargetLookups(ctx context.Context, running map[string]<-chan struct{}, ready func() bool) bool {
	if len(running) == 0 {
		return ready()
	}
	ended := make(chan struct{}, len(running))
	stop := make(chan struct{})
	defer close(stop)
	for _, ch := range running {
		go func(ch <-chan struct{}) {
			select {
			case <-ch:
				ended <- struct{}{}
			case <-stop:
			}
		}(ch)
	}
	for range running {
		select {
		case <-ended:
		case <-ctx.Done():
			return ready()
		}
		if ready() {
			return true
		}
	}
	return false
}
