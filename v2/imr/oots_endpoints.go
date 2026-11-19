/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"
	"fmt"
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
// lame endpoint holds back only itself.

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
		imr.lgDns().Debug("transport signal: a redirect ignored for want of validation",
			"servername", server.Name, "target", rec.target, "port", rec.port, "transports", MarshalTransport(rec.raw),
			"state", cache.SignalStateString(state), "via", set.via, "path", cache.FormatSignalPath(set.path))
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
// is started. A udp or tcp endpoint with no usable address (fallsBackToPort53)
// gives way to addr on port 53. A context marked withDefaultEndpoints always
// gets the default endpoint. Forced TCP asks for Do53TCP, so it goes to the
// tcp endpoint or port 53, never to the udp one.
func (imr *Imr) endpointFor(ctx context.Context, server *cache.AuthServer, zone *cache.Zone, addr string, t core.Transport) (endpointDial, error) {
	if defaultEndpointsOnly(ctx) {
		return endpointDial{addr: addr}, nil
	}
	return imr.resolveEndpoint(server, zone, addr, t, true)
}

// resolveEndpoint is endpointFor's choice for a context not marked
// withDefaultEndpoints. lookup says whether a target whose addresses are not
// known is looked up: not for the stub probe, which only reports. An address
// is usable when neither the server's backoff nor the zone's lameness holds
// it at the endpoint's port (endpointUsable).
//
// A port the signal gave explicitly that is the client's own default for t
// is the default endpoint's socket, and is kept under 0 like it: a signal
// that names port 853 for DoT, or 53 for udp, shares the backoff and RTT of
// one that leaves the port out.
func (imr *Imr) resolveEndpoint(server *cache.AuthServer, zone *cache.Zone, addr string, t core.Transport, lookup bool) (endpointDial, error) {
	ep := server.GetTransportEndpoint(t)
	if ep.Port != 0 && ep.Port == imr.clientDefaultPort(t) {
		ep.Port = 0
	}
	if ep.Target == "" {
		if ep.Port != 0 && fallsBackToPort53(t) && !endpointUsable(server, zone, addr, ep.Port, t) {
			return endpointDial{addr: addr}, nil
		}
		return endpointDial{addr: addr, port: ep.Port, keyPort: ep.Port}, nil
	}
	addrs, known := imr.endpointAddrs.get(ep.Target, time.Now())
	if !known {
		if lookup {
			imr.startEndpointLookup(ep.Target)
		}
		return endpointDial{addr: addr}, nil
	}
	pick := imr.chooseEndpointAddr(server, zone, addrs, ep.Port, t)
	if pick == "" {
		if fallsBackToPort53(t) {
			return endpointDial{addr: addr}, nil
		}
		return endpointDial{}, errEndpointUnavailable{server: server.Name, target: ep.Target, transport: t}
	}
	return endpointDial{addr: pick, port: ep.Port, redirect: true, keyPort: ep.Port}, nil
}

// attemptKey is the address and port an attempt for t at the server's own
// address addr would dial for a query to zone, and book its backoff, RTT and
// lameness under (endpointFor). lookup says whether a target whose addresses
// are not known is looked up, as endpointFor does: selection does, so that a
// default endpoint in backoff, which keeps the tuple from being tried, does
// not keep the target from being found either. ok is false when no attempt
// would be made.
func (imr *Imr) attemptKey(ctx context.Context, server *cache.AuthServer, zone *cache.Zone, addr string, t core.Transport, lookup bool) (string, uint16, bool) {
	if defaultEndpointsOnly(ctx) {
		return addr, 0, true
	}
	d, err := imr.resolveEndpoint(server, zone, addr, t, lookup)
	if err != nil {
		return "", 0, false
	}
	return d.addr, d.keyPort, true
}

// tupleRTT is the RTT of what an attempt for tup would dial (attemptKey).
func (imr *Imr) tupleRTT(ctx context.Context, zone *cache.Zone, tup ServerAddrXportTuple) (time.Duration, bool) {
	a, p, ok := imr.attemptKey(ctx, tup.Server, zone, tup.Addr, tup.Transport, false)
	if !ok {
		return 0, false
	}
	return tup.Server.GetEndpointAddrRTT(a, p, tup.Transport)
}

// endpointUsable reports whether an attempt for t may dial addr at port:
// neither the server's backoff nor the zone's lameness holds it there. A nil
// zone has no lameness.
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
// use or held suspect, never one in backoff or lame for zone at this port and
// transport; of the rest the lowest RTT, an address with no sample counting
// as unprobedRTTSentinel. "" when none is left.
func (imr *Imr) chooseEndpointAddr(server *cache.AuthServer, zone *cache.Zone, addrs []string, port uint16, t core.Transport) string {
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
		if !server.AllowsAddrFamily(a) {
			continue
		}
		if imr.FamilyTracker != nil && imr.FamilyTracker.IsSuspect(cache.FamilyOf(a)) {
			continue
		}
		if !endpointUsable(server, zone, a, port, t) {
			continue
		}
		rtt, ok := server.GetEndpointAddrRTT(a, port, t)
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

// endpointAddrTracker holds the addresses found for each target, until the
// TTL of the records they came from, and the lookups in flight. Its zero
// value is ready for use.
type endpointAddrTracker struct {
	mu      sync.Mutex
	entries map[string]endpointAddrEntry
	pending map[string]bool
	retry   map[string]time.Time
}

type endpointAddrEntry struct {
	addrs  []string
	expire time.Time
}

// get returns target's addresses, and whether they are known and live.
func (tr *endpointAddrTracker) get(target string, now time.Time) ([]string, bool) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	e, ok := tr.entries[core.CanonicalizeName(target)]
	if !ok || len(e.addrs) == 0 || !now.Before(e.expire) {
		return nil, false
	}
	return append([]string(nil), e.addrs...), true
}

// begin claims the lookup of target: false when one is in flight, or the last
// one failed less than endpointAddrRetry ago.
func (tr *endpointAddrTracker) begin(target string, now time.Time) bool {
	key := core.CanonicalizeName(target)
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.pending[key] || now.Before(tr.retry[key]) {
		return false
	}
	if tr.pending == nil {
		tr.pending = map[string]bool{}
	}
	tr.pending[key] = true
	return true
}

// finish ends the lookup of target with the addresses found, live until
// expire. No address is a failure, retried after endpointAddrRetry. Entries
// and retry marks that have run out are dropped, so the tracker holds only
// the targets that are live or waiting.
func (tr *endpointAddrTracker) finish(target string, addrs []string, expire, now time.Time) {
	key := core.CanonicalizeName(target)
	tr.mu.Lock()
	defer tr.mu.Unlock()
	delete(tr.pending, key)
	for k, e := range tr.entries {
		if !now.Before(e.expire) {
			delete(tr.entries, k)
		}
	}
	for k, at := range tr.retry {
		if !now.Before(at) {
			delete(tr.retry, k)
		}
	}
	if len(addrs) == 0 || !now.Before(expire) {
		if tr.retry == nil {
			tr.retry = map[string]time.Time{}
		}
		tr.retry[key] = now.Add(endpointAddrRetry)
		return
	}
	if tr.entries == nil {
		tr.entries = map[string]endpointAddrEntry{}
	}
	tr.entries[key] = endpointAddrEntry{addrs: addrs, expire: expire}
	delete(tr.retry, key)
}

// set records target's addresses directly, live until expire.
func (tr *endpointAddrTracker) set(target string, addrs []string, expire time.Time) {
	tr.finish(target, addrs, expire, time.Now())
}

// endpointAddrLookupHook, when set, stands in for lookupEndpointAddrs: tests
// set it, so that no lookup leaves the process.
var endpointAddrLookupHook func(imr *Imr, target string) ([]string, time.Time)

// startEndpointLookup looks up target's addresses off the query path, unless
// a lookup is in flight or failed a moment ago.
func (imr *Imr) startEndpointLookup(target string) {
	if imr.Cache == nil || !imr.endpointAddrs.begin(target, time.Now()) {
		return
	}
	lookup := (*Imr).lookupEndpointAddrs
	if endpointAddrLookupHook != nil {
		lookup = endpointAddrLookupHook
	}
	go func() {
		addrs, expire := lookup(imr, target)
		imr.endpointAddrs.finish(target, addrs, expire, time.Now())
		imr.lgDns().Debug("transport signal: endpoint addresses", "target", target, "addrs", addrs, "expire", expire)
	}()
}

// lookupEndpointAddrs looks up target's A and AAAA, CNAMEs followed, as for
// any nameserver name, through the servers' default endpoints. An answer held
// Bogus is not used; Insecure is, as a nameserver's address is (section 4).
// It returns the addresses and when the first of their records expires, the
// links of a CNAME chain included (addrsExpiry).
func (imr *Imr) lookupEndpointAddrs(target string) ([]string, time.Time) {
	ctx, cancel := detachedContext(5 * time.Second)
	defer cancel()
	ctx = withDefaultEndpoints(ctx)
	var addrs []string
	var expire time.Time
	for _, qtype := range imr.Cache.AddressTypes() {
		resp, err := imr.imrQuery(ctx, target, qtype, dns.ClassINET, false)
		if err != nil || resp == nil || resp.RRset == nil || resp.ValidationState == cache.ValidationStateBogus {
			continue
		}
		found, exp := imr.endpointAddrsOf(target, qtype, resp, time.Now())
		if len(found) == 0 {
			continue
		}
		addrs = append(addrs, found...)
		if expire.IsZero() || exp.Before(expire) {
			expire = exp
		}
	}
	return addrs, expire
}

// endpointAddrsOf returns the addresses resp carries for <target, qtype> and
// when they run out (addrsExpiry). It returns none when that is already past,
// or not known, as for an answer reached through a CNAME chain the lookup
// carried no expiry for: an address is kept only while every record that led
// to it is.
func (imr *Imr) endpointAddrsOf(target string, qtype uint16, resp *Response, now time.Time) ([]string, time.Time) {
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
// its first link to run out (Response.ChainExpiration): a link that changes
// may lead elsewhere. The lookup carries the chain's expiry with its answer,
// so a link that changed or left the cache since does not count. The zero
// time when the chain's expiry is not known.
//
// A response reached through a chain carries no Expiration: the addresses are
// not cached under the question. Their entry is read under the chain's last
// name instead, and counts only while it holds the RRset resp carries, as
// lookupEntry judges an entry; one stored since is another lookup's.
func (imr *Imr) addrsExpiry(target string, qtype uint16, resp *Response) time.Time {
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
