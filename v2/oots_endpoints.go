/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"sort"
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
// When every address of an endpoint is backed off, the attempt fails without
// a dial, and the query goes on to its next tuple, ending at the nameserver's
// own name on port 53 (Do53, the last resort candidateTransports keeps).

// honouredRecords is recs without the records whose target the set's path does
// not allow: all of them unless the path validated Secure (R1, R5). Their
// records with TargetName "." stay, whatever the state (R2, R4). Each record
// ignored is logged and counted on server. One ignored while the path was
// undecided marks the set as waiting for the verifying lookup.
func (imr *Imr) honouredRecords(server *cache.AuthServer, set *svcbSignalSet, recs []ootsRecord) []ootsRecord {
	state := cache.SignalPathState(set.path)
	if state == cache.ValidationStateSecure {
		return recs
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
	return out
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
	// keyPort is the port backoff and RTT are kept under: the endpoint's at
	// a target's address, 0 at the server's own address, as it always was.
	keyPort uint16
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
// addr goes. At the server's own name it is addr, at the endpoint's port. At
// a target it is the best usable address of the target, once those are known;
// until then the default endpoint, addr at the usual port, and the lookup of
// the target's addresses is started. A context marked withDefaultEndpoints
// always gets the default endpoint.
func (imr *Imr) endpointFor(ctx context.Context, server *cache.AuthServer, addr string, t core.Transport) (endpointDial, error) {
	if defaultEndpointsOnly(ctx) {
		return endpointDial{addr: addr}, nil
	}
	ep := server.GetTransportEndpoint(t)
	if ep.Target == "" {
		return endpointDial{addr: addr, port: ep.Port}, nil
	}
	addrs, known := imr.endpointAddrs.get(ep.Target, time.Now())
	if !known {
		imr.startEndpointLookup(ep.Target)
		return endpointDial{addr: addr}, nil
	}
	pick := imr.chooseEndpointAddr(server, addrs, ep.Port, t)
	if pick == "" {
		return endpointDial{}, errEndpointUnavailable{server: server.Name, target: ep.Target, transport: t}
	}
	return endpointDial{addr: pick, port: ep.Port, redirect: true, keyPort: ep.Port}, nil
}

// chooseEndpointAddr picks among a target's addresses as prioritizeServers
// does among a server's own: never one on this host unless
// allow-loopback-nameservers is set, never one of an address family not in
// use or held suspect, never one in backoff at this port and transport; of
// the rest the lowest RTT, an address with no sample counting as
// unprobedRTTSentinel. "" when none is left.
func (imr *Imr) chooseEndpointAddr(server *cache.AuthServer, addrs []string, port uint16, t core.Transport) string {
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
		if !server.IsEndpointAddrAvailable(a, port, t) {
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
// expire. No address is a failure, retried after endpointAddrRetry.
func (tr *endpointAddrTracker) finish(target string, addrs []string, expire, now time.Time) {
	key := core.CanonicalizeName(target)
	tr.mu.Lock()
	defer tr.mu.Unlock()
	delete(tr.pending, key)
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
		if !imr.Quiet {
			lgDns.Debug("transport signal: endpoint addresses", "target", target, "addrs", addrs, "expire", expire)
		}
	}()
}

// lookupEndpointAddrs looks up target's A and AAAA, CNAMEs followed, as for
// any nameserver name, through the servers' default endpoints. An answer held
// Bogus is not used; Insecure is, as a nameserver's address is (section 4).
// It returns the addresses and when the first of their records expires.
func (imr *Imr) lookupEndpointAddrs(target string) ([]string, time.Time) {
	ctx, cancel := detachedContext(5 * time.Second)
	defer cancel()
	ctx = withDefaultEndpoints(ctx)
	var addrs []string
	var expire time.Time
	for _, qtype := range imr.Cache.AddressTypes() {
		resp, err := imr.ImrQuery(ctx, target, qtype, dns.ClassINET, nil)
		if err != nil || resp == nil || resp.RRset == nil || resp.ValidationState == cache.ValidationStateBogus {
			continue
		}
		found := false
		for _, rr := range resp.RRset.RRs {
			switch a := rr.(type) {
			case *dns.A:
				addrs = append(addrs, a.A.String())
				found = true
			case *dns.AAAA:
				addrs = append(addrs, a.AAAA.String())
				found = true
			}
		}
		if !found {
			continue
		}
		exp := resp.Expiration
		if exp.IsZero() {
			exp = time.Now().Add(cache.GetMinTTL(resp.RRset.RRs))
		}
		if expire.IsZero() || exp.Before(expire) {
			expire = exp
		}
	}
	return addrs, expire
}
