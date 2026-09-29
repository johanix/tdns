/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"container/list"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Per-client transport counters for tdns-imr: for each client address, how
// many queries arrived over which transport, and when each transport was last
// used, since startup or the last reset. They answer "which transports do my
// clients use?" -- and, for one client, "is it really talking to me over DoT?".
//
// Off by default (imrengine.client-stats.enabled): the counters record client
// addresses, which a production resolver should not do unasked. When off,
// nothing on the query path changes at all: the listeners get the handler they
// always had. When on, each listener's handler is wrapped once, at setup, by a
// wrapper that knows its transport. The transport cannot be told from the
// response writer (DoT and Do53/TCP both look like TCP), which is why the
// wrapping is per listener.
//
// No query names and no answers are recorded. The embedded resolver's loopback
// debug window (listeners.imr-debug-address) is not counted.

// DefaultImrClientStatsMax is imrengine.client-stats.max-clients when unset.
const DefaultImrClientStatsMax = 4096

// clientTransport is one of the five ways a client reaches the resolver.
type clientTransport int

const (
	ctDo53UDP clientTransport = iota
	ctDo53TCP
	ctDoT
	ctDoQ
	ctDoH
	numClientTransports
)

// ImrClientTransports names the transports, in the order the counters use.
var ImrClientTransports = [numClientTransports]string{"do53/udp", "do53/tcp", "dot", "doq", "doh"}

type clientStatsEntry struct {
	addr    netip.Addr
	counts  [numClientTransports]uint64
	last    [numClientTransports]time.Time
	lastAny time.Time // the latest of last: what eviction goes by
	elem    *list.Element
}

// ImrClientStats holds the counters.
type ImrClientStats struct {
	mu      sync.Mutex
	max     int
	since   time.Time
	clients map[netip.Addr]*clientStatsEntry
	lru     *list.List // front: the most recently seen client

	evictedClients uint64
	evicted        [numClientTransports]uint64
}

func newImrClientStats(max int) *ImrClientStats {
	if max <= 0 {
		max = DefaultImrClientStatsMax
	}
	return &ImrClientStats{
		max:     max,
		since:   time.Now(),
		clients: map[netip.Addr]*clientStatsEntry{},
		lru:     list.New(),
	}
}

// clientAddr is the client's address from a response writer's RemoteAddr,
// unmapped: a client seen as 192.0.2.10 over one transport and as
// ::ffff:192.0.2.10 over another is the same client, and one row.
func clientAddr(ra net.Addr) (netip.Addr, bool) {
	// The listeners' own address types are read directly: formatting the
	// address as a string to parse it again would be most of the cost of
	// counting a query.
	switch a := ra.(type) {
	case nil:
		return netip.Addr{}, false
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap(), true
		}
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap(), true
		}
	case dohPeerAddr:
		return a.ap.Addr().Unmap(), true
	}
	return peerIP(ra.String()) // peerIP unmaps
}

// record counts one query from ra over t.
func (s *ImrClientStats) record(ra net.Addr, t clientTransport, now time.Time) {
	addr, ok := clientAddr(ra)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, found := s.clients[addr]
	if !found {
		if len(s.clients) >= s.max {
			s.evictOldestLocked()
		}
		e = &clientStatsEntry{addr: addr}
		e.elem = s.lru.PushFront(e)
		s.clients[addr] = e
	} else {
		s.lru.MoveToFront(e.elem)
	}
	e.counts[t]++
	e.last[t] = now
	e.lastAny = now
}

// evictOldestLocked drops the client least recently seen on any transport,
// folding its counts into the evicted aggregate so that totals stay honest.
func (s *ImrClientStats) evictOldestLocked() {
	back := s.lru.Back()
	if back == nil {
		return
	}
	e := back.Value.(*clientStatsEntry)
	s.lru.Remove(back)
	delete(s.clients, e.addr)
	s.evictedClients++
	for i, c := range e.counts {
		s.evicted[i] += c
	}
}

// wrap returns handler, counting each query by its client and t first.
func (s *ImrClientStats) wrap(handler func(dns.ResponseWriter, *dns.Msg), t clientTransport) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		s.record(w.RemoteAddr(), t, time.Now())
		handler(w, r)
	}
}

// imrListenerHandlers are the handlers the resolver's listeners get.
type imrListenerHandlers struct {
	udp, tcp, dot, doh, doq func(dns.ResponseWriter, *dns.Msg)
}

// listenerHandlers gives every listener handler unchanged when cs is nil (the
// counters are off), and a counting wrapper per transport when it is not.
func listenerHandlers(handler func(dns.ResponseWriter, *dns.Msg), cs *ImrClientStats) imrListenerHandlers {
	if cs == nil {
		return imrListenerHandlers{udp: handler, tcp: handler, dot: handler, doh: handler, doq: handler}
	}
	return imrListenerHandlers{
		udp: cs.wrap(handler, ctDo53UDP),
		tcp: cs.wrap(handler, ctDo53TCP),
		dot: cs.wrap(handler, ctDoT),
		doh: cs.wrap(handler, ctDoH),
		doq: cs.wrap(handler, ctDoQ),
	}
}

// ImrClientStatsRow is one client in a report. Counts and LastSeen are keyed
// by the names in ImrClientTransports; a transport the client never used is
// absent.
type ImrClientStatsRow struct {
	Client   string               `json:"client"`
	Counts   map[string]uint64    `json:"counts"`
	LastSeen map[string]time.Time `json:"last_seen"`
	LastAny  time.Time            `json:"last_any"`
	Total    uint64               `json:"total"`
}

// ImrClientStatsReport is a snapshot of the counters.
type ImrClientStatsReport struct {
	Since          time.Time           `json:"since"`   // startup or the last reset
	Clients        int                 `json:"clients"` // clients held, before any filter
	Rows           []ImrClientStatsRow `json:"rows"`    // the clients that matched, by address
	EvictedClients uint64              `json:"evicted_clients"`
	EvictedCounts  map[string]uint64   `json:"evicted_counts,omitempty"`
	Reset          bool                `json:"reset,omitempty"` // the counters were cleared after this snapshot
}

// ParseClientFilter reads addresses and prefixes for Snapshot.
func ParseClientFilter(specs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		if p, err := netip.ParsePrefix(spec); err == nil {
			out = append(out, netip.PrefixFrom(p.Addr().Unmap(), unmappedBits(p)).Masked())
			continue
		}
		a, err := netip.ParseAddr(spec)
		if err != nil {
			return nil, fmt.Errorf("%q is neither an address nor a prefix", spec)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// unmappedBits is a prefix length for the unmapped form of p's address: an
// IPv4-mapped IPv6 prefix loses the 96 bits of its ::ffff: head.
func unmappedBits(p netip.Prefix) int {
	if p.Addr().Is4In6() {
		if b := p.Bits() - 96; b >= 0 {
			return b
		}
		return 0
	}
	return p.Bits()
}

// Snapshot returns the counters for the clients filter selects (all when it is
// empty). With reset, the WHOLE store is cleared afterwards -- every client, the
// evicted aggregate and since -- whatever the filter: a filter only chooses
// what is returned. Clearing only the selected clients would let an operator
// believe they had started a new period when they had not.
func (s *ImrClientStats) Snapshot(filter []netip.Prefix, reset bool) ImrClientStatsReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := ImrClientStatsReport{Since: s.since, Clients: len(s.clients), EvictedClients: s.evictedClients}
	if s.evictedClients > 0 {
		rep.EvictedCounts = map[string]uint64{}
		for i, c := range s.evicted {
			if c > 0 {
				rep.EvictedCounts[ImrClientTransports[i]] = c
			}
		}
	}
	for addr, e := range s.clients {
		if len(filter) > 0 && !prefixesContain(filter, addr) {
			continue
		}
		row := ImrClientStatsRow{Client: addr.String(), Counts: map[string]uint64{}, LastSeen: map[string]time.Time{}, LastAny: e.lastAny}
		for i, c := range e.counts {
			if c == 0 {
				continue
			}
			row.Counts[ImrClientTransports[i]] = c
			row.LastSeen[ImrClientTransports[i]] = e.last[i]
			row.Total += c
		}
		rep.Rows = append(rep.Rows, row)
	}
	sort.Slice(rep.Rows, func(i, j int) bool {
		a, _ := netip.ParseAddr(rep.Rows[i].Client)
		b, _ := netip.ParseAddr(rep.Rows[j].Client)
		return a.Less(b)
	})
	if reset {
		s.clients = map[netip.Addr]*clientStatsEntry{}
		s.lru.Init()
		s.evictedClients = 0
		s.evicted = [numClientTransports]uint64{}
		s.since = time.Now()
		rep.Reset = true
	}
	return rep
}

func prefixesContain(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
