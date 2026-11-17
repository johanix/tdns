/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Per-server transport counters for the resolver's own queries: for each
// authoritative server, how many answers came back over which transport, how
// many attempts failed, and the transport signal (OOTS) the server gave -- so
// that what a server asked for and what the resolver did can be read side by
// side. They are the counters "imr stats transport-stats" lists per zone, read
// once per server: a server serving five zones is one row here, not five.

// ImrAuthTransportsRow is one auth server in a report. Counts, LastUsed and Failed
// are keyed by the names in ImrClientTransports (Do53 over UDP and TCP apart);
// a transport never used is absent.
type ImrAuthTransportsRow struct {
	Server       string            `json:"server"`
	Src          string            `json:"src,omitempty"`           // "answer", "glue", "hint", "priming", "stub", ...
	Shared       bool              `json:"shared"`                  // false: a stub zone's private instance, counted apart
	Zones        []string          `json:"zones,omitempty"`         // the zones that list this server
	Signal       map[string]uint8  `json:"signal,omitempty"`        // the signal as given: only the transports it named. Absent: none
	SignalSource string            `json:"signal_source,omitempty"` // "oots", "alpn", "config" (a stub), "operator" (set server transport)
	Counts       map[string]uint64 `json:"counts"`                  // answers carried, by actual wire transport
	// ByPrivacy splits Counts by whose query it was: a client's PRIVACY level
	// ("none", "opportunistic", "strict") or "internal" (the resolver's own).
	// Only the classes with answers are present.
	ByPrivacy map[string]map[string]uint64 `json:"by_privacy,omitempty"`
	// Expected is the share, in percent, of first picks selection gives each
	// transport (do53, dot, doq, doh) for a query at each privacy level, from
	// the weights it uses. "strict" is absent when the server cannot carry a
	// strict query.
	Expected    map[string]map[string]uint8 `json:"expected,omitempty"`
	LastUsed    map[string]time.Time        `json:"last_used"`
	LastAny     time.Time                   `json:"last_any,omitzero"`
	Total       uint64                      `json:"total"`
	Failed      map[string]uint64           `json:"failed,omitempty"` // attempts that errored, by actual wire transport
	FailedTotal uint64                      `json:"failed_total"`
	Truncated   uint64                      `json:"truncated"` // Do53/UDP answers TC=1, retried over TCP
}

// ImrAuthTransportsReport is a snapshot of the per-server counters.
type ImrAuthTransportsReport struct {
	Since   time.Time              `json:"since"`          // resolver start or the last reset
	Zone    string                 `json:"zone,omitempty"` // only the servers of this zone were selected
	Servers int                    `json:"servers"`        // servers held, before any filter
	Rows    []ImrAuthTransportsRow `json:"rows"`           // the servers that matched, by name
	Reset   bool                   `json:"reset,omitempty"`
}

// ParseServerFilter reads server names for ImrAuthTransportsSnapshot. A name
// selects that server and every server below it, as a prefix does for an
// address: "example.net." selects ns1.example.net. and ns2.example.net.
func ParseServerFilter(specs []string) ([]string, error) {
	var out []string
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		name := dns.Fqdn(spec)
		if _, ok := dns.IsDomainName(name); !ok {
			return nil, fmt.Errorf("%q is not a domain name", spec)
		}
		out = append(out, name)
	}
	return out, nil
}

// ImrAuthTransportsSnapshot returns the counters of the servers filter selects
// (all when it is empty), and with zone only those of the servers zone lists.
// With reset, EVERY server's counters are cleared afterwards, whatever the
// selection, as with the client counters: clearing only the selected servers
// would let an operator believe a new period had started when it had not.
func ImrAuthTransportsSnapshot(rc *cache.RRsetCacheT, filter []string, zone string, reset bool) ImrAuthTransportsReport {
	since, stats := rc.AuthServerStats(reset)
	rep := ImrAuthTransportsReport{Since: since, Zone: zone, Servers: len(stats), Reset: reset}
	for _, s := range stats {
		if len(filter) > 0 && !namesCover(filter, s.Name) {
			continue
		}
		if zone != "" && !zonesInclude(s.Zones, zone) {
			continue
		}
		row := ImrAuthTransportsRow{
			Server:    s.Name,
			Src:       s.Src,
			Shared:    s.Shared,
			Zones:     s.Zones,
			Counts:    map[string]uint64{},
			LastUsed:  map[string]time.Time{},
			Truncated: s.Truncated,
			Expected:  map[string]map[string]uint8{},
		}
		if s.Received != nil {
			row.Signal = transportWeightsToStrings(s.Received.Weights)
			row.SignalSource = s.Received.Source
		}
		for _, level := range []edns0.PrivacyLevel{edns0.PrivacyNone, edns0.PrivacyOpportunistic, edns0.PrivacyStrict} {
			if shares := expectedShares(s.Transports, s.Weights, level); shares != nil {
				row.Expected[level.String()] = transportWeightsToStrings(shares)
			}
		}
		for t, c := range s.Used {
			row.Counts[authTransportColumn(t)] += c
			row.Total += c
		}
		for class, used := range s.UsedByClass {
			if len(used) == 0 {
				continue
			}
			if row.ByPrivacy == nil {
				row.ByPrivacy = map[string]map[string]uint64{}
			}
			counts := map[string]uint64{}
			for t, c := range used {
				counts[authTransportColumn(t)] += c
			}
			row.ByPrivacy[cache.TrafficClass(class).String()] = counts
		}
		for t, at := range s.LastUsed {
			row.LastUsed[authTransportColumn(t)] = at
			if at.After(row.LastAny) {
				row.LastAny = at
			}
		}
		if len(s.Failed) > 0 {
			row.Failed = map[string]uint64{}
			for t, c := range s.Failed {
				row.Failed[authTransportColumn(t)] += c
				row.FailedTotal += c
			}
		}
		rep.Rows = append(rep.Rows, row)
	}
	return rep
}

// authTransportColumn names a wire transport as the client counters do, so
// that the two tables share their columns.
func authTransportColumn(t core.Transport) string {
	switch t {
	case core.TransportDo53:
		return ImrClientTransports[ctDo53UDP]
	case core.TransportDo53TCP:
		return ImrClientTransports[ctDo53TCP]
	case core.TransportDoT:
		return ImrClientTransports[ctDoT]
	case core.TransportDoQ:
		return ImrClientTransports[ctDoQ]
	case core.TransportDoH:
		return ImrClientTransports[ctDoH]
	}
	return transportName(t)
}

func zonesInclude(zones []string, zone string) bool {
	for _, z := range zones {
		if core.EqualNames(z, zone) {
			return true
		}
	}
	return false
}

func namesCover(names []string, name string) bool {
	for _, n := range names {
		if dns.IsSubDomain(n, name) {
			return true
		}
	}
	return false
}
