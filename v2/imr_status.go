/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"time"

	core "github.com/johanix/tdns/v2/core"
)

// ImrStatus is the IMR block of the config-status API response: priming
// state plus the configured stub and forward zones with per-upstream
// reachability. Populated for every daemon that carries an IMR — tdns-imr
// itself, and the embedded resolver in tdns-auth / tdns-agent — so the
// resolver's state is observable wherever it runs.
type ImrStatus struct {
	Primed    bool      `json:"primed"`
	PrimedVia string    `json:"primed_via,omitempty"` // "hints+fetch" or "hints-only (root forwarded)"
	PrimedAt  time.Time `json:"primed_at,omitzero"`

	// RootNS* describe what the cache holds for ". NS" RIGHT NOW. Primed
	// above says only that priming once happened, which stayed true for
	// nearly three hours while the resolver could not resolve anything it
	// had not already cached.
	RootNSPresent bool      `json:"root_ns_present"`
	RootNSExpires time.Time `json:"root_ns_expires,omitzero"`
	RootNSCount   int       `json:"root_ns_count,omitempty"`

	StubZones    []string               `json:"stub_zones,omitempty"`
	ForwardZones []ImrForwardZoneStatus `json:"forward_zones,omitempty"`
	// ZonesLoadedAt is when the stub/forward table in this report was
	// published — startup, or the last reload that APPLIED a table,
	// whether or not it changed anything. It answers "did my reload reach
	// this daemon", not "when did routing last change"; the diff in the
	// reload reply answers the latter.
	ZonesLoadedAt time.Time `json:"zones_loaded_at,omitzero"`
}

type ImrForwardZoneStatus struct {
	Zone      string              `json:"zone"`
	TrustAD   bool                `json:"trust_ad,omitempty"`
	Upstreams []ImrUpstreamStatus `json:"upstreams"`
	// Quarantined: no usable upstream is left, so names under the zone
	// SERVFAIL. Service-impacting, unlike a quarantined upstream on a zone
	// that still has others.
	Quarantined      bool   `json:"quarantined,omitempty"`
	QuarantineReason string `json:"quarantine_reason,omitempty"`
}

// ImrUpstreamStatus is one forward upstream's reachability state. Unreachable
// means the LAST exchange was a transport-level failure; a response with any
// rcode counts as reachable.
type ImrUpstreamStatus struct {
	Upstream    string `json:"upstream"` // "addr:port/transport"
	Transport   string `json:"transport"`
	Unreachable bool   `json:"unreachable,omitempty"`
	// Quarantined: unusable as configured, so never dialled. Disjoint from
	// Unreachable, which is a verdict about exchanges that did happen.
	Quarantined      bool      `json:"quarantined,omitempty"`
	QuarantineReason string    `json:"quarantine_reason,omitempty"`
	Queries          uint64    `json:"queries"`
	Failures         uint64    `json:"failures"`
	LastSuccess      time.Time `json:"last_success,omitzero"`
	LastError        string    `json:"last_error,omitempty"`
	LastErrTime      time.Time `json:"last_error_time,omitzero"`
}

// StatusReport assembles the ImrStatus block for the config-status API.
// Nil-safe: a daemon without a running IMR reports no block at all.
func (imr *Imr) StatusReport() *ImrStatus {
	if imr == nil {
		return nil
	}
	table := imr.zoneTable()
	st := &ImrStatus{
		PrimedVia:     imr.PrimedVia,
		PrimedAt:      imr.PrimedAt,
		StubZones:     append([]string(nil), table.stubs...),
		ZonesLoadedAt: table.loadedAt,
	}
	if imr.Cache != nil {
		st.Primed = imr.Cache.IsPrimed()
	}
	st.RootNSPresent, st.RootNSExpires, st.RootNSCount = imr.RootNSStatus()
	for _, fz := range table.forwards {
		fzs := ImrForwardZoneStatus{Zone: fz.Zone, TrustAD: fz.TrustAD}
		fzs.Quarantined, fzs.QuarantineReason = fz.quarantineState()
		for _, up := range fz.Upstreams {
			up.mu.Lock()
			fzs.Upstreams = append(fzs.Upstreams, ImrUpstreamStatus{
				Upstream:         up.Label,
				Transport:        core.TransportToString[up.Transport],
				Unreachable:      up.failing,
				Quarantined:      up.quarantined,
				QuarantineReason: up.quarantineWhy,
				Queries:          up.queries,
				Failures:         up.failures,
				LastSuccess:      up.lastSuccess,
				LastError:        up.lastErrMsg,
				LastErrTime:      up.lastErrTime,
			})
			up.mu.Unlock()
		}
		st.ForwardZones = append(st.ForwardZones, fzs)
	}
	return st
}
