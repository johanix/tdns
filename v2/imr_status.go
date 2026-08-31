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

	StubZones    []string               `json:"stub_zones,omitempty"`
	ForwardZones []ImrForwardZoneStatus `json:"forward_zones,omitempty"`
}

type ImrForwardZoneStatus struct {
	Zone      string              `json:"zone"`
	TrustAD   bool                `json:"trust_ad,omitempty"`
	Upstreams []ImrUpstreamStatus `json:"upstreams"`
}

// ImrUpstreamStatus is one forward upstream's reachability state. Unreachable
// means the LAST exchange was a transport-level failure; a response with any
// rcode counts as reachable.
type ImrUpstreamStatus struct {
	Upstream    string    `json:"upstream"` // "addr:port/transport"
	Transport   string    `json:"transport"`
	Unreachable bool      `json:"unreachable,omitempty"`
	Queries     uint64    `json:"queries"`
	Failures    uint64    `json:"failures"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrTime time.Time `json:"last_error_time,omitzero"`
}

// StatusReport assembles the ImrStatus block for the config-status API.
// Nil-safe: a daemon without a running IMR reports no block at all.
func (imr *Imr) StatusReport() *ImrStatus {
	if imr == nil {
		return nil
	}
	st := &ImrStatus{
		PrimedVia: imr.PrimedVia,
		PrimedAt:  imr.PrimedAt,
		StubZones: append([]string(nil), imr.stubZones...),
	}
	if imr.Cache != nil {
		st.Primed = imr.Cache.IsPrimed()
	}
	for _, fz := range imr.Forwards {
		fzs := ImrForwardZoneStatus{Zone: fz.Zone, TrustAD: fz.TrustAD}
		for _, up := range fz.Upstreams {
			up.mu.Lock()
			fzs.Upstreams = append(fzs.Upstreams, ImrUpstreamStatus{
				Upstream:    up.Label,
				Transport:   core.TransportToString[up.Transport],
				Unreachable: up.failing,
				Queries:     up.queries,
				Failures:    up.failures,
				LastSuccess: up.lastSuccess,
				LastError:   up.lastErrMsg,
				LastErrTime: up.lastErrTime,
			})
			up.mu.Unlock()
		}
		st.ForwardZones = append(st.ForwardZones, fzs)
	}
	return st
}
