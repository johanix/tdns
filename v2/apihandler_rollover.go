/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// APIRolloverStatus handles GET /api/v1/rollover/status?zone=<fqdn>.
// Reads RolloverZoneRow + per-state DnssecKeyStore rows + the zone's
// DnssecPolicy and returns the operator-facing RolloverStatus struct.
// Side-effect free; no per-zone lock taken — sqlite WAL gives
// snapshot reads while writers (the rollover tick, mutating
// handlers) are in flight.
func APIRolloverStatus(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		zone := strings.TrimSpace(r.URL.Query().Get("zone"))
		if zone == "" {
			http.Error(w, "missing zone parameter", http.StatusBadRequest)
			return
		}
		zone = dns.Fqdn(zone)

		kdb := conf.Internal.KeyDB
		if kdb == nil {
			http.Error(w, "keystore not initialized", http.StatusServiceUnavailable)
			return
		}

		// Resolve the zone's DnssecPolicy from the loaded ZoneData.
		// The policy may be nil for zones that don't have one
		// configured; ComputeRolloverStatus tolerates that.
		var pol *DnssecPolicy
		if zd, ok := Zones.Get(zone); ok && zd != nil {
			pol = zd.DnssecPolicy
		}

		out, err := ComputeRolloverStatus(kdb, zone, pol, time.Now())
		if err != nil {
			lgApi.Warn("rollover/status: ComputeRolloverStatus failed", "zone", zone, "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}

// APIRolloverAsap handles POST /api/v1/rollover/asap. Body:
// {"zone": "..."}. Computes earliest then persists the manual-
// rollover request. Held under the per-zone lock so the
// compute+set sequence is atomic against the rollover tick.
func APIRolloverAsap(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req RolloverAsapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}
		zone, kdb, pol, ok := resolveRolloverWriteRequest(conf, w, req.Zone, true)
		if !ok {
			return
		}

		lock := AcquireRolloverLock(zone)
		lock.Lock()
		defer lock.Unlock()

		now := time.Now()
		res, err := ComputeEarliestRollover(kdb, zone, pol, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := SetManualRolloverRequest(kdb, zone, now, res.Earliest); err != nil {
			lgApi.Warn("rollover/asap: SetManualRolloverRequest failed", "zone", zone, "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(RolloverAsapResponse{
			Zone:        zone,
			RequestedAt: now.UTC().Format(time.RFC3339),
			Earliest:    res.Earliest.UTC().Format(time.RFC3339),
			FromIdx:     res.FromIdx,
			ToIdx:       res.ToIdx,
		})
	}
}

// APIRolloverCancel handles POST /api/v1/rollover/cancel. Body:
// {"zone": "..."}. Clears manual_rollover_* on the zone row.
func APIRolloverCancel(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req RolloverCancelRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}
		zone, kdb, _, ok := resolveRolloverWriteRequest(conf, w, req.Zone, false)
		if !ok {
			return
		}

		lock := AcquireRolloverLock(zone)
		lock.Lock()
		defer lock.Unlock()

		if err := ClearManualRolloverRequest(kdb, zone); err != nil {
			lgApi.Warn("rollover/cancel: ClearManualRolloverRequest failed", "zone", zone, "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(RolloverCancelResponse{Zone: zone, Cleared: true})
	}
}

// APIRolloverReset handles POST /api/v1/rollover/reset. Body:
// {"zone": "...", "keyid": N}. Clears last_rollover_error on one
// RolloverKeyState row.
func APIRolloverReset(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req RolloverResetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}
		if req.KeyID == 0 {
			http.Error(w, "keyid must be 1..65535", http.StatusBadRequest)
			return
		}
		zone, kdb, _, ok := resolveRolloverWriteRequest(conf, w, req.Zone, false)
		if !ok {
			return
		}

		lock := AcquireRolloverLock(zone)
		lock.Lock()
		defer lock.Unlock()

		if err := ClearLastRolloverError(kdb, zone, req.KeyID); err != nil {
			lgApi.Warn("rollover/reset: ClearLastRolloverError failed", "zone", zone, "keyid", req.KeyID, "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(RolloverResetResponse{Zone: zone, KeyID: req.KeyID, Cleared: true})
	}
}

// APIRolloverUnstick handles POST /api/v1/rollover/unstick. Body:
// {"zone": "..."}. Clears next_push_at to skip the softfail-delay
// and probe on the next tick.
func APIRolloverUnstick(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req RolloverUnstickRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}
		zone, kdb, _, ok := resolveRolloverWriteRequest(conf, w, req.Zone, false)
		if !ok {
			return
		}

		lock := AcquireRolloverLock(zone)
		lock.Lock()
		defer lock.Unlock()

		if err := UnstickRollover(kdb, zone); err != nil {
			lgApi.Warn("rollover/unstick: UnstickRollover failed", "zone", zone, "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(RolloverUnstickResponse{Zone: zone, Cleared: true})
	}
}

// resolveRolloverWriteRequest validates the zone and looks up the
// kdb / DnssecPolicy from the loaded ZoneData. requirePolicy=true
// for handlers like asap that compute against the policy; cancel,
// reset, and unstick do not need a policy. Returns false (and
// writes the HTTP error) if validation fails.
func resolveRolloverWriteRequest(conf *Config, w http.ResponseWriter, rawZone string, requirePolicy bool) (string, *KeyDB, *DnssecPolicy, bool) {
	zone := strings.TrimSpace(rawZone)
	if zone == "" {
		http.Error(w, "missing zone", http.StatusBadRequest)
		return "", nil, nil, false
	}
	zone = dns.Fqdn(zone)
	kdb := conf.Internal.KeyDB
	if kdb == nil {
		http.Error(w, "keystore not initialized", http.StatusServiceUnavailable)
		return "", nil, nil, false
	}
	var pol *DnssecPolicy
	if zd, ok := Zones.Get(zone); ok && zd != nil {
		pol = zd.DnssecPolicy
	}
	if requirePolicy && pol == nil {
		http.Error(w, fmt.Sprintf("zone %s has no DNSSEC policy", zone), http.StatusBadRequest)
		return "", nil, nil, false
	}
	return zone, kdb, pol, true
}

// APIRolloverWhen handles GET /api/v1/rollover/when?zone=<fqdn>.
// Wraps ComputeEarliestRollover into wire-friendly types. Returns
// 400 when the zone has no DnssecPolicy attached (since "when can
// the next rollover safely fire" is undefined without one).
func APIRolloverWhen(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		zone := strings.TrimSpace(r.URL.Query().Get("zone"))
		if zone == "" {
			http.Error(w, "missing zone parameter", http.StatusBadRequest)
			return
		}
		zone = dns.Fqdn(zone)

		kdb := conf.Internal.KeyDB
		if kdb == nil {
			http.Error(w, "keystore not initialized", http.StatusServiceUnavailable)
			return
		}

		var pol *DnssecPolicy
		if zd, ok := Zones.Get(zone); ok && zd != nil {
			pol = zd.DnssecPolicy
		}
		if pol == nil {
			http.Error(w, "zone has no DNSSEC policy", http.StatusBadRequest)
			return
		}

		out, err := ComputeRolloverWhen(kdb, zone, pol, time.Now())
		if err != nil {
			// Errors here are usually operationally-expected (e.g.
			// "rollover already in progress" — no successor key yet).
			// Return 200 with the message so the CLI can render it.
			lgApi.Debug("rollover/when: ComputeRolloverWhen returned error", "zone", zone, "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}
