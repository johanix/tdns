/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"encoding/json"
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
