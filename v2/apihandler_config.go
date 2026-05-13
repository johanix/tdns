/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

// APIConfigPaths handles GET /api/v1/config/paths[?zone=<fqdn>].
// Returns the daemon's main config-file path and keystore (sqlite)
// path so a CLI like `auto-rollover validate` can re-parse the same
// YAML the daemon is running. When ?zone= is supplied, the zone's
// active dnssecpolicy name is returned alongside, telling the
// validator which dnssecpolicies block to check.
//
// Read-only; no zone lock taken. Safe to call from any client.
func APIConfigPaths(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := ConfigPathsResponse{
			ConfigFile: conf.Internal.CfgFile,
		}
		if conf.Internal.KeyDB != nil {
			out.DBFile = conf.Internal.KeyDB.DBFile
		}
		if zone := strings.TrimSpace(r.URL.Query().Get("zone")); zone != "" {
			zone = dns.Fqdn(zone)
			if zd, ok := Zones.Get(zone); ok && zd != nil {
				out.PolicyName = zd.DnssecPolicyName
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}
