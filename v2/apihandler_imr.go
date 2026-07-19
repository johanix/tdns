/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// APIimr handles the /imr management API endpoint -- in-process IMR
// inspection and control for tdns-agent, tdns-auth, and tdns-imr.
// (This file used to be apihandler_agent.go and the endpoint used
// to be /agent. After the MP migration only IMR commands remained
// here, so the route and handler were renamed. tdns-mp keeps its
// own /agent endpoint for MP-specific commands and now also exposes
// /imr backed by an analogous APIimr handler.)
// ImrServerTransportStats is the per-server transport-usage snapshot carried
// over the /imr API for `tdns-cli imr stats transport-stats`. Count maps are
// keyed by transport name (do53, do53-tcp, dot, doh, doq).
type ImrServerTransportStats struct {
	Zone      string            `json:"zone"`
	Server    string            `json:"server"`
	Weights   map[string]uint8  `json:"weights,omitempty"` // advertised OOTS weights (name-keyed), for signal rendering
	Attempted map[string]uint64 `json:"attempted,omitempty"`
	Used      map[string]uint64 `json:"used,omitempty"`
	Failed    map[string]uint64 `json:"failed,omitempty"`
	Truncated uint64            `json:"truncated"`
}

// transportName returns the string name for t, with a stable fallback so an
// unregistered transport (a future enum value missing from TransportToString)
// never produces an empty-string map key in the API JSON.
func transportName(t core.Transport) string {
	if name, ok := core.TransportToString[t]; ok {
		return name
	}
	return fmt.Sprintf("unknown-%d", t)
}

// transportCountsToStrings converts a transport-keyed counter map to a
// name-keyed one for JSON transport over the API.
func transportCountsToStrings(m map[core.Transport]uint64) map[string]uint64 {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]uint64, len(m))
	for t, c := range m {
		out[transportName(t)] = c
	}
	return out
}

// transportWeightsToStrings converts a transport-keyed weight map to a
// name-keyed one for JSON transport over the API.
func transportWeightsToStrings(m map[core.Transport]uint8) map[string]uint8 {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]uint8, len(m))
	for t, w := range m {
		out[transportName(t)] = w
	}
	return out
}

// ZoneMatchesSelector reports whether zone (an fqdn) is selected by an optional
// exact-zone / suffix filter pair — DNS-label-aware and case-insensitive. When
// both are set, exactZone takes precedence; when both are empty, everything
// matches. A suffix matches the zone itself and any subdomain of it, never a
// partial label (e.g. suffix "sync.se." does NOT match "dsync.se."). Shared by
// the /imr API handler and the cli transport-stats filter so the two cannot
// diverge.
func ZoneMatchesSelector(zone, exactZone, suffix string) bool {
	switch {
	case exactZone != "":
		return strings.EqualFold(zone, exactZone)
	case suffix != "":
		return dns.IsSubDomain(suffix, zone)
	default:
		return true
	}
}

func (conf *Config) APIimr() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var amp ImrMgmtPost
		err := decoder.Decode(&amp)
		if err != nil {
			lgApi.Warn("error decoding imr command post", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /imr request", "cmd", amp.Command, "from", r.RemoteAddr)

		resp := ImrMgmtResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("json encoder failed", "err", err)
			}
		}()

		switch amp.Command {
		case "imr-query":
			imr := Globals.ImrEngine
			if imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			qname, _ := amp.Data["qname"].(string)
			qtypeStr, _ := amp.Data["qtype"].(string)
			if qname == "" || qtypeStr == "" {
				resp.Error = true
				resp.ErrorMsg = "qname and qtype are required"
				return
			}
			qname = dns.Fqdn(qname)
			qtype, ok := dns.StringToType[strings.ToUpper(qtypeStr)]
			if !ok {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("unknown RR type: %s", qtypeStr)
				return
			}
			crrset := imr.Cache.Get(qname, qtype)
			if crrset == nil {
				resp.Msg = fmt.Sprintf("No cache entry for %s %s", qname, qtypeStr)
				return
			}
			entry := map[string]interface{}{
				"name":       crrset.Name,
				"rrtype":     dns.TypeToString[crrset.RRtype],
				"rcode":      dns.RcodeToString[int(crrset.Rcode)],
				"ttl":        crrset.Ttl,
				"expiration": crrset.Expiration.Format(time.RFC3339),
				"expires_in": time.Until(crrset.Expiration).Truncate(time.Second).String(),
				"context":    fmt.Sprintf("%d", crrset.Context),
				"state":      fmt.Sprintf("%d", crrset.State),
			}
			if crrset.RRset != nil {
				var rrs []string
				for _, rr := range crrset.RRset.RRs {
					rrs = append(rrs, rr.String())
				}
				entry["records"] = rrs
			}
			resp.Data = entry
			resp.Msg = fmt.Sprintf("Cache entry for %s %s", qname, dns.TypeToString[qtype])

		case "imr-flush":
			imr := Globals.ImrEngine
			if imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			qname, _ := amp.Data["qname"].(string)
			if qname == "" {
				resp.Error = true
				resp.ErrorMsg = "qname is required"
				return
			}
			qname = dns.Fqdn(qname)
			removed, err := imr.Cache.FlushDomain(qname, false)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("flush failed: %v", err)
				return
			}
			resp.Msg = fmt.Sprintf("Flushed %d cache entries at and below %s", removed, qname)

		case "imr-reset":
			imr := Globals.ImrEngine
			if imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			removed := imr.Cache.FlushAll()
			resp.Msg = fmt.Sprintf("IMR cache reset: flushed %d entries (root NS and glue preserved)", removed)

		case "imr-show":
			imr := Globals.ImrEngine
			if imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			identity := amp.Id
			if identity == "" {
				resp.Error = true
				resp.ErrorMsg = "id (--id) is required"
				return
			}
			identity = dns.Fqdn(identity)

			var entries []map[string]interface{}
			idCanon := strings.ToLower(identity)
			for item := range imr.Cache.RRsets.IterBuffered() {
				cr := item.Val
				name := strings.ToLower(cr.Name)
				if name != idCanon && !strings.HasSuffix(name, "."+idCanon) {
					continue
				}
				entry := map[string]interface{}{
					"name":       cr.Name,
					"rrtype":     dns.TypeToString[cr.RRtype],
					"rcode":      dns.RcodeToString[int(cr.Rcode)],
					"ttl":        cr.Ttl,
					"expiration": cr.Expiration.Format(time.RFC3339),
					"expires_in": time.Until(cr.Expiration).Truncate(time.Second).String(),
				}
				if cr.RRset != nil {
					var rrs []string
					for _, rr := range cr.RRset.RRs {
						rrs = append(rrs, rr.String())
					}
					entry["records"] = rrs
				}
				entries = append(entries, entry)
			}
			resp.Data = entries
			resp.Msg = fmt.Sprintf("Found %d cache entries for identity %s", len(entries), identity)

		case "imr-dump-tuning":
			t := conf.Imr.Tuning
			p := cache.GetBackoffPolicy()
			upgradeStr := "true (legacy default)"
			if t.UpgradeIndirectCacheHits != nil {
				if *t.UpgradeIndirectCacheHits {
					upgradeStr = "true (explicit)"
				} else {
					upgradeStr = "false (explicit)"
				}
			}
			data := map[string]interface{}{
				"backoff": map[string]interface{}{
					"first_failure":   p.FirstFailure.String(),
					"max_failure":     p.MaxFailure.String(),
					"multiplier":      p.Multiplier,
					"jitter_fraction": p.JitterFraction,
					"routing_failure": p.RoutingFailure.String(),
					"lame_delegation": p.LameDelegation.String(),
				},
				"address_family": map[string]interface{}{
					"window_duration":   t.AddressFamily.WindowDuration.String(),
					"failure_threshold": t.AddressFamily.FailureThreshold,
					"suspect_duration":  t.AddressFamily.SuspectDuration.String(),
					"probe_interval":    t.AddressFamily.ProbeInterval.String(),
				},
				"discovery": map[string]interface{}{
					"retry_after_failure": t.Discovery.RetryAfterFailure.String(),
					"max_failures":        t.Discovery.MaxFailures,
				},
				"query_budget":                t.QueryBudget.String(),
				"upgrade_indirect_cache_hits": upgradeStr,
			}
			resp.Data = data
			resp.Msg = "IMR tuning snapshot"

		case "imr-dump-zone-backoffs":
			imr := Globals.ImrEngine
			if imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			zoneFilter, _ := amp.Data["zone"].(string)
			if zoneFilter != "" {
				zoneFilter = dns.Fqdn(zoneFilter)
			}
			now := time.Now()
			type zoneRecord struct {
				Zone      string `json:"zone"`
				Address   string `json:"address"`
				Transport string `json:"transport"`
				NextTry   string `json:"next_try"`
				Remain    string `json:"remaining"`
				Count     uint8  `json:"failure_count"`
				Err       string `json:"last_error,omitempty"`
			}
			var records []zoneRecord
			for item := range imr.Cache.ZoneMap.IterBuffered() {
				if zoneFilter != "" && item.Key != zoneFilter {
					continue
				}
				snap := item.Val.SnapshotAddressBackoffs(now)
				for key, b := range snap {
					rem := b.NextTry.Sub(now)
					if rem < 0 {
						rem = 0
					}
					records = append(records, zoneRecord{
						Zone: item.Key, Address: key.Addr,
						Transport: core.TransportToString[key.Transport],
						NextTry:   b.NextTry.Format(time.RFC3339),
						Remain:    rem.Truncate(time.Second).String(),
						Count:     b.FailureCount, Err: b.LastError,
					})
				}
			}
			resp.Data = records
			if len(records) == 0 {
				if zoneFilter != "" {
					resp.Msg = fmt.Sprintf("No zone-scoped backoffs for %s", zoneFilter)
				} else {
					resp.Msg = "No zone-scoped backoffs recorded"
				}
			} else {
				resp.Msg = fmt.Sprintf("%d zone-scoped backoffs", len(records))
			}

		case "imr-transport-stats":
			imr := Globals.ImrEngine
			if imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			zoneFilter, _ := amp.Data["zone"].(string)
			if zoneFilter != "" {
				zoneFilter = dns.Fqdn(zoneFilter)
			}
			suffixFilter, _ := amp.Data["suffix"].(string)
			if suffixFilter != "" {
				suffixFilter = dns.Fqdn(suffixFilter)
			}
			var records []ImrServerTransportStats
			for item := range imr.Cache.ServerMap.IterBuffered() {
				if !ZoneMatchesSelector(item.Key, zoneFilter, suffixFilter) {
					continue
				}
				for name, server := range item.Val {
					ts := server.SnapshotTransportStats()
					records = append(records, ImrServerTransportStats{
						Zone:      item.Key,
						Server:    name,
						Weights:   transportWeightsToStrings(server.GetTransportWeights()),
						Attempted: transportCountsToStrings(ts.Attempted),
						Used:      transportCountsToStrings(ts.Used),
						Failed:    transportCountsToStrings(ts.Failed),
						Truncated: ts.Truncated,
					})
				}
			}
			resp.Data = records
			if len(records) == 0 {
				switch {
				case zoneFilter != "":
					resp.Msg = fmt.Sprintf("No auth servers recorded for %s", zoneFilter)
				case suffixFilter != "":
					resp.Msg = fmt.Sprintf("No auth servers recorded with suffix %s", suffixFilter)
				default:
					resp.Msg = "No auth servers recorded"
				}
			} else {
				resp.Msg = fmt.Sprintf("Transport stats for %d server(s)", len(records))
			}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown IMR command: %s", amp.Command)
			resp.Error = true
		}
	}
}
