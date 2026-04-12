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

	"github.com/miekg/dns"
)

// APIagent handles the /agent management API endpoint.
// After MP migration, only IMR commands remain here. All MP
// commands (config, add-rr, resync, discover, etc.) are now
// handled by tdns-mp's APIagent.
func (conf *Config) APIagent(refreshZoneCh chan<- ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var amp AgentMgmtPost
		err := decoder.Decode(&amp)
		if err != nil {
			lgApi.Warn("error decoding agent command post", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /agent request", "cmd", amp.Command, "from", r.RemoteAddr)

		resp := AgentMgmtResponse{
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
			identity := string(amp.AgentId)
			if identity == "" {
				resp.Error = true
				resp.ErrorMsg = "agent_id (--id) is required"
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

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown agent command: %s", amp.Command)
			resp.Error = true
		}
	}
}
