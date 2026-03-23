/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	"github.com/miekg/dns"
)

func APIcombiner(app *AppDetails, refreshZoneCh chan<- ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var cp CombinerPost
		err := decoder.Decode(&cp)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "combiner", "err", err)
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /combiner request", "cmd", cp.Command, "from", r.RemoteAddr)

		resp := CombinerResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "combiner", "err", err)
			}
		}()

		cp.Zone = dns.Fqdn(cp.Zone)
		zd, exist := Zones.Get(cp.Zone)
		if !exist {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", cp.Zone)
			return
		}

		switch cp.Command {
		case "add":
			_, err := zd.AddCombinerDataNG("", cp.Data)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
			resp.Msg = fmt.Sprintf("Added local RRsets for zone %s", cp.Zone)

		case "list":
			if zd.CombinerData == nil {
				resp.Msg = fmt.Sprintf("No local data for zone %s", cp.Zone)
				return
			}

			resp.Data = zd.GetCombinerDataNG()
			resp.Msg = fmt.Sprintf("Local data for zone %s", cp.Zone)

		case "remove":
			// TODO: Implement remove functionality
			resp.Error = true
			resp.ErrorMsg = "Remove operation not yet implemented"
			return

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown combiner command: %s", cp.Command)
			resp.Error = true
		}
	}
}

// APIcombinerEdits handles /combiner/edits requests for managing pending, approved and rejected edits.
func APIcombinerEdits(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var cp CombinerEditPost
		err := decoder.Decode(&cp)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "combinerEdits", "err", err)
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /combiner/edits request", "cmd", cp.Command, "from", r.RemoteAddr)

		resp := CombinerEditResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "combinerEdits", "err", err)
			}
		}()

		kdb := conf.Internal.KeyDB
		if kdb == nil {
			resp.Error = true
			resp.ErrorMsg = "KeyDB not initialized"
			return
		}

		// Commands that require a valid, loaded zone.
		zoneCommands := map[string]bool{
			"list": true, "list-approved": true, "list-rejected": true,
			"list-current": true, "reapply": true,
		}
		if zoneCommands[cp.Command] {
			zone := dns.Fqdn(cp.Zone)
			if zone == "" || zone == "." {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}
			if _, exists := Zones.Get(zone); !exists {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("zone %s is not known to this combiner", zone)
				return
			}
		}

		switch cp.Command {
		case "list":
			zone := dns.Fqdn(cp.Zone)
			pending, err := kdb.ListPendingEdits(zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("failed to list pending edits: %v", err)
				return
			}
			resp.Pending = pending
			resp.Msg = fmt.Sprintf("%d pending edit(s) for zone %s", len(pending), zone)

		case "approve":
			if cp.EditID <= 0 {
				resp.Error = true
				resp.ErrorMsg = "edit_id is required"
				return
			}

			rec, err := kdb.ApprovePendingEdit(cp.EditID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("failed to approve edit #%d: %v", cp.EditID, err)
				return
			}

			// Apply the edit via CombinerProcessUpdate
			syncReq := &CombinerSyncRequest{
				SenderID:       rec.SenderID,
				DeliveredBy:    rec.DeliveredBy,
				Zone:           rec.Zone,
				Records:        rec.Records,
				DistributionID: rec.DistributionID,
				Timestamp:      rec.ReceivedAt,
			}

			// Only apply protected-namespace checks to remote agents.
			var protectedNamespaces []string
			if conf.MultiProvider != nil {
				isLocal := false
				for _, a := range conf.MultiProvider.Agents {
					if a != nil && a.Identity == rec.SenderID {
						isLocal = true
						break
					}
				}
				if !isLocal {
					protectedNamespaces = conf.MultiProvider.ProtectedNamespaces
				}
			}

			tm := conf.Internal.TransportManager
			apiLocalAgents := make(map[string]bool)
			if conf.MultiProvider != nil {
				for _, a := range conf.MultiProvider.Agents {
					if a != nil && a.Identity != "" {
						apiLocalAgents[a.Identity] = true
					}
				}
			}
			syncResp := CombinerProcessUpdate(syncReq, protectedNamespaces, apiLocalAgents, kdb, tm)

			lgApi.Info("approved edit", "editID", cp.EditID, "zone", rec.Zone, "status", syncResp.Status, "applied", len(syncResp.AppliedRecords), "removed", len(syncResp.RemovedRecords), "rejected", len(syncResp.RejectedItems))

			// Send confirmation back to the agent that delivered the edit.
			// For forwarded messages, DeliveredBy is our local agent (not the originator).
			confirmTarget := rec.DeliveredBy
			if confirmTarget == "" {
				confirmTarget = rec.SenderID // Fallback for direct delivery
			}
			if tm != nil {
				combinerSendConfirmation(tm, confirmTarget, syncResp)
			}

			// Notify downstream servers about the zone change.
			if syncResp.Status != "error" {
				if zd, ok := Zones.Get(dns.Fqdn(rec.Zone)); ok && len(zd.Downstreams) > 0 {
					go zd.NotifyDownstreams()
				}
			}

			resp.Msg = fmt.Sprintf("Edit #%d approved and applied for zone %s (status=%s, applied=%d, rejected=%d)",
				cp.EditID, rec.Zone, syncResp.Status, len(syncResp.AppliedRecords), len(syncResp.RejectedItems))

		case "reject":
			if cp.EditID <= 0 {
				resp.Error = true
				resp.ErrorMsg = "edit_id is required"
				return
			}
			if cp.Reason == "" {
				resp.Error = true
				resp.ErrorMsg = "reason is required for rejection"
				return
			}

			rec, err := kdb.RejectPendingEdit(cp.EditID, cp.Reason)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("failed to reject edit #%d: %v", cp.EditID, err)
				return
			}

			// Build rejection response — all records become RejectedItems
			var rejectedItems []RejectedItem
			for _, rrStrings := range rec.Records {
				for _, rr := range rrStrings {
					rejectedItems = append(rejectedItems, RejectedItem{
						Record: rr,
						Reason: cp.Reason,
					})
				}
			}

			syncResp := &CombinerSyncResponse{
				DistributionID: rec.DistributionID,
				Zone:           rec.Zone,
				Status:         "error",
				Message:        fmt.Sprintf("rejected by operator: %s", cp.Reason),
				RejectedItems:  rejectedItems,
				Timestamp:      time.Now(),
			}

			// Send rejection confirmation back to the agent that delivered the edit.
			confirmTarget := rec.DeliveredBy
			if confirmTarget == "" {
				confirmTarget = rec.SenderID
			}
			tm := conf.Internal.TransportManager
			if tm != nil {
				combinerSendConfirmation(tm, confirmTarget, syncResp)
			}

			resp.Msg = fmt.Sprintf("Edit #%d rejected for zone %s (reason: %s)", cp.EditID, rec.Zone, cp.Reason)

		case "list-approved":
			zone := dns.Fqdn(cp.Zone)
			approved, err := kdb.ListApprovedEdits(zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("failed to list approved edits: %v", err)
				return
			}
			resp.Approved = approved
			resp.Msg = fmt.Sprintf("%d approved edit(s) for zone %s", len(approved), zone)

		case "list-rejected":
			zone := dns.Fqdn(cp.Zone)
			rejected, err := kdb.ListRejectedEdits(zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("failed to list rejected edits: %v", err)
				return
			}
			resp.Rejected = rejected
			resp.Msg = fmt.Sprintf("%d rejected edit(s) for zone %s", len(rejected), zone)

		case "list-current":
			zone := dns.Fqdn(cp.Zone)
			zd, ok := Zones.Get(zone)
			if !ok || zd == nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("zone %s not found", zone)
				return
			}
			// Build agent -> rrtype -> []rr from AgentContributions
			current := make(map[string]map[string][]string)
			zd.mu.Lock()
			if zd.AgentContributions != nil {
				for agentID, ownerMap := range zd.AgentContributions {
					for _, rrtypeMap := range ownerMap {
						for rrtype, rrset := range rrtypeMap {
							if current[agentID] == nil {
								current[agentID] = make(map[string][]string)
							}
							rtStr := dns.TypeToString[rrtype]
							for _, rr := range rrset.RRs {
								current[agentID][rtStr] = append(current[agentID][rtStr], rr.String())
							}
						}
					}
				}
			}
			zd.mu.Unlock()
			resp.Current = current
			totalRRs := 0
			for _, rrtypeMap := range current {
				for _, rrs := range rrtypeMap {
					totalRRs += len(rrs)
				}
			}
			resp.Msg = fmt.Sprintf("%d current contribution(s) from %d agent(s) for zone %s",
				totalRRs, len(current), zone)

		case "reapply":
			zone := dns.Fqdn(cp.Zone)
			msg, err := combinerReapplyContributions(zone, kdb)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
			resp.Msg = msg

		case "clear":
			// Determine which tables to clear. Empty Tables list means all.
			tables := make(map[string]bool)
			for _, t := range cp.Tables {
				tables[t] = true
			}
			clearAll := len(tables) == 0

			zone := cp.Zone
			var parts []string
			var errs []error

			if clearAll || tables["pending"] {
				n, err := kdb.ClearPendingEdits(zone)
				if err != nil {
					errs = append(errs, fmt.Errorf("pending: %w", err))
				} else {
					parts = append(parts, fmt.Sprintf("%d pending", n))
				}
			}
			if clearAll || tables["approved"] {
				n, err := kdb.ClearApprovedEdits(zone)
				if err != nil {
					errs = append(errs, fmt.Errorf("approved: %w", err))
				} else {
					parts = append(parts, fmt.Sprintf("%d approved", n))
				}
			}
			if clearAll || tables["rejected"] {
				n, err := kdb.ClearRejectedEdits(zone)
				if err != nil {
					errs = append(errs, fmt.Errorf("rejected: %w", err))
				} else {
					parts = append(parts, fmt.Sprintf("%d rejected", n))
				}
			}
			if clearAll || tables["current"] {
				n, err := kdb.ClearContributions(zone)
				if err != nil {
					errs = append(errs, fmt.Errorf("contributions: %w", err))
				} else {
					parts = append(parts, fmt.Sprintf("%d contributions", n))
				}
				// Also clear in-memory AgentContributions and rebuild CombinerData
				if zone != "" {
					if zd, ok := Zones.Get(zone); ok {
						zd.mu.Lock()
						zd.AgentContributions = nil
						zd.rebuildCombinerData()
						zd.mu.Unlock()
					}
				} else {
					for _, zd := range Zones.Items() {
						zd.mu.Lock()
						zd.AgentContributions = nil
						zd.rebuildCombinerData()
						zd.mu.Unlock()
					}
				}
			}

			if len(errs) > 0 {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("clear errors: %v", errs)
				return
			}
			scope := "all zones"
			if zone != "" {
				scope = zone
			}
			resp.Msg = fmt.Sprintf("Cleared %s (%s)", strings.Join(parts, ", "), scope)

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown combiner edits command: %s", cp.Command)
			resp.Error = true
		}
	}
}

func APIcombinerDebug(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var cp CombinerDebugPost
		err := decoder.Decode(&cp)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "combinerDebug", "err", err)
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /combiner/debug request", "cmd", cp.Command, "from", r.RemoteAddr)

		resp := CombinerDebugResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "combinerDebug", "err", err)
			}
		}()

		switch cp.Command {
		case "show-combiner-data":
			combinerData := make(map[string]map[string]map[string][]string)
			agentContribs := make(map[string]map[string]map[string]map[string][]string)

			collectZone := func(zd *ZoneData) {
				// Merged CombinerData
				if zd.CombinerData != nil {
					zoneData := make(map[string]map[string][]string)
					for item := range zd.CombinerData.IterBuffered() {
						ownerName := item.Key
						ownerData := item.Val
						rrTypeData := make(map[string][]string)
						for _, rrtype := range ownerData.RRtypes.Keys() {
							rrset, _ := ownerData.RRtypes.Get(rrtype)
							var rrs []string
							for _, rr := range rrset.RRs {
								rrs = append(rrs, rr.String())
							}
							rrTypeData[dns.TypeToString[rrtype]] = rrs
						}
						zoneData[ownerName] = rrTypeData
					}
					if len(zoneData) > 0 {
						combinerData[zd.ZoneName] = zoneData
					}
				}

				// Per-agent AgentContributions
				if zd.AgentContributions != nil {
					for agentID, ownerMap := range zd.AgentContributions {
						for owner, rrtypeMap := range ownerMap {
							for rrtype, rrset := range rrtypeMap {
								var rrs []string
								for _, rr := range rrset.RRs {
									rrs = append(rrs, rr.String())
								}
								// Lazily initialize nested maps
								if agentContribs[zd.ZoneName] == nil {
									agentContribs[zd.ZoneName] = make(map[string]map[string]map[string][]string)
								}
								if agentContribs[zd.ZoneName][agentID] == nil {
									agentContribs[zd.ZoneName][agentID] = make(map[string]map[string][]string)
								}
								if agentContribs[zd.ZoneName][agentID][owner] == nil {
									agentContribs[zd.ZoneName][agentID][owner] = make(map[string][]string)
								}
								agentContribs[zd.ZoneName][agentID][owner][dns.TypeToString[rrtype]] = rrs
							}
						}
					}
				}
			}

			if cp.Zone != "" {
				zone := dns.Fqdn(cp.Zone)
				zd, exists := Zones.Get(zone)
				if !exists {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("zone %q not found", zone)
					return
				}
				collectZone(zd)
			} else {
				for _, zd := range Zones.Items() {
					collectZone(zd)
				}
			}

			resp.CombinerData = combinerData
			resp.AgentContributions = agentContribs
			resp.Msg = fmt.Sprintf("Combiner data retrieved for %d zone(s)", len(combinerData))

		case "agent-ping":
			tm := conf.Internal.TransportManager
			if tm == nil {
				resp.Error = true
				resp.ErrorMsg = "TransportManager not initialized"
				return
			}
			agentID := cp.AgentID
			if agentID == "" {
				resp.Error = true
				resp.ErrorMsg = "agent_id is required for agent-ping"
				return
			}
			agentID = dns.Fqdn(agentID)

			peer, ok := tm.PeerRegistry.Get(agentID)
			if !ok {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent %q not found in peer registry", agentID)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			pingResp, err := tm.SendPing(ctx, peer)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("ping to agent %s failed: %v", agentID, err)
				return
			}

			resp.Msg = fmt.Sprintf("ping ok: %s echoed nonce %s",
				pingResp.ResponderID, pingResp.Nonce)

		case "agent-resync":
			tm := conf.Internal.TransportManager
			if tm == nil {
				resp.Error = true
				resp.ErrorMsg = "TransportManager not initialized"
				return
			}

			// Determine which agents to resync
			var agentPeers []*transport.Peer
			if cp.AgentID != "" {
				agentID := dns.Fqdn(cp.AgentID)
				peer, ok := tm.PeerRegistry.Get(agentID)
				if !ok {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("agent %q not found in peer registry", agentID)
					return
				}
				agentPeers = append(agentPeers, peer)
			} else {
				agentPeers = tm.PeerRegistry.All()
			}

			// Determine which zones to resync
			var zones []string
			if cp.Zone != "" {
				zone := dns.Fqdn(cp.Zone)
				if _, exists := Zones.Get(zone); !exists {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("zone %q not found", zone)
					return
				}
				zones = append(zones, zone)
			} else {
				for _, zd := range Zones.Items() {
					zones = append(zones, zd.ZoneName)
				}
			}

			// Send RFI SYNC to each agent for each zone
			var results []string
			var errCount int
			for _, peer := range agentPeers {
				for _, zone := range zones {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					_, err := tm.SendSyncWithFallback(ctx, peer, &transport.SyncRequest{
						SenderID:    tm.LocalID,
						Zone:        zone,
						Records:     map[string][]string{},
						Timestamp:   time.Now(),
						MessageType: "rfi",
						RfiType:     "SYNC",
					})
					cancel()
					if err != nil {
						results = append(results, fmt.Sprintf("  %s / %s: error: %v", peer.ID, zone, err))
						errCount++
					} else {
						results = append(results, fmt.Sprintf("  %s / %s: RFI SYNC sent", peer.ID, zone))
					}
				}
			}

			summary := fmt.Sprintf("Resync: sent RFI SYNC to %d agent(s) for %d zone(s) (%d errors)\n",
				len(agentPeers), len(zones), errCount)
			for _, r := range results {
				summary += r + "\n"
			}
			resp.Msg = summary

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown combiner debug command: %s", cp.Command)
			resp.Error = true
		}
	}
}
