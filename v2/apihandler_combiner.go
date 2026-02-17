/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
			log.Println("APIcombiner: error decoding combiner command post:", err)
		}

		log.Printf("API: received /combiner request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := CombinerResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
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
			err := zd.AddCombinerDataNG("", cp.Data)
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

func APIcombinerDebug(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var cp CombinerDebugPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APIcombinerDebug: error decoding debug post:", err)
		}

		log.Printf("API: received /combiner/debug request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := CombinerDebugResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("APIcombinerDebug: error encoding response: %v", err)
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
			ct := conf.Internal.CombinerTransport
			if ct == nil {
				resp.Error = true
				resp.ErrorMsg = "CombinerTransport not initialized"
				return
			}
			agentID := cp.AgentID
			if agentID == "" {
				resp.Error = true
				resp.ErrorMsg = "agent_id is required for agent-ping"
				return
			}
			agentID = dns.Fqdn(agentID)

			nonce := fmt.Sprintf("combiner-ping-%d", time.Now().UnixNano())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			pingResp, err := ct.Ping(ctx, agentID, &transport.PingRequest{
				SenderID:  ct.LocalID,
				Nonce:     nonce,
				Timestamp: time.Now(),
			})
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("ping to agent %s failed: %v", agentID, err)
				return
			}

			resp.Msg = fmt.Sprintf("ping ok (dns transport): %s echoed nonce %s",
				pingResp.ResponderID, pingResp.Nonce)

		case "agent-resync":
			ct := conf.Internal.CombinerTransport
			if ct == nil {
				resp.Error = true
				resp.ErrorMsg = "CombinerTransport not initialized"
				return
			}

			// Determine which agents to resync
			var agents []*PeerConf
			if cp.AgentID != "" {
				agentID := dns.Fqdn(cp.AgentID)
				if a := conf.Combiner.FindAgent(agentID); a != nil {
					agents = append(agents, a)
				} else {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("agent %q not found in config", agentID)
					return
				}
			} else {
				agents = conf.Combiner.Agents
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
			for _, agent := range agents {
				for _, zone := range zones {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					_, err := ct.Sync(ctx, agent.Identity, &transport.SyncRequest{
						SenderID:    ct.LocalID,
						Zone:        zone,
						Records:     map[string][]string{},
						Timestamp:   time.Now(),
						MessageType: "rfi",
						RfiType:     "SYNC",
					})
					cancel()
					if err != nil {
						results = append(results, fmt.Sprintf("  %s / %s: error: %v", agent.Identity, zone, err))
						errCount++
					} else {
						results = append(results, fmt.Sprintf("  %s / %s: RFI SYNC sent", agent.Identity, zone))
					}
				}
			}

			summary := fmt.Sprintf("Resync: sent RFI SYNC to %d agent(s) for %d zone(s) (%d errors)\n",
				len(agents), len(zones), errCount)
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
