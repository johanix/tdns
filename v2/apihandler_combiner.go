/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

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

func APIcombinerDebug() func(w http.ResponseWriter, r *http.Request) {
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

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown combiner debug command: %s", cp.Command)
			resp.Error = true
		}
	}
}
