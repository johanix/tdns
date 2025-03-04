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

func (conf *Config) APIagent(refreshZoneCh chan<- ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var cp AgentPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APIagent: error decoding agent command post:", err)
		}

		log.Printf("API: received /agent request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := AgentResponse{
			Time:     time.Now(),
			Identity: conf.Agent.Identity,
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
		case "hsync-status":
			// Get the apex owner object
			owner, err := zd.GetOwner(zd.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s error: %v", cp.Zone, err)
				return
			}

			// Get the HSYNC RRset from the apex
			hsyncRRset := owner.RRtypes.GetOnlyRRSet(TypeHSYNC)
			if len(hsyncRRset.RRs) == 0 {
				resp.Msg = fmt.Sprintf("Zone %s has no HSYNC RRset", cp.Zone)
				return
			}

			// Convert the RRs to strings for transmission
			hsyncStrs := make([]string, len(hsyncRRset.RRs))
			for i, rr := range hsyncRRset.RRs {
				hsyncStrs[i] = rr.String()
			}
			resp.HsyncRRs = hsyncStrs

			// Get the actual agents from the registry
			resp.Agents = conf.Internal.Registry.GetRemoteAgents(cp.Zone)
			resp.Msg = fmt.Sprintf("HSYNC RRset and agents for zone %s", cp.Zone)

		case "hsync-locate":
			if cp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "No agent identity specified"
				return
			}

			cp.AgentId = dns.Fqdn(cp.AgentId)
			new, agent, err := conf.Internal.Registry.LocateAgent(cp.AgentId)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Failed to locate agent %s: %v", cp.AgentId, err)
				return
			}

			if new {
				resp.Msg = fmt.Sprintf("Located new agent %s", cp.AgentId)
			} else {
				resp.Msg = fmt.Sprintf("Found existing agent %s", cp.AgentId)
			}

			resp.Agents = []*Agent{agent}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown agent command: %s", cp.Command)
			resp.Error = true
		}
	}
}
