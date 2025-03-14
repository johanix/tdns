/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	// "encoding/json"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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
			sanitizedResp := SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		// XXX: hsync cmds should move to its own endpoint, not be mixed with agent
		var zd *ZoneData
		var exist bool
		cp.Zone = dns.Fqdn(cp.Zone)
		if cp.Command != "config" {
			zd, exist = Zones.Get(cp.Zone)
			if !exist {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", cp.Zone)
				return
			}
		}

		switch cp.Command {
		case "config":
			tmp := SanitizeForJSON(conf.Agent)
			resp.AgentConfig = tmp.(LocalAgentConf)
			resp.AgentConfig.Api.CertData = ""
			resp.AgentConfig.Api.KeyData = ""

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
			resp.Agents, err = conf.Internal.Registry.GetRemoteAgents(cp.Zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error getting remote agents: %v", err)
				return
			}
			resp.Msg = fmt.Sprintf("HSYNC RRset and agents for zone %s", cp.Zone)

		case "hsync-locate":
			if cp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "No agent identity specified"
				return
			}

			cp.AgentId = dns.Fqdn(cp.AgentId)
			agent, err := conf.Internal.Registry.GetAgentInfo(cp.AgentId)
			if err != nil {
				// Start async lookup and return a message that lookup is in progress
				conf.Internal.Registry.LocateAgent(cp.AgentId, "")
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent lookup in progress for %s", cp.AgentId)
				return
			}

			// If agent info is incomplete, start a new lookup
			if agent.State == AgentStateNeeded {
				conf.Internal.Registry.LocateAgent(cp.AgentId, "")
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent information is incomplete for %s, lookup in progress", cp.AgentId)
				return
			}

			resp.Agents = []*Agent{agent}
			resp.Msg = fmt.Sprintf("Found existing agent %s", cp.AgentId)

			//		case "list-known-agents":
			//			resp.Agents, err = conf.Internal.Registry.GetRemoteAgents(cp.Zone)

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown agent command: %s", cp.Command)
			resp.Error = true
		}
	}
}

func APIbeat(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.HeartbeatQ == nil {
		log.Println("APIbeat: HeartbeatQ channel is not set. Cannot forward heartbeats. This is a fatal error.")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentMsgResponse{
			Time: time.Now(),
			Msg:  "Hi there!",
		}
		log.Printf("APIbeat: received /beat request from %s.\n", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var bp AgentBeatPost
		err := decoder.Decode(&bp)

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("APIbeat: error encoding response: %v\n", err)
			}
		}()

		if err != nil {
			log.Printf("APIbeat: error decoding beat post: %+v", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		switch bp.MessageType {
		case "BEAT", "FULLBEAT":
			resp.Status = "ok"
			conf.Internal.HeartbeatQ <- AgentMsgReport{
				Transport: "api",
				Msg: &AgentMsgPost{
					MessageType: bp.MessageType,
					Identity:    bp.MyIdentity,
					Time:        time.Now(),
					Zones:       bp.Zones,
				},
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown heartbeat type: %s", bp.MessageType)
		}
	}
}

// This is the agent-to-agent sync API hello handler.
func APIhello(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	if conf.Internal.HelloQ == nil {
		log.Println("APIhello: HelloQ channel is not set. Cannot forward HELLO msgs. This is a fatal error.")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentMsgResponse{
			Time: time.Now(),
		}
		log.Printf("APIhello: received /hello request from %s.\n", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var hp AgentMsgPost
		err := decoder.Decode(&hp)

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("APIhello: error encoding response: %v\n", err)
			}
		}()

		if err != nil {
			log.Printf("APIhello: error decoding hello post: %+v", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		resp.Msg = fmt.Sprintf("Hello there, %s! Nice of you to call on us. I'm a TDNS agent with identity %q.", hp.Identity, conf.Agent.Identity)

		switch hp.MessageType {
		case "HELLO":
			resp.Status = "ok" // important
			conf.Internal.HelloQ <- AgentMsgReport{
				Transport: "api",
				Msg: &AgentMsgPost{
					MessageType: "HELLO",
					Identity:    hp.Identity,
					Time:        time.Now(),
					Zone:        hp.Zone,
				},
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown hello type: %s", hp.MessageType)
		}
	}
}
